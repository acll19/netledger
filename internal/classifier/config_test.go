package classifier

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigSnapshotValidatesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("destinations:\n  internet: [not-a-cidr]\n"), 0600))

	_, err := LoadConfigSnapshot(path)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "internet")
	assert.Contains(t, err.Error(), "not-a-cidr")
}

func TestMatcherHolderWatchReloadsValidConfigAndKeepsLastGoodOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	initialConfig := []byte("destinations:\n  internet: [203.0.113.0/24]\n")
	require.NoError(t, os.WriteFile(path, initialConfig, 0600))

	initial, err := LoadConfigSnapshot(path)
	require.NoError(t, err)
	holder := NewMatcherHolder(initial)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- holder.Watch(ctx, path, 5*time.Millisecond)
	}()
	defer func() {
		cancel()
		require.NoError(t, <-done)
	}()

	updatedConfig := []byte("destinations:\n  internet: [198.51.100.0/24]\n")
	writeConfigAtomically(t, path, updatedConfig)
	require.Eventually(t, func() bool {
		return holder.ReloadSuccesses() == 1
	}, time.Second, 5*time.Millisecond)

	updatedHash, err := LoadConfigSnapshot(path)
	require.NoError(t, err)
	assert.Equal(t, updatedHash.SHA256, holder.SHA256())
	assertMatcherMatches(t, holder.Get(), "198.51.100.1", true)
	assertMatcherMatches(t, holder.Get(), "203.0.113.1", false)

	writeConfigAtomically(t, path, []byte("destinations:\n  internet: [invalid]\n"))
	require.Eventually(t, func() bool {
		return holder.ReloadFailures() > 0
	}, time.Second, 5*time.Millisecond)

	assert.Equal(t, updatedHash.SHA256, holder.SHA256())
	assertMatcherMatches(t, holder.Get(), "198.51.100.1", true)
	assertMatcherMatches(t, holder.Get(), "203.0.113.1", false)

	recoveredConfig := []byte("destinations:\n  internet: [192.0.2.0/24]\n")
	writeConfigAtomically(t, path, recoveredConfig)
	require.Eventually(t, func() bool {
		return holder.ReloadSuccesses() == 2
	}, time.Second, 5*time.Millisecond)

	recoveredHash, err := LoadConfigSnapshot(path)
	require.NoError(t, err)
	assert.Equal(t, recoveredHash.SHA256, holder.SHA256())
	assertMatcherMatches(t, holder.Get(), "192.0.2.1", true)
	assertMatcherMatches(t, holder.Get(), "198.51.100.1", false)
}

func writeConfigAtomically(t *testing.T, path string, contents []byte) {
	t.Helper()
	temporaryPath := path + ".tmp"
	require.NoError(t, os.WriteFile(temporaryPath, contents, 0600))
	require.NoError(t, os.Rename(temporaryPath, path))
}

func TestMatcherHolderWatchRequiresPositiveInterval(t *testing.T) {
	snapshot, err := parseConfigSnapshot([]byte("destinations: {}\n"))
	require.NoError(t, err)
	holder := NewMatcherHolder(snapshot)

	err = holder.Watch(context.Background(), "unused", 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "positive")
}

func assertMatcherMatches(t *testing.T, matcher *Matcher, address string, want bool) {
	t.Helper()
	_, got := matcher.internet.lookup(netip.MustParseAddr(address))
	assert.Equal(t, want, got, "address %s", address)
}
