package classifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

type DirectClassification struct {
	Region string   `yaml:"region"`
	Zone   string   `yaml:"zone"`
	IPs    []string `yaml:"ips"`
}

type Destinations struct {
	InZone               []string               `yaml:"in-zone"`
	InRegion             []string               `yaml:"in-region"`
	CrossRegion          []string               `yaml:"cross-region"`
	Internet             []string               `yaml:"internet"`
	DirectClassification []DirectClassification `yaml:"direct-classification"`
}

type Config struct {
	Destinations Destinations `yaml:"destinations"`
}

type ConfigSnapshot struct {
	Config  Config
	Matcher *Matcher
	SHA256  string
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

func LoadConfigSnapshot(path string) (ConfigSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ConfigSnapshot{}, err
	}
	return parseConfigSnapshot(data)
}

func parseConfigSnapshot(data []byte) (ConfigSnapshot, error) {
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("parse config: %w", err)
	}

	matcher, err := NewMatcher(config.Destinations)
	if err != nil {
		return ConfigSnapshot{}, err
	}

	sum := sha256.Sum256(data)
	return ConfigSnapshot{
		Config:  config,
		Matcher: matcher,
		SHA256:  hex.EncodeToString(sum[:]),
	}, nil
}

type MatcherHolder struct {
	snapshot        atomic.Pointer[ConfigSnapshot]
	reloadSuccesses atomic.Uint64
	reloadFailures  atomic.Uint64
}

func NewMatcherHolder(snapshot ConfigSnapshot) *MatcherHolder {
	holder := &MatcherHolder{}
	holder.snapshot.Store(&snapshot)
	return holder
}

func (h *MatcherHolder) Get() *Matcher {
	return h.snapshot.Load().Matcher
}

func (h *MatcherHolder) SHA256() string {
	return h.snapshot.Load().SHA256
}

func (h *MatcherHolder) ReloadSuccesses() uint64 {
	return h.reloadSuccesses.Load()
}

func (h *MatcherHolder) ReloadFailures() uint64 {
	return h.reloadFailures.Load()
}

func (h *MatcherHolder) Watch(ctx context.Context, path string, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("config watch interval must be positive")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		data, err := os.ReadFile(path)
		if err != nil {
			h.reloadFailures.Add(1)
			slog.Error("config reload failed; keeping previous configuration", "path", path, "error", err)
			continue
		}

		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		if hash == h.SHA256() {
			continue
		}

		snapshot, err := parseConfigSnapshot(data)
		if err != nil {
			h.reloadFailures.Add(1)
			slog.Error("config reload failed; keeping previous configuration", "path", path, "error", err)
			continue
		}

		h.snapshot.Store(&snapshot)
		h.reloadSuccesses.Add(1)
		shortHash := snapshot.SHA256
		if len(shortHash) > 12 {
			shortHash = shortHash[:12]
		}
		slog.Info("config reloaded", "path", path, "sha256", shortHash)
	}
}
