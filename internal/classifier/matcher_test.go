package classifier

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"testing"

	"github.com/acll19/netledger/internal/classifier/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMatcherRejectsInvalidCIDR(t *testing.T) {
	tests := []struct {
		name         string
		destinations Destinations
		wantContext  string
	}{
		{
			name: "direct classification",
			destinations: Destinations{
				DirectClassification: []DirectClassification{{IPs: []string{"not-a-cidr"}}},
			},
			wantContext: "direct classification",
		},
		{
			name:         "internet",
			destinations: Destinations{Internet: []string{"not-a-cidr"}},
			wantContext:  "internet",
		},
		{
			name:         "in-zone",
			destinations: Destinations{InZone: []string{"not-a-cidr"}},
			wantContext:  "in-zone",
		},
		{
			name:         "in-region",
			destinations: Destinations{InRegion: []string{"not-a-cidr"}},
			wantContext:  "in-region",
		},
		{
			name:         "cross-region",
			destinations: Destinations{CrossRegion: []string{"not-a-cidr"}},
			wantContext:  "cross-region",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMatcher(tt.destinations)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantContext)
			assert.Contains(t, err.Error(), "not-a-cidr")
		})
	}
}

func TestPrefixTableLookup(t *testing.T) {
	table := newPrefixTable[string]()
	require.NoError(t, table.insert("10.0.0.0/8", "broad"))
	require.NoError(t, table.insert("10.1.0.0/16", "specific"))
	require.NoError(t, table.insert("10.1.2.0/24", "most-specific"))
	require.NoError(t, table.insert("10.1.2.99/24", "duplicate prefix"))
	require.NoError(t, table.insert("2001:db8::/32", "ipv6"))
	table.finalize()

	tests := []struct {
		address string
		want    string
		found   bool
	}{
		{address: "10.1.2.3", want: "most-specific", found: true},
		{address: "10.1.3.3", want: "specific", found: true},
		{address: "10.2.3.4", want: "broad", found: true},
		{address: "2001:db8::1", want: "ipv6", found: true},
		{address: "192.0.2.1", found: false},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			got, ok := table.lookup(netip.MustParseAddr(tt.address))

			assert.Equal(t, tt.found, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDoClassifyUsesMostSpecificDirectClassification(t *testing.T) {
	matcher, err := NewMatcher(Destinations{
		DirectClassification: []DirectClassification{
			{Region: "broad-region", Zone: "broad-zone", IPs: []string{"10.0.0.0/8"}},
			{Region: "specific-region", Zone: "specific-zone", IPs: []string{"10.1.0.0/16"}},
			{Region: "duplicate-region", Zone: "duplicate-zone", IPs: []string{"10.1.0.0/16"}},
		},
	})
	require.NoError(t, err)

	flowKey := metrics.FlowKey{}
	classified := doClassify(netip.MustParseAddr("10.1.2.3"), "specific-region", "specific-zone", &flowKey, matcher)

	assert.True(t, classified)
	assert.True(t, flowKey.SameRegion)
	assert.True(t, flowKey.SameZone)
	assert.False(t, flowKey.Internet)
}

func TestPrefixTableMatchesLinearScanForRandomCIDRs(t *testing.T) {
	random := rand.New(rand.NewSource(42))
	cidrs := make([]string, 256)
	table := newPrefixTable[struct{}]()
	for i := range cidrs {
		address := netip.AddrFrom4([4]byte{
			byte(random.Uint32()),
			byte(random.Uint32()),
			byte(random.Uint32()),
			byte(random.Uint32()),
		})
		cidrs[i] = netip.PrefixFrom(address, random.Intn(33)).String()
		require.NoError(t, table.insert(cidrs[i], struct{}{}))
	}
	table.finalize()

	for i := 0; i < 512; i++ {
		address := netip.AddrFrom4([4]byte{
			byte(random.Uint32()),
			byte(random.Uint32()),
			byte(random.Uint32()),
			byte(random.Uint32()),
		})
		_, got := table.lookup(address)
		assert.Equal(t, linearCIDRMatch(address, cidrs), got, "address %s", address)
	}
}

func linearCIDRMatch(address netip.Addr, cidrs []string) bool {
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		if network.Contains(net.ParseIP(address.String())) {
			return true
		}
	}
	return false
}

func BenchmarkCIDRClassification(b *testing.B) {
	for _, size := range []int{1000, 10000, 30000} {
		cidrs := make([]string, size)
		table := newPrefixTable[struct{}]()
		for i := range cidrs {
			address := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
			cidrs[i] = address.String() + "/32"
			if err := table.insert(cidrs[i], struct{}{}); err != nil {
				b.Fatal(err)
			}
		}
		table.finalize()
		missingAddress := netip.MustParseAddr("192.0.2.1")

		b.Run(fmt.Sprintf("linear/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				linearCIDRMatch(missingAddress, cidrs)
			}
		})
		b.Run(fmt.Sprintf("prefix-table/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				table.lookup(missingAddress)
			}
		})
	}
}
