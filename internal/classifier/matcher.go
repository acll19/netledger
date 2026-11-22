package classifier

import (
	"fmt"
	"net/netip"
	"sort"
)

type prefixTable[V any] struct {
	lens []int
	m    map[netip.Prefix]V
}

func newPrefixTable[V any]() *prefixTable[V] {
	return &prefixTable[V]{m: make(map[netip.Prefix]V)}
}

func (t *prefixTable[V]) insert(cidr string, value V) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	prefix = prefix.Masked()
	if _, exists := t.m[prefix]; !exists {
		t.m[prefix] = value
	}
	return nil
}

func (t *prefixTable[V]) finalize() {
	seen := make(map[int]struct{})
	for prefix := range t.m {
		seen[prefix.Bits()] = struct{}{}
	}

	t.lens = t.lens[:0]
	for length := range seen {
		t.lens = append(t.lens, length)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(t.lens)))
}

func (t *prefixTable[V]) lookup(addr netip.Addr) (V, bool) {
	addr = addr.Unmap()
	for _, length := range t.lens {
		prefix, err := addr.Prefix(length)
		if err == nil {
			if value, ok := t.m[prefix]; ok {
				return value, true
			}
		}
	}

	var zero V
	return zero, false
}

type Matcher struct {
	direct      *prefixTable[DirectClassification]
	internet    *prefixTable[struct{}]
	inZone      *prefixTable[struct{}]
	inRegion    *prefixTable[struct{}]
	crossRegion *prefixTable[struct{}]
}

func NewMatcher(destinations Destinations) (*Matcher, error) {
	matcher := &Matcher{
		direct:      newPrefixTable[DirectClassification](),
		internet:    newPrefixTable[struct{}](),
		inZone:      newPrefixTable[struct{}](),
		inRegion:    newPrefixTable[struct{}](),
		crossRegion: newPrefixTable[struct{}](),
	}

	for _, classification := range destinations.DirectClassification {
		for _, cidr := range classification.IPs {
			if err := matcher.direct.insert(cidr, classification); err != nil {
				return nil, fmt.Errorf("direct classification: %w", err)
			}
		}
	}

	for _, category := range []struct {
		name  string
		cidrs []string
		table *prefixTable[struct{}]
	}{
		{name: "internet", cidrs: destinations.Internet, table: matcher.internet},
		{name: "in-zone", cidrs: destinations.InZone, table: matcher.inZone},
		{name: "in-region", cidrs: destinations.InRegion, table: matcher.inRegion},
		{name: "cross-region", cidrs: destinations.CrossRegion, table: matcher.crossRegion},
	} {
		for _, cidr := range category.cidrs {
			if err := category.table.insert(cidr, struct{}{}); err != nil {
				return nil, fmt.Errorf("%s: %w", category.name, err)
			}
		}
	}

	matcher.direct.finalize()
	matcher.internet.finalize()
	matcher.inZone.finalize()
	matcher.inRegion.finalize()
	matcher.crossRegion.finalize()

	return matcher, nil
}
