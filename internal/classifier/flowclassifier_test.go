package classifier

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/acll19/netledger/internal/classifier/metrics"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createFlowEntry(srcIP, dstIP string, srcPort, dstPort uint16, direction int, txBytes, rxBytes uint64) payload.FlowEntry {
	return payload.FlowEntry{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Direction: direction,
		TxBytes:   txBytes,
		RxBytes:   rxBytes,
	}
}

func createFlowEntryWithPods(srcIP, dstIP string, srcPort, dstPort uint16, direction int, txBytes, rxBytes uint64,
	srcPodName, srcPodNamespace, dstPodName, dstPodNamespace string) payload.FlowEntry {
	entry := createFlowEntry(srcIP, dstIP, srcPort, dstPort, direction, txBytes, rxBytes)
	entry.SrcPodName = srcPodName
	entry.SrcPodNamespace = srcPodNamespace
	entry.DstPodName = dstPodName
	entry.DstPodNamespace = dstPodNamespace
	return entry
}

func createPodIndex() map[metrics.PodKey]PodInfo {
	return map[metrics.PodKey]PodInfo{
		{Name: "pod-1", Namespace: "default"}:  {Node: "node-1", IPs: []uint32{167838209}}, // 10.0.1.1
		{Name: "pod-2", Namespace: "default"}:  {Node: "node-2", IPs: []uint32{167838210}}, // 10.0.1.2
		{Name: "pod-3", Namespace: "kube-sys"}: {Node: "node-1", IPs: []uint32{167838211}}, // 10.0.1.3
	}
}

func createNodeIndex() map[string]NodeInfo {
	return map[string]NodeInfo{
		"node-1": {Zone: "us-east-1a", Region: "us-east-1", InternalIp: "10.0.0.1"},
		"node-2": {Zone: "us-west-1a", Region: "us-west-1", InternalIp: "10.0.0.2"},
	}
}

func createDefaultConfig() Config {
	return Config{
		Destinations: Destinations{
			InZone: []string{
				"10.0.1.0/24",
			},
			InRegion: []string{
				"10.0.0.0/8",
			},
			CrossRegion: []string{
				"172.16.0.0/12",
			},
			Internet: []string{
				"8.8.8.0/24",
			},
			DirectClassification: []DirectClassification{
				{
					Region: "eu-west-1",
					Zone:   "eu-west-1a",
					IPs:    []string{"192.168.0.0/16"},
				},
			},
		},
	}
}

func createTestClassifyOptions(config Config) ClassifyOptions {
	return ClassifyOptions{
		PodIndex:      createPodIndex(),
		PodIpIndex:    map[uint32]metrics.PodKey{},
		NodeIndex:     createNodeIndex(),
		NodeIpIndex:   map[uint32]string{},
		IngStatistics: make(metrics.StatisticMap),
		EgStatistics:  make(metrics.StatisticMap),
		Config:        config,
		Mutex:         &sync.RWMutex{},
	}
}

func TestClassify(t *testing.T) {
	t.Run("should return empty flowlogs when entries are empty", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		data := payload.Flow{Entries: []payload.FlowEntry{}}

		result := Classify(data, opts)

		assert.Empty(t, result)
	})

	t.Run("should classify egress traffic when pod info is embedded in the flow entry", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 1000, 500,
			"pod-1", "default", "pod-2", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		assert.Equal(t, "default/pod-1", result[0].Src)
		assert.Equal(t, "default/pod-2", result[0].Dst)
		assert.Equal(t, network.Egress, result[0].Direction)
		assert.Equal(t, uint64(1500), result[0].Bytes)
	})

	t.Run("should classify ingress traffic when pod info is embedded in the flow entry", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.2", "10.0.1.1", 9000, 8000, network.Ingress, 500, 1000,
			"pod-2", "default", "pod-1", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		assert.Equal(t, "default/pod-2", result[0].Src)
		assert.Equal(t, "default/pod-1", result[0].Dst)
		assert.Equal(t, network.Ingress, result[0].Direction)
		assert.Equal(t, uint64(1500), result[0].Bytes)
	})

	t.Run("should classify egress traffic as in-zone when destination matches in-zone CIDR", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "10.0.1.100", 8000, 80, network.Egress, 2000, 1000,
			"pod-1", "default", "external-pod", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     true,
			SameRegion:   true,
			Internet:     false,
		}
		assert.Equal(t, uint64(2000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should classify egress traffic as in-region when destination matches in-region CIDR", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "10.1.0.1", 8000, 80, network.Egress, 2000, 1000,
			"pod-1", "default", "external-pod", "external",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     false,
			SameRegion:   true,
			Internet:     false,
		}
		assert.Equal(t, uint64(2000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should classify egress traffic as cross-region when destination matches cross-region CIDR", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "172.16.0.1", 8000, 80, network.Egress, 2000, 1000,
			"pod-1", "default", "external-pod", "external",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     false,
			SameRegion:   false,
			Internet:     false,
		}
		assert.Equal(t, uint64(2000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should classify egress traffic as internet when destination matches internet CIDR", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "8.8.8.8", 8000, 53, network.Egress, 2000, 1000,
			"pod-1", "default", "external-dns", "external",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     false,
			SameRegion:   false,
			Internet:     true,
		}
		assert.Equal(t, uint64(2000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should classify egress traffic with direct classification when destination matches direct classification IPs", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "192.168.1.1", 8000, 80, network.Egress, 2000, 1000,
			"pod-1", "default", "external-pod", "external",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     false,
			SameRegion:   false,
			Internet:     false,
		}
		assert.Equal(t, uint64(2000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should classify ingress traffic as in-zone when source matches in-zone CIDR", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.100", "10.0.1.1", 80, 8000, network.Ingress, 1000, 2000,
			"external-pod", "default", "pod-1", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: false,
			SameZone:     true,
			SameRegion:   true,
			Internet:     false,
		}
		assert.Equal(t, uint64(2000), opts.IngStatistics[flowKey].Traffic)
	})

	t.Run("should classify ingress traffic as internet when source matches internet CIDR", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"8.8.8.8", "10.0.1.1", 53, 8000, network.Ingress, 1000, 2000,
			"external-dns", "external", "pod-1", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: false,
			SameZone:     false,
			SameRegion:   false,
			Internet:     true,
		}
		assert.Equal(t, uint64(2000), opts.IngStatistics[flowKey].Traffic)
	})

	t.Run("should classify ingress traffic with direct classification when source matches direct classification IPs", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"192.168.1.1", "10.0.1.1", 80, 8000, network.Ingress, 1000, 2000,
			"external-pod", "external", "pod-1", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: false,
			SameZone:     false,
			SameRegion:   false,
			Internet:     false,
		}
		assert.Equal(t, uint64(2000), opts.IngStatistics[flowKey].Traffic)
	})

	t.Run("should process multiple entries when flow contains multiple entries", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entries := []payload.FlowEntry{
			createFlowEntryWithPods("10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 1000, 500,
				"pod-1", "default", "pod-2", "default"),
			createFlowEntryWithPods("10.0.1.2", "10.0.1.1", 9000, 8000, network.Ingress, 500, 1000,
				"pod-2", "default", "pod-1", "default"),
		}
		data := payload.Flow{Entries: entries}

		result := Classify(data, opts)

		assert.Len(t, result, 2)
		assert.Equal(t, "default/pod-1", result[0].Src)
		assert.Equal(t, "default/pod-2", result[1].Src)
	})

	t.Run("should accumulate statistics when same flow key appears multiple times", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entries := []payload.FlowEntry{
			createFlowEntryWithPods("10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 1000, 500,
				"pod-1", "default", "pod-2", "default"),
			createFlowEntryWithPods("10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 2000, 1000,
				"pod-1", "default", "pod-2", "default"),
		}
		data := payload.Flow{Entries: entries}

		result := Classify(data, opts)

		require.Len(t, result, 2)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     true,
			SameRegion:   true,
			Internet:     false,
		}
		assert.Equal(t, uint64(3000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should update egress statistics when processing egress entry", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "172.16.0.1", 8000, 80, network.Egress, 5000, 3000,
			"pod-1", "default", "external-pod", "external",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		Classify(data, opts)

		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     false,
			SameRegion:   false,
			Internet:     false,
		}
		assert.Equal(t, uint64(5000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should update ingress statistics when processing ingress entry", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"172.16.0.1", "10.0.1.1", 80, 8000, network.Ingress, 3000, 5000,
			"external-pod", "external", "pod-1", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		Classify(data, opts)

		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: false,
			SameZone:     false,
			SameRegion:   false,
			Internet:     false,
		}
		assert.Equal(t, uint64(5000), opts.IngStatistics[flowKey].Traffic)
	})

	t.Run("should update both egress and ingress statistics when processing egress entry", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 1000, 500,
			"pod-1", "default", "pod-2", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		Classify(data, opts)

		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     true,
			SameRegion:   true,
			Internet:     false,
		}
		assert.Equal(t, uint64(1000), opts.EgStatistics[flowKey].Traffic)
		assert.Equal(t, uint64(500), opts.IngStatistics[flowKey].Traffic)
	})

	t.Run("should update both ingress and egress statistics when processing ingress entry", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.2", "10.0.1.1", 9000, 8000, network.Ingress, 500, 1000,
			"pod-2", "default", "pod-1", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		Classify(data, opts)

		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: false,
			SameZone:     true,
			SameRegion:   true,
			Internet:     false,
		}
		assert.Equal(t, uint64(500), opts.EgStatistics[flowKey].Traffic)
		assert.Equal(t, uint64(1000), opts.IngStatistics[flowKey].Traffic)
	})

	t.Run("should mark traffic as internet when destination is internet address for egress", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "200.1.2.3", 8000, 443, network.Egress, 2000, 1000,
			"pod-1", "default", "external-service", "external",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     false,
			SameRegion:   false,
			Internet:     true,
		}
		assert.Equal(t, uint64(2000), opts.EgStatistics[flowKey].Traffic)
	})

	t.Run("should mark traffic as internet when source is internet address for ingress", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"200.1.2.3", "10.0.1.1", 443, 8000, network.Ingress, 1000, 2000,
			"external-service", "external", "pod-1", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: false,
			SameZone:     false,
			SameRegion:   false,
			Internet:     true,
		}
		assert.Equal(t, uint64(2000), opts.IngStatistics[flowKey].Traffic)
	})

	t.Run("should populate flowlog with parsed IPv4 addresses", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 1000, 500,
			"pod-1", "default", "pod-2", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		assert.Equal(t, netip.MustParseAddr("10.0.1.1"), result[0].SrcIP)
		assert.Equal(t, netip.MustParseAddr("10.0.1.2"), result[0].DstIP)
		assert.Equal(t, 8000, result[0].SrcPort)
		assert.Equal(t, 9000, result[0].DstPort)
	})

	t.Run("should calculate bytes as sum of TX and RX bytes", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		txBytes := uint64(5432)
		rxBytes := uint64(3210)
		entry := createFlowEntryWithPods(
			"10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, txBytes, rxBytes,
			"pod-1", "default", "pod-2", "default",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		assert.Equal(t, txBytes+rxBytes, result[0].Bytes)
	})

	t.Run("direct classification should take precedence when multiple classification methods match", func(t *testing.T) {
		// The function checks classifications in order: DirectClassification, Internet, InZone, InRegion, CrossRegion
		// This test ensures that if multiple match, the direct classification is used
		config := createDefaultConfig()
		config.Destinations.DirectClassification = append(config.Destinations.DirectClassification, DirectClassification{
			Region: "eu-central-1",
			Zone:   "eu-central-1a",
			IPs:    []string{"8.8.8.0/24"},
		})

		opts := createTestClassifyOptions(config)
		entry := createFlowEntryWithPods(
			"10.0.1.1", "8.8.8.8", 8000, 53, network.Egress, 2000, 1000,
			"pod-1", "default", "dns-service", "external",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		flowKey := metrics.FlowKey{
			PodName:      "pod-1",
			Namespace:    "default",
			PodInitiated: true,
			SameZone:     false,
			SameRegion:   false,
			Internet:     false,
		}
		_, found := opts.EgStatistics[flowKey]
		assert.True(t, found)
	})

	t.Run("should construct pod names as namespace/name", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntryWithPods(
			"10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 1000, 500,
			"my-pod", "my-namespace", "other-pod", "other-namespace",
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		assert.Equal(t, "my-namespace/my-pod", result[0].Src)
		assert.Equal(t, "other-namespace/other-pod", result[0].Dst)
	})

	t.Run("should lookup pod by IP when pod names are not embedded in the flow entry", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		ip1, _ := network.StringIpToNetIp("10.0.1.1")
		ip2, _ := network.StringIpToNetIp("10.0.1.2")
		opts.PodIpIndex[network.IpToUint32(ip1)] = metrics.PodKey{
			Name:      "pod-1",
			Namespace: "default",
		}
		opts.PodIpIndex[network.IpToUint32(ip2)] = metrics.PodKey{
			Name:      "pod-2",
			Namespace: "default",
		}

		entry := createFlowEntry(
			"10.0.1.1", "10.0.1.2", 8000, 9000, network.Egress, 1000, 500,
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		assert.Equal(t, "default/pod-1", result[0].Src)
		assert.Equal(t, "default/pod-2", result[0].Dst)
	})

	t.Run("should return empty pod key when IP is not found in podIpIndex", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := createFlowEntry(
			"10.0.99.99", "10.0.88.88", 8000, 9000, network.Egress, 1000, 500,
		)
		data := payload.Flow{Entries: []payload.FlowEntry{entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)

		assert.Equal(t, "/", result[0].Src)
		assert.Equal(t, "/", result[0].Dst)
	})

	t.Run("should handle invalid IP string in searchPod", func(t *testing.T) {
		opts := createTestClassifyOptions(createDefaultConfig())
		entry := &payload.FlowEntry{
			SrcIP:     "invalid-ip",
			DstIP:     "also-invalid",
			SrcPort:   8000,
			DstPort:   9000,
			Direction: network.Egress,
			TxBytes:   1000,
			RxBytes:   500,
		}
		data := payload.Flow{Entries: []payload.FlowEntry{*entry}}

		result := Classify(data, opts)

		require.Len(t, result, 1)
		assert.Equal(t, "/", result[0].Src)
		assert.Equal(t, "/", result[0].Dst)
	})
}
