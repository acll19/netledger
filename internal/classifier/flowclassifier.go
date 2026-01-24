package classifier

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/acll19/netledger/internal/classifier/metrics"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
)

type PodInfo struct {
	Node string
	IPs  []uint32
}

type NodeInfo struct {
	Zone   string
	Region string
}

type FlowLog struct {
	Src     string
	SrcIp   netip.Addr
	SrcPort int
	Dst     string
	DstIP   netip.Addr
	DstPort int
	Bytes   int
}

func Classify(data []payload.FlowEntry,
	podIndex map[metrics.PodKey]PodInfo,
	podIpIndex map[uint32]metrics.PodKey,
	nodeIndex map[string]NodeInfo,
	ingStatistics metrics.StatisticMap,
	egStatistics metrics.StatisticMap,
) []FlowLog {
	FlowLogs := make([]FlowLog, 0, len(data))
	processedPods := make(map[string]metrics.PodKey)
	for _, entry := range data {
		var srcPod, dstPod metrics.PodKey
		srcIp := entry.SrcIP
		dstIp := entry.DstIP
		var srcZone, dstZone, srcRegion, dstRegion string
		switch entry.Direction {
		case "egress":
			var podFound bool
			srcPod, podFound = searchPod(processedPods, srcIp, podIpIndex)
			if !podFound {
				continue
			}
			processedPods[srcIp] = srcPod

			dstPod, podFound = searchPod(processedPods, dstIp, podIpIndex)
			if !podFound {
				continue
			}
			processedPods[dstIp] = dstPod
		case "ingress":
			var podFound bool
			dstPod, podFound = searchPod(processedPods, dstIp, podIpIndex)
			if !podFound {
				continue
			}
			processedPods[dstIp] = dstPod

			srcPod, podFound = searchPod(processedPods, srcIp, podIpIndex)
			if !podFound {
				continue
			}
			processedPods[srcIp] = srcPod
		}

		sp := podIndex[srcPod]
		srcNode := sp.Node
		srcZone = nodeIndex[srcNode].Zone
		srcRegion = nodeIndex[srcNode].Region

		dp := podIndex[dstPod]
		dstNode := dp.Node
		dstZone = nodeIndex[dstNode].Zone
		dstRegion = nodeIndex[dstNode].Region

		srcParsed, err := netip.ParseAddr(srcIp)
		if err != nil {
			log.Printf("Failed to parse src IP: %v", err)
		}
		dstParsed, err := netip.ParseAddr(dstIp)
		if err != nil {
			log.Printf("Failed to parse dst IP: %v", err)
		}

		FlowLogs = append(FlowLogs, FlowLog{
			Src:     fmt.Sprintf("%s/%s", srcPod.Namespace, srcPod.Name),
			SrcIp:   srcParsed,
			SrcPort: int(entry.SrcPort),
			Dst:     fmt.Sprintf("%s/%s", dstPod.Namespace, dstPod.Name),
			DstIP:   dstParsed,
			DstPort: int(entry.DstPort),
			Bytes:   int(entry.Traffic),
		})

		currentFlowSize := metrics.FlowSize{
			Traffic: entry.Traffic,
		}

		flowKey := metrics.FlowKey{
			Internet:   network.IsInternetIP(srcParsed) || network.IsInternetIP(dstParsed),
			SameZone:   srcZone == dstZone,
			SameRegion: srcRegion == dstRegion,
		}

		if entry.Direction == "ingress" {
			flowKey.PodName = dstPod.Name
			flowKey.Namespace = dstPod.Namespace

			if fs, found := ingStatistics[flowKey]; found {
				fs.Traffic += currentFlowSize.Traffic
				ingStatistics[flowKey] = fs
			} else {
				ingStatistics[flowKey] = currentFlowSize
			}
		} else {
			flowKey.PodName = srcPod.Name
			flowKey.Namespace = srcPod.Namespace

			if fs, found := egStatistics[flowKey]; found {
				fs.Traffic += currentFlowSize.Traffic
				egStatistics[flowKey] = fs
			} else {
				egStatistics[flowKey] = currentFlowSize
			}
		}

	}
	return FlowLogs
}

func searchPod(processedPods map[string]metrics.PodKey, ip string, podIpIndex map[uint32]metrics.PodKey) (metrics.PodKey, bool) {
	if podMeta, ok := processedPods[ip]; ok {
		pod := metrics.PodKey{
			Namespace: podMeta.Namespace,
			Name:      podMeta.Name,
		}
		return pod, true
	} else {
		parsedIP, err := network.StringIpToNetIp(ip)
		if err != nil {
			return metrics.PodKey{}, false
		}
		pod, ok := podIpIndex[network.IpToUint32(parsedIP)]
		return pod, ok
	}
}
