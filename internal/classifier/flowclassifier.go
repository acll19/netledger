package classifier

import (
	"fmt"
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
	Src       string
	SrcIP     netip.Addr
	SrcPort   int
	Dst       string
	DstIP     netip.Addr
	DstPort   int
	Direction int
	Bytes     int
}

func Classify(data []payload.FlowEntry,
	podIndex map[metrics.PodKey]PodInfo,
	podIpIndex map[uint32]metrics.PodKey,
	nodeIndex map[string]NodeInfo,
	ingStatistics metrics.StatisticMap,
	egStatistics metrics.StatisticMap,
) []FlowLog {
	flowLogs := make([]FlowLog, 0, len(data))
	for _, entry := range data {
		var srcPod, dstPod metrics.PodKey
		srcIp := entry.SrcIP
		dstIp := entry.DstIP
		var srcZone, dstZone, srcRegion, dstRegion string
		var srcParsed, dstParsed netip.Addr

		srcPod, _ = searchPod(srcIp, entry, podIpIndex)
		dstPod, _ = searchPod(dstIp, entry, podIpIndex)

		srcPodInfo := podIndex[srcPod]
		srcNode := srcPodInfo.Node
		srcZone = nodeIndex[srcNode].Zone
		srcRegion = nodeIndex[srcNode].Region

		dstPodInfo := podIndex[dstPod]
		dstNode := dstPodInfo.Node
		dstZone = nodeIndex[dstNode].Zone
		dstRegion = nodeIndex[dstNode].Region

		srcParsed, _ = netip.ParseAddr(srcIp)
		dstParsed, _ = netip.ParseAddr(dstIp)

		isInternet := network.IsInternetIP(srcParsed) || network.IsInternetIP(dstParsed)

		flowKey := metrics.FlowKey{
			Internet:   isInternet,
			SameZone:   srcZone == dstZone,
			SameRegion: srcRegion == dstRegion,
		}

		if !isInternet && srcPod.Name != "" && dstPod.Name != "" {
			flowKey.PodName = srcPod.Name
			flowKey.Namespace = srcPod.Namespace
			currentFlow := egStatistics[flowKey]
			egStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.TxBytes + currentFlow.Traffic,
			}

			flowKey.PodName = dstPod.Name
			flowKey.Namespace = dstPod.Namespace
			currentFlow = ingStatistics[flowKey]
			ingStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.RxBytes + currentFlow.Traffic,
			}
		}

		if isInternet {
			switch entry.Direction {
			case 0: // egress
				flowKey.PodName = srcPod.Name
				flowKey.Namespace = srcPod.Namespace
				currentFlow := egStatistics[flowKey]
				egStatistics[flowKey] = metrics.FlowSize{
					Traffic: entry.TxBytes + currentFlow.Traffic,
				}
			case 1: // ingress
				flowKey.PodName = dstPod.Name
				flowKey.Namespace = dstPod.Namespace
				currentFlow := ingStatistics[flowKey]
				ingStatistics[flowKey] = metrics.FlowSize{
					Traffic: entry.RxBytes + currentFlow.Traffic,
				}
			}
		}

		flowLogs = append(flowLogs, FlowLog{
			Src:       fmt.Sprintf("%s/%s", srcPod.Namespace, srcPod.Name),
			SrcIP:     srcParsed,
			SrcPort:   int(entry.SrcPort),
			Dst:       fmt.Sprintf("%s/%s", dstPod.Namespace, dstPod.Name),
			DstIP:     dstParsed,
			DstPort:   int(entry.DstPort),
			Direction: entry.Direction,
			Bytes:     int(entry.TxBytes) + int(entry.RxBytes), // show total for now
		})
	}
	return flowLogs
}

func searchPod(ip string, entry payload.FlowEntry, podIpIndex map[uint32]metrics.PodKey) (metrics.PodKey, bool) {
	parsedIP, err := network.StringIpToNetIp(ip)
	if err != nil {
		return metrics.PodKey{}, false
	}
	pod, ok := podIpIndex[network.IpToUint32(parsedIP)]

	if !ok {
		if ip == entry.SrcIP && entry.SrcPodName != "" {
			return metrics.PodKey{Name: entry.SrcPodName, Namespace: entry.SrcPodNamespace}, false
		}
		if ip == entry.DstIP && entry.DstPodName != "" {
			return metrics.PodKey{Name: entry.DstPodName, Namespace: entry.DstPodNamespace}, false
		}
	}
	return pod, ok
}
