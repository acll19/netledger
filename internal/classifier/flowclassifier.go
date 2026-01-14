package classifier

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/acll19/netledger/internal/classifier/statistics"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
)

type PodInfo struct {
	Node string
	IPs  []uint32
}

type NodeInfo struct {
	Zone string
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
	podIndex map[statistics.PodKey]PodInfo,
	podIpIndex map[uint32]statistics.PodKey,
	nodeIndex map[string]string,
	ingStatistics statistics.StatisticMap,
	egStatistics statistics.StatisticMap,
) []FlowLog {
	FlowLogs := make([]FlowLog, 0, len(data))
	processedIngressPods := make(map[string]statistics.PodKey)
	processedEgressPods := make(map[string]statistics.PodKey)
	for _, entry := range data {
		var srcPod, dstPod statistics.PodKey
		srcIp := entry.SrcIP
		dstIp := entry.DstIP
		var srcZone, dstZone string // TODO src & dst regions too

		switch entry.Direction {
		case "egress":
			if entry.PodName != "unknown" {
				processedEgressPods[srcIp] = statistics.PodKey{
					Namespace: entry.PodNamespace,
					Name:      entry.PodName,
				}
				srcPod = statistics.PodKey{
					Namespace: entry.PodNamespace,
					Name:      entry.PodName,
				}
			} else {
				if podMeta, ok := processedEgressPods[srcIp]; ok {
					srcPod = statistics.PodKey{
						Namespace: podMeta.Namespace,
						Name:      podMeta.Name,
					}
				} else {
					parsedIP, err := network.StringIpToNetIp(srcIp)
					if err != nil {
						continue
					}
					pod, ok := podIpIndex[network.IpToUint32(parsedIP)]
					if !ok {
						continue
					}
					if !ok {
						continue
					}
					srcPod = pod
				}
			}
		case "ingress":
			if entry.PodName != "unknown" {
				processedIngressPods[dstIp] = statistics.PodKey{
					Namespace: entry.PodNamespace,
					Name:      entry.PodName,
				}
				dstPod = statistics.PodKey{
					Namespace: entry.PodNamespace,
					Name:      entry.PodName,
				}
			} else {
				if podMeta, ok := processedIngressPods[dstIp]; ok {
					dstPod = statistics.PodKey{
						Namespace: podMeta.Namespace,
						Name:      podMeta.Name,
					}
				} else {
					parsedIP, err := network.StringIpToNetIp(dstIp)
					if err != nil {
						continue
					}
					pod, ok := podIpIndex[network.IpToUint32(parsedIP)]
					if !ok {
						continue
					}
					dstPod = pod
				}
			}
		}

		sp := podIndex[srcPod]
		srcNode := sp.Node
		srcZone = nodeIndex[srcNode]

		dp := podIndex[dstPod]
		dstNode := dp.Node
		dstZone = nodeIndex[dstNode]

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

		currentFlowSize := statistics.FlowSize{
			Traffic: entry.Traffic,
		}

		flowKey := statistics.FlowKey{
			Internet:   network.IsInternetIP(srcParsed) || network.IsInternetIP(dstParsed),
			SameZone:   srcZone == dstZone,
			SameRegion: false, // TODO implement
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
