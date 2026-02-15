package classifier

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	ck8s "github.com/acll19/netledger/internal/classifier/kubernetes"
	"github.com/acll19/netledger/internal/classifier/metrics"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
)

type PodInfo struct {
	Node string
	IPs  []uint32
}

type NodeInfo struct {
	Zone       string
	Region     string
	InternalIp string
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
	svcIndex map[string]ck8s.ServiceInfo,
	serviceIpNet *net.IPNet,
) []FlowLog {
	flowLogs := make([]FlowLog, 0, len(data))
	nodePortConnections, otherServiceConnections, cursor := processHostConnections(data, nodeIndex, svcIndex)

	for i := cursor; i < len(data); i++ {
		entry := data[i]
		var srcPod, dstPod metrics.PodKey
		srcIp := entry.SrcIP
		dstIp := entry.DstIP
		srcPort := entry.SrcPort
		dstPort := entry.DstPort

		srcTarget := fmt.Sprintf("%s:%d", srcIp, srcPort)
		dstTarget := fmt.Sprintf("%s:%d", dstIp, dstPort)

		if target, ok := svcIndex[srcTarget]; ok {
			slog.Info("Found service for src target", slog.String("target", target.Name))
		}
		if target, ok := svcIndex[dstTarget]; ok {
			slog.Info("Found service for dst target", slog.String("target", target.Name))
		}

		var isNodePort bool
		if ip, err := network.StringIpToNetIp(dstIp); err == nil && serviceIpNet.Contains(ip) {
			for _, conn := range nodePortConnections {
				if slices.Contains(conn.Svc.Backends, srcIp) {
					isNodePort = true
				}
			}
		}

		var isSelectorlessServiceWithInternetEndpointSlice bool
		if ip, err := network.StringIpToNetIp(dstIp); err == nil && serviceIpNet.Contains(ip) {
			for _, conn := range otherServiceConnections {
				if conn.Svc.ClusterIP == dstIp {
					isSelectorlessServiceWithInternetEndpointSlice = true
					break
				}
			}
		}

		// check if srcIp is a service (take a random backend)
		// if ip, err := network.StringIpToNetIp(srcIp); err == nil && serviceIpNet.Contains(ip) {
		// 	if addrs, ok := svcIndex[srcIp]; ok {
		// 		randIndex := rand.Intn(len(addrs.Backends))
		// 		srcIp = addrs.Backends[randIndex]
		// 	}
		// }

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
		isInternet := isNodePort ||
			isSelectorlessServiceWithInternetEndpointSlice ||
			network.IsInternetIP(srcParsed) ||
			network.IsInternetIP(dstParsed)

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
		} else {
			// This could be
			// - internet,
			// - pod to svc typed ExternalName,
			// - pod to svc without selectors with endpoint slices to public IPs,
			// - external initiated requests to pod,
			// - etc.
			switch entry.Direction {
			case 0: // egress
				flowKey.PodName = srcPod.Name
				flowKey.Namespace = srcPod.Namespace
				currentFlow := egStatistics[flowKey]
				egStatistics[flowKey] = metrics.FlowSize{
					Traffic: entry.TxBytes + currentFlow.Traffic,
				}

				// we count RX for the same pod
				currentFlow = ingStatistics[flowKey]
				ingStatistics[flowKey] = metrics.FlowSize{
					Traffic: entry.RxBytes + currentFlow.Traffic,
				}
			case 1: // ingress
				flowKey.PodName = dstPod.Name
				flowKey.Namespace = dstPod.Namespace
				currentFlow := ingStatistics[flowKey]
				ingStatistics[flowKey] = metrics.FlowSize{
					Traffic: entry.RxBytes + currentFlow.Traffic,
				}

				currentFlow = egStatistics[flowKey]
				egStatistics[flowKey] = metrics.FlowSize{
					Traffic: entry.TxBytes + currentFlow.Traffic,
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

type svcConnection struct {
	Conn payload.FlowEntry
	Svc  ck8s.ServiceInfo
}

func processHostConnections(data []payload.FlowEntry,
	nodeIndex map[string]NodeInfo,
	svcIndex map[string]ck8s.ServiceInfo) (map[string]svcConnection, map[string]svcConnection, int) {

	nodePortConnections := make(map[string]svcConnection, len(data))
	otherServiceConnections := make(map[string]svcConnection, len(data))

	nodePortServices := make([]ck8s.ServiceInfo, 0)
	for _, svc := range svcIndex {
		if len(svc.NodePorts) > 0 {
			nodePortServices = append(nodePortServices, svc)
		}
	}

	nodeIps := make([]string, 0, len(nodeIndex))
	for _, nodeInfo := range nodeIndex {
		nodeIps = append(nodeIps, nodeInfo.InternalIp)
	}

	cursor := 0
	for cursor < len(data) {
		d := data[cursor]
		slog.Info(d.SrcIP + " -> " + d.DstIP)
		if d.IsObservedInHost != 1 {
			break
		}

		dstIp := d.DstIP
		srcIp := d.SrcIP
		if slices.Contains(nodeIps, dstIp) {
			dstPort := d.DstPort
			for _, svc := range nodePortServices {
				for _, p := range svc.NodePorts {
					if p == int32(dstPort) {
						nodePortConnections[dstIp] = svcConnection{
							Conn: d,
							Svc:  svc,
						}
					}
				}
			}
		}

		if slices.Contains(nodeIps, srcIp) {
			for _, svc := range svcIndex {
				for _, b := range svc.Backends {
					if b == dstIp {
						otherServiceConnections[svc.ClusterIP] = svcConnection{
							Conn: d,
							Svc:  svc,
						}
					}
				}
			}
		}

		cursor++
	}
	return nodePortConnections, otherServiceConnections, cursor
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
