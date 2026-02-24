package classifier

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"

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

type ClassifyOptions struct {
	PodIndex      map[metrics.PodKey]PodInfo
	PodIpIndex    map[uint32]metrics.PodKey
	NodeIndex     map[string]NodeInfo
	NodeIpIndex   map[uint32]string
	SvcIndex      map[string]ck8s.ServiceInfo
	ServiceIpNet  *net.IPNet
	IngStatistics metrics.StatisticMap
	EgStatistics  metrics.StatisticMap
}

func Classify(data []payload.FlowEntry, opts ClassifyOptions) []FlowLog {
	flowLogs := make([]FlowLog, 0, len(data))
	for _, entry := range data {
		var srcPod, dstPod metrics.PodKey
		srcIp := entry.SrcIP
		dstIp := entry.DstIP
		srcPort := entry.SrcPort
		dstPort := entry.DstPort

		srcTarget := fmt.Sprintf("%s:%d", srcIp, srcPort)
		dstTarget := fmt.Sprintf("%s:%d", dstIp, dstPort)

		// Pod to ClusterIP
		if target, ok := opts.SvcIndex[srcTarget]; ok {
			if target.AddrTargetRef[srcIp] != nil {
				srcPod = metrics.PodKey{
					Name:      target.AddrTargetRef[srcIp].Name,
					Namespace: target.AddrTargetRef[srcIp].Namespace,
				}
			}

			randIndex := rand.Intn(len(target.Backends))
			srcIp = target.Backends[randIndex]
		}

		if target, ok := opts.SvcIndex[dstTarget]; ok {
			if target.AddrTargetRef[dstIp] != nil {
				dstPod = metrics.PodKey{
					Name:      target.AddrTargetRef[dstIp].Name,
					Namespace: target.AddrTargetRef[dstIp].Namespace,
				}
			}

			randIndex := rand.Intn(len(target.Backends))
			dstIp = target.Backends[randIndex]
		}
		// end Pod to ClusterIP

		// var isNodePort bool
		// if ip, err := network.StringIpToNetIp(dstIp); err == nil && serviceIpNet.Contains(ip) {
		// 	for _, conn := range nodePortConnections {
		// 		if slices.Contains(conn.Svc.Backends, srcIp) {
		// 			isNodePort = true
		// 		}
		// 	}
		// }

		// var isSelectorlessServiceWithInternetEndpointSlice bool
		// if ip, err := network.StringIpToNetIp(dstIp); err == nil && serviceIpNet.Contains(ip) {
		// 	for _, conn := range otherServiceConnections {
		// 		if conn.Svc.ClusterIP == dstIp {
		// 			isSelectorlessServiceWithInternetEndpointSlice = true
		// 			break
		// 		}
		// 	}
		// }

		var srcZone, dstZone, srcRegion, dstRegion string
		var srcParsed, dstParsed netip.Addr

		if srcPod.Name == "" {
			srcPod, _ = searchPod(srcIp, entry, opts.PodIpIndex)
		}
		if dstPod.Name == "" {
			dstPod, _ = searchPod(dstIp, entry, opts.PodIpIndex)
		}

		srcPodInfo := opts.PodIndex[srcPod]
		srcNode := srcPodInfo.Node
		srcZone = opts.NodeIndex[srcNode].Zone
		srcRegion = opts.NodeIndex[srcNode].Region

		dstPodInfo := opts.PodIndex[dstPod]
		dstNode := dstPodInfo.Node
		dstZone = opts.NodeIndex[dstNode].Zone
		dstRegion = opts.NodeIndex[dstNode].Region

		srcParsed, _ = netip.ParseAddr(srcIp)
		dstParsed, _ = netip.ParseAddr(dstIp)
		isInternet := network.IsInternetIP(srcParsed) || network.IsInternetIP(dstParsed)

		statKey := metrics.FlowKey{
			Internet:   isInternet,
			SameZone:   srcZone == dstZone,
			SameRegion: srcRegion == dstRegion,
		}

		if !isInternet && srcPod.Name != "" && dstPod.Name != "" {
			switch entry.Direction {
			// Because both tx and rx are connection bytes accummulated since the connection was established,
			// we need to subtract the previous value to avoid double counting when we update the flow size for both ingress and egress.
			case 0: // egress
				srcKey := metrics.FlowKey{PodName: srcPod.Name, Namespace: srcPod.Namespace}
				opts.EgStatistics[srcKey] = metrics.FlowSize{
					Traffic: entry.TxBytes + (opts.EgStatistics[srcKey].Traffic - entry.TxBytes),
				}

				opts.IngStatistics[srcKey] = metrics.FlowSize{
					Traffic: entry.RxBytes + (opts.IngStatistics[srcKey].Traffic - entry.RxBytes),
				}

			case 1: // ingress
				dstKey := metrics.FlowKey{PodName: dstPod.Name, Namespace: dstPod.Namespace}
				opts.IngStatistics[dstKey] = metrics.FlowSize{
					Traffic: entry.RxBytes + (opts.IngStatistics[dstKey].Traffic - entry.RxBytes),
				}

				opts.EgStatistics[dstKey] = metrics.FlowSize{
					Traffic: entry.TxBytes + (opts.EgStatistics[dstKey].Traffic - entry.TxBytes),
				}
			}
		} else {
			// This could be
			// - internet,
			// - pod to svc typed ExternalName,
			// - pod to svc without selectors with endpoint slices to public IPs,
			// - external initiated requests to NodePort or LoadBalancer services,
			// - etc.
			switch entry.Direction {
			case 0: // egress
				statKey.PodName = srcPod.Name
				statKey.Namespace = srcPod.Namespace
				currentFlow := opts.EgStatistics[statKey]
				opts.EgStatistics[statKey] = metrics.FlowSize{
					Traffic: entry.TxBytes + (currentFlow.Traffic - entry.TxBytes),
				}

				// we count RX for the same pod
				currentFlow = opts.IngStatistics[statKey]
				opts.IngStatistics[statKey] = metrics.FlowSize{
					Traffic: entry.RxBytes + (currentFlow.Traffic - entry.RxBytes),
				}
			case 1: // ingress
				statKey.PodName = dstPod.Name
				statKey.Namespace = dstPod.Namespace
				currentFlow := opts.IngStatistics[statKey]
				opts.IngStatistics[statKey] = metrics.FlowSize{
					Traffic: entry.RxBytes + (currentFlow.Traffic - entry.RxBytes),
				}

				currentFlow = opts.EgStatistics[statKey]
				opts.EgStatistics[statKey] = metrics.FlowSize{
					Traffic: entry.TxBytes + (currentFlow.Traffic - entry.TxBytes),
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
