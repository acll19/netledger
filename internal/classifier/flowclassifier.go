package classifier

import (
	"fmt"
	"net"
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

		var srcZone, dstZone, srcRegion, dstRegion string
		var srcParsed, dstParsed netip.Addr

		srcPod, _ = searchPod(srcIp, entry, opts.PodIpIndex)
		dstPod, _ = searchPod(dstIp, entry, opts.PodIpIndex)

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

		flowKey := metrics.FlowKey{
			Internet:   isInternet,
			SameZone:   srcZone == dstZone,
			SameRegion: srcRegion == dstRegion,
		}

		switch entry.Direction {
		case 0: // egress
			flowKey.PodName = srcPod.Name
			flowKey.Namespace = srcPod.Namespace
			flowKey.PodInitiated = true
			currentFlow := opts.EgStatistics[flowKey]
			opts.EgStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.TxBytes + currentFlow.Traffic,
			}

			// we count RX for the same pod
			currentFlow = opts.IngStatistics[flowKey]
			opts.IngStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.RxBytes + currentFlow.Traffic,
			}
		case 1: // ingress
			flowKey.PodName = dstPod.Name
			flowKey.Namespace = dstPod.Namespace
			currentFlow := opts.IngStatistics[flowKey]
			opts.IngStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.RxBytes + currentFlow.Traffic,
			}

			currentFlow = opts.EgStatistics[flowKey]
			opts.EgStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.TxBytes + currentFlow.Traffic,
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
			Bytes:     int(entry.TxBytes) + int(entry.RxBytes),
		})
	}
	return flowLogs
}

func searchPod(ip string, entry payload.FlowEntry, podIpIndex map[uint32]metrics.PodKey) (metrics.PodKey, bool) {
	if ip == entry.SrcIP && entry.SrcPodName != "" {
		return metrics.PodKey{Name: entry.SrcPodName, Namespace: entry.SrcPodNamespace}, false
	}

	if ip == entry.DstIP && entry.DstPodName != "" {
		return metrics.PodKey{Name: entry.DstPodName, Namespace: entry.DstPodNamespace}, false
	}

	parsedIP, err := network.StringIpToNetIp(ip)
	if err != nil {
		return metrics.PodKey{}, false
	}
	pod, ok := podIpIndex[network.IpToUint32(parsedIP)]

	return pod, ok
}
