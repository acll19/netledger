package classifier

import (
	"fmt"
	"net/netip"
	"sync"

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
	Src          string
	SrcIP        netip.Addr
	SrcPort      int
	Dst          string
	DstIP        netip.Addr
	DstPort      int
	Direction    int
	Bytes        uint64
	PodInitiated int
	NatGateway   bool
}

type ClassifyOptions struct {
	PodIndex      map[metrics.PodKey]PodInfo
	PodIpIndex    map[uint32]metrics.PodKey
	NodeIndex     map[string]NodeInfo
	NodeIpIndex   map[uint32]string
	IngStatistics metrics.StatisticMap
	EgStatistics  metrics.StatisticMap
	Matcher       *Matcher
	Mutex         *sync.RWMutex
}

func Classify(data payload.Flow, opts ClassifyOptions) []FlowLog {
	flowLogs := make([]FlowLog, 0, len(data.Entries))
	for _, entry := range data.Entries {
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

		flowKey := metrics.FlowKey{}
		flowKey.PodInitiated = true
		if entry.PodInitiated == 0 {
			flowKey.PodInitiated = false
			flowKey.NatGateway = false
		}

		switch entry.Direction {
		case network.Egress:
			classified := doClassify(dstParsed, srcRegion, srcZone, &flowKey, opts.Matcher)
			if !classified {
				isInternet := network.IsInternetIP(dstParsed)
				flowKey.Internet = isInternet
				flowKey.NatGateway = isInternet && flowKey.PodInitiated
				flowKey.SameRegion = srcRegion == dstRegion
				flowKey.SameZone = srcZone == dstZone
			}

			flowKey.PodName = srcPod.Name
			flowKey.Namespace = srcPod.Namespace

			opts.Mutex.Lock()
			currentFlow := opts.EgStatistics[flowKey]
			opts.EgStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.TxBytes + currentFlow.Traffic,
			}

			currentFlow = opts.IngStatistics[flowKey]
			opts.IngStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.RxBytes + currentFlow.Traffic,
			}
			opts.Mutex.Unlock()
		case network.Ingress:
			classified := doClassify(srcParsed, dstRegion, dstZone, &flowKey, opts.Matcher)
			if !classified {
				isInternet := network.IsInternetIP(srcParsed)
				flowKey.Internet = isInternet
				flowKey.NatGateway = isInternet && flowKey.PodInitiated
				flowKey.SameRegion = srcRegion == dstRegion
				flowKey.SameZone = srcZone == dstZone
			}

			flowKey.PodName = dstPod.Name
			flowKey.Namespace = dstPod.Namespace

			opts.Mutex.Lock()
			currentFlow := opts.IngStatistics[flowKey]
			opts.IngStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.RxBytes + currentFlow.Traffic,
			}

			currentFlow = opts.EgStatistics[flowKey]
			opts.EgStatistics[flowKey] = metrics.FlowSize{
				Traffic: entry.TxBytes + currentFlow.Traffic,
			}
			opts.Mutex.Unlock()
		}

		flowLogs = append(flowLogs, FlowLog{
			Src:          fmt.Sprintf("%s/%s", srcPod.Namespace, srcPod.Name),
			SrcIP:        srcParsed,
			SrcPort:      int(entry.SrcPort),
			Dst:          fmt.Sprintf("%s/%s", dstPod.Namespace, dstPod.Name),
			DstIP:        dstParsed,
			DstPort:      int(entry.DstPort),
			Direction:    int(entry.Direction),
			PodInitiated: int(entry.PodInitiated),
			Bytes:        entry.TxBytes + entry.RxBytes,
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

func doClassify(ip netip.Addr, region, zone string, flowKey *metrics.FlowKey, matcher *Matcher) bool {
	if classification, ok := matcher.direct.lookup(ip); ok {
		flowKey.SameRegion = classification.Region == region
		flowKey.SameZone = classification.Zone == zone
		flowKey.Internet = false
		return true
	}

	if _, ok := matcher.internet.lookup(ip); ok {
		flowKey.Internet = true
		flowKey.SameRegion = false
		flowKey.SameZone = false
		flowKey.NatGateway = flowKey.PodInitiated
		return true
	}

	if _, ok := matcher.inZone.lookup(ip); ok {
		flowKey.SameZone = true
		flowKey.SameRegion = true
		flowKey.Internet = false
		return true
	}

	if _, ok := matcher.inRegion.lookup(ip); ok {
		flowKey.SameRegion = true
		flowKey.SameZone = false
		flowKey.Internet = false
		return true
	}

	if _, ok := matcher.crossRegion.lookup(ip); ok {
		flowKey.SameRegion = false
		flowKey.SameZone = false
		flowKey.Internet = false
		return true
	}

	return false
}
