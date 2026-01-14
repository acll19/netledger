package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"

	"github.com/acll19/netledger/internal/classifier/statistics"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	classifierK8s "github.com/acll19/netledger/internal/classifier/kubernetes"
)

type PodInfo struct {
	Node string
	IPs  []uint32
}

type NodeInfo struct {
	Zone string
}

type Server struct {
	Clientset     *kubernetes.Clientset
	PodIpIndex    map[uint32]statistics.PodKey // maps Pod IPv4s to Pod name
	NodeIpIndex   map[uint32]string            // maps Node IPv4s to Node name (for hostNetwork pods)
	PodIndex      map[statistics.PodKey]PodInfo
	NodeIndex     map[string]string // maps node name to Node zone
	IngStatistics statistics.StatisticMap
	EgStatistics  statistics.StatisticMap
	mutex         sync.RWMutex
}

func (s *Server) Start(reg *prometheus.Registry) {
	http.Handle("/metrics", instrumentHandler(reg, "metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{})))
	http.Handle("/write-network-statistics", instrumentHandler(reg, "write_statistics", http.HandlerFunc(s.handlePayload)))
	log.Println("Starting server on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (s *Server) WatchPods() {
	classifierK8s.WatchPods(s.Clientset, s.onPodAdd, s.onPodDelete, s.onPodUpdate)
}

func (s *Server) WatchNodes() {
	classifierK8s.WatchNodes(s.Clientset, s.onNodeAdd, s.onNodeDelete, s.onNodeUpdate)
}

func (s *Server) onPodAdd(obj interface{}) {
	s.handlePod(obj)
}

func (s *Server) handlePod(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return
	}

	// Get the host IP to check for hostNetwork pods
	var hostIP uint32
	if pod.Status.HostIP != "" {
		parsedHostIP := net.ParseIP(pod.Status.HostIP)
		if parsedHostIP != nil && parsedHostIP.To4() != nil {
			hostIP = network.IpToUint32(parsedHostIP)
		}
	}

	ips := make([]uint32, 0, len(pod.Status.PodIPs))
	for _, podIP := range pod.Status.PodIPs {
		ip := net.ParseIP(podIP.IP)
		if ip == nil || ip.To4() == nil {
			log.Println("ip is not IPv4, currently only IPv4 is supported")
			continue
		}

		ips = append(ips, network.IpToUint32(ip))
	}

	s.mutex.Lock()
	s.PodIndex[statistics.PodKey{
		Namespace: pod.Namespace,
		Name:      pod.Name,
	}] = PodInfo{
		Node: pod.Spec.NodeName,
		IPs:  ips,
	}
	for _, ip := range ips {
		// If the pod IP matches the host IP, it's using hostNetwork
		// In this case, use the node as the key instead of the pod
		if hostIP != 0 && ip == hostIP {
			s.NodeIpIndex[ip] = pod.Spec.NodeName
		} else {
			s.PodIpIndex[ip] = statistics.PodKey{
				Namespace: pod.Namespace,
				Name:      pod.Name,
			}
		}
	}
	s.mutex.Unlock()
}

func (s *Server) onPodUpdate(oldObj, newObj interface{}) {
	s.handlePod(newObj)
}

func (s *Server) onPodDelete(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return
	}
	k := statistics.PodKey{
		Namespace: pod.Namespace,
		Name:      pod.Name,
	}

	// Get the host IP to check for hostNetwork pods
	var hostIP uint32
	if pod.Status.HostIP != "" {
		parsedHostIP := net.ParseIP(pod.Status.HostIP)
		if parsedHostIP != nil && parsedHostIP.To4() != nil {
			hostIP = network.IpToUint32(parsedHostIP)
		}
	}

	s.mutex.Lock()
	info, found := s.PodIndex[k]
	if found {
		for _, ip := range info.IPs {
			// Only delete from podIpIndex if it's not a host IP
			// Host IPs are in NodeIpIndex and shared across hostNetwork pods
			if hostIP == 0 || ip != hostIP {
				delete(s.PodIpIndex, ip)
			}
		}
		delete(s.PodIndex, k)
	}

	// TODO: must delete from statistics (ing and eg)
	s.mutex.Unlock()
}

func (s *Server) onNodeAdd(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}
	zone, ok := node.GetLabels()["topology.kubernetes.io/zone"]
	if !ok {
		zone = "unknown"
	}
	s.mutex.Lock()
	s.NodeIndex[node.Name] = zone
	s.mutex.Unlock()
}

func (s *Server) onNodeUpdate(oldObj, newObj interface{}) {
	node, ok := newObj.(*v1.Node)
	if !ok {
		return
	}
	zone, ok := node.GetLabels()["topology.kubernetes.io/zone"]
	if !ok {
		zone = "unknown"
	}
	s.mutex.Lock()
	s.NodeIndex[node.Name] = zone
	s.mutex.Unlock()
}

func (s *Server) onNodeDelete(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}

	// Get node's IP addresses and remove them from NodeIpIndex
	s.mutex.Lock()
	// Clean up any node IPs associated with this node
	for ip, nodeName := range s.NodeIpIndex {
		if nodeName == node.Name {
			delete(s.NodeIpIndex, ip)
		}
	}
	delete(s.NodeIndex, node.Name)
	s.mutex.Unlock()
	log.Printf("Node deleted: %s", node.Name)
}

type flowLog struct {
	src     string
	srcIp   netip.Addr
	srcPort int
	dst     string
	dstIP   netip.Addr
	dstPort int
	bytes   int
}

func (s *Server) handlePayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	data, err := payload.Decode(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	flowLogs := make([]flowLog, 0, len(data))

	s.mutex.Lock()

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
					pod, ok := s.PodIpIndex[network.IpToUint32(parsedIP)]
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
					pod, ok := s.PodIpIndex[network.IpToUint32(parsedIP)]
					if !ok {
						continue
					}
					dstPod = pod
				}
			}
		}

		sp := s.PodIndex[srcPod]
		srcNode := sp.Node
		srcZone = s.NodeIndex[srcNode]

		dp := s.PodIndex[dstPod]
		dstNode := dp.Node
		dstZone = s.NodeIndex[dstNode]

		srcParsed, err := netip.ParseAddr(srcIp)
		if err != nil {
			log.Printf("Failed to parse src IP: %v", err)
		}
		dstParsed, err := netip.ParseAddr(dstIp)
		if err != nil {
			log.Printf("Failed to parse dst IP: %v", err)
		}

		flowLogs = append(flowLogs, flowLog{
			src:     fmt.Sprintf("%s/%s", srcPod.Namespace, srcPod.Name),
			srcIp:   srcParsed,
			srcPort: int(entry.SrcPort),
			dst:     fmt.Sprintf("%s/%s", dstPod.Namespace, dstPod.Name),
			dstIP:   dstParsed,
			dstPort: int(entry.DstPort),
			bytes:   int(entry.Traffic),
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

			if fs, found := s.IngStatistics[flowKey]; found {
				fs.Traffic += currentFlowSize.Traffic
				s.IngStatistics[flowKey] = fs
			} else {
				s.IngStatistics[flowKey] = currentFlowSize
			}
		} else {
			flowKey.PodName = srcPod.Name
			flowKey.Namespace = srcPod.Namespace

			if fs, found := s.EgStatistics[flowKey]; found {
				fs.Traffic += currentFlowSize.Traffic
				s.EgStatistics[flowKey] = fs
			} else {
				s.EgStatistics[flowKey] = currentFlowSize
			}
		}

	}

	s.mutex.Unlock()

	for _, flowLog := range flowLogs {
		log.Println(flowLog.src,
			"(",
			flowLog.srcIp,
			")",
			"from port",
			flowLog.srcPort,
			"to",
			flowLog.dst,
			"(",
			flowLog.dstIP,
			")",
			"at port",
			flowLog.dstPort,
			"with",
			strconv.Itoa(flowLog.bytes),
			"bytes")
	}
}

func (s *Server) Describe(ch chan<- *prometheus.Desc) {
	ch <- statistics.IngressDesc
	ch <- statistics.EgressDesc
}

func (s *Server) Collect(ch chan<- prometheus.Metric) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for fk, s := range s.IngStatistics {
		ch <- prometheus.MustNewConstMetric(
			statistics.IngressDesc,
			prometheus.CounterValue,
			float64(s.Traffic),
			fk.Namespace,
			fk.PodName,
			strconv.FormatBool(fk.Internet),
			strconv.FormatBool(fk.SameRegion),
			strconv.FormatBool(fk.SameZone),
		)
	}

	for fk, s := range s.EgStatistics {
		ch <- prometheus.MustNewConstMetric(
			statistics.EgressDesc,
			prometheus.CounterValue,
			float64(s.Traffic),
			fk.Namespace,
			fk.PodName,
			strconv.FormatBool(fk.Internet),
			strconv.FormatBool(fk.SameRegion),
			strconv.FormatBool(fk.SameZone),
		)
	}
}
