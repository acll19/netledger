package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/acll19/netledger/internal/classifier"
	"github.com/acll19/netledger/internal/classifier/metrics"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	classifierK8s "github.com/acll19/netledger/internal/classifier/kubernetes"
)

type Server struct {
	clientset     *kubernetes.Clientset
	podIpIndex    map[uint32]metrics.PodKey // maps Pod IPv4s to Pod name
	nodeIpIndex   map[uint32]string         // maps Node IPv4s to Node name (for hostNetwork pods)
	podIndex      map[metrics.PodKey]classifier.PodInfo
	nodeIndex     map[string]classifier.NodeInfo
	ingStatistics metrics.StatisticMap
	egStatistics  metrics.StatisticMap
	mutex         sync.RWMutex
}

func NewServer(clientset *kubernetes.Clientset) *Server {
	server := &Server{
		clientset:     clientset,
		podIpIndex:    map[uint32]metrics.PodKey{},
		nodeIpIndex:   map[uint32]string{},
		podIndex:      map[metrics.PodKey]classifier.PodInfo{},
		nodeIndex:     map[string]classifier.NodeInfo{},
		ingStatistics: metrics.StatisticMap{},
		egStatistics:  metrics.StatisticMap{},
	}
	return server
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
	classifierK8s.WatchPods(s.clientset, s.onPodAdd, s.onPodDelete, s.onPodUpdate)
}

func (s *Server) WatchNodes() {
	classifierK8s.WatchNodes(s.clientset, s.onNodeAdd, s.onNodeDelete, s.onNodeUpdate)
}

func (s *Server) onPodAdd(obj any) {
	s.handlePod(obj)
}

func (s *Server) handlePod(obj any) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return
	}

	// Get the host IP to check for hostNetwork pods
	var hostIP uint32
	if pod.Status.HostIP != "" {
		parsedHostIP, _ := network.StringIpToNetIp(pod.Status.HostIP)
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
	s.podIndex[metrics.PodKey{
		Namespace: pod.Namespace,
		Name:      pod.Name,
	}] = classifier.PodInfo{
		Node: pod.Spec.NodeName,
		IPs:  ips,
	}
	for _, ip := range ips {
		// If the pod IP matches the host IP, it's using hostNetwork
		// In this case, use the node as the key instead of the pod
		if hostIP != 0 && ip == hostIP {
			s.nodeIpIndex[ip] = pod.Spec.NodeName
		} else {
			s.podIpIndex[ip] = metrics.PodKey{
				Namespace: pod.Namespace,
				Name:      pod.Name,
			}
		}
	}
	s.mutex.Unlock()
}

func (s *Server) onPodUpdate(oldObj, newObj any) {
	s.handlePod(newObj)
}

func (s *Server) onPodDelete(obj any) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return
	}
	k := metrics.PodKey{
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
	info, found := s.podIndex[k]
	if found {
		for _, ip := range info.IPs {
			// Only delete from podIpIndex if it's not a host IP
			// Host IPs are in NodeIpIndex and shared across hostNetwork pods
			if hostIP == 0 || ip != hostIP {
				delete(s.podIpIndex, ip)
			}
		}
		delete(s.podIndex, k)

		newEgStats := make(metrics.StatisticMap)
		for statK, stat := range s.egStatistics {
			if statK.PodName != k.Name {
				newEgStats[statK] = stat
			}
		}
		s.egStatistics = newEgStats

		newIngStats := make(metrics.StatisticMap)
		for statK, stat := range s.ingStatistics {
			if statK.PodName != k.Name {
				newIngStats[statK] = stat
			}
		}
		s.ingStatistics = newIngStats
	}

	s.mutex.Unlock()
}

func (s *Server) onNodeAdd(obj any) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}
	zone, ok := node.GetLabels()["topology.kubernetes.io/zone"]
	region, ok := node.GetLabels()["topology.kubernetes.io/region"]
	if !ok {
		zone = "unknown"
	}
	s.mutex.Lock()
	s.nodeIndex[node.Name] = classifier.NodeInfo{
		Region: region,
		Zone:   zone,
	}
	s.mutex.Unlock()
}

func (s *Server) onNodeUpdate(oldObj, newObj any) {
	node, ok := newObj.(*v1.Node)
	if !ok {
		return
	}
	zone, ok := node.GetLabels()["topology.kubernetes.io/zone"]
	region, ok := node.GetLabels()["topology.kubernetes.io/region"]
	if !ok {
		zone = "unknown"
	}
	s.mutex.Lock()
	s.nodeIndex[node.Name] = classifier.NodeInfo{
		Zone:   zone,
		Region: region,
	}
	s.mutex.Unlock()
}

func (s *Server) onNodeDelete(obj any) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}

	// Get node's IP addresses and remove them from NodeIpIndex
	s.mutex.Lock()
	// Clean up any node IPs associated with this node
	for ip, nodeName := range s.nodeIpIndex {
		if nodeName == node.Name {
			delete(s.nodeIpIndex, ip)
		}
	}
	delete(s.nodeIndex, node.Name)
	s.mutex.Unlock()
	log.Printf("Node deleted: %s", node.Name)
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

	s.mutex.Lock()
	flowLogs := classifier.Classify(
		data,
		s.podIndex,
		s.podIpIndex,
		s.nodeIndex,
		s.ingStatistics,
		s.egStatistics)
	s.mutex.Unlock()

	for _, fl := range flowLogs {
		log.Println(
			"source",
			fmt.Sprintf("%s(%s:%d)", fl.Src, fl.SrcIP, fl.SrcPort),
			"destination",
			fmt.Sprintf("%s(%s:%d)", fl.Dst, fl.DstIP, fl.DstPort),
			"direction",
			fl.Direction,
			"bytes =",
			strconv.Itoa(fl.Bytes),
		)
	}
}

func (s *Server) Describe(ch chan<- *prometheus.Desc) {
	ch <- metrics.IngressDesc
	ch <- metrics.EgressDesc
}

func (s *Server) Collect(ch chan<- prometheus.Metric) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for fk, s := range s.ingStatistics {
		ch <- prometheus.MustNewConstMetric(
			metrics.IngressDesc,
			prometheus.CounterValue,
			float64(s.Traffic),
			fk.Namespace,
			fk.PodName,
			strconv.FormatBool(fk.Internet),
			strconv.FormatBool(fk.SameRegion),
			strconv.FormatBool(fk.SameZone),
		)
	}

	for fk, s := range s.egStatistics {
		ch <- prometheus.MustNewConstMetric(
			metrics.EgressDesc,
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
