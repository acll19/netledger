package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/acll19/netledger/internal/classifier"
	"github.com/acll19/netledger/internal/classifier/metrics"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	ck8s "github.com/acll19/netledger/internal/classifier/kubernetes"
)

type Server struct {
	clientset       *kubernetes.Clientset
	podIpIndex      map[uint32]metrics.PodKey // maps Pod IPv4s to Pod name
	nodeIpIndex     map[uint32]string         // maps Node IPv4s to Node name (for hostNetwork pods)
	podIndex        map[metrics.PodKey]classifier.PodInfo
	nodeIndex       map[string]classifier.NodeInfo
	svcIndex        map[string]ck8s.ServiceInfo
	ingStatistics   metrics.StatisticMap
	egStatistics    metrics.StatisticMap
	svcInformer     cache.SharedIndexInformer
	epSliceInformer cache.SharedIndexInformer
	serviceIpNet    *net.IPNet
	mutex           sync.RWMutex
}

func NewServer(clientset *kubernetes.Clientset, svcInformer, epSliceInformer cache.SharedIndexInformer, serviceIpNet *net.IPNet) *Server {
	server := &Server{
		clientset:       clientset,
		svcInformer:     svcInformer,
		epSliceInformer: epSliceInformer,
		serviceIpNet:    serviceIpNet,
		podIpIndex:      map[uint32]metrics.PodKey{},
		nodeIpIndex:     map[uint32]string{},
		podIndex:        map[metrics.PodKey]classifier.PodInfo{},
		nodeIndex:       map[string]classifier.NodeInfo{},
		ingStatistics:   metrics.StatisticMap{},
		egStatistics:    metrics.StatisticMap{},
		svcIndex:        map[string]ck8s.ServiceInfo{},
	}
	return server
}

func (s *Server) Start(ctx context.Context, reg *prometheus.Registry) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics",
		instrumentHandler(reg, "metrics",
			promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		),
	)
	mux.Handle("/write-network-statistics",
		instrumentHandler(reg, "write_statistics",
			http.HandlerFunc(s.handlePayload),
		),
	)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		log.Println("Starting server on port 8080...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Block until SIGTERM
	<-ctx.Done()
	log.Println("Shutdown signal received")

	// Give outstanding requests time to finish
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return server.Shutdown(shutdownCtx)
}

func (s *Server) WatchPods() {
	ck8s.WatchPods(s.clientset, s.onPodAdd, s.onPodDelete, s.onPodUpdate)
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

func (s *Server) WatchNodes() {
	ck8s.WatchNodes(s.clientset, s.onNodeAdd, s.onNodeDelete, s.onNodeUpdate)
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

	var ip string
	for _, addr := range node.Status.Addresses {
		if addr.Type == v1.NodeInternalIP {
			ip = addr.Address
			break
		}
	}

	s.mutex.Lock()
	s.nodeIndex[node.Name] = classifier.NodeInfo{
		Region:     region,
		Zone:       zone,
		InternalIp: ip,
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

func (s *Server) WatchServices() {
	ck8s.WatchServices(s.clientset, s.onServiceAdd, s.onServiceDelete, s.onServiceUpdate)
}

func (s *Server) onServiceAdd(obj any) {
	s.handleService(obj)
}

func (s *Server) onServiceDelete(obj any) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		return
	}

	var svcKey string
	for key, svcInfo := range s.svcIndex {
		if svcInfo.Name == svc.Name {
			svcKey = key
			break
		}
	}

	s.mutex.Lock()
	delete(s.svcIndex, svcKey)
	s.mutex.Unlock()
}

func (s *Server) onServiceUpdate(oldObj, newObj any) {
	s.handleService(newObj)
}

func (s *Server) handleService(obj any) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		return
	}

	svcInfo := ck8s.NewServiceInfp(svc)
	if svcInfo.Name == "None" || svcInfo.Name == "" {
		return
	}

	containerPorts := make([]int32, 0)
	for _, port := range svc.Spec.Ports {
		containerPorts = append(containerPorts, port.TargetPort.IntVal)
	}
	svcInfo.ContainerPorts = containerPorts

	addresses := make([]string, 0)
	targetRefs := make(map[string]*v1.ObjectReference)
	eps := ck8s.GetEndpointSlices(s.epSliceInformer)

	isEndpointActive := func(e discovery.Endpoint) bool {
		if !*e.Conditions.Ready {
			return false
		}
		return true
	}

	for _, ep := range eps {
		svcName := ep.Labels["kubernetes.io/service-name"]
		if svcName == svc.Name && ep.Namespace == svc.Namespace {
			for _, e := range ep.Endpoints {
				if isEndpointActive(e) {
					for _, addr := range e.Addresses {
						addresses = append(addresses, addr)
						targetRefs[addr] = e.TargetRef
					}
				}
			}
			svcInfo.Backends = addresses
			svcInfo.AddrTargetRef = targetRefs
			break
		}
	}

	for _, cp := range containerPorts {
		for _, addr := range addresses {
			key := fmt.Sprintf("%s:%d", addr, cp)
			s.mutex.Lock()
			s.svcIndex[key] = svcInfo
			s.mutex.Unlock()
		}
	}
}

func (s *Server) WatchEndpointSlices() {
	ck8s.WatchEndpointSlices(s.clientset, s.onEndpointSliceAdd, s.onEndpointSliceDelete, s.onEndpointSliceUpdate)
}

func (s *Server) onEndpointSliceAdd(obj any) {
	s.handleEndpointSlice(obj)
}

func (s *Server) onEndpointSliceDelete(obj any) {
	eps, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		return
	}

	svcName := eps.Labels["kubernetes.io/service-name"]
	if svcName == "" {
		return
	}

	var svc ck8s.ServiceInfo
	var svcKey string
	for key, svcInfo := range s.svcIndex {
		if svcInfo.Name == svcName {
			svc = s.svcIndex[key]
			svcKey = key
			break
		}
	}

	epsToDelete := make(map[string]struct{}, len(svc.Backends))
	for _, ep := range eps.Endpoints {
		for _, addr := range ep.Addresses {
			epsToDelete[addr] = struct{}{}
		}
	}

	updatedEndpoints := svc.Backends[:0]
	for _, b := range svc.Backends {
		if _, found := epsToDelete[b]; !found {
			updatedEndpoints = append(updatedEndpoints, b)
		}
	}

	svc.Backends = updatedEndpoints

	s.mutex.Lock()
	s.svcIndex[svcKey] = svc
	s.mutex.Unlock()
}

func (s *Server) onEndpointSliceUpdate(oldObj, newObj any) {
	s.handleEndpointSlice(newObj)
}

func (s *Server) handleEndpointSlice(obj any) {
	eps, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		return
	}

	svcName := eps.Labels["kubernetes.io/service-name"]
	if svcName == "" {
		return
	}

	var svcInfo ck8s.ServiceInfo
	for _, si := range s.svcIndex {
		if si.Name == svcName {
			svcInfo = si
			break
		}
	}

	backends := make([]string, 0)
	for _, ep := range eps.Endpoints {
		for _, addr := range ep.Addresses {
			backends = append(backends, addr)
		}
	}

	svcInfo.Backends = append(svcInfo.Backends, backends...)

	for _, cp := range svcInfo.ContainerPorts {
		for _, addr := range backends {
			key := fmt.Sprintf("%s:%d", addr, cp)
			s.mutex.Lock()
			s.svcIndex[key] = svcInfo
			s.mutex.Unlock()
		}
	}

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
		s.egStatistics,
		s.svcIndex,
		s.serviceIpNet,
	)
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
