package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	ck8s "github.com/acll19/netledger/internal/classifier/kubernetes"
)

type registeredAgent struct {
	node        string
	startupTime int64
	lastSeen    time.Time
}

type Server struct {
	clientset       *kubernetes.Clientset
	podIpIndex      map[uint32]metrics.PodKey // maps Pod IPv4s to Pod name
	nodeIpIndex     map[uint32]string         // maps Node IPv4s to Node name (for hostNetwork pods)
	podIndex        map[metrics.PodKey]classifier.PodInfo
	nodeIndex       map[string]classifier.NodeInfo
	ingStatistics   metrics.StatisticMap
	egStatistics    metrics.StatisticMap
	svcInformer     cache.SharedIndexInformer
	epSliceInformer cache.SharedIndexInformer
	serviceIpNet    *net.IPNet
	mutex           sync.RWMutex
	agentsHeartBeat map[string]*registeredAgent // map to track registered agents by node name
	config          classifier.Config
	watcherStopCh   chan struct{}
}

func NewServer(clientset *kubernetes.Clientset, serviceIpNet *net.IPNet, config classifier.Config) *Server {
	server := &Server{
		clientset:       clientset,
		serviceIpNet:    serviceIpNet,
		podIpIndex:      map[uint32]metrics.PodKey{},
		nodeIpIndex:     map[uint32]string{},
		podIndex:        map[metrics.PodKey]classifier.PodInfo{},
		nodeIndex:       map[string]classifier.NodeInfo{},
		ingStatistics:   metrics.StatisticMap{},
		egStatistics:    metrics.StatisticMap{},
		agentsHeartBeat: map[string]*registeredAgent{},
		config:          config,
		watcherStopCh:   make(chan struct{}),
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
		slog.Info("Starting server on port 8080...")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
		}
	}()

	go s.cleanupDeadAgents(ctx)

	// Block until SIGTERM
	<-ctx.Done()
	slog.Info("Shutdown signal received")

	// Give outstanding requests time to finish
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return server.Shutdown(shutdownCtx)
}

func (s *Server) cleanupDeadAgents(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	select {
	case <-ctx.Done():
		slog.Info("Stopping registered agent cleanup")
		close(s.watcherStopCh)
		return
	case <-ticker.C:
		s.mutex.Lock()
		threadhold := 60 * time.Minute // TODO: make this configurable
		for node, agent := range s.agentsHeartBeat {
			if time.Since(agent.lastSeen) > threadhold {
				slog.Info("Removing registered agent due to inactivity", "node", node)
				delete(s.agentsHeartBeat, node)
			}
		}
		s.mutex.Unlock()
	}
}

func (s *Server) WatchPods() {
	ck8s.WatchPods(s.watcherStopCh, s.clientset, s.onPodAdd, s.onPodDelete, s.onPodUpdate)
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
			slog.Warn("ip is not IPv4, currently only IPv4 is supported")
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
	ck8s.WatchNodes(s.watcherStopCh, s.clientset, s.onNodeAdd, s.onNodeDelete, s.onNodeUpdate)
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
	slog.Debug("Node deleted", "name", node.Name)
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

	classifyOptions := classifier.ClassifyOptions{
		PodIndex:      s.podIndex,
		PodIpIndex:    s.podIpIndex,
		NodeIndex:     s.nodeIndex,
		NodeIpIndex:   s.nodeIpIndex,
		ServiceIpNet:  s.serviceIpNet,
		IngStatistics: s.ingStatistics,
		EgStatistics:  s.egStatistics,
		Config:        s.config,
		Mutex:         &s.mutex,
	}

	// Do not classify flows from agents that have recently restarted to protect against delta spikes in
	// traffic due to agent restarts.
	agent := data.AgentNode
	startupTime := data.StartupTime
	if _, exists := s.agentsHeartBeat[agent]; !exists {
		slog.Debug(fmt.Sprintf("Registering new agent %s with startup time %d", agent, startupTime))
		s.agentsHeartBeat[agent] = &registeredAgent{
			node:        agent,
			startupTime: startupTime,
			lastSeen:    time.Now(),
		}
	} else {
		s.agentsHeartBeat[agent].lastSeen = time.Now()
		ra := s.agentsHeartBeat[agent]
		if startupTime != ra.startupTime {
			slog.Info(fmt.Sprintf("Skipping data from agent %s due to restart detected (received: %d, registered: %d)", agent, startupTime, ra.startupTime))
			s.agentsHeartBeat[agent].startupTime = startupTime
			return
		}
	}

	flowLogs := classifier.Classify(
		data,
		classifyOptions,
	)

	for _, fl := range flowLogs {
		slog.Debug(
			"Classified flow",
			"source",
			fmt.Sprintf("%s(%s:%d)", fl.Src, fl.SrcIP, fl.SrcPort),
			"destination",
			fmt.Sprintf("%s(%s:%d)", fl.Dst, fl.DstIP, fl.DstPort),
			"direction",
			strconv.Itoa(fl.Direction),
			"bytes",
			strconv.FormatUint(fl.Bytes, 10),
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
			strconv.FormatBool(fk.PodInitiated),
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
			strconv.FormatBool(fk.PodInitiated),
			strconv.FormatBool(fk.Internet),
			strconv.FormatBool(fk.SameRegion),
			strconv.FormatBool(fk.SameZone),
		)
	}
}
