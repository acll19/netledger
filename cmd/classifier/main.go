// TODO
// agent will send pod namespace and name
// if pod not found assign "unknown"
// should keep map of active pod (pod IP to pod metadata)
// when informed that pod was deleted, move to tombstone cache for 120 seconds...
// ...before deleting for good
// should classify traffic
// should emit Prometheus metric
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/acll19/netledger/internal/payload"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type PodInfo struct {
	Node string
	IPs  []uint32
}

type NodeInfo struct {
	Zone string
}

type FlowSize struct {
	traffic uint64
}

type FlowKey struct {
	podName    string
	namespace  string
	internet   bool
	sameZone   bool
	sameRegion bool
}

type Server struct {
	clientset     *kubernetes.Clientset
	podIpIndex    map[uint32]podKey // maps Pod IPv4s to Pod name
	nodeIpIndex   map[uint32]string // maps Node IPv4s to Node name (for hostNetwork pods)
	podIndex      map[podKey]PodInfo
	nodeIndex     map[string]string // maps node name to Node zone
	ingStatistics map[FlowKey]FlowSize
	egStatistics  map[FlowKey]FlowSize
	mutex         sync.RWMutex
}

func main() {
	kubeconfig := os.Getenv("KUBECONFIG")
	if len(kubeconfig) == 0 {
		log.Fatal("KUBECONFIG environment variable is not set")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatalf("Error creating kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating kubernetes client: %v", err)
	}

	server := &Server{
		clientset:     clientset,
		podIpIndex:    map[uint32]podKey{},
		nodeIpIndex:   map[uint32]string{},
		podIndex:      map[podKey]PodInfo{},
		nodeIndex:     map[string]string{},
		ingStatistics: map[FlowKey]FlowSize{},
		egStatistics:  map[FlowKey]FlowSize{},
	}

	// Start watching Pods and Nodes
	go server.watchPods()
	go server.watchNodes()

	reg := prometheus.NewRegistry()

	reg.MustRegister(server)

	http.Handle("/metrics", instrumentHandler(reg, "metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{})))
	http.Handle("/write-network-statistics", instrumentHandler(reg, "write_statistics", http.HandlerFunc(server.handlePayload)))
	log.Println("Starting server on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func instrumentHandler(reg prometheus.Registerer, handlerName string, handler http.Handler) http.Handler {
	reg = prometheus.WrapRegistererWith(prometheus.Labels{"handler": handlerName}, reg)

	requestsTotal := promauto.With(reg).NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Tracks the number of HTTP requests.",
		}, []string{"method", "code"},
	)

	return promhttp.InstrumentHandlerCounter(requestsTotal, handler)
}

func (s *Server) watchPods() {
	watchList := cache.NewListWatchFromClient(
		s.clientset.CoreV1().RESTClient(),
		"pods",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchList,
		ObjectType:    &v1.Pod{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    s.onPodAdd,
			UpdateFunc: s.onPodUpdate,
			DeleteFunc: s.onPodDelete,
		},
	})

	controller.Run(make(chan struct{}))

}

func (s *Server) watchNodes() {
	watchList := cache.NewListWatchFromClient(
		s.clientset.CoreV1().RESTClient(),
		"nodes",
		metav1.NamespaceAll,
		fields.Everything(),
	)
	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watchList,
		ObjectType:    &v1.Node{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    s.onNodeAdd,
			UpdateFunc: s.onNodeUpdate,
			DeleteFunc: s.onNodeDelete,
		},
	})
	controller.Run(make(chan struct{}))
}

// ipToUint32 converts an IPv4 address to a uint32
func ipToUint32(ip net.IP) uint32 {
	parts := strings.Split(ip.String(), ".")
	var result uint32
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			panic(fmt.Sprintf("Error converting IP part to integer: %s", err))
		}
		result |= uint32(num) << (24 - 8*i)
	}
	return result
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
			hostIP = ipToUint32(parsedHostIP)
		}
	}

	ips := make([]uint32, 0, len(pod.Status.PodIPs))
	for _, podIP := range pod.Status.PodIPs {
		ip := net.ParseIP(podIP.IP)
		if ip == nil || ip.To4() == nil {
			log.Println("ip is not IPv4, currently only IPv4 is supported")
			continue
		}

		ips = append(ips, ipToUint32(ip))
	}

	s.mutex.Lock()
	s.podIndex[podKey{
		namespace: pod.Namespace,
		name:      pod.Name,
	}] = PodInfo{
		Node: pod.Spec.NodeName,
		IPs:  ips,
	}
	for _, ip := range ips {
		// If the pod IP matches the host IP, it's using hostNetwork
		// In this case, use the node as the key instead of the pod
		if hostIP != 0 && ip == hostIP {
			s.nodeIpIndex[ip] = pod.Spec.NodeName
		} else {
			s.podIpIndex[ip] = podKey{
				namespace: pod.Namespace,
				name:      pod.Name,
			}
		}
	}
	s.mutex.Unlock()
}

func (s *Server) onPodUpdate(oldObj, newObj interface{}) {
	s.handlePod(newObj)
}

type podKey struct {
	namespace string
	name      string
}

func (s *Server) onPodDelete(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return
	}
	k := podKey{
		namespace: pod.Namespace,
		name:      pod.Name,
	}

	// Get the host IP to check for hostNetwork pods
	var hostIP uint32
	if pod.Status.HostIP != "" {
		parsedHostIP := net.ParseIP(pod.Status.HostIP)
		if parsedHostIP != nil && parsedHostIP.To4() != nil {
			hostIP = ipToUint32(parsedHostIP)
		}
	}

	s.mutex.Lock()
	info, found := s.podIndex[k]
	if found {
		for _, ip := range info.IPs {
			// Only delete from podIpIndex if it's not a host IP
			// Host IPs are in nodeIpIndex and shared across hostNetwork pods
			if hostIP == 0 || ip != hostIP {
				delete(s.podIpIndex, ip)
			}
		}
		delete(s.podIndex, k)
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
	s.nodeIndex[node.Name] = zone
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
	s.nodeIndex[node.Name] = zone
	s.mutex.Unlock()
}

func (s *Server) onNodeDelete(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}

	// Get node's IP addresses and remove them from nodeIpIndex
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

type flowLog struct {
	src     string
	srcIp   netip.Addr
	srcPort int
	dst     string
	dstIP   netip.Addr
	dstPort int
	bytes   int
}

func Uint32ToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
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

	processedIngressPods := make(map[string]podKey)
	processedEgressPods := make(map[string]podKey)
	for _, entry := range data {
		var srcPod, dstPod podKey
		srcIp := entry.SrcIP
		dstIp := entry.DstIP
		var srcZone, dstZone string // TODO src & dst regions too

		switch entry.Direction {
		case "egress":
			if entry.PodName != "unknown" {
				processedEgressPods[srcIp] = podKey{
					namespace: entry.PodNamespace,
					name:      entry.PodName,
				}
				srcPod = podKey{
					namespace: entry.PodNamespace,
					name:      entry.PodName,
				}
			} else {
				if podMeta, ok := processedEgressPods[srcIp]; ok {
					srcPod = podKey{
						namespace: podMeta.namespace,
						name:      podMeta.name,
					}
				} else {
					ipBytes := strings.Split(srcIp, ".")
					b0, _ := strconv.Atoi(ipBytes[0])
					b1, _ := strconv.Atoi(ipBytes[1])
					b2, _ := strconv.Atoi(ipBytes[2])
					b3, _ := strconv.Atoi(ipBytes[3])
					pod, ok := s.podIpIndex[ipToUint32(net.IPv4(
						byte(b0),
						byte(b1),
						byte(b2),
						byte(b3),
					))]
					if !ok {
						continue
					}
					srcPod = pod
				}
			}
		case "ingress":
			if entry.PodName != "unknown" {
				processedIngressPods[dstIp] = podKey{
					namespace: entry.PodNamespace,
					name:      entry.PodName,
				}
				dstPod = podKey{
					namespace: entry.PodNamespace,
					name:      entry.PodName,
				}
			} else {
				if podMeta, ok := processedIngressPods[dstIp]; ok {
					dstPod = podKey{
						namespace: podMeta.namespace,
						name:      podMeta.name,
					}
				} else {
					ipBytes := strings.Split(dstIp, ".")
					b0, _ := strconv.Atoi(ipBytes[0])
					b1, _ := strconv.Atoi(ipBytes[1])
					b2, _ := strconv.Atoi(ipBytes[2])
					b3, _ := strconv.Atoi(ipBytes[3])
					pod, ok := s.podIpIndex[ipToUint32(net.IPv4(
						byte(b0),
						byte(b1),
						byte(b2),
						byte(b3),
					))]
					if !ok {
						continue
					}
					dstPod = pod
				}
			}
		}

		sp := s.podIndex[srcPod]
		srcNode := sp.Node
		srcZone = s.nodeIndex[srcNode]

		dp := s.podIndex[dstPod]
		dstNode := dp.Node
		dstZone = s.nodeIndex[dstNode]

		srcParsed, err := netip.ParseAddr(srcIp)
		if err != nil {
			log.Printf("Failed to parse src IP: %v", err)
		}
		dstParsed, err := netip.ParseAddr(dstIp)
		if err != nil {
			log.Printf("Failed to parse dst IP: %v", err)
		}

		flowLogs = append(flowLogs, flowLog{
			src:     fmt.Sprintf("%s/%s", srcPod.namespace, srcPod.name),
			srcIp:   srcParsed,
			srcPort: int(entry.SrcPort),
			dst:     fmt.Sprintf("%s/%s", dstPod.namespace, dstPod.name),
			dstIP:   dstParsed,
			dstPort: int(entry.DstPort),
			bytes:   int(entry.Traffic),
		})

		currentFlowSize := FlowSize{
			traffic: entry.Traffic,
		}

		flowKey := FlowKey{
			internet:   isInternetIP(srcParsed) || isInternetIP(dstParsed),
			sameZone:   srcZone == dstZone,
			sameRegion: false, // TODO implement
		}

		if entry.Direction == "ingress" {
			flowKey.podName = dstPod.name
			flowKey.namespace = dstPod.namespace

			if fs, found := s.ingStatistics[flowKey]; found {
				fs.traffic += currentFlowSize.traffic
				s.ingStatistics[flowKey] = fs
			} else {
				s.ingStatistics[flowKey] = currentFlowSize
			}
		} else {
			flowKey.podName = srcPod.name
			flowKey.namespace = srcPod.namespace

			if fs, found := s.egStatistics[flowKey]; found {
				fs.traffic += currentFlowSize.traffic
				s.egStatistics[flowKey] = fs
			} else {
				s.egStatistics[flowKey] = currentFlowSize
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

// isInternetIP returns true if the IP is globally routable
// on the public Internet.
func isInternetIP(ip netip.Addr) bool {
	// Must be global unicast
	if !ip.IsGlobalUnicast() {
		return false
	}

	if ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}

	return true
}

var (
	ingressDesc = prometheus.NewDesc(
		"netledger_pod_network_ingress_bytes_total",
		"The amount of traffic ingressed to the pod",
		[]string{"namespace", "pod_name", "internet", "same_region", "same_zone"},
		nil,
	)

	egressDesc = prometheus.NewDesc(
		"netledger_pod_network_egress_bytes_total",
		"The amount of traffic egressed from the pod",
		[]string{"namespace", "pod_name", "internet", "same_region", "same_zone"},
		nil,
	)
)

func (s *Server) Describe(ch chan<- *prometheus.Desc) {
	ch <- ingressDesc
	ch <- egressDesc
}

func (s *Server) Collect(ch chan<- prometheus.Metric) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for fk, s := range s.ingStatistics {
		ch <- prometheus.MustNewConstMetric(
			ingressDesc,
			prometheus.CounterValue,
			float64(s.traffic),
			fk.namespace,
			fk.podName,
			strconv.FormatBool(fk.internet),
			strconv.FormatBool(fk.sameRegion),
			strconv.FormatBool(fk.sameZone),
		)
	}

	for fk, s := range s.egStatistics {
		ch <- prometheus.MustNewConstMetric(
			egressDesc,
			prometheus.CounterValue,
			float64(s.traffic),
			fk.namespace,
			fk.podName,
			strconv.FormatBool(fk.internet),
			strconv.FormatBool(fk.sameRegion),
			strconv.FormatBool(fk.sameZone),
		)
	}
}
