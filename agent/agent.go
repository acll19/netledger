package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/acll19/netledger/internal/byteorder"
	"github.com/acll19/netledger/internal/cgroup"
	"github.com/acll19/netledger/internal/payload"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func Run(flushInterval time.Duration, node, server string, debug bool) error {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := loadNetledger()
	if err != nil {
		return fmt.Errorf("loading netledger: %w", err)
	}

	var objs netledgerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	var activeLinks []link.Link
	cgroupEgressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.EgressConnectionTracker,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupEgressLink)

	cgroupIngressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.IngressConnectionTracker,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupIngressLink)

	log.Println("Number of active links: ", len(activeLinks))

	defer func() {
		for _, link := range activeLinks {
			if err := link.Close(); err != nil {
				slog.Error("error closing link object:", err)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	informer, err := setupPodInformer(ctx, node)
	if err != nil {
		return fmt.Errorf("setting up informer: %w", err)
	}

	// Channel to listen to interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	size := objs.IpMap.MaxEntries()
	keys := make([]netledgerIpKey, size)
	values := make([]netledgerIpValue, size)
	for {
		select {
		case <-stop:
			slog.Info("Shutting down...")
			return nil
		case <-ctx.Done():
			slog.Info("Shutting down...")
			return nil
		case <-ticker.C:
			slog.Info("reading data from eBPF maps")

			keys = keys[:size]
			values = values[:size]
			opts := &ebpf.BatchOptions{}
			cursor := new(ebpf.MapBatchCursor)
			n, err := objs.IpMap.BatchLookupAndDelete(cursor, keys, values, opts)
			slog.Debug("batch lookup result", "n", n, "err", err, "mapSize", objs.IpMap.MaxEntries())
			if n <= 0 {
				log.Println("no data, skipping")
				continue
			}
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Println("failed to read data:", err)
				continue
			}
			keys = keys[:n]
			values = values[:n]

			podsOnHost := getPods(informer)
			fKeys, fValues := filterSrcOrDstIpOnCurrentHost(keys, values, podsOnHost)

			// debug
			log.Println("debug printing", len(fKeys), "keys", "started with", n, "keys before filtering to host-local pods (", len(keys), ")")
			entries := make([]payload.FlowEntry, 0, len(fKeys))
			for i := range len(fKeys) {
				pod, err := cgroup.GetPodByCgroupID(fKeys[i].CgroupId, podsOnHost)
				var name, ns string
				if err != nil {
					if debug {
						slog.Info("skipping traffic from non-pod cgroup", "cgroup_id", fKeys[i].CgroupId, "reason", err)
					}
					name = "unknown"
					ns = "unknown"
				} else {
					name = pod.Name
					ns = pod.Namespace
				}

				direction := "egress"
				if fKeys[i].Direction == 1 {
					direction = "ingress"
				}

				srcIpSrcIp := net.IPv4(byte(fKeys[i].SrcIp), byte(fKeys[i].SrcIp>>8), byte(fKeys[i].SrcIp>>16), byte(fKeys[i].SrcIp>>24)).String()
				dstIpDstIp := net.IPv4(byte(fKeys[i].DstIp), byte(fKeys[i].DstIp>>8), byte(fKeys[i].DstIp>>16), byte(fKeys[i].DstIp>>24)).String()

				if debug {
					slog.Info(fmt.Sprintf("[%s] %s:%d -> %s:%d: %d bytes (pod: %s/%s)\n", direction, srcIpSrcIp, fKeys[i].SrcPort, dstIpDstIp, fKeys[i].DstPort, fValues[i].PacketSize, ns, name))
				}

				entry := payload.FlowEntry{
					Direction: direction,
					SrcIP:     srcIpSrcIp,
					SrcPort:   fKeys[i].SrcPort,
					DstIP:     dstIpDstIp,
					DstPort:   fKeys[i].DstPort,
					Traffic:   fValues[i].PacketSize,
				}
				entries = append(entries, entry)
			}

			if len(entries) > 0 {
				slog.Info(fmt.Sprintf("Sending %d entries to API server\n", len(entries)))
				serverCtx := context.WithoutCancel(context.Background())
				err := sendDataToServer(serverCtx, server, entries)
				if err != nil {
					slog.Error(err.Error())
				}
			}
		}
	}
}

func setupPodInformer(ctx context.Context, node string) (cache.SharedIndexInformer, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if len(kubeconfig) == 0 {
		return nil, errors.New("KUBECONFIG environment variable is not set")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Error creating kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating kubernetes client: %v", err)
	}

	log.Println("Watching pods for node: ", node)
	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = "spec.nodeName=" + node
		}))
	informer := factory.Core().V1().Pods().Informer()
	go informer.Run(ctx.Done())

	// Wait for the initial LIST to populate the cache
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return nil, fmt.Errorf("timed out waiting for caches to sync")
	}

	return informer, nil
}

func getPods(informer cache.SharedIndexInformer) []*v1.Pod {
	objs := informer.GetStore().List()
	res := make([]*v1.Pod, 0, len(objs))

	for _, obj := range objs {
		res = append(res, obj.(*v1.Pod))
	}

	return res
}

func filterSrcOrDstIpOnCurrentHost(keys []netledgerIpKey, values []netledgerIpValue, podsOnHost []*v1.Pod) ([]netledgerIpKey, []netledgerIpValue) {
	ipsOnHost := make(map[uint32]struct{}, len(podsOnHost)) // pods may have multiple IPs so this is just an approximation

	for _, pod := range podsOnHost {
		for _, podIP := range pod.Status.PodIPs {
			ip := net.ParseIP(podIP.IP)
			if ip == nil || ip.To4() == nil {
				log.Println("ip is not IPv4, currently only IPv4 is supported")
				continue
			}

			ipsOnHost[ipToUint32(ip)] = struct{}{}
		}
	}

	resKeys := make([]netledgerIpKey, 0, len(keys))
	resValues := make([]netledgerIpValue, 0, len(values))
	for i := range keys {
		if _, found := ipsOnHost[byteorder.Ntohl(keys[i].SrcIp)]; found {
			resKeys = append(resKeys, keys[i])
			resValues = append(resValues, values[i])
		} else {
			if _, found := ipsOnHost[byteorder.Ntohl(keys[i].DstIp)]; found {
				resKeys = append(resKeys, keys[i])
				resValues = append(resValues, values[i])
			}
		}
	}

	return resKeys, resValues
}

// ipToUint32 converts an IPv4 address to a uint32
func ipToUint32(ip net.IP) uint32 {
	parts := strings.Split(ip.String(), ".")
	var result uint32
	for i, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil {
			log.Fatalf("Error converting IP part to integer: %s", err)
		}
		result |= uint32(num) << (24 - 8*i)
	}
	return result
}

func sendDataToServer(ctx context.Context, server string, flowEntries []payload.FlowEntry) error {
	content := payload.Encode(flowEntries)
	req, err := http.NewRequest("POST", server, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req = req.WithContext(ctx)

	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer res.Body.Close()

	respContent, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if res.StatusCode != 200 {
		return fmt.Errorf("write not successful: %s", string(respContent))
	}

	return nil
}
