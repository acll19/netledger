package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/acll19/netledger/internal/agent/bpf"
	"github.com/acll19/netledger/internal/agent/cgroup"
	"github.com/acll19/netledger/internal/agent/kubernetes"
	"github.com/acll19/netledger/internal/network"
	"github.com/acll19/netledger/internal/payload"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	v1 "k8s.io/api/core/v1"
)

type podEvent struct {
	eventType string
	pod       *v1.Pod
}

type Agent struct {
	Node           string
	Server         string
	StartupTime    int64
	Interval       time.Duration
	podCgroupCache map[uint64]*v1.Pod
	cgroupPodCache map[string][]uint64 // map of pod UID to slice of cgroup IDs for handling pod deletions
	podChannel     chan podEvent
	httpClient     *http.Client
	objs           *bpf.NetLedgerObjects
}

func NewAgent(objs *bpf.NetLedgerObjects, node, server string, startupTime int64, interval time.Duration) *Agent {
	var httpClient = &http.Client{
		Timeout: 2 * time.Second, // TODO: consider making this configurable
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout:   500 * time.Millisecond, // TODO: consider making this configurable
				KeepAlive: 30 * time.Second,       // TODO: consider making this configurable
			}).DialContext,
			TLSHandshakeTimeout:   500 * time.Millisecond, // TODO: consider making this configurable
			ResponseHeaderTimeout: 1 * time.Second,        // TODO: consider making this configurable
			ExpectContinueTimeout: 200 * time.Millisecond, // TODO: consider making this configurable
		},
	}

	return &Agent{
		Node:           node,
		Server:         server,
		StartupTime:    startupTime,
		Interval:       interval,
		podCgroupCache: make(map[uint64]*v1.Pod),
		cgroupPodCache: make(map[string][]uint64),
		podChannel:     make(chan podEvent, 100), // TODO: consider making this buffer size configurable
		httpClient:     httpClient,
		objs:           objs,
	}
}

func LoadEBPF() (*bpf.NetLedgerObjects, []link.Link, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := bpf.LoadNetLedger()
	if err != nil {
		return nil, nil, fmt.Errorf("loading netledger: %w", err)
	}

	if err := os.MkdirAll("/sys/fs/bpf/netledger", 0755); err != nil {
		return nil, nil, fmt.Errorf("error creating directory for pinning eBPF maps: %w", err)
	}
	var objs bpf.NetLedgerObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/netledger",
		},
	}
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		return nil, nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	activeLinks := make([]link.Link, 0)
	cgroupEgressLink, err := bpf.AttachRootCgroup(objs.CgEgress, ebpf.AttachCGroupInetEgress)
	if err != nil {
		return nil, nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupEgressLink)

	cgroupIngressLink, err := bpf.AttachRootCgroup(objs.CgIngress, ebpf.AttachCGroupInetIngress)
	if err != nil {
		return nil, nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupIngressLink)

	cgroupConnectLink, err := bpf.AttachRootCgroup(objs.CgConnect4, ebpf.AttachCGroupInet4Connect)
	if err != nil {
		return nil, nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupConnectLink)

	cgroupBindLink, err := bpf.AttachRootCgroup(objs.CgBind4, ebpf.AttachCGroupInet4Bind)
	if err != nil {
		return nil, nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupBindLink)

	cgroupSockopsLink, err := bpf.AttachRootCgroup(objs.TcpSockops, ebpf.AttachCGroupSockOps)
	if err != nil {
		return nil, nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupSockopsLink)
	slog.Info("Number of active links", "count", len(activeLinks))

	slog.Debug("AKII: before")
	eth0Iface, err := bpf.GetHostEth0Iface()
	if err != nil {
		return nil, nil, fmt.Errorf("getting eth0 interface: %w", err)
	}

	// The IDEA is capture hostNetwork traffic at TC and correlate with cgroup data.
	// The problem is that Cilium modifies the data path and traffic from such pods does not traverse through the nodes eth0 interface.
	// How to solve that?
	slog.Debug("AKII: got eth0 interface", "name", eth0Iface.Name, "index", eth0Iface.Index)
	// li, err := bpf.AttachTcxToInterface(eth0Iface, objs.TcIngress, ebpf.AttachTCXIngress)
	// if err != nil {
	// 	slog.Error("attaching TCX to eth0 interface", "error", err)
	// 	return nil, nil, fmt.Errorf("attaching TCX to eth0 interface: %w", err)
	// }
	// slog.Debug("AKII: attached TCX ingress", "link", fmt.Sprintf("%+v", li))
	// activeLinks = append(activeLinks, li)

	err = bpf.AttachClassicTC("eth0", objs.TcIngress.FD(), true)
	if err != nil {
		slog.Error("attaching classic TC to eth0 interface for ingress", "error", err)
		return nil, nil, fmt.Errorf("attaching classic TC to eth0 interface for ingress: %w", err)
	}

	// le, err := bpf.AttachTcxToInterface(eth0Iface, objs.TcEgress, ebpf.AttachTCXEgress)
	// if err != nil {
	// 	slog.Error("attaching TCX to eth0 interface", "error", err)
	// 	return nil, nil, fmt.Errorf("attaching TCX to eth0 interface: %w", err)
	// }
	// slog.Debug("AKII: attached TCX to eth0 interface for egress")
	// activeLinks = append(activeLinks, le)

	err = bpf.AttachClassicTC("eth0", objs.TcEgress.FD(), false)
	if err != nil {
		slog.Error("attaching classic TC to eth0 interface for egress", "error", err)
		return nil, nil, fmt.Errorf("attaching classic TC to eth0 interface for egress: %w", err)
	}

	slog.Debug("AKII: sleeping 30s for inspection")
	time.Sleep(30 * time.Second)
	slog.Debug("AKII: done sleeping")

	return &objs, activeLinks, nil
}

func (a *Agent) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go kubernetes.WatchPods(a.onPodAdd, a.onPodDelete, a.onPodUpdate)
	go a.processPodEvents(ctx)

	// Channel to listen to interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()

	size := a.objs.ConnMap.MaxEntries()
	keys := make([]uint64, size)
	values := make([]bpf.NetLedgerConnVal, size)
	lastSeen := make(map[uint64]bpf.NetLedgerConnVal, size) // map[key]value for calculating deltas

	for {
		select {
		case <-stop:
			slog.Info("Shutting down...")
			return nil
		case <-ctx.Done():
			slog.Info("Shutting down...")
			return nil
		case <-ticker.C:
			slog.Debug("reading data from eBPF maps")

			keys = keys[:size]
			values = values[:size]
			opts := &ebpf.BatchOptions{}
			cursor := new(ebpf.MapBatchCursor)
			n, err := a.objs.ConnMap.BatchLookup(cursor, keys, values, opts)
			var errMsg string
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errMsg = err.Error()
			}
			slog.Debug("batch lookup result", "received entries", strconv.Itoa(n), "err", errMsg, "mapSize", strconv.FormatUint(uint64(a.objs.ConnMap.MaxEntries()), 10))
			if n <= 0 {
				slog.Debug("no data, skipping")
				continue
			}
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("failed to read data", "message", err.Error())
				continue
			}
			keys = keys[:n]
			values = values[:n]

			entries := make([]payload.FlowEntry, 0, len(keys))

			for i := range len(keys) {
				// Filter out entries that are not associated with any cgroup (i.e., not associated with any process)
				if values[i].CgroupId == 0 {
					continue
				}

				if values[i].HaveSrc == 0 || values[i].HaveDst == 0 {
					continue
				}

				if values[i].TxBytes == 0 && values[i].RxBytes == 0 {
					continue
				}

				lastVal, found := lastSeen[keys[i]]
				tx := values[i].TxBytes
				rx := values[i].RxBytes
				if found {
					tx -= lastVal.TxBytes
					if tx == math.MaxUint64 {
						tx = values[i].TxBytes
					}
					rx -= lastVal.RxBytes
					if rx == math.MaxUint64 {
						rx = values[i].RxBytes
					}
				}
				lastSeen[keys[i]] = values[i]

				if tx == 0 && rx == 0 {
					continue
				}

				srcIp := network.Uint32ToIP(values[i].SrcIp)
				dstIp := network.Uint32ToIP(values[i].DstIp)

				var srcPod, srcNs, dstPod, dstNs string
				pod := a.podCgroupCache[values[i].CgroupId]
				if pod == nil {
					// If the cgroup ID is not in the cache, it means we haven't seen a pod with that cgroup ID yet (or the pod has been deleted)
					slog.Debug(fmt.Sprintf("cgroup ID %d not found in cache", values[i].CgroupId))
					continue
				}

				if values[i].ConnDirection == network.Egress {
					srcPod = pod.Name
					srcNs = pod.Namespace
				} else {
					dstPod = pod.Name
					dstNs = pod.Namespace
				}

				sport := values[i].SrcPort
				dport := values[i].DstPort

				srcAddr := fmt.Sprintf("%s:%d", srcIp.To4().String(), sport)
				dstAddr := fmt.Sprintf("%s:%d", dstIp.To4().String(), dport)

				slog.Debug(fmt.Sprintf("[Direction %d] %s -> %s: %d tx bytes, %d rx bytes (srcPod: %s/%s, dstPod: %s/%s)",
					values[i].ConnDirection,
					srcAddr,
					dstAddr,
					values[i].TxBytes,
					values[i].RxBytes,
					srcNs,
					srcPod,
					dstNs,
					dstPod,
				))

				entry := payload.FlowEntry{
					Direction:       int(values[i].ConnDirection),
					SrcIP:           srcIp.To4().String(),
					SrcPort:         sport,
					DstIP:           dstIp.To4().String(),
					DstPort:         dport,
					TxBytes:         tx,
					RxBytes:         rx,
					SrcPodName:      srcPod,
					SrcPodNamespace: srcNs,
					DstPodName:      dstPod,
					DstPodNamespace: dstNs,
				}
				entries = append(entries, entry)
			}

			if len(entries) > 0 {
				go func() {
					slog.Debug(fmt.Sprintf("Sending %d entries to API server", len(entries)))
					serverCtx := context.WithoutCancel(context.Background())
					err := a.sendDataToServer(serverCtx, entries, a.StartupTime)
					if err != nil {
						slog.Error(err.Error())
					}
				}()
			}

			a.removeClosedConnections(lastSeen, keys, values, a.objs.ConnMap)
		}
	}
}

func (a *Agent) sendDataToServer(ctx context.Context, flowEntries []payload.FlowEntry, startupTime int64) error {
	content := payload.Encode(payload.Flow{
		AgentNode:   a.Node,
		StartupTime: startupTime,
		Entries:     flowEntries,
	})
	req, err := http.NewRequest("POST", a.Server, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req = req.WithContext(ctx)
	res, err := a.httpClient.Do(req)
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

func (a *Agent) removeClosedConnections(
	lastSeen map[uint64]bpf.NetLedgerConnVal,
	currentConnsKeys []uint64,
	currentConnsValues []bpf.NetLedgerConnVal,
	connMap *ebpf.Map) {

	for i := range len(currentConnsKeys) {
		if currentConnsValues[i].ConnectionClosed == 1 {
			if err := connMap.Delete(currentConnsKeys[i]); err != nil {
				slog.Error("error deleting closed connection from map", "key", currentConnsKeys[i], "error", err.Error())
			}
			delete(lastSeen, currentConnsKeys[i])
		}
	}
}

func (a *Agent) onPodAdd(obj any) {
	a.podChannel <- podEvent{eventType: "add", pod: obj.(*v1.Pod)}
}

func (a *Agent) onPodDelete(obj any) {
	a.podChannel <- podEvent{eventType: "delete", pod: obj.(*v1.Pod)}
}

func (a *Agent) onPodUpdate(oldObj, newObj any) {
	newPod := newObj.(*v1.Pod)
	a.podChannel <- podEvent{eventType: "update", pod: newPod}
}

func (a *Agent) processPodEvents(ctx context.Context) {
	m := sync.RWMutex{}
	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping pod event processor")
			return
		case evt := <-a.podChannel:
			m.Lock()
			switch evt.eventType {
			case "add":
				slog.Debug("Pod added", "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
				cg, err := cgroup.CacheCgroupIDToPod(evt.pod, a.podCgroupCache, a.cgroupPodCache)
				if err != nil {
					slog.Error("Error caching cgroup ID to pod", "error", err.Error())
				} else if evt.pod.Spec.HostNetwork && cg != nil {
					val := byte(1)
					if err := a.objs.HostNetworkPodsMap.Put(*cg, val); err != nil {
						slog.Error("Failed to insert into map", "error", err)
					}
				}

			case "update":
				slog.Debug("Pod updated", "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
				_, err := cgroup.CacheCgroupIDToPod(evt.pod, a.podCgroupCache, a.cgroupPodCache)
				if err != nil {
					slog.Error("Error caching cgroup ID to pod", "error", err.Error())
				}
			case "delete":
				slog.Debug("Pod deleted", "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
				uid := string(evt.pod.UID)
				if cgroupIDs, exists := a.cgroupPodCache[uid]; exists {
					for _, cgroupID := range cgroupIDs {
						delete(a.podCgroupCache, cgroupID)
						if a.objs.HostNetworkPodsMap != nil && a.objs.HostNetworkPodsMap.FD() >= 0 {
							a.objs.HostNetworkPodsMap.Delete(cgroupID)
						}
					}
					delete(a.cgroupPodCache, uid)
				}
			default:
				slog.Error("Unknown event type", "eventType", evt.eventType, "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
			}
			m.Unlock()
		}
	}
}
