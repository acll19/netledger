package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	Node                          string
	Server                        string
	StartupTime                   int64
	Interval                      time.Duration
	cgroupToPodCache              map[uint64]*kubernetes.PodMeta
	podToCgroupsCache             map[string][]uint64 // map of pod UID to slice of cgroup IDs for handling pod deletions
	podEventsCh                   chan podEvent
	staleConnCleanUpIntervalInSec int
	httpClient                    *http.Client
	mLock                         *sync.RWMutex

	objs *bpf.NetLedgerObjects
}

func NewAgent(c Config, startupTime int64) *Agent {
	var httpClient = &http.Client{
		Timeout: c.HttpClient.Timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				KeepAliveConfig: net.KeepAliveConfig{
					Enable: true,
				},
			}).DialContext,
		},
	}

	return &Agent{
		Node:                          c.Node,
		Server:                        c.ClassifierEndpoint,
		StartupTime:                   startupTime,
		Interval:                      c.StatsPollInterval,
		cgroupToPodCache:              make(map[uint64]*kubernetes.PodMeta),
		podToCgroupsCache:             make(map[string][]uint64),
		podEventsCh:                   make(chan podEvent, c.MaxPodEventsAtOnce),
		staleConnCleanUpIntervalInSec: c.StaleConnCleanupIntervalInSec,
		httpClient:                    httpClient,
		mLock:                         &sync.RWMutex{},
	}
}

func (a *Agent) LoadEBPF() (*bpf.NetLedgerObjects, []link.Link, error) {
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

	// TODO: map max entries should come from config
	// to do that, the agent must check if map entries has changed and if so it must delete the pinned
	// map before loading. Otherwise the program will fail to load. This will caused dropped tracked connections

	var objs bpf.NetLedgerObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/netledger",
		},
	}
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		return nil, nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	a.objs = &objs

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

	cgroupSockopsLink, err := bpf.AttachRootCgroup(objs.TcpSockops, ebpf.AttachCGroupSockOps)
	if err != nil {
		return nil, nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupSockopsLink)

	cgroupConnect4Link, err := bpf.AttachRootCgroup(objs.CgConnect4, ebpf.AttachCGroupInet4Connect)
	if err != nil {
		return nil, nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupConnect4Link)

	slog.Info("Number of active links", "count", len(activeLinks))

	return &objs, activeLinks, nil
}

func (a *Agent) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcherStopCh := make(chan struct{})
	go kubernetes.WatchPods(watcherStopCh, a.onPodAdd, a.onPodDelete, a.onPodUpdate)
	go a.processPodEvents(ctx)
	go a.cleanUpStaleConnections(ctx)

	// Channel to listen to interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()

	size := a.objs.ConnStats.MaxEntries()
	sKeys := make([]uint64, size)
	stats := make([]bpf.NetLedgerConnStats, size)

	for {
		select {
		case <-stop:
			slog.Info("Shutting down...")
			close(watcherStopCh)
			return nil
		case <-ctx.Done():
			slog.Info("Shutting down...")
			return nil
		case <-ticker.C:
			sKeys = sKeys[:size]
			stats = stats[:size]
			opts := &ebpf.BatchOptions{}
			cursor := new(ebpf.MapBatchCursor)
			n, err := a.objs.ConnStats.BatchLookupAndDelete(cursor, sKeys, stats, opts)
			var errMsg string
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errMsg = err.Error()
			}
			slog.Info("reading eBPF map", "received entries", strconv.Itoa(n), "err", errMsg, "mapSize", strconv.FormatUint(uint64(a.objs.ConnStats.MaxEntries()), 10))
			if n <= 0 {
				slog.Debug("no data, skipping")
				continue
			}
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("failed to read data", "message", err.Error())
				continue
			}

			sKeys = sKeys[:n]
			stats = stats[:n]

			slog.Debug("debug printing", "keys", len(sKeys), "started with", n)
			entries := make([]payload.FlowEntry, 0, len(sKeys))

			for i := range len(sKeys) {
				// Filter out entries that are not associated with any cgroup (i.e., not associated with any process)
				if stats[i].CgroupId == 0 {
					continue
				}

				if stats[i].TxBytes == 0 && stats[i].RxBytes == 0 {
					continue
				}

				var srcPod, srcNs, dstPod, dstNs string
				var srcIp, dstIp net.IP
				var sport, dport uint16
				var pod *kubernetes.PodMeta

				a.mLock.Lock()
				pod = a.cgroupToPodCache[stats[i].CgroupId]
				a.mLock.Unlock()
				if pod == nil {
					// If the cgroup ID is not in the cache, it means we haven't seen a pod with that cgroup ID yet (or the pod has been deleted)
					slog.Debug(
						fmt.Sprintf("cgroup ID %d not found in cache", stats[i].CgroupId),
						"src:port", fmt.Sprintf("%s:%d", network.Uint32ToIP(stats[i].DstIp4).To4().String(), stats[i].DstPort),
						"dst:port", fmt.Sprintf("%s:%d", network.Uint32ToIP(stats[i].SrcIp4).To4().String(), stats[i].SrcPort),
					)
					continue
				}

				if stats[i].ConnDirection == network.Egress {
					srcPod = pod.Name
					srcNs = pod.Namespace
					srcIp = network.Uint32ToIP(stats[i].SrcIp4)
					sport = stats[i].SrcPort
					dstIp = network.Uint32ToIP(stats[i].DstIp4)
					dport = stats[i].DstPort
				} else {
					dstPod = pod.Name
					dstNs = pod.Namespace
					srcIp = network.Uint32ToIP(stats[i].DstIp4)
					sport = stats[i].SrcPort
					dstIp = network.Uint32ToIP(stats[i].SrcIp4)
					dport = stats[i].DstPort
				}

				srcAddr := fmt.Sprintf("%s:%d", srcIp.To4().String(), sport)
				dstAddr := fmt.Sprintf("%s:%d", dstIp.To4().String(), dport)

				slog.Debug(fmt.Sprintf("[Direction %d|Pod Initiated %d] %s -> %s: %d tx bytes, %d rx bytes (srcPod: %s/%s, dstPod: %s/%s)",
					stats[i].PodInitiated,
					stats[i].ConnDirection,
					srcAddr,
					dstAddr,
					stats[i].TxBytes,
					stats[i].RxBytes,
					srcNs,
					srcPod,
					dstNs,
					dstPod,
				))

				entry := payload.FlowEntry{
					PodInitiated:    stats[i].PodInitiated,
					Direction:       stats[i].ConnDirection,
					SrcIP:           srcIp.To4().String(),
					SrcPort:         sport,
					DstIP:           dstIp.To4().String(),
					DstPort:         dport,
					TxBytes:         stats[i].TxBytes,
					RxBytes:         stats[i].RxBytes,
					SrcPodName:      srcPod,
					SrcPodNamespace: srcNs,
					DstPodName:      dstPod,
					DstPodNamespace: dstNs,
				}
				entries = append(entries, entry)
			}

			if len(entries) > 0 {
				go func() {
					slog.Debug(fmt.Sprintf("Sending %d entries to classifier", len(entries)))
					serverCtx := context.WithoutCancel(context.Background())
					err := a.sendDataToServer(serverCtx, entries, a.StartupTime)
					if err != nil {
						slog.Error(err.Error())
					}
				}()
			}
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

func (a *Agent) onPodAdd(obj any) {
	pod := obj.(*v1.Pod)
	if pod.Status.Phase != v1.PodRunning {
		slog.Debug("ignoring pod that is not in running state", "namespace", pod.Namespace, "pod", pod.Name, "status", pod.Status)
		return
	}
	a.podEventsCh <- podEvent{eventType: "add", pod: pod}
}

func (a *Agent) onPodDelete(obj any) {
	a.podEventsCh <- podEvent{eventType: "delete", pod: obj.(*v1.Pod)}
}

func (a *Agent) onPodUpdate(oldObj, newObj any) {
	newPod := newObj.(*v1.Pod)

	var et string
	switch newPod.Status.Phase {
	case v1.PodRunning:
		et = "update"
	case v1.PodSucceeded:
		et = "delete" // trigger cleanup of cgroup cache and stale entries in ebpf maps
	case v1.PodFailed:
		et = "delete"
	default:
		slog.Debug("ignoring updated pod that is not in relevant state (running, succeeded or failed)", "namespace", newPod.Namespace, "pod", newPod.Name, "status", newPod.Status)
		return
	}

	a.podEventsCh <- podEvent{eventType: et, pod: newPod}
}

func (a *Agent) cleanUpStaleConnections(ctx context.Context) {
	i := time.Duration(a.staleConnCleanUpIntervalInSec) * time.Second
	ticker := time.NewTicker(i * time.Minute)
	defer ticker.Stop()
	size := a.objs.ConnMeta.MaxEntries()
	mKeys := make([]uint64, size)
	mValues := make([]bpf.NetLedgerConnMeta, size)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping stale connection cleanup")
			return
		case <-ticker.C:
			mKeys = mKeys[:size]
			mValues = mValues[:size]
			opts := &ebpf.BatchOptions{}
			cursor := new(ebpf.MapBatchCursor)
			n, err := a.objs.ConnMeta.BatchLookup(cursor, mKeys, mValues, opts)
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("failed to read data for stale connection cleanup", "message", err.Error())
				continue
			}

			if n <= 0 {
				slog.Debug("no data for stale connection cleanup, skipping")
				continue
			}

			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("failed to read data for stale connection cleanup", "message", err.Error())
				continue
			}

			mKeys = mKeys[:n]
			mValues = mValues[:n]

			staledConns := make([]uint64, 0, n)
			for i := range len(mKeys) {
				cgroup := mValues[i].CgroupId
				if _, exist := a.cgroupToPodCache[cgroup]; !exist {
					staledConns = append(staledConns, mKeys[i])
				}
			}

			if len(staledConns) > 0 {
				slog.Info("Cleaning up stale connections", "count", len(staledConns))
				if _, err := a.objs.ConnMeta.BatchDelete(staledConns, nil); err != nil {
					slog.Error("failed to delete stale connections", "message", err.Error())
				}
			}
		}
	}
}

func (a *Agent) processPodEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping pod event processor")
			return
		case evt := <-a.podEventsCh:
			a.mLock.Lock()
			switch evt.eventType {
			case "add":
				slog.Debug("Pod added", "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
				err := cgroup.CacheCgroupIDToPod(evt.pod, a.cgroupToPodCache, a.podToCgroupsCache)
				if err != nil {
					slog.Error("Error caching cgroup ID to pod", "error", err.Error())
				}
			case "update":
				slog.Debug("Pod updated", "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
				err := cgroup.CacheCgroupIDToPod(evt.pod, a.cgroupToPodCache, a.podToCgroupsCache)
				if err != nil {
					slog.Error("Error caching cgroup ID to pod", "error", err.Error())
				}
			case "delete":
				slog.Debug("Pod deleted", "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
				uid := string(evt.pod.UID)
				if cgroupIDs, exists := a.podToCgroupsCache[uid]; exists {
					for _, cgroupID := range cgroupIDs {
						delete(a.cgroupToPodCache, cgroupID)
					}
					delete(a.podToCgroupsCache, uid)
				}
			default:
				slog.Error("Unknown event type", "eventType", evt.eventType, "namespace", evt.pod.Namespace, "pod", evt.pod.Name)
			}
			a.mLock.Unlock()
		}
	}
}
