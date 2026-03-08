package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
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

func Run(flushInterval time.Duration, node, server string, debug bool) error {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := bpf.LoadNetLedger()
	if err != nil {
		return fmt.Errorf("loading netledger: %w", err)
	}

	if err := os.MkdirAll("/sys/fs/bpf/netledger", 0755); err != nil {
		return fmt.Errorf("error creating directory for pinning eBPF maps: %w", err)
	}
	var objs bpf.NetLedgerObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/netledger",
		},
	}
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	activeLinks := make([]link.Link, 0)
	cgroupEgressLink, err := bpf.AttachRootCgroup(objs.CgEgress, ebpf.AttachCGroupInetEgress)
	if err != nil {
		return fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupEgressLink)

	cgroupIngressLink, err := bpf.AttachRootCgroup(objs.CgIngress, ebpf.AttachCGroupInetIngress)
	if err != nil {
		return fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupIngressLink)

	cgroupConnectLink, err := bpf.AttachRootCgroup(objs.CgConnect4, ebpf.AttachCGroupInet4Connect)
	if err != nil {
		return fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupConnectLink)

	cgroupBindLink, err := bpf.AttachRootCgroup(objs.CgBind4, ebpf.AttachCGroupInet4Bind)
	if err != nil {
		return fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupBindLink)

	cgroupSockopsLink, err := bpf.AttachRootCgroup(objs.TcpSockops, ebpf.AttachCGroupSockOps)
	if err != nil {
		return fmt.Errorf("attach cgroup skb: %w", err)
	}
	activeLinks = append(activeLinks, cgroupSockopsLink)
	log.Println("Number of active links: ", len(activeLinks))

	defer func() {
		for _, link := range activeLinks {
			if err := link.Close(); err != nil {
				slog.Error("error closing link object", "message: ", err.Error())
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	informer, err := kubernetes.SetupPodInformer(ctx, node)
	if err != nil {
		return fmt.Errorf("error setting up informer: %w", err)
	}

	// Channel to listen to interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	size := objs.ConnMap.MaxEntries()
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
			slog.Info("reading data from eBPF maps")

			keys = keys[:size]
			values = values[:size]
			opts := &ebpf.BatchOptions{}
			cursor := new(ebpf.MapBatchCursor)
			n, err := objs.ConnMap.BatchLookup(cursor, keys, values, opts)
			slog.Debug("batch lookup result", "n", n, "err", err, "mapSize", objs.ConnMap.MaxEntries())
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

			podsOnHost := kubernetes.GetPods(informer)

			// debug
			log.Println("debug printing", len(keys), "keys", "started with", n, "keys before filtering to host-local pods (", len(keys), ")")
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

				srcIp := network.Uint32ToIP(values[i].SrcIp)
				dstIp := network.Uint32ToIP(values[i].DstIp)

				var srcPod, srcNs, dstPod, dstNs string
				p := searchPod(srcIp.To4().String(), values[i], podsOnHost)
				if p != nil {
					srcPod = p.Name
					srcNs = p.Namespace
				}
				p = searchPod(dstIp.To4().String(), values[i], podsOnHost)
				if p != nil {
					dstPod = p.Name
					dstNs = p.Namespace
				}

				sport := values[i].SrcPort
				dport := values[i].DstPort

				srcAddr := fmt.Sprintf("%s:%d", srcIp.To4().String(), sport)
				dstAddr := fmt.Sprintf("%s:%d", dstIp.To4().String(), dport)

				if debug {
					slog.Info(fmt.Sprintf("[Direction %d] %s -> %s: %d tx bytes, %d rx bytes (srcPod: %s/%s, dstPod: %s/%s)\n",
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
				}

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
					slog.Info(fmt.Sprintf("Sending %d entries to API server\n", len(entries)))
					serverCtx := context.WithoutCancel(context.Background())
					err := sendDataToServer(serverCtx, server, entries)
					if err != nil {
						slog.Error(err.Error())
					}
				}()
			}

			removeClosedConnections(lastSeen, keys, values, objs.ConnMap)
		}
	}
}

func searchPod(ip string, connVal bpf.NetLedgerConnVal, podsOnHost []*v1.Pod) *v1.Pod {
	srcIp := network.Uint32ToIP(connVal.SrcIp)
	if connVal.ConnDirection == 0 && srcIp.To4().String() == ip {
		pod, _ := cgroup.GetPodByCgroupID(connVal.CgroupId, podsOnHost)
		if pod != nil {
			return pod
		}
	}

	dstIp := network.Uint32ToIP(connVal.DstIp)
	if connVal.ConnDirection == 1 && dstIp.To4().String() == ip {
		pod, _ := cgroup.GetPodByCgroupID(connVal.CgroupId, podsOnHost)
		if pod != nil {
			return pod
		}
	}
	return nil
}

var httpClient = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   500 * time.Millisecond,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   500 * time.Millisecond,
		ResponseHeaderTimeout: 1 * time.Second,
		ExpectContinueTimeout: 200 * time.Millisecond,
	},
}

func sendDataToServer(ctx context.Context, server string, flowEntries []payload.FlowEntry) error {
	content := payload.Encode(flowEntries)
	req, err := http.NewRequest("POST", server, bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req = req.WithContext(ctx)
	res, err := httpClient.Do(req)
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

func removeClosedConnections(
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
