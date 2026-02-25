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
	"github.com/acll19/netledger/internal/network/byteorder"
	"github.com/acll19/netledger/internal/payload"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	v1 "k8s.io/api/core/v1"
)

func Run(flushInterval time.Duration, node, server, serviceCidr string, debug bool) error {
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

	ip, ipNet, err := net.ParseCIDR(serviceCidr)
	if err != nil || ip == nil || ip.To4() == nil {
		return fmt.Errorf("error parsing service CIDR, %w", err)
	}

	ipUint := network.IpToUint32(ip)
	maskUint := network.MaskToUint32(ipNet.Mask)

	if err := spec.Variables["service_subnet_prefix"].Set(byteorder.Htonl(ipUint)); err != nil {
		return fmt.Errorf("setting service prefix from CIDR: %w", err)
	}

	if err := spec.Variables["service_subnet_mask"].Set(byteorder.Htonl(maskUint)); err != nil {
		return fmt.Errorf("setting service mask from CIDR: %w", err)
	}

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
			fKeys, fValues := filterSrcOrDstIpOnCurrentHost(keys, values, podsOnHost)

			// debug
			log.Println("debug printing", len(fKeys), "keys", "started with", n, "keys before filtering to host-local pods (", len(keys), ")")
			entries := make([]payload.FlowEntry, 0, len(fKeys))

			for i := range len(fKeys) {
				if fValues[i].HaveSrc == 0 || fValues[i].HaveDst == 0 {
					continue
				}

				if fValues[i].TxBytes == 0 && fValues[i].RxBytes == 0 {
					continue
				}

				lastVal, found := lastSeen[fKeys[i]]
				// If we have seen this key before, and the values are the same, skip
				if found {
					if lastVal.TxBytes == fValues[i].TxBytes && lastVal.RxBytes == fValues[i].RxBytes {
						continue
					}
				}
				tx := fValues[i].TxBytes
				rx := fValues[i].RxBytes
				if found {
					tx -= lastVal.TxBytes
					if tx == math.MaxUint64 {
						tx = fValues[i].TxBytes
					}
					rx -= lastVal.RxBytes
					if rx == math.MaxUint64 {
						rx = fValues[i].RxBytes
					}
				}
				lastSeen[fKeys[i]] = fValues[i]

				srcIp := network.Uint32ToIP(fValues[i].SrcIp)
				dstIp := network.Uint32ToIP(fValues[i].DstIp)

				var srcPod, srcNs, dstPod, dstNs string
				p := searchPod(srcIp.To4().String(), fValues[i], podsOnHost)
				if p != nil {
					srcPod = p.Name
					srcNs = p.Namespace
				}
				p = searchPod(dstIp.To4().String(), fValues[i], podsOnHost)
				if p != nil {
					dstPod = p.Name
					dstNs = p.Namespace
				}

				sport := fValues[i].SrcPort
				dport := fValues[i].DstPort

				srcAddr := fmt.Sprintf("%s:%d", srcIp.To4().String(), sport)
				dstAddr := fmt.Sprintf("%s:%d", dstIp.To4().String(), dport)

				if debug {
					slog.Info(fmt.Sprintf("[Direction %d] %s -> %s: %d tx bytes, %d rx bytes (srcPod: %s/%s, dstPod: %s/%s)\n",
						fValues[i].ConnDirection,
						srcAddr,
						dstAddr,
						fValues[i].TxBytes,
						fValues[i].RxBytes,
						srcNs,
						srcPod,
						dstNs,
						dstPod,
					))
				}

				entry := payload.FlowEntry{
					Direction:       int(fValues[i].ConnDirection),
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

			removeClosedConnections(lastSeen, fKeys)
		}
	}
}

func filterSrcOrDstIpOnCurrentHost(keys []uint64, values []bpf.NetLedgerConnVal, podsOnHost []*v1.Pod) ([]uint64, []bpf.NetLedgerConnVal) {
	ipsOnHost := make(map[uint32]struct{}, len(podsOnHost)) // pods may have multiple IPs so this is just an approximation

	for _, pod := range podsOnHost {
		for _, podIP := range pod.Status.PodIPs {
			ip := net.ParseIP(podIP.IP)
			if ip == nil || ip.To4() == nil {
				log.Println("ip is not IPv4, currently only IPv4 is supported")
				continue
			}

			ipsOnHost[network.IpToUint32(ip)] = struct{}{}
		}
	}

	resKeys := make([]uint64, 0, len(keys))
	resValues := make([]bpf.NetLedgerConnVal, 0, len(values))
	for i := range values {
		if _, found := ipsOnHost[byteorder.Ntohl(values[i].SrcIp)]; found {
			resKeys = append(resKeys, keys[i])
			resValues = append(resValues, values[i])
		} else {
			if _, found := ipsOnHost[byteorder.Ntohl(values[i].DstIp)]; found {
				resKeys = append(resKeys, keys[i])
				resValues = append(resValues, values[i])
			}
		}
	}

	return resKeys, resValues
}

func searchPod(ip string, connVal bpf.NetLedgerConnVal, podsOnHost []*v1.Pod) *v1.Pod {
	for _, pod := range podsOnHost {
		for _, podIP := range pod.Status.PodIPs {
			if ip == podIP.IP {
				return pod
			}
		}
	}

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

func removeClosedConnections(lastSeen map[uint64]bpf.NetLedgerConnVal, currentConnsKeys []uint64) {
	currentConnsKeyMap := make(map[uint64]struct{}, len(currentConnsKeys))
	for _, key := range currentConnsKeys {
		currentConnsKeyMap[key] = struct{}{}
	}

	for cookie := range lastSeen {
		if _, exists := currentConnsKeyMap[cookie]; !exists {
			delete(lastSeen, cookie)
		}
	}
}
