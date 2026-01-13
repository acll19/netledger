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

	var objs bpf.NetLedgerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	ip, ipNet, err := net.ParseCIDR(serviceCidr)
	if err != nil || ip == nil || ip.To4() == nil {
		return fmt.Errorf("Invalid Service CIDR")
	}

	ipUint := network.InterfacepToUint32(ip)
	maskUint := network.MaskToUint32(ipNet.Mask)

	if err := spec.Variables["service_subnet_prefix"].Set(byteorder.Htonl(ipUint)); err != nil {
		return fmt.Errorf("setting service prefix from CIDR: %w", err)
	}

	if err := spec.Variables["service_subnet_mask"].Set(byteorder.Htonl(maskUint)); err != nil {
		return fmt.Errorf("setting service mask from CIDR: %w", err)
	}

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

	ifaces, err := network.ListCiliumVeths()
	if err != nil {
		return fmt.Errorf("failed to list cilium veths: %w", err)
	}

	for _, iface := range ifaces {
		// TODO when pods die, its link needs to be closed
		// TODO avoid attaching the same veth twice
		fmt.Println(iface.Name)
		link, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.EgressTcxConnectionTracker,
			Attach:    ebpf.AttachType(ebpf.AttachTCXEgress),
		})
		if err != nil {
			return fmt.Errorf("attach tcx program to interface %s: %w", iface.Name, err)
		}

		activeLinks = append(activeLinks, link)
	}

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

	informer, err := kubernetes.SetupPodInformer(ctx, node)
	if err != nil {
		return fmt.Errorf("setting up informer: %w", err)
	}

	// Channel to listen to interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	size := objs.IpMap.MaxEntries()
	keys := make([]bpf.NetLedgerIpKey, size)
	values := make([]bpf.NetLedgerIpValue, size)
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

			podsOnHost := kubernetes.GetPods(informer)
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
					Direction:    direction,
					SrcIP:        srcIpSrcIp,
					SrcPort:      fKeys[i].SrcPort,
					DstIP:        dstIpDstIp,
					DstPort:      fKeys[i].DstPort,
					Traffic:      fValues[i].PacketSize,
					PodName:      name,
					PodNamespace: ns,
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

func filterSrcOrDstIpOnCurrentHost(keys []bpf.NetLedgerIpKey, values []bpf.NetLedgerIpValue, podsOnHost []*v1.Pod) ([]bpf.NetLedgerIpKey, []bpf.NetLedgerIpValue) {
	ipsOnHost := make(map[uint32]struct{}, len(podsOnHost)) // pods may have multiple IPs so this is just an approximation

	for _, pod := range podsOnHost {
		for _, podIP := range pod.Status.PodIPs {
			ip := net.ParseIP(podIP.IP)
			if ip == nil || ip.To4() == nil {
				log.Println("ip is not IPv4, currently only IPv4 is supported")
				continue
			}

			ipsOnHost[network.InterfacepToUint32(ip)] = struct{}{}
		}
	}

	resKeys := make([]bpf.NetLedgerIpKey, 0, len(keys))
	resValues := make([]bpf.NetLedgerIpValue, 0, len(values))
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
