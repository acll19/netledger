package bpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func AttachRootCgroup(prg *ebpf.Program, attachType ebpf.AttachType) (link.Link, error) {
	cgroupIngressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  attachType,
		Program: prg,
	})
	if err != nil {
		return nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	return cgroupIngressLink, err
}

func GetHostEth0Iface() (net.Interface, error) {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		return net.Interface{}, fmt.Errorf("getting eth0 interface: %w", err)
	}
	return *iface, nil
}

func AttachTcxToInterface(iface net.Interface, prg *ebpf.Program, attachType ebpf.AttachType) (link.Link, error) {
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prg,
		Attach:    attachType,
	})
	if err != nil {
		return nil, fmt.Errorf("attach tcx program to interface %s: %w", iface.Name, err)
	}

	return l, nil
}

func AttachClassicTC(ifaceName string, progFd int, ingress bool) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}

	// 1. Ensure clsact qdisc exists
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// Ignore "file exists"
	_ = netlink.QdiscAdd(qdisc)

	// 2. Select ingress or egress
	parent := netlink.HANDLE_MIN_INGRESS
	if !ingress {
		parent = netlink.HANDLE_MIN_EGRESS
	}

	// 3. Attach BPF filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    uint32(parent),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFd,
		Name:         "tc_prog",
		DirectAction: true,
	}

	return netlink.FilterAdd(filter)
}
