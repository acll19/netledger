package bpf

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func AttachRootCgroup(prg *ebpf.Program) (link.Link, error) {
	cgroupIngressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: prg,
	})
	if err != nil {
		return nil, fmt.Errorf("attach cgroup skb: %w", err)
	}
	return cgroupIngressLink, err
}

func AttachTcxToCiliumHostVeths(ifaces []net.Interface, prg *ebpf.Program, attachType ebpf.AttachType) ([]link.Link, map[int]net.Interface, error) {
	ifacesMap := make(map[int]net.Interface)
	activeLinks := make([]link.Link, 0)
	for _, iface := range ifaces {
		l, err := attachTcxToCiliumHostVeth(iface, prg, attachType)
		if err != nil {
			return nil, nil, err
		}
		activeLinks = append(activeLinks, l)
		ifacesMap[iface.Index] = iface
	}

	return activeLinks, ifacesMap, nil
}

func attachTcxToCiliumHostVeth(iface net.Interface, prg *ebpf.Program, attachType ebpf.AttachType) (link.Link, error) {
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

func ManageTCXLinks(ifacesMap map[int]net.Interface, activeLinks []link.Link, prg *ebpf.Program, attachType ebpf.AttachType) (chan struct{}, error) {
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})

	if err := netlink.LinkSubscribe(ch, done); err != nil {
		return nil, fmt.Errorf("error subscribing to link changes: %w", err)
	}

	go func() {
		for update := range ch {
			switch update.Header.Type {
			case unix.RTM_DELLINK:
				ifIndex := update.Attrs().Index
				delete(ifacesMap, ifIndex)
				for _, l := range activeLinks {
					i, err := l.Info()
					if err != nil {
						slog.Error("error getting link info", "message: ", err.Error())
						continue
					}
					if i.Type == link.TCXType && i.TCX().Ifindex == uint32(ifIndex) {
						if err := l.Close(); err != nil {
							slog.Error("error closing link object", "message: ", err.Error())
						}
					}
				}
			case unix.RTM_NEWLINK:
				if strings.HasPrefix(update.Attrs().Name, "lxc") {
					iface, err := net.InterfaceByName(update.Attrs().Name)
					if err != nil {
						slog.Error("error getting interface by name", "interface", update.Attrs().Name, "error", err)
						return
					}
					l, err := attachTcxToCiliumHostVeth(*iface, prg, attachType)
					if err != nil {
						slog.Error("error attaching tcx program to interface", "interface", update.Attrs().Name, "error", err)
						return
					}
					activeLinks = append(activeLinks, l)
					ifacesMap[update.Attrs().Index] = *iface
				}

			}
		}
	}()

	return done, nil
}
