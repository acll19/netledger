package network

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// ipToUint32 converts an IPv4 address to a uint32
func IpToUint32(ip net.IP) uint32 {
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

// maskToUint32 converts a net.IPMask to a uint32
func MaskToUint32(mask net.IPMask) uint32 {
	var result uint32
	for _, byteValue := range mask {
		result = (result << 8) | uint32(byteValue)
	}
	return result
}

// ListCiliumVeths returns all network interfaces whose name starts with "lxc".
func ListCiliumVeths() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	var ciliumIfaces []net.Interface
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "lxc") {
			ciliumIfaces = append(ciliumIfaces, iface)
		}
	}

	return ciliumIfaces, nil
}
