package network

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
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

func GetHostEth0Interface() (net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, fmt.Errorf("failed to list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Name == "eth0" && iface.Flags&net.FlagUp != 0 {
			return iface, nil
		}
	}

	return net.Interface{}, fmt.Errorf("host eth0 interface not found or not up")
}

func StringIpToNetIp(ip string) (net.IP, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}
	return parsedIP, nil
}

func Uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b)
}

// isInternetIP returns true if the IP is globally routable
// on the public Internet.
func IsInternetIP(ip netip.Addr) bool {
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
