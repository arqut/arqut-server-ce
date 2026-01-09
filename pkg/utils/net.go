package utils

import (
	"fmt"
	"net"
)

func GetLocalIPs(onlyIPv4 bool) ([]string, error) {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}

		ip := ipnet.IP
		// IPv4?
		if ip4 := ip.To4(); ip4 != nil {
			ips = append(ips, ip4.String())
			continue
		}
		// IPv6?
		if !onlyIPv4 && ip.To16() != nil {
			ips = append(ips, ip.String())
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no non-loopback interface addresses found")
	}
	return ips, nil
}

func GetLocalSubnets() ([]string, error) {
	var subnets []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}

		ip := ipnet.IP

		// IPv4
		if ip4 := ip.To4(); ip4 != nil {
			// Calculate actual subnet using the real netmask
			subnet := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
			subnets = append(subnets, subnet.String())
			continue
		}

		// IPv6
		if ip.To16() != nil {
			// Skip link-local addresses
			if ip.IsLinkLocalUnicast() {
				continue
			}
			// Use actual subnet from interface
			subnet := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
			subnets = append(subnets, subnet.String())
		}
	}

	if len(subnets) == 0 {
		return nil, fmt.Errorf("no non-loopback interface subnets found")
	}
	return subnets, nil
}
