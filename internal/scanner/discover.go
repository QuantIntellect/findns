package scanner

import (
	"fmt"
	"net"
)

// SubnetsFromIPs returns unique /24 CIDRs derived from the given IP list.
func SubnetsFromIPs(ips []string) []string {
	seen := make(map[string]struct{})
	var cidrs []string
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
		if _, ok := seen[cidr]; !ok {
			seen[cidr] = struct{}{}
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

// ExpandSubnets expands /24 CIDRs to individual host IPs (.1 through .254),
// excluding any IPs present in the exclude set.
func ExpandSubnets(cidrs []string, exclude map[string]struct{}) []string {
	var ips []string
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil {
			continue
		}
		for i := 1; i <= 254; i++ {
			candidate := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], i)
			if _, ok := exclude[candidate]; !ok {
				ips = append(ips, candidate)
			}
		}
	}
	return ips
}
