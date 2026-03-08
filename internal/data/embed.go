package data

import (
	"bufio"
	"embed"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"strings"
)

//go:embed ir-cidrs.txt
var irCIDRsFS embed.FS

//go:embed ir-resolvers.txt
var irResolversFS embed.FS

// IRResolvers returns the bundled list of known Iranian DNS resolver IPs.
// These are pre-verified resolvers (source: net2share/ir-resolvers).
func IRResolvers() ([]string, error) {
	data, err := irResolversFS.ReadFile("ir-resolvers.txt")
	if err != nil {
		return nil, err
	}

	var ips []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip := line
		if host, _, err := net.SplitHostPort(line); err == nil {
			ip = host
		}
		if net.ParseIP(ip) != nil {
			ips = append(ips, ip)
		}
	}
	return ips, sc.Err()
}

// IRCIDRs returns all embedded Iranian CIDR ranges.
func IRCIDRs() ([]string, error) {
	data, err := irCIDRsFS.ReadFile("ir-cidrs.txt")
	if err != nil {
		return nil, err
	}

	var cidrs []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			cidrs = append(cidrs, line)
		}
	}
	return cidrs, sc.Err()
}

// countUsable returns the number of usable host IPs in a CIDR (excluding network/broadcast for IPv4 > /31).
func countUsable(ipNet *net.IPNet) int {
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return 0 // skip IPv6
	}
	if ones == 32 {
		return 1
	}
	if ones == 31 {
		return 2
	}
	// 2^(32-ones) - 2  (subtract network + broadcast)
	total := 1 << (32 - ones)
	return total - 2
}

// TotalUsableIPs returns the total number of usable IPs across all CIDRs.
func TotalUsableIPs(cidrs []string) (int, error) {
	total := 0
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return 0, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		total += countUsable(ipNet)
	}
	return total, nil
}

// nthUsableIP returns the Nth usable host IP in a subnet (0-indexed).
func nthUsableIP(ipNet *net.IPNet, n int) net.IP {
	ones, _ := ipNet.Mask.Size()

	ip := copyIP(ipNet.IP.To4())
	if ip == nil {
		return nil
	}

	// For /32, only index 0 is valid
	if ones == 32 {
		return ip
	}
	// For /31, index 0 and 1
	if ones == 31 {
		offset := big.NewInt(int64(n))
		ipInt := ipToInt(ip)
		ipInt.Add(ipInt, offset)
		return intToIP(ipInt)
	}
	// For other subnets, skip network address (+1)
	offset := big.NewInt(int64(n + 1))
	ipInt := ipToInt(ip)
	ipInt.Add(ipInt, offset)
	return intToIP(ipInt)
}

// ExpandCIDRsSampled expands CIDR ranges, picking samplePer random IPs per subnet.
// If samplePer <= 0, all usable IPs are returned.
func ExpandCIDRsSampled(cidrs []string, samplePer int) ([]string, error) {
	var ips []string
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}

		n := countUsable(ipNet)
		if n == 0 {
			continue
		}

		if samplePer <= 0 || samplePer >= n {
			// Return all usable IPs
			for i := 0; i < n; i++ {
				ips = append(ips, nthUsableIP(ipNet, i).String())
			}
		} else {
			// Pick samplePer unique random indices — no full expansion needed
			picked := make(map[int]struct{}, samplePer)
			for len(picked) < samplePer {
				picked[rand.Intn(n)] = struct{}{}
			}
			for idx := range picked {
				ips = append(ips, nthUsableIP(ipNet, idx).String())
			}
		}
	}
	return ips, nil
}

// ExpandCIDRsBatch expands CIDRs and returns a slice of at most batchSize IPs,
// starting from offset. Returns the IPs and the total count.
// Only expands the CIDRs that overlap with the [offset, offset+batchSize) window.
func ExpandCIDRsBatch(cidrs []string, offset, batchSize int) (ips []string, total int, err error) {
	// First pass: calculate total and find which CIDRs we need
	type cidrInfo struct {
		ipNet      *net.IPNet
		startIdx   int // global index of first IP in this CIDR
		usableCount int
	}
	var infos []cidrInfo
	pos := 0
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		n := countUsable(ipNet)
		if n == 0 {
			continue
		}
		infos = append(infos, cidrInfo{ipNet, pos, n})
		pos += n
	}
	total = pos
	end := offset + batchSize

	// Second pass: only expand CIDRs that overlap with [offset, end)
	for _, info := range infos {
		cidrEnd := info.startIdx + info.usableCount
		// Skip CIDRs entirely before or after our window
		if cidrEnd <= offset || info.startIdx >= end {
			continue
		}
		// Calculate which IPs in this CIDR fall within our window
		localStart := 0
		if offset > info.startIdx {
			localStart = offset - info.startIdx
		}
		localEnd := info.usableCount
		if end < cidrEnd {
			localEnd = end - info.startIdx
		}
		for i := localStart; i < localEnd; i++ {
			ips = append(ips, nthUsableIP(info.ipNet, i).String())
		}
	}
	return ips, total, nil
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func ipToInt(ip net.IP) *big.Int {
	return new(big.Int).SetBytes(ip.To4())
}

func intToIP(i *big.Int) net.IP {
	b := i.Bytes()
	ip := make(net.IP, 4)
	copy(ip[4-len(b):], b)
	return ip
}
