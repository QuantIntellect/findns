package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

func LoadInput(path string, includeFailed bool) ([]string, error) {
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		return loadJSON(path, includeFailed)
	}
	return loadText(path)
}

func loadText(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []string
	seen := make(map[string]struct{})
	var skipped, dupes, cidrCount int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		// Accept DoH URLs (https://...)
		if strings.HasPrefix(line, "https://") {
			if _, ok := seen[line]; !ok {
				seen[line] = struct{}{}
				entries = append(entries, line)
			} else {
				dupes++
			}
			continue
		}
		// Try CIDR notation (e.g. 1.2.3.0/24)
		if strings.Contains(line, "/") {
			ips, err := expandCIDR(line)
			if err == nil {
				cidrCount++
				for _, cip := range ips {
					if _, ok := seen[cip]; !ok {
						seen[cip] = struct{}{}
						entries = append(entries, cip)
					} else {
						dupes++
					}
				}
				continue
			}
		}
		ip := line
		// Strip optional :port suffix
		if host, _, err := net.SplitHostPort(line); err == nil {
			ip = host
		}
		if net.ParseIP(ip) == nil {
			skipped++
			continue
		}
		if _, ok := seen[ip]; ok {
			dupes++
			continue
		}
		seen[ip] = struct{}{}
		entries = append(entries, ip)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cidrCount > 0 {
		fmt.Fprintf(os.Stderr, "input: expanded %d CIDR ranges -> %d IPs\n", cidrCount, len(entries))
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "input: skipped %d invalid entries\n", skipped)
	}
	if dupes > 0 {
		fmt.Fprintf(os.Stderr, "input: removed %d duplicate entries\n", dupes)
	}
	if len(entries) > 100000 {
		fmt.Fprintf(os.Stderr, "warning: %d IPs is a lot — consider using smaller CIDR ranges or filtering first\n", len(entries))
	}
	return entries, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses for IPv4 ranges > /31
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func loadJSON(path string, includeFailed bool) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(report.Passed)+len(report.Failed))
	for _, rec := range report.Passed {
		ips = append(ips, rec.IP)
	}
	if includeFailed {
		for _, rec := range report.Failed {
			ips = append(ips, rec.IP)
		}
	}
	return ips, nil
}
