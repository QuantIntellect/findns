package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

// Regex for Linux/macOS: "rtt min/avg/max/mdev = 4.123/5.456/6.789/..."
var pingAvgRegex = regexp.MustCompile(`= [\d.]+/([\d.]+)/`)

// Regex for Windows: "Average = 5ms"
var pingAvgWindowsRegex = regexp.MustCompile(`Average = (\d+)ms`)

func parsePingAvg(output string) float64 {
	// Try Unix format first
	m := pingAvgRegex.FindStringSubmatch(output)
	if len(m) >= 2 {
		v, err := strconv.ParseFloat(m[1], 64)
		if err == nil {
			return v
		}
	}
	// Try Windows format
	m = pingAvgWindowsRegex.FindStringSubmatch(output)
	if len(m) >= 2 {
		v, err := strconv.ParseFloat(m[1], 64)
		if err == nil {
			return v
		}
	}
	return 0
}

func buildPingArgs(count, timeoutSecs, deadlineSecs int, ip string) []string {
	switch runtime.GOOS {
	case "windows":
		// Windows: ping -n count -w timeout_ms ip
		return []string{"-n", fmt.Sprintf("%d", count), "-w", fmt.Sprintf("%d", timeoutSecs*1000), ip}
	case "darwin":
		// macOS: ping -c count -W timeout_ms ip (no -w deadline)
		return []string{"-c", fmt.Sprintf("%d", count), "-W", fmt.Sprintf("%d", timeoutSecs*1000), ip}
	default:
		// Linux: ping -c count -W timeout_secs -w deadline_secs ip
		return []string{"-c", fmt.Sprintf("%d", count), "-W", fmt.Sprintf("%d", timeoutSecs), "-w", fmt.Sprintf("%d", deadlineSecs), ip}
	}
}

func PingCheck(count int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		secs := int(timeout.Seconds())
		if secs < 1 {
			secs = 1
		}
		deadline := count*secs + 2
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadline+2)*time.Second)
		defer cancel()

		args := buildPingArgs(count, secs, deadline, ip)
		cmd := exec.CommandContext(ctx, "ping", args...)
		out, _ := cmd.CombinedOutput()
		avg := parsePingAvg(string(out))
		if avg <= 0 {
			return false, nil
		}
		return true, Metrics{"ping_ms": avg}
	}
}

func ResolveCheck(domain string, count int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		var successes []float64

		for i := 0; i < count; i++ {
			start := time.Now()
			if QueryA(ip, domain, timeout) {
				ms := float64(time.Since(start).Microseconds()) / 1000.0
				successes = append(successes, ms)
			}
		}

		if len(successes) == 0 {
			return false, nil
		}

		var sum float64
		for _, v := range successes {
			sum += v
		}
		return true, Metrics{"resolve_ms": roundMs(sum / float64(len(successes)))}
	}
}

func TunnelCheck(domain string, count int) CheckFunc {
	return func(ip string, timeout time.Duration) (bool, Metrics) {
		var successes []float64

		for i := 0; i < count; i++ {
			start := time.Now()

			// Query a random subdomain TXT record — same as what dnstt-client does.
			// If the resolver forwards it to the authoritative server, the tunnel works.
			// NS queries fail on most setups because dnstt-server/dnstm don't serve NS records.
			qname := fmt.Sprintf("tun-%s.%s", randLabel(8), domain)
			r, ok := queryRaw(ip, qname, dns.TypeTXT, timeout)
			if !ok || r == nil {
				continue
			}
			// SERVFAIL/REFUSED = resolver can't reach the authoritative server
			if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused {
				continue
			}

			ms := float64(time.Since(start).Microseconds()) / 1000.0
			successes = append(successes, ms)
		}

		if len(successes) == 0 {
			return false, nil
		}

		var sum float64
		for _, v := range successes {
			sum += v
		}
		return true, Metrics{"resolve_ms": roundMs(sum / float64(len(successes)))}
	}
}
