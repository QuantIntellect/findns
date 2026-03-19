package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DnsttMTU caps the upstream DNS query payload size (dnstt-client -mtu flag).
// 0 means use dnstt-client's default (maximum capacity).
var DnsttMTU int

func PortPool(base, count int) chan int {
	ch := make(chan int, count)
	for i := 0; i < count; i++ {
		ch <- base + i
	}
	return ch
}

func execCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, name, args...)
}

// e2eDiag stores the first e2e failure diagnostic message so both CLI and
// TUI can display it. Only the first failure is captured (via sync.Once).
var e2eDiag struct {
	mu  sync.Mutex
	msg string
}

// E2EDiagnostic returns the first e2e failure diagnostic, or "".
func E2EDiagnostic() string {
	e2eDiag.mu.Lock()
	defer e2eDiag.mu.Unlock()
	return e2eDiag.msg
}

// ResetE2EDiagnostic clears the stored diagnostic so a fresh scan starts clean.
func ResetE2EDiagnostic() {
	e2eDiag.mu.Lock()
	e2eDiag.msg = ""
	e2eDiag.mu.Unlock()
}

func setDiag(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e2eDiag.mu.Lock()
	if e2eDiag.msg == "" {
		e2eDiag.msg = msg
	}
	e2eDiag.mu.Unlock()
}

// DnsttCheckBin verifies the dnstt Noise handshake completes through a resolver.
func DnsttCheckBin(bin, domain, pubkey string, ports chan int) CheckFunc {
	return dnsttCheck(bin, domain, pubkey, ports)
}

func DnsttCheck(domain, pubkey string, ports chan int) CheckFunc {
	return dnsttCheck("dnstt-client", domain, pubkey, ports)
}

func dnsttCheck(bin, domain, pubkey string, ports chan int) CheckFunc {
	var diagOnce atomic.Bool

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}

		start := time.Now()

		var stderrBuf bytes.Buffer
		args := []string{
			"-udp", net.JoinHostPort(ip, "53"),
			"-pubkey", pubkey,
		}
		if DnsttMTU > 0 {
			args = append(args, "-mtu", strconv.Itoa(DnsttMTU))
		}
		args = append(args, domain, fmt.Sprintf("127.0.0.1:%d", port))
		cmd := execCommandContext(ctx, bin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = &stderrBuf
		if err := cmd.Start(); err != nil {
			ports <- port
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/dnstt: cannot start %s: %v", bin, err)
			}
			return false, nil
		}

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		defer func() {
			cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			time.Sleep(300 * time.Millisecond)
			ports <- port
		}()

		// Wait for SOCKS port to open, then do a SOCKS5 handshake through
		// the tunnel. This is much faster than spawning curl — we just need
		// to verify that data flows bidirectionally through the DNS tunnel.
		if !waitAndTestSOCKS5Connect(ctx, port, exited) {
			if diagOnce.CompareAndSwap(false, true) {
				processExitedEarly := false
				select {
				case <-exited:
					processExitedEarly = true
				default:
				}
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
				}
				stderr := strings.TrimSpace(stderrBuf.String())
				if stderr != "" {
					setDiag("e2e/dnstt first failure (ip=%s): dnstt-client stderr: %s", ip, truncate(stderr, 300))
				} else if processExitedEarly {
					setDiag("e2e/dnstt first failure (ip=%s): dnstt-client exited early with no stderr", ip)
				} else {
					setDiag("e2e/dnstt first failure (ip=%s): SOCKS5 handshake through tunnel timed out within %v", ip, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}

// waitAndTestSOCKS5Connect waits for the SOCKS port to open, performs a
// SOCKS5 auth handshake, then sends a SOCKS5 CONNECT request to a remote
// host. The CONNECT request travels through the DNS tunnel:
//
//	client → dnstt-client → DNS tunnel → resolver → dnstt-server → connect attempt → reply back
//
// Getting ANY SOCKS5 reply (even a failure code like 0x01) proves
// bidirectional data flow through the DNS tunnel. We don't require 0x00
// (success) because the server may not have internet access — but the
// reply itself proves the tunnel carried data both ways.
func waitAndTestSOCKS5Connect(ctx context.Context, port int, exited <-chan struct{}) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Poll until SOCKS port accepts a connection, then reuse that
	// connection — avoids ghost streams from close-and-reopen.
	for {
		select {
		case <-ctx.Done():
			return false
		case <-exited:
			return false
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			select {
			case <-ctx.Done():
				return false
			case <-exited:
				return false
			case <-time.After(300 * time.Millisecond):
			}
			continue
		}

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}

		// Step 1: SOCKS5 auth (local to dnstt-client)
		// version=5, 1 method, no-auth(0x00)
		if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			conn.Close()
			return false
		}
		authResp := make([]byte, 2)
		if _, err = io.ReadFull(conn, authResp); err != nil {
			conn.Close()
			return false
		}
		if authResp[0] != 0x05 {
			conn.Close()
			return false
		}

		// Step 2: SOCKS5 CONNECT to example.com:80
		// This goes through the DNS tunnel — the real e2e proof.
		// Format: VER=5, CMD=1(connect), RSV=0, ATYP=3(domain),
		//         LEN, DOMAIN, PORT_HI, PORT_LO
		domain := "example.com"
		connectReq := make([]byte, 0, 7+len(domain))
		connectReq = append(connectReq, 0x05, 0x01, 0x00, 0x03)
		connectReq = append(connectReq, byte(len(domain)))
		connectReq = append(connectReq, []byte(domain)...)
		connectReq = append(connectReq, 0x00, 0x50) // port 80
		if _, err = conn.Write(connectReq); err != nil {
			conn.Close()
			return false
		}

		// Step 3: Read SOCKS5 CONNECT reply (at least 4 bytes: VER, REP, RSV, ATYP)
		// Any valid SOCKS5 reply proves the tunnel works — even failure codes
		// like 0x01 (general failure) mean data traveled through the tunnel
		// and came back.
		connectResp := make([]byte, 4)
		if _, err = io.ReadFull(conn, connectResp); err != nil {
			conn.Close()
			return false
		}
		conn.Close()

		// VER must be 0x05 = valid SOCKS5 reply came back through tunnel
		return connectResp[0] == 0x05
	}
}

// SlipstreamCheckBin is like SlipstreamCheck but uses an explicit binary path.
func SlipstreamCheckBin(bin, domain, certPath string, ports chan int) CheckFunc {
	return slipstreamCheck(bin, domain, certPath, ports)
}

func SlipstreamCheck(domain, certPath string, ports chan int) CheckFunc {
	return slipstreamCheck("slipstream-client", domain, certPath, ports)
}

func slipstreamCheck(bin, domain, certPath string, ports chan int) CheckFunc {
	var diagOnce atomic.Bool

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}

		start := time.Now()

		args := []string{
			"-d", domain,
			"-r", net.JoinHostPort(ip, "53"),
			"-l", fmt.Sprintf("%d", port),
		}
		if certPath != "" {
			args = append(args, "--cert", certPath)
		}
		var stderrBuf bytes.Buffer
		cmd := execCommandContext(ctx, bin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = &stderrBuf
		if err := cmd.Start(); err != nil {
			ports <- port
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/slipstream: cannot start %s: %v", bin, err)
			}
			return false, nil
		}

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		defer func() {
			cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			time.Sleep(300 * time.Millisecond)
			ports <- port
		}()

		if !waitAndTestSOCKS5Connect(ctx, port, exited) {
			if diagOnce.CompareAndSwap(false, true) {
				processExitedEarly := false
				select {
				case <-exited:
					processExitedEarly = true
				default:
				}
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
				}
				stderr := strings.TrimSpace(stderrBuf.String())
				if stderr != "" {
					setDiag("e2e/slipstream first failure (ip=%s): stderr: %s", ip, truncate(stderr, 300))
				} else if processExitedEarly {
					setDiag("e2e/slipstream first failure (ip=%s): process exited early with no stderr", ip)
				} else {
					setDiag("e2e/slipstream first failure (ip=%s): curl could not get HTTP 200 through SOCKS within %v", ip, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{"e2e_ms": ms}
	}
}


// ThroughputCheckBin tests actual data transfer through the DNS tunnel by
// performing an HTTP GET request via the SOCKS5 proxy. This goes beyond the
// e2e handshake test — it verifies that meaningful payload (1-2KB+) flows
// bidirectionally through the tunnel.
func ThroughputCheckBin(bin, domain, pubkey string, ports chan int) CheckFunc {
	var diagOnce atomic.Bool

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}

		start := time.Now()

		var stderrBuf bytes.Buffer
		args := []string{
			"-udp", net.JoinHostPort(ip, "53"),
			"-pubkey", pubkey,
		}
		if DnsttMTU > 0 {
			args = append(args, "-mtu", strconv.Itoa(DnsttMTU))
		}
		args = append(args, domain, fmt.Sprintf("127.0.0.1:%d", port))
		cmd := execCommandContext(ctx, bin, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = &stderrBuf
		if err := cmd.Start(); err != nil {
			ports <- port
			return false, nil
		}

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		defer func() {
			cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			time.Sleep(300 * time.Millisecond)
			ports <- port
		}()

		transferred, ok := waitAndTestThroughput(ctx, port, exited)
		if !ok {
			if diagOnce.CompareAndSwap(false, true) {
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
				}
				stderr := strings.TrimSpace(stderrBuf.String())
				if stderr != "" {
					setDiag("throughput first failure (ip=%s): %s", ip, truncate(stderr, 300))
				} else {
					setDiag("throughput first failure (ip=%s): could not transfer data within %v", ip, timeout)
				}
			}
			return false, nil
		}
		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		return true, Metrics{
			"throughput_bytes": float64(transferred),
			"throughput_ms":   ms,
		}
	}
}

// waitAndTestThroughput waits for the SOCKS port to open, performs a full
// SOCKS5 CONNECT to example.com:80, sends an HTTP GET request, and reads
// the response. This proves that real data (not just a handshake) can flow
// through the DNS tunnel.
func waitAndTestThroughput(ctx context.Context, port int, exited <-chan struct{}) (int, bool) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	for {
		select {
		case <-ctx.Done():
			return 0, false
		case <-exited:
			return 0, false
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			select {
			case <-ctx.Done():
				return 0, false
			case <-exited:
				return 0, false
			case <-time.After(300 * time.Millisecond):
			}
			continue
		}

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}

		// Step 1: SOCKS5 auth
		if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			conn.Close()
			return 0, false
		}
		authResp := make([]byte, 2)
		if _, err = io.ReadFull(conn, authResp); err != nil || authResp[0] != 0x05 {
			conn.Close()
			return 0, false
		}

		// Step 2: SOCKS5 CONNECT to example.com:80
		target := "example.com"
		connectReq := make([]byte, 0, 7+len(target))
		connectReq = append(connectReq, 0x05, 0x01, 0x00, 0x03)
		connectReq = append(connectReq, byte(len(target)))
		connectReq = append(connectReq, []byte(target)...)
		connectReq = append(connectReq, 0x00, 0x50) // port 80
		if _, err = conn.Write(connectReq); err != nil {
			conn.Close()
			return 0, false
		}

		// Step 3: Read SOCKS5 CONNECT reply header
		hdr := make([]byte, 4) // VER, REP, RSV, ATYP
		if _, err = io.ReadFull(conn, hdr); err != nil {
			conn.Close()
			return 0, false
		}
		if hdr[0] != 0x05 || hdr[1] != 0x00 {
			// CONNECT failed — server may lack internet access
			conn.Close()
			return 0, false
		}
		// Drain remaining CONNECT reply based on ATYP
		switch hdr[3] {
		case 0x01: // IPv4: 4 addr + 2 port
			io.ReadFull(conn, make([]byte, 6))
		case 0x03: // Domain: 1 len + domain + 2 port
			lenBuf := make([]byte, 1)
			if _, err = io.ReadFull(conn, lenBuf); err == nil {
				io.ReadFull(conn, make([]byte, int(lenBuf[0])+2))
			}
		case 0x04: // IPv6: 16 addr + 2 port
			io.ReadFull(conn, make([]byte, 18))
		}

		// Step 4: Send HTTP GET request through the tunnel
		httpReq := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
		if _, err = conn.Write([]byte(httpReq)); err != nil {
			conn.Close()
			return 0, false
		}

		// Step 5: Read HTTP response
		buf := make([]byte, 65536)
		totalRead := 0
		for {
			n, readErr := conn.Read(buf[totalRead:])
			totalRead += n
			if readErr != nil || totalRead >= len(buf) {
				break
			}
		}
		conn.Close()

		// Need at least 100 bytes to confirm real data transfer
		if totalRead < 100 {
			return totalRead, false
		}
		return totalRead, true
	}
}

func truncate(s string, maxLen int) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

