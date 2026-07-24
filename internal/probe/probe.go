// Package probe implements the four probe methods a transport can use:
// tcp, http, icmp, and exec. See design.md §1 (why Go: no runtime
// dependency on `ping`/`ip` being on PATH) and §6.2 (the exec contract).
package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/julian-corbet/nixnet-corbet-ch/internal/config"
)

// Result is what a single probe run produced.
type Result struct {
	Healthy bool
	// Address, if non-empty, overrides the transport's configured address
	// for this tick — the entire dynamic-address mechanism from
	// design.md §6.2. Only ever set by the exec method.
	Address string
	Detail  string
}

// Run dispatches to the method-specific prober. ctx should already carry
// the transport's probe.timeoutMs deadline; each prober additionally
// enforces it locally so a hung dial can't outlive the tick.
func Run(ctx context.Context, t config.Transport) (Result, error) {
	timeout := time.Duration(t.Probe.TimeoutMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch t.Probe.Method {
	case "tcp":
		return runTCP(ctx, t)
	case "http":
		return runHTTP(ctx, t)
	case "icmp":
		return runICMP(ctx, t)
	case "exec":
		return runExec(ctx, t)
	default:
		return Result{}, fmt.Errorf("unknown probe method %q", t.Probe.Method)
	}
}

func runTCP(ctx context.Context, t config.Transport) (Result, error) {
	target := t.EffectiveTarget()
	if target == "" {
		return Result{}, fmt.Errorf("tcp probe: no target/address configured")
	}
	port := t.Probe.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(target, strconv.Itoa(port))

	dialer := net.Dialer{}
	if t.Probe.BindToInterface && t.Interface != "" {
		dialer.Control = bindToDeviceControl(t.Interface)
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{Healthy: false, Detail: err.Error()}, nil
	}
	_ = conn.Close()
	return Result{Healthy: true, Detail: "tcp connect ok"}, nil
}

func runHTTP(ctx context.Context, t config.Transport) (Result, error) {
	target := t.EffectiveTarget()
	if target == "" {
		return Result{}, fmt.Errorf("http probe: no target/address configured")
	}
	url := target
	if !strings.Contains(url, "://") {
		host := url
		if t.Probe.Port != 0 && t.Probe.Port != 80 && !strings.Contains(host, ":") {
			host = net.JoinHostPort(host, strconv.Itoa(t.Probe.Port))
		}
		path := t.Probe.Path
		if path == "" {
			path = "/"
		}
		url = "http://" + host + path
	}

	transport := &http.Transport{}
	if t.Probe.BindToInterface && t.Interface != "" {
		dialer := net.Dialer{Control: bindToDeviceControl(t.Interface)}
		transport.DialContext = dialer.DialContext
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, fmt.Errorf("http probe: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Healthy: false, Detail: err.Error()}, nil
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	healthy := resp.StatusCode < 400
	return Result{Healthy: healthy, Detail: fmt.Sprintf("http status %d", resp.StatusCode)}, nil
}

func runICMP(ctx context.Context, t config.Transport) (Result, error) {
	target := t.EffectiveTarget()
	if target == "" {
		return Result{}, fmt.Errorf("icmp probe: no target/address configured")
	}
	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return Result{Healthy: false, Detail: fmt.Sprintf("resolve: %v", err)}, nil
	}

	// Privileged raw ICMP ("ip4:icmp"), via the standard library directly
	// rather than icmp.ListenPacket's wrapper — *net.IPConn is what
	// exposes SyscallConn(), which SO_BINDTODEVICE needs below.
	// golang.org/x/net/icmp is still used for wire encoding/decoding
	// (icmp.Message, icmp.ParseMessage), matching design.md §1's call to
	// use it for "its own unprivileged ICMP" (raw here; unprivileged
	// SOCK_DGRAM ICMP is a possible future addition, see experiments/).
	// Requires CAP_NET_RAW, which modules/core.nix grants via
	// AmbientCapabilities whenever any transport uses method=icmp or
	// bindToInterface=true (design.md §8).
	pc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return Result{Healthy: false, Detail: fmt.Sprintf("listen (need CAP_NET_RAW): %v", err)}, nil
	}
	defer pc.Close()

	if t.Probe.BindToInterface && t.Interface != "" {
		ipConn, ok := pc.(*net.IPConn)
		if !ok {
			return Result{Healthy: false, Detail: "bindToInterface: underlying conn is not *net.IPConn"}, nil
		}
		if err := bindIPConnToDevice(ipConn, t.Interface); err != nil {
			return Result{Healthy: false, Detail: fmt.Sprintf("bind to %s: %v", t.Interface, err)}, nil
		}
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = pc.SetDeadline(deadline)
	}

	id := int(time.Now().UnixNano() & 0xffff)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("nixnet")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return Result{}, fmt.Errorf("icmp probe: marshal: %w", err)
	}
	if _, err := pc.WriteTo(wb, dst); err != nil {
		return Result{Healthy: false, Detail: fmt.Sprintf("write: %v", err)}, nil
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFrom(rb)
		if err != nil {
			return Result{Healthy: false, Detail: fmt.Sprintf("no reply: %v", err)}, nil
		}
		if peer.String() != dst.String() {
			continue // stray reply from a different host; keep waiting for ours
		}
		rm, err := icmp.ParseMessage(1, rb[:n]) // 1 == ICMPv4 protocol number
		if err != nil {
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			return Result{Healthy: true, Detail: "icmp echo reply"}, nil
		}
	}
}

// runExec implements the provider exec-probe contract from design.md §6.2:
// exit code 0 = healthy, non-zero = unhealthy (the only guaranteed
// signal); an optional single line of JSON on stdout
// ({"address":...,"healthy":...,"detail":...}) may additionally override
// the address and surface free-text detail. `healthy` in the JSON is
// informational only — the exit code always wins.
//
// probe.exec is a full command line ("<store-path> arg1 arg2 ..."), not a
// bare path — see config.Probe.Exec's doc comment. It is tokenized here
// and exec'd directly, never through a shell, so a provider script never
// gains an implicit dependency on /bin/sh existing on PATH.
func runExec(ctx context.Context, t config.Transport) (Result, error) {
	argv, err := tokenize(t.Probe.Exec)
	if err != nil {
		return Result{}, fmt.Errorf("exec probe: %w", err)
	}
	if len(argv) == 0 {
		return Result{}, fmt.Errorf("exec probe: probe.exec is empty")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	stdout, err := cmd.Output()
	exitErr, isExitErr := err.(*exec.ExitError)

	healthy := err == nil
	if err != nil && !isExitErr {
		// Couldn't even start the process (missing binary, timeout before
		// exec, ...) — unhealthy, not a hard daemon error, so one bad
		// provider script can't take down the whole tick loop.
		return Result{Healthy: false, Detail: err.Error()}, nil
	}
	_ = exitErr

	res := Result{Healthy: healthy}
	line := firstNonEmptyLine(stdout)
	if line != "" {
		var envelope struct {
			Address string `json:"address"`
			Healthy *bool  `json:"healthy"`
			Detail  string `json:"detail"`
		}
		if jsonErr := json.Unmarshal([]byte(line), &envelope); jsonErr == nil {
			res.Address = envelope.Address
			res.Detail = envelope.Detail
			// Exit code remains authoritative; envelope.Healthy is
			// deliberately never consulted here (design.md §6.2).
		} else {
			res.Detail = fmt.Sprintf("exec probe: stdout was not the one-line JSON envelope: %v", jsonErr)
		}
	}
	if res.Detail == "" {
		if healthy {
			res.Detail = "exec exit 0"
		} else {
			res.Detail = "exec exit non-zero"
		}
	}
	return res, nil
}

func firstNonEmptyLine(b []byte) string {
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			return line
		}
	}
	return ""
}

// tokenize does minimal shell-word splitting (whitespace-separated,
// single/double quotes respected, no globbing/expansion/escapes beyond a
// literal backslash-space). Nix store paths never contain literal spaces,
// so this only ever needs to split "<path> arg1 arg2 ...".
func tokenize(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteRune(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else {
				cur.WriteRune(c)
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteRune(c)
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in exec command line %q", s)
	}
	flush()
	return tokens, nil
}
