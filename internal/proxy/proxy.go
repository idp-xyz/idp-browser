// Package proxy is the browser's egress proxy: the only way a Chromium of idp-browser reaches anything, and it reaches
// public addresses only (ADR-0001 D3 to D6).
//
// It is idp-sandbox's egress proxy (D13, D22 there) with the policy changed. The sandbox's proxy lets a run reach the
// hosts an operator listed; this one has no list of hosts, because a browser goes where the page sends it, and instead
// refuses by ADDRESS: it resolves the name itself, applies idp-web's address rules (internal/addr) to every answer, and
// dials only addresses it checked, by Happy Eyeballs (dialrace.go). It speaks CONNECT (HTTPS, WebSocket) and plain-HTTP
// forwarding, caches nothing, and logs one audit line per request: render, host, port, decision, reason, bytes,
// milliseconds, never a path, a query string or a body.
//
// Who may use it: only a render the renderer registered (registry.go, admin.go). The browser's requests carry the
// render's id and a random token as Proxy-Authorization; a request without a live pair is answered 407 and nothing else
// is looked at. Each render has a budget (requests, total bytes, bytes per response, a deadline) that is counted here.
package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"idp-browser/internal/addr"
)

// Entry is one audit line (ADR-0001 D6): what was asked and what was decided. Host is the host of the request as the
// browser wrote it, cut to 253 bytes; there is no path, query string or body field, so none can be logged by mistake.
type Entry struct {
	Render   string
	Host     string
	Port     int
	Decision string // allow or deny
	Reason   string // ok, or why not: no_credential, unknown_render, bad_token, expired, port, bad_host, not_public, unresolved, limit_requests, limit_bytes, limit_response, deadline, busy, upstream
	Bytes    int64  // both directions
	MS       int64
}

// Auditor receives every audit line.
type Auditor interface{ Audit(Entry) }

// SlogAuditor writes the lines as structured log records.
type SlogAuditor struct{ Log *slog.Logger }

// Audit implements Auditor.
func (a SlogAuditor) Audit(e Entry) {
	a.Log.Info("egress", "render", e.Render, "host", e.Host, "port", e.Port, "decision", e.Decision, "reason", e.Reason, "bytes", e.Bytes, "ms", e.MS)
}

// Proxy is the forward proxy.
type Proxy struct {
	Registry *Registry
	// Ports the proxy connects to (default 80 and 443).
	Ports []int
	// TestOrigins are exact "host:port" pairs exempt from the port and the address rules: acceptance only, as idp-web's
	// IDP_WEB_TEST_ORIGINS (ADR-0001 D13). The renderer's own address rules take the same list.
	TestOrigins map[string]bool
	// DialFamily is the address families dialed and which first (default prefer-ipv4).
	DialFamily  DialFamily
	DialTimeout time.Duration // default 10 s
	MaxConns    int           // concurrent connections (default 256)
	MaxLifetime time.Duration // a tunnel is cut after this long even inside the render's deadline (default 5 min)
	Audit       Auditor
	Resolver    interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}

	dialFn func(ctx context.Context, network, address string) (net.Conn, error) // tests: replaces the TCP dial after the checks
	active atomic.Int64
	once   sync.Once

	// counters for /metrics
	Allowed, Denied atomic.Int64
}

func (p *Proxy) init() {
	p.once.Do(func() {
		if p.Registry == nil {
			p.Registry = &Registry{}
		}
		if p.DialTimeout == 0 {
			p.DialTimeout = 10 * time.Second
		}
		if p.MaxConns == 0 {
			p.MaxConns = 256
		}
		if p.MaxLifetime == 0 {
			p.MaxLifetime = 5 * time.Minute
		}
		if p.Resolver == nil {
			p.Resolver = net.DefaultResolver
		}
		if p.Audit == nil {
			p.Audit = SlogAuditor{slog.Default()}
		}
		if len(p.Ports) == 0 {
			p.Ports = []int{80, 443}
		}
	})
}

func (p *Proxy) record(rd *Render, host string, port int, decision, reason string, bytes int64, start time.Time) {
	if len(host) > 253 {
		host = host[:253]
	}
	e := Entry{Host: host, Port: port, Decision: decision, Reason: reason, Bytes: bytes, MS: time.Since(start).Milliseconds()}
	if rd != nil {
		e.Render = rd.id
		if decision == "deny" {
			rd.refuse(host, port, reason)
		}
	}
	if decision == "allow" {
		p.Allowed.Add(1)
	} else {
		p.Denied.Add(1)
	}
	p.Audit.Audit(e)
}

// splitHostPort splits "host:port" with a default port; the brackets of an IPv6 literal are removed.
func splitHostPort(hostport, defaultPort string) (string, int, error) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		// no port: "host", "1.2.3.4" or "[::1]"
		if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
			h = hostport[1 : len(hostport)-1]
		} else if !strings.Contains(hostport, ":") {
			h = hostport
		} else {
			return "", 0, err
		}
		ps = defaultPort
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("bad port")
	}
	return h, port, nil
}

// authenticate reads Proxy-Authorization: Basic base64(renderID:token).
func (p *Proxy) authenticate(r *http.Request) (*Render, string) {
	h := r.Header.Get("Proxy-Authorization")
	scheme, rest, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Basic") {
		return nil, "no_credential"
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return nil, "no_credential"
	}
	id, token, ok := strings.Cut(string(raw), ":")
	if !ok {
		return nil, "no_credential"
	}
	return p.Registry.Lookup(id, []byte(token))
}

// ServeHTTP handles CONNECT and absolute-URI forwarding.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.init()
	start := time.Now()
	if p.active.Add(1) > int64(p.MaxConns) {
		p.active.Add(-1)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer p.active.Add(-1)
	target := r.Host
	defaultPort := "443"
	if r.Method != http.MethodConnect {
		if r.URL.Host != "" {
			target = r.URL.Host
		}
		defaultPort = "80"
	}
	host, port, perr := splitHostPort(target, defaultPort)
	if perr != nil {
		host, port = target, 0
	}
	rd, why := p.authenticate(r)
	if rd == nil {
		p.record(nil, host, port, "deny", why, 0, start)
		w.Header().Set("Proxy-Authenticate", `Basic realm="idp-browser-proxy"`)
		http.Error(w, "this proxy serves renders: "+why, http.StatusProxyAuthRequired)
		return
	}
	if perr != nil {
		p.record(rd, host, port, "deny", "bad_host", 0, start)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodConnect && (r.URL.Scheme != "http" || r.URL.Host == "") {
		p.record(rd, host, port, "deny", "bad_host", 0, start)
		http.Error(w, "this is a proxy: use an absolute http:// URI or CONNECT", http.StatusBadRequest)
		return
	}
	if ok, reason := rd.admit(); !ok {
		p.record(rd, host, port, "deny", reason, 0, start)
		http.Error(w, "the render's budget is used up: "+reason, http.StatusTooManyRequests)
		return
	}
	// the address rules, before anything is resolved or dialed
	ips, reason := p.check(r.Context(), host, port)
	if reason != "" {
		p.record(rd, host, port, "deny", reason, 0, start)
		http.Error(w, "the browser may not reach "+host+": "+reason, http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r, rd, host, port, ips, start)
		return
	}
	p.forward(w, r, rd, host, port, ips, start)
}

func (p *Proxy) portAllowed(port int) bool {
	for _, x := range p.Ports {
		if x == port {
			return true
		}
	}
	return false
}

// check applies the port rule and the address rules to host:port and returns the addresses that may be dialed, or the
// reason why none may. Every address that came back must be public: a name with one private answer among its public
// ones is a name an attacker controls (the same rule as idp-web's checkedDial).
func (p *Proxy) check(ctx context.Context, host string, port int) ([]netip.Addr, string) {
	exempt := p.TestOrigins[net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port))]
	if !exempt && !p.portAllowed(port) {
		return nil, "port"
	}
	// addr.Target is the one parser of host forms (non-canonical IP spellings, userinfo, IDNA, bad labels are refused there)
	a, err := addr.TargetWith("http://"+net.JoinHostPort(host, strconv.Itoa(port))+"/", addr.Options{TestOrigins: p.TestOrigins, Ports: p.Ports})
	if err != nil {
		if errors.Is(err, addr.ErrNotPublic) {
			return nil, "not_public"
		}
		return nil, "bad_host"
	}
	var ips []netip.Addr
	if a.IP.IsValid() {
		ips = []netip.Addr{a.IP}
	} else {
		ips, err = p.Resolver.LookupNetIP(ctx, "ip", a.Host)
		if err != nil || len(ips) == 0 {
			return nil, "unresolved"
		}
	}
	if !a.Exempt {
		for _, ip := range ips {
			if !addr.Public(ip) {
				return nil, "not_public"
			}
		}
	}
	return ips, ""
}

// dial connects to one of ips, all of which check approved, by Happy Eyeballs.
func (p *Proxy) dial(ctx context.Context, ips []netip.Addr, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, p.DialTimeout)
	defer cancel()
	dial := p.dialFn
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return dialRace(ctx, dial, p.DialFamily, ips, port)
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request, rd *Render, host string, port int, ips []netip.Addr, start time.Time) {
	up, err := p.dial(rd.ctx, ips, port)
	if err != nil {
		p.record(rd, host, port, "deny", "upstream", 0, start)
		http.Error(w, "the origin did not answer", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "cannot hijack", http.StatusInternalServerError)
		return
	}
	c, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	deadline := time.Now().Add(p.MaxLifetime)
	if d, ok := rd.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	_ = up.SetDeadline(deadline)
	var in, out atomic.Int64
	stop := context.AfterFunc(rd.ctx, func() { c.Close(); up.Close() }) // the render's deadline, its end, or its byte budget
	defer stop()
	perTunnel := rd.limits.MaxResponseBytes
	done := make(chan struct{}, 2)
	go func() { // client -> origin; the client finishing sending is a half-close, the origin may still answer
		copyCounted(up, c, func(n int) bool { out.Add(int64(n)); return rd.addBytes(n, false) })
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() { // origin -> client; the origin finishing, or its response budget, ends the whole tunnel
		copyCounted(c, up, func(n int) bool {
			if in.Add(int64(n)) > perTunnel {
				rd.setLimit("response")
				return false
			}
			return rd.addBytes(n, true)
		})
		_ = c.Close()
		_ = up.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
	_ = c.Close()
	_ = up.Close()
	reason := "ok"
	switch {
	case rd.limitHit() == "bytes":
		reason = "limit_bytes"
	case in.Load() > perTunnel:
		reason = "limit_response"
	}
	p.record(rd, host, port, "allow", reason, in.Load()+out.Load(), start)
}

// copyCounted copies src to dst, telling count the size of every chunk; count returning false stops the copy.
func copyCounted(dst io.Writer, src io.Reader, count func(n int) bool) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if !count(n) {
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

var hopHeaders = []string{"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// forward makes one plain-HTTP request for the browser. The response is refused when it announces more than the
// per-response budget and cut when it turns out to have more; either way the render is told.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, rd *Render, host string, port int, ips []netip.Addr, start time.Time) {
	tr := &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return p.dial(ctx, ips, port) }, // the checked addresses, never a second lookup
		DisableKeepAlives: true, ResponseHeaderTimeout: 30 * time.Second, Proxy: nil,
	}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(rd.ctx, cancel)
	defer stop()
	out := r.Clone(ctx)
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	var sent atomic.Int64
	if r.Body != nil && r.Body != http.NoBody {
		out.Body = io.NopCloser(&countingReader{r: r.Body, count: func(n int) bool { sent.Add(int64(n)); return rd.addBytes(n, false) }})
	}
	resp, err := tr.RoundTrip(out)
	if err != nil {
		reason := "upstream"
		if rd.ctx.Err() != nil {
			reason = "deadline"
			if rd.limitHit() == "bytes" {
				reason = "limit_bytes"
			}
		}
		p.record(rd, host, port, "deny", reason, sent.Load(), start)
		http.Error(w, "the origin did not answer", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.ContentLength > rd.limits.MaxResponseBytes {
		rd.setLimit("response")
		p.record(rd, host, port, "deny", "limit_response", sent.Load(), start)
		http.Error(w, "the response is larger than the render may receive", http.StatusBadGateway)
		return
	}
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	var got int64
	over := ""
	buf := make([]byte, 32<<10)
	for over == "" {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			got += int64(n)
			switch {
			case got > rd.limits.MaxResponseBytes:
				rd.setLimit("response")
				over = "limit_response"
			case !rd.addBytes(n, true):
				over = "limit_bytes"
			default:
				if _, werr := w.Write(buf[:n]); werr != nil {
					over = "client"
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	reason := "ok"
	if over == "limit_response" || over == "limit_bytes" {
		reason = over
	}
	p.record(rd, host, port, "allow", reason, sent.Load()+got, start)
	if over == "limit_response" || over == "limit_bytes" {
		panic(http.ErrAbortHandler) // the browser must see a broken response, not a short one that looks complete
	}
}

type countingReader struct {
	r     io.Reader
	count func(n int) bool
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 && !c.count(n) {
		return n, errors.New("the render's byte budget is used up")
	}
	return n, err
}

// String is for tests and logs.
func (e Entry) String() string {
	return fmt.Sprintf("%s %s:%d %s %s %d %dms", e.Render, e.Host, e.Port, e.Decision, e.Reason, e.Bytes, e.MS)
}
