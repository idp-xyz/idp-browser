package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

type capture struct {
	mu sync.Mutex
	es []Entry
}

func (c *capture) Audit(e Entry) { c.mu.Lock(); c.es = append(c.es, e); c.mu.Unlock() }
func (c *capture) entries() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Entry(nil), c.es...)
}
func (c *capture) last(t *testing.T) Entry {
	t.Helper()
	es := c.entries()
	if len(es) == 0 {
		t.Fatal("no audit line")
	}
	return es[len(es)-1]
}

// env is a proxy whose every dial goes to one local origin, with a name table, a registered render, and a canary: a
// listener on loopback that stands for the inside of the network and must never be dialed.
type env struct {
	p      *Proxy
	srv    *httptest.Server
	audit  *capture
	origin *httptest.Server
	hits   atomic.Int64 // requests the origin received
	dials  atomic.Int64 // connections the proxy made after its checks
	id     string
	token  string
	canary net.Listener
	canHit atomic.Int64
}

func newEnv(t *testing.T, mut func(*Proxy), life time.Duration, lim Limits) *env {
	t.Helper()
	e := &env{audit: &capture{}, id: "r1", token: strings.Repeat("t", 32)}
	e.origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		switch {
		case strings.HasPrefix(r.URL.Path, "/big"):
			w.Header().Set("Content-Length", "2000000")
			w.Write(make([]byte, 2000000))
		case strings.HasPrefix(r.URL.Path, "/stream"):
			f := w.(http.Flusher)
			for i := 0; i < 200; i++ { // no Content-Length: chunked
				w.Write(make([]byte, 10000))
				f.Flush()
			}
		default:
			fmt.Fprint(w, "from the origin")
		}
	}))
	t.Cleanup(e.origin.Close)
	var err error
	if e.canary, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.canary.Close() })
	go func() {
		for {
			c, err := e.canary.Accept()
			if err != nil {
				return
			}
			e.canHit.Add(1)
			c.Close()
		}
	}()
	e.p = &Proxy{
		Registry: &Registry{},
		Audit:    e.audit,
		Resolver: resolver{
			"public.test":    {netip.MustParseAddr("93.184.216.34")},
			"private.test":   {netip.MustParseAddr("10.1.2.3")},
			"loop.test":      {netip.MustParseAddr("127.0.0.1")},
			"meta.test":      {netip.MustParseAddr("169.254.169.254")},
			"mixed.test":     {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("192.168.0.9")},
			"mixed6.test":    {netip.MustParseAddr("2606:4700::1"), netip.MustParseAddr("fd00::1")},
			"mapped.test":    {netip.MustParseAddr("::ffff:127.0.0.1")},
			"nat64.test":     {netip.MustParseAddr("64:ff9b::7f00:1")},
			"v6public.test":  {netip.MustParseAddr("2606:4700::1")},
			"allpublic.test": {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("151.101.0.223")},
		},
	}
	e.p.dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
		e.dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, e.origin.Listener.Addr().String())
	}
	if mut != nil {
		mut(e.p)
	}
	if life == 0 {
		life = time.Minute
	}
	if err := e.p.Registry.Register(e.id, []byte(e.token), life, lim); err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(e.p)
	t.Cleanup(e.srv.Close)
	return e
}

func basic(id, token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+token))
}

// connect sends CONNECT to the proxy with the given Proxy-Authorization ("" for none) and returns the answer.
func (e *env) connect(t *testing.T, authority, auth string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	hdr := ""
	if auth != "" {
		hdr = "Proxy-Authorization: " + auth + "\r\n"
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", authority, authority, hdr)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	return resp, c, br
}

func (e *env) goodAuth() string { return basic(e.id, e.token) }

// get makes a plain-HTTP request through the proxy as the render.
func (e *env) get(t *testing.T, rawURL, auth string) (*http.Response, []byte, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", rawURL, nil)
	if auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	pu, _ := e.srv.Listener.Addr().(*net.TCPAddr)
	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://" + pu.String()) }, DisableKeepAlives: true,
		ProxyConnectHeader: http.Header{}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

// A refusal must leave no trace on the network: nothing dialed, nothing at the canary.
func (e *env) assertUntouched(t *testing.T) {
	t.Helper()
	time.Sleep(20 * time.Millisecond)
	if e.dials.Load() != 0 || e.hits.Load() != 0 || e.canHit.Load() != 0 {
		t.Errorf("dials %d, origin hits %d, canary hits %d: a refused request reached the network", e.dials.Load(), e.hits.Load(), e.canHit.Load())
	}
}

func TestEveryNonPublicClassIsRefusedForConnectAndNothingIsDialed(t *testing.T) {
	canaryAddr := "placeholder"
	cases := []struct{ name, authority, reason string }{
		{"loopback", "127.0.0.1:443", "not_public"},
		{"loopback 127.8", "127.8.8.8:443", "not_public"},
		{"loopback v6", "[::1]:443", "not_public"},
		{"private 10", "10.0.0.1:443", "not_public"},
		{"private 172.16", "172.16.5.5:443", "not_public"},
		{"private 192.168", "192.168.1.1:80", "not_public"},
		{"cgnat", "100.64.0.1:443", "not_public"},
		{"link local", "169.254.1.1:443", "not_public"},
		{"metadata", "169.254.169.254:80", "not_public"},
		{"metadata v6 (AWS)", "[fd00:ec2::254]:80", "not_public"},
		{"link local v6", "[fe80::1]:443", "not_public"},
		{"unique local v6", "[fd00::1]:443", "not_public"},
		{"this network", "0.0.0.0:443", "not_public"},
		{"multicast", "224.0.0.1:443", "not_public"},
		{"broadcast", "255.255.255.255:443", "not_public"},
		{"documentation", "192.0.2.1:443", "not_public"},
		{"benchmarking", "198.18.0.1:443", "not_public"},
		{"IPv4-mapped loopback", "[::ffff:127.0.0.1]:443", "not_public"},
		{"IPv4-mapped metadata, hex spelling", "[::ffff:a9fe:a9fe]:443", "bad_host"},
		{"IPv4-mapped metadata", "[::ffff:169.254.169.254]:443", "not_public"},
		{"IPv4-mapped private", "[::ffff:10.0.0.1]:443", "not_public"},
		{"NAT64 loopback", "[64:ff9b::7f00:1]:443", "not_public"},
		{"NAT64 metadata", "[64:ff9b::a9fe:a9fe]:443", "not_public"},
		{"NAT64 local-use /48", "[64:ff9b:1::7f00:1]:443", "not_public"},
		{"6to4 loopback", "[2002:7f00:1::]:443", "not_public"},
		{"Teredo", "[2001:0:4136:e378:8000:63bf:80ff:fffe]:443", "not_public"},
		{"IPv4-compatible", "[::7f00:1]:443", "not_public"},
		{"a name that resolves privately", "private.test:443", "not_public"},
		{"a name that resolves to loopback", "loop.test:443", "not_public"},
		{"a name that resolves to the metadata address", "meta.test:80", "not_public"},
		{"public and private answers mixed", "mixed.test:443", "not_public"},
		{"public and unique-local v6 mixed", "mixed6.test:443", "not_public"},
		{"a name that resolves to IPv4-mapped loopback", "mapped.test:443", "not_public"},
		{"a name that resolves to NAT64 loopback", "nat64.test:443", "not_public"},
		{"decimal spelling of 127.0.0.1", "2130706433:443", "bad_host"},
		{"hex spelling of 127.0.0.1", "0x7f.1:443", "bad_host"},
		{"short spelling of 127.0.0.1", "127.1:443", "bad_host"},
		{"octal spelling", "0177.0.0.1:443", "bad_host"},
		{"a name that does not resolve", "nowhere.test:443", "unresolved"},
	}
	_ = canaryAddr
	e := newEnv(t, nil, 0, Limits{})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, _, _ := e.connect(t, c.authority, e.goodAuth())
			if resp.StatusCode != 403 && resp.StatusCode != 400 {
				t.Fatalf("%s: status %d", c.authority, resp.StatusCode)
			}
			last := e.audit.last(t)
			if last.Decision != "deny" || last.Reason != c.reason || last.Render != "r1" {
				t.Errorf("audit %v, want a deny for %s", last, c.reason)
			}
		})
	}
	e.assertUntouched(t)
}

// The same classes by plain HTTP: the absolute URI names the target, and the answer is the same.
func TestEveryNonPublicClassIsRefusedForPlainHTTPToo(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{})
	for _, u := range []string{"http://127.0.0.1/", "http://127.0.0.1:" + portOf(e.canary.Addr()) + "/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/",
		"http://[::1]/", "http://[::ffff:7f00:1]/", "http://private.test/", "http://mixed.test/", "http://[64:ff9b::7f00:1]/"} {
		resp, _, err := e.get(t, u, e.goodAuth())
		if err != nil || resp.StatusCode != 403 {
			t.Errorf("%s: %v %v", u, resp, err)
		}
	}
	e.assertUntouched(t)
}

func portOf(a net.Addr) string { _, p, _ := net.SplitHostPort(a.String()); return p }

func TestPublicNamesAndLiteralsAreServed(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{})
	for _, authority := range []string{"public.test:443", "public.test:80", "allpublic.test:443", "v6public.test:443", "93.184.216.34:443", "[2606:4700::1]:443"} {
		resp, c, br := e.connect(t, authority, e.goodAuth())
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", authority, resp.StatusCode)
		}
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if b, _ := io.ReadAll(br); !strings.Contains(string(b), "from the origin") {
			t.Errorf("%s: %q", authority, b)
		}
	}
}

func TestPortsOtherThanTheListedAreRefused(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{})
	for _, authority := range []string{"public.test:22", "public.test:25", "public.test:8080", "public.test:6379", "93.184.216.34:3306", "public.test:0", "public.test:65536"} {
		resp, _, _ := e.connect(t, authority, e.goodAuth())
		if resp.StatusCode != 403 && resp.StatusCode != 400 {
			t.Errorf("%s: %d", authority, resp.StatusCode)
		}
	}
	if last := e.audit.entries()[0]; last.Reason != "port" {
		t.Errorf("reason %q", last.Reason)
	}
	e.assertUntouched(t)
}

func TestTheListOfPortsIsConfigurable(t *testing.T) {
	e := newEnv(t, func(p *Proxy) { p.Ports = []int{443, 8443} }, 0, Limits{})
	if resp, _, _ := e.connect(t, "public.test:8443", e.goodAuth()); resp.StatusCode != 200 {
		t.Errorf("8443 listed: %d", resp.StatusCode)
	}
	if resp, _, _ := e.connect(t, "public.test:80", e.goodAuth()); resp.StatusCode != 403 {
		t.Errorf("80 not listed: %d", resp.StatusCode)
	}
}

// A test origin opens its own host:port and nothing around it.
func TestATestOriginIsExemptExactlyAndAsNothingElseIs(t *testing.T) {
	e := newEnv(t, func(p *Proxy) { p.TestOrigins = map[string]bool{"127.0.0.1:9999": true, "private.test:8081": true} }, 0, Limits{})
	for _, a := range []string{"127.0.0.1:9999", "private.test:8081"} {
		if resp, _, _ := e.connect(t, a, e.goodAuth()); resp.StatusCode != 200 {
			t.Errorf("%s: %d", a, resp.StatusCode)
		}
	}
	for _, a := range []string{"127.0.0.1:9998", "127.0.0.1:443", "localhost:9999", "private.test:443", "private.test:8082", "10.0.0.1:9999"} {
		if resp, _, _ := e.connect(t, a, e.goodAuth()); resp.StatusCode == 200 {
			t.Errorf("%s was served", a)
		}
	}
}

func TestWithoutALiveCredentialNothingIsLookedAtAndNothingIsDialed(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{})
	now := time.Now()
	for _, tc := range []struct{ name, auth, reason string }{
		{"no credential", "", "no_credential"},
		{"not basic", "Bearer " + e.token, "no_credential"},
		{"not base64", "Basic !!!", "no_credential"},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("r1")), "no_credential"},
		{"an id nobody registered", basic("r2", e.token), "unknown_render"},
		{"the right id with another token", basic("r1", strings.Repeat("u", 32)), "bad_token"},
		{"the token of another render as the id", basic(e.token, e.token), "unknown_render"},
		{"an empty token", basic("r1", ""), "bad_token"},
	} {
		resp, _, _ := e.connect(t, "public.test:443", tc.auth)
		if resp.StatusCode != 407 {
			t.Errorf("%s: %d", tc.name, resp.StatusCode)
		}
		if got := e.audit.last(t); got.Reason != tc.reason || got.Decision != "deny" || got.Render != "" {
			t.Errorf("%s: audit %v, want reason %s and no render", tc.name, got, tc.reason)
		}
	}
	// a plain request too
	if resp, _, err := e.get(t, "http://public.test/", ""); err != nil || resp.StatusCode != 407 {
		t.Errorf("plain without a credential: %v %v", resp, err)
	}
	// a second render's token does not open the first's
	if err := e.p.Registry.Register("r2", []byte(strings.Repeat("v", 32)), time.Minute, Limits{}); err != nil {
		t.Fatal(err)
	}
	if resp, _, _ := e.connect(t, "public.test:443", basic("r1", strings.Repeat("v", 32))); resp.StatusCode != 407 {
		t.Errorf("a foreign token: %d", resp.StatusCode)
	}
	_ = now
	e.assertUntouched(t)
}

func TestAnExpiredOrFinishedRendersTokenIsRefused(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{})
	clock := time.Now()
	e.p.Registry.now = func() time.Time { return clock }
	if err := e.p.Registry.Register("short", []byte(strings.Repeat("s", 32)), 5*time.Second, Limits{}); err != nil {
		t.Fatal(err)
	}
	auth := basic("short", strings.Repeat("s", 32))
	if resp, _, _ := e.connect(t, "public.test:443", auth); resp.StatusCode != 200 {
		t.Fatalf("live: %d", resp.StatusCode)
	}
	clock = clock.Add(6 * time.Second)
	if resp, _, _ := e.connect(t, "public.test:443", auth); resp.StatusCode != 407 {
		t.Errorf("past the deadline: %d", resp.StatusCode)
	}
	if got := e.audit.last(t); got.Reason != "expired" {
		t.Errorf("reason %q", got.Reason)
	}
	// finished: the usage comes back once, and the token is dead
	if _, ok := e.p.Registry.Finish("r1"); !ok {
		t.Fatal("no usage")
	}
	if resp, _, _ := e.connect(t, "public.test:443", e.goodAuth()); resp.StatusCode != 407 {
		t.Errorf("after Finish: %d", resp.StatusCode)
	}
	if got := e.audit.last(t); got.Reason != "expired" {
		t.Errorf("reason after Finish %q", got.Reason)
	}
}

func TestTheRequestBudgetIsCounted(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{MaxRequests: 3})
	for i := 0; i < 3; i++ {
		resp, c, _ := e.connect(t, "public.test:443", e.goodAuth())
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
		c.Close()
	}
	resp, _, _ := e.connect(t, "public.test:443", e.goodAuth())
	if resp.StatusCode != 429 {
		t.Fatalf("the fourth: %d", resp.StatusCode)
	}
	if resp, _, err := e.get(t, "http://public.test/", e.goodAuth()); err != nil || resp.StatusCode != 429 {
		t.Errorf("a plain request over the budget: %v %v", resp, err)
	}
	if got := e.audit.last(t); got.Reason != "limit_requests" {
		t.Errorf("reason %q", got.Reason)
	}
	u, _ := e.p.Registry.Finish("r1")
	if u.Limit != "requests" || u.Requests != 3 || u.Blocked < 2 {
		t.Errorf("usage %+v", u)
	}
}

func TestTheTotalByteBudgetEndsTheTunnelsOfTheRender(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{MaxBytes: 50_000})
	resp, c, br := e.connect(t, "public.test:80", e.goodAuth())
	if resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	fmt.Fprint(c, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
	n, _ := io.Copy(io.Discard, br)
	if n >= 100_000 {
		t.Errorf("%d bytes came through a 50000-byte budget", n)
	}
	// the budget is the render's: a new tunnel of the same render is refused
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, _, _ := e.connect(t, "public.test:80", e.goodAuth())
		if resp.StatusCode == 429 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a new tunnel after the budget: %d", resp.StatusCode)
		}
	}
	if got := e.audit.last(t); got.Reason != "limit_bytes" {
		t.Errorf("reason %q", got.Reason)
	}
	if u, _ := e.p.Registry.Finish("r1"); u.Limit != "bytes" {
		t.Errorf("usage %+v", u)
	}
}

func TestAResponseOverTheResponseBudgetIsRefusedOrCut(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{MaxResponseBytes: 100_000})
	// announced: refused before a byte is sent
	resp, _, err := e.get(t, "http://public.test/big", e.goodAuth())
	if err != nil || resp.StatusCode != 502 {
		t.Fatalf("announced: %v %v", resp, err)
	}
	if got := e.audit.last(t); got.Reason != "limit_response" || got.Decision != "deny" {
		t.Errorf("audit %v", got)
	}
	// not announced (chunked, 2 MB): the browser sees a broken response, not a short complete one
	_, body, err := e.get(t, "http://public.test/stream", e.goodAuth())
	if err == nil {
		t.Errorf("a truncated response looked complete: %d bytes", len(body))
	}
	if got := e.audit.last(t); got.Reason != "limit_response" {
		t.Errorf("audit %v", got)
	}
	// a response inside the budget is served whole
	if _, body, err := e.get(t, "http://public.test/", e.goodAuth()); err != nil || string(body) != "from the origin" {
		t.Errorf("%q %v", body, err)
	}
	// a tunnel is cut at the same budget
	r2, c, br := e.connect(t, "public.test:80", e.goodAuth())
	if r2.StatusCode != 200 {
		t.Fatalf("%d", r2.StatusCode)
	}
	fmt.Fprint(c, "GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
	if n, _ := io.Copy(io.Discard, br); n > 100_000+64<<10 {
		t.Errorf("%d bytes through a tunnel with a 100000-byte response budget", n)
	}
}

func TestTheDeadlineEndsTheTunnelsAndThenTheToken(t *testing.T) {
	e := newEnv(t, nil, 300*time.Millisecond, Limits{})
	resp, c, br := e.connect(t, "public.test:80", e.goodAuth())
	if resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Error("an idle tunnel produced data")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the tunnel outlived the deadline by %v", took)
	}
	if r, _, _ := e.connect(t, "public.test:80", e.goodAuth()); r.StatusCode != 407 {
		t.Errorf("after the deadline: %d", r.StatusCode)
	}
}

// Audit: render, host, port, decision, reason, bytes, ms; never a path, a query string or a body.
func TestAuditLinesNeverHoldAPathAQueryOrABody(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex
	e := newEnv(t, func(p *Proxy) {
		p.Audit = SlogAuditor{slog.New(slog.NewJSONHandler(&lockedWriter{&mu, &buf}, nil))}
	}, 0, Limits{})
	e.get(t, "http://public.test/secret/path?token=abc123&q=hello", e.goodAuth())
	e.get(t, "http://private.test/admin/users?id=77", e.goodAuth())
	resp, c, br := e.connect(t, "public.test:443", e.goodAuth())
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	fmt.Fprint(c, "POST /tunnel/path?k=v HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\nConnection: close\r\n\r\nsecret-body")
	io.Copy(io.Discard, br)
	c.Close()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	for _, bad := range []string{"secret", "token", "abc123", "hello", "admin", "users", "tunnel", "k=v", "?"} {
		if strings.Contains(out, bad) {
			t.Errorf("the audit holds %q:\n%s", bad, out)
		}
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines, want one per request:\n%s", len(lines), out)
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"render", "host", "port", "decision", "reason", "bytes", "ms"} {
			if _, ok := m[k]; !ok {
				t.Errorf("line without %s: %s", k, l)
			}
		}
		if m["render"] != "r1" {
			t.Errorf("render %v", m["render"])
		}
	}
	// by construction too: the line has no field that could carry a path
	var names []string
	for i := 0; i < reflect.TypeOf(Entry{}).NumField(); i++ {
		names = append(names, reflect.TypeOf(Entry{}).Field(i).Name)
	}
	if !reflect.DeepEqual(names, []string{"Render", "Host", "Port", "Decision", "Reason", "Bytes", "MS"}) {
		t.Errorf("Entry has the fields %v", names)
	}
	if !strings.Contains(lines[2], `"bytes"`) || strings.Contains(lines[2], `"bytes":0`) {
		t.Errorf("the tunnel's line should count bytes: %s", lines[2])
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

// No caching: the same request twice reaches the origin twice.
func TestNothingIsCached(t *testing.T) {
	e := newEnv(t, nil, 0, Limits{})
	for i := 0; i < 3; i++ {
		if _, b, err := e.get(t, "http://public.test/cacheable", e.goodAuth()); err != nil || string(b) != "from the origin" {
			t.Fatalf("%q %v", b, err)
		}
	}
	if e.hits.Load() != 3 {
		t.Errorf("the origin saw %d requests for 3", e.hits.Load())
	}
}

func TestTheCredentialIsNotForwardedToTheOrigin(t *testing.T) {
	var got atomic.Value
	e := newEnv(t, nil, 0, Limits{})
	e.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Proxy-Authorization") + "|" + r.Header.Get("Authorization"))
		fmt.Fprint(w, "ok")
	})
	req, _ := http.NewRequest("GET", e.srv.URL, nil)
	_ = req
	if _, _, err := e.get(t, "http://public.test/", e.goodAuth()); err != nil {
		t.Fatal(err)
	}
	if v, _ := got.Load().(string); v != "|" {
		t.Errorf("the origin received %q", v)
	}
}

// Happy Eyeballs through the proxy, as in idp-sandbox's and idp-web's tests: the first address never answers, the second
// does; a blocked address is never dialed.
func TestProxyTunnelsThroughTheSecondAddressWhenTheFirstDoesNotAnswer(t *testing.T) {
	var asked []string
	var mu sync.Mutex
	var cancelled atomic.Int64
	e := newEnv(t, func(p *Proxy) {
		p.Resolver = resolver{"dual.test": {netip.MustParseAddr("2606:4700::1"), netip.MustParseAddr("93.184.216.34")}}
		p.DialFamily = Dual // the hang is the first attempt
	}, 0, Limits{})
	origin := e.origin.Listener.Addr().String()
	e.p.dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		asked = append(asked, address)
		mu.Unlock()
		if strings.HasPrefix(address, "[2606:4700::1]") {
			<-ctx.Done()
			cancelled.Add(1)
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, origin)
	}
	t0 := time.Now()
	resp, c, br := e.connect(t, "dual.test:443", e.goodAuth())
	if resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	if took := time.Since(t0); took > 3*time.Second {
		t.Errorf("took %v", took)
	}
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: dual.test\r\nConnection: close\r\n\r\n")
	if body, _ := io.ReadAll(br); !strings.Contains(string(body), "from the origin") {
		t.Fatalf("%q", body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for cancelled.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cancelled.Load() == 0 {
		t.Error("the hanging attempt was not cancelled")
	}
}

func TestProxyUsesIPv4WhenIPv6ConnectsAndThenStalls(t *testing.T) {
	var asked []string
	var mu sync.Mutex
	e := newEnv(t, func(p *Proxy) {
		p.Resolver = resolver{"stall.test": {netip.MustParseAddr("2606:4700::1"), netip.MustParseAddr("93.184.216.34")}} // prefer-ipv4 is the default
	}, 0, Limits{})
	origin := e.origin.Listener.Addr().String()
	e.p.dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		asked = append(asked, address)
		mu.Unlock()
		if strings.HasPrefix(address, "[") {
			a, b := net.Pipe()
			t.Cleanup(func() { a.Close(); b.Close() })
			return a, nil
		}
		return (&net.Dialer{}).DialContext(ctx, network, origin)
	}
	resp, c, br := e.connect(t, "stall.test:443", e.goodAuth())
	if resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: stall.test\r\nConnection: close\r\n\r\n")
	if body, _ := io.ReadAll(br); !strings.Contains(string(body), "from the origin") {
		t.Fatalf("%q", body)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, a := range asked {
		if strings.HasPrefix(a, "[") {
			t.Errorf("dialed %s", a)
		}
	}
}

// Only the addresses that were checked are dialed, on the checked port, and the name is resolved once.
func TestOnlyCheckedAddressesAreDialedAndTheNameIsResolvedOnce(t *testing.T) {
	var lookups atomic.Int64
	var asked []string
	var mu sync.Mutex
	e := newEnv(t, nil, 0, Limits{})
	e.p.Resolver = countingResolver{resolver{"rebind.test": {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("151.101.0.223")}}, &lookups}
	origin := e.origin.Listener.Addr().String()
	e.p.dialFn = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		asked = append(asked, address)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, origin)
	}
	if _, _, err := e.get(t, "http://rebind.test/", e.goodAuth()); err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 1 {
		t.Errorf("%d lookups", lookups.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, a := range asked {
		if a != "93.184.216.34:80" && a != "151.101.0.223:80" {
			t.Errorf("dialed %s", a)
		}
	}
}

type countingResolver struct {
	r resolver
	n *atomic.Int64
}

func (c countingResolver) LookupNetIP(ctx context.Context, n, h string) ([]netip.Addr, error) {
	c.n.Add(1)
	return c.r.LookupNetIP(ctx, n, h)
}

func TestAdminRegistersAndFinishesRendersAndNeedsItsKey(t *testing.T) {
	reg := &Registry{Ceiling: Limits{MaxRequests: 10, MaxBytes: 1000, MaxResponseBytes: 500}}
	key := []byte(strings.Repeat("k", 32))
	srv := httptest.NewServer(&Admin{Registry: reg, Key: key})
	defer srv.Close()
	do := func(method, path, auth, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	good := "Bearer " + string(key)
	reg1 := `{"token":"` + strings.Repeat("a", 32) + `","lifetimeMs":20000,"maxRequests":5000,"maxBytes":999999}`
	if c, _ := do("PUT", "/v1/renders/x1", "", reg1); c != 401 {
		t.Errorf("no key: %d", c)
	}
	if c, _ := do("PUT", "/v1/renders/x1", "Bearer "+strings.Repeat("z", 32), reg1); c != 401 {
		t.Errorf("another key: %d", c)
	}
	if reg.Live() != 0 {
		t.Fatal("a render was registered without the key")
	}
	if c, _ := do("PUT", "/v1/renders/x1", good, reg1); c != 204 {
		t.Errorf("register: %d", c)
	}
	if c, _ := do("PUT", "/v1/renders/x1", good, reg1); c != 409 {
		t.Errorf("the same id twice: %d", c)
	}
	if c, _ := do("PUT", "/v1/renders/x2", good, `{"token":"short","lifetimeMs":1000}`); c != 409 {
		t.Errorf("a short token: %d", c)
	}
	if c, _ := do("PUT", "/v1/renders/x3", good, `{"token":"`+strings.Repeat("b", 32)+`","lifetimeMs":86400000}`); c != 409 {
		t.Errorf("a day-long lifetime: %d", c)
	}
	// the limits are lowered to the ceiling, never raised
	r, why := reg.Lookup("x1", []byte(strings.Repeat("a", 32)))
	if r == nil {
		t.Fatal(why)
	}
	if r.limits != (Limits{MaxRequests: 10, MaxBytes: 999 + 1, MaxResponseBytes: 500}) {
		t.Errorf("limits %+v", r.limits)
	}
	c, out := do("DELETE", "/v1/renders/x1", good, "")
	if c != 200 || !strings.Contains(out, `"requests":0`) {
		t.Errorf("finish: %d %s", c, out)
	}
	if c, _ := do("DELETE", "/v1/renders/x1", good, ""); c != 404 {
		t.Errorf("finish twice: %d", c)
	}
	if c, _ := do("DELETE", "/v1/renders/x1", "", ""); c != 401 {
		t.Errorf("finish without the key: %d", c)
	}
}
