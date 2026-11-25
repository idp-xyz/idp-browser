//go:build browser

// Package browsertest runs the renderer against a real Chromium, a test origin and the proxy, all in one process: the
// browser-tagged tests of ADR-0001 (make test-browser runs them inside the image, as the user the pod runs as). The
// origin is exempt from the address rules by the test-origin setting, as idp-web's IDP_WEB_TEST_ORIGINS; everything else
// the pages ask for goes through the real proxy under the real rules, with a resolver that has private answers.
package browsertest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"idp-browser/internal/proxy"
	"idp-browser/internal/render"
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
	es []proxy.Entry
}

func (c *capture) Audit(e proxy.Entry) { c.mu.Lock(); c.es = append(c.es, e); c.mu.Unlock() }
func (c *capture) all() []proxy.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]proxy.Entry(nil), c.es...)
}

// forHost returns the audit lines of one host.
func (c *capture) forHost(h string) []proxy.Entry {
	var out []proxy.Entry
	for _, e := range c.all() {
		if e.Host == h {
			out = append(out, e)
		}
	}
	return out
}

type rig struct {
	t      *testing.T
	mux    *http.ServeMux
	origin *httptest.Server
	tls    *httptest.Server
	audit  *capture
	px     *proxy.Proxy
	reg    *proxy.Registry
	pxSrv  *httptest.Server
	admin  *httptest.Server
	pool   *render.Pool
	cfg    render.Config

	mu   sync.Mutex
	hits map[string]int

	canary    net.Listener
	canaryHit atomic.Int64
	udp       net.PacketConn
	udpHit    atomic.Int64
}

type opts struct {
	cfg    func(*render.Config)
	proxy  func(*proxy.Proxy)
	ceil   proxy.Limits
	noPool bool
	tls    bool
}

func chromePath() string {
	if p := os.Getenv("IDP_BROWSER_TEST_CHROME"); p != "" {
		return p
	}
	return "/headless-shell/headless-shell"
}

func newRig(t *testing.T, o opts) *rig {
	t.Helper()
	r := &rig{t: t, mux: http.NewServeMux(), audit: &capture{}, hits: map[string]int{}}
	counted := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hits[req.URL.Path]++
		r.mu.Unlock()
		r.mux.ServeHTTP(w, req)
	})
	r.origin = httptest.NewServer(counted)
	t.Cleanup(r.origin.Close)
	var err error
	if r.canary, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.canary.Close() })
	go func() {
		for {
			c, err := r.canary.Accept()
			if err != nil {
				return
			}
			r.canaryHit.Add(1)
			c.Close()
		}
	}()
	if r.udp, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.udp.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := r.udp.ReadFrom(buf); err != nil {
				return
			}
			r.udpHit.Add(1)
		}
	}()

	origins := map[string]bool{strings.TrimPrefix(r.origin.URL, "http://"): true}
	var spki []string
	if o.tls { // an HTTPS origin of our own, whose key (and no other) Chromium is told to trust
		r.tls = httptest.NewUnstartedServer(counted)
		r.tls.EnableHTTP2 = true // a page's many requests then share one tunnel, where the proxy cannot count them
		r.tls.StartTLS()
		t.Cleanup(r.tls.Close)
		origins[strings.TrimPrefix(r.tls.URL, "https://")] = true
		sum := sha256.Sum256(r.tls.Certificate().RawSubjectPublicKeyInfo)
		spki = []string{base64.StdEncoding.EncodeToString(sum[:])}
	}
	r.reg = &proxy.Registry{Ceiling: o.ceil}
	r.px = &proxy.Proxy{Registry: r.reg, Audit: r.audit, TestOrigins: origins, Resolver: resolver{
		"private.test":  {netip.MustParseAddr("10.1.1.1")},
		"metadata.test": {netip.MustParseAddr("169.254.169.254")},
		"loop.test":     {netip.MustParseAddr("127.0.0.1")},
		"mixed.test":    {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.1")},
	}}
	if o.proxy != nil {
		o.proxy(r.px)
	}
	r.pxSrv = httptest.NewServer(r.px)
	t.Cleanup(r.pxSrv.Close)
	key := make([]byte, 24)
	_, _ = rand.Read(key)
	adminKey := []byte(fmt.Sprintf("%x", key))
	r.admin = httptest.NewServer(&proxy.Admin{Registry: r.reg, Key: adminKey})
	t.Cleanup(r.admin.Close)

	cfg := render.DefaultConfig()
	cfg.ChromePath = chromePath()
	cfg.Pool = 1
	cfg.ProfileDir = t.TempDir()
	cfg.ProxyAddr = strings.TrimPrefix(r.pxSrv.URL, "http://")
	cfg.ProxyAdmin = r.admin.URL
	cfg.ProxyAdminKey = adminKey
	cfg.TestOrigins = origins
	cfg.TestTrustSPKI = spki
	cfg.QueueWait = 0
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	if v := os.Getenv("IDP_BROWSER_TEST_NO_SANDBOX"); v != "" { // gvisor or kata: the run itself is isolated, as the pod is
		cfg.NoSandbox, cfg.IsolatedBy = true, v
	}
	if o.cfg != nil {
		o.cfg(&cfg)
	}
	r.cfg = cfg
	if !o.noPool {
		if r.pool, err = render.New(cfg); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.pool.Close)
	}
	return r
}

func (r *rig) url(path string) string { return r.origin.URL + path }

func (r *rig) hostPort() string { return strings.TrimPrefix(r.origin.URL, "http://") }

func (r *rig) page(path, html string) {
	r.mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, html)
	})
}

func (r *rig) hitCount(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[path]
}

func (r *rig) canaryPort() string { _, p, _ := net.SplitHostPort(r.canary.Addr().String()); return p }

// render makes one render with a generous clock for the test itself.
func (r *rig) render(req render.Request) (*render.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return r.pool.Render(ctx, req)
}

func (r *rig) mustRender(req render.Request) *render.Result {
	r.t.Helper()
	res, err := r.render(req)
	if err != nil {
		r.t.Fatalf("render %s: %v", req.URL, err)
	}
	return res
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	re, ok := err.(*render.Error)
	if !ok || re.Code != code {
		t.Fatalf("error %v, want code %s", err, code)
	}
}

// healthy: the pool still renders after something went wrong.
func (r *rig) healthy(path string) {
	r.t.Helper()
	res := r.mustRender(render.Request{URL: r.url(path), TimeoutMS: 20000})
	if !strings.Contains(res.HTML, "HEALTHY") {
		r.t.Fatalf("the pool does not render after the abuse: %.200q", res.HTML)
	}
}
