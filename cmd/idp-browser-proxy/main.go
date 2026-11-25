// idp-browser-proxy: the egress proxy of the browser (ADR-0001 D3 to D6). Chromium's only way to the internet, and it
// reaches public addresses only. It is a binary of its own because it is a pod of its own: the renderer's pods may reach
// only this proxy, and this proxy may reach the internet and not the cluster (NetworkPolicy). Configuration is by
// environment; the key is read from a file. A configuration error is written to stderr and the exit status is 2.
//
//	IDP_BROWSER_PROXY_LISTEN        the proxy port (CONNECT and plain HTTP; default 127.0.0.1:3128)
//	IDP_BROWSER_PROXY_ADMIN_LISTEN  the admin port, where the renderer registers and ends renders (default 127.0.0.1:3129)
//	IDP_BROWSER_PROXY_ADMIN_KEY_FILE  the key shared with the renderer (at least 32 bytes). Required
//	IDP_BROWSER_PRIVATE_NETWORK     true: allows non-loopback listen addresses (the NetworkPolicy lets only the renderer reach them)
//	IDP_BROWSER_PROXY_METRICS       /healthz /readyz /metrics (default 127.0.0.1:9591)
//	IDP_BROWSER_PORTS               the ports the proxy connects to (default 80,443)
//	IDP_BROWSER_PROXY_MAX_REQUESTS  the most requests a render may make (default 300), IDP_BROWSER_PROXY_MAX_BYTES total (default 20971520),
//	                                IDP_BROWSER_PROXY_MAX_RESPONSE_BYTES per response (default 10485760): the ceilings; a render may ask for less
//	IDP_BROWSER_DIAL_FAMILY         prefer-ipv4 (default), dual, ipv4-only or ipv6-only: the address families dialed and which goes first
//	IDP_BROWSER_PROXY_MAX_CONNS     concurrent connections (default 256)
//	IDP_BROWSER_TEST_ORIGINS        for tests only: host:port pairs exempt from the port and address rules
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"idp-browser/internal/envcfg"
	"idp-browser/internal/proxy"
)

var version = "dev"

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var r envcfg.Reader
	listen := r.String("IDP_BROWSER_PROXY_LISTEN", "127.0.0.1:3128")
	adminListen := r.String("IDP_BROWSER_PROXY_ADMIN_LISTEN", "127.0.0.1:3129")
	metrics := r.String("IDP_BROWSER_PROXY_METRICS", "127.0.0.1:9591")
	private := r.Bool("IDP_BROWSER_PRIVATE_NETWORK", false)
	key := r.File("IDP_BROWSER_PROXY_ADMIN_KEY_FILE")
	ceiling := proxy.Limits{
		MaxRequests:      r.Int("IDP_BROWSER_PROXY_MAX_REQUESTS", proxy.DefaultLimits.MaxRequests, 1, 1_000_000),
		MaxBytes:         r.Int64("IDP_BROWSER_PROXY_MAX_BYTES", proxy.DefaultLimits.MaxBytes, 1024, 1<<40),
		MaxResponseBytes: r.Int64("IDP_BROWSER_PROXY_MAX_RESPONSE_BYTES", proxy.DefaultLimits.MaxResponseBytes, 1024, 1<<40),
	}
	ports := r.Ports("IDP_BROWSER_PORTS", []int{80, 443})
	family, ferr := proxy.ParseDialFamily(os.Getenv("IDP_BROWSER_DIAL_FAMILY"))
	if ferr != nil {
		die("IDP_BROWSER_DIAL_FAMILY: %v", ferr)
	}
	maxConns := r.Int("IDP_BROWSER_PROXY_MAX_CONNS", 256, 1, 1<<20)
	origins := r.Origins("IDP_BROWSER_TEST_ORIGINS")
	if r.Err != nil {
		die("%v", r.Err)
	}
	if len(key) < 32 {
		die("IDP_BROWSER_PROXY_ADMIN_KEY_FILE is required and must hold at least 32 bytes (openssl rand -hex 32)")
	}
	for _, l := range []string{listen, adminListen} {
		if !envcfg.Loopback(l) && !private {
			die("%s is not a loopback address: set IDP_BROWSER_PRIVATE_NETWORK=true to say that the NetworkPolicy limits who reaches it", l)
		}
	}
	if len(origins) > 0 {
		log.Warn("TEST ORIGINS are set: the address rules do not apply to them. Never in production.", "origins", len(origins))
	}
	reg := &proxy.Registry{Ceiling: ceiling}
	p := &proxy.Proxy{Registry: reg, Ports: ports, TestOrigins: origins, DialFamily: family, MaxConns: maxConns, Audit: proxy.SlogAuditor{Log: log}}
	srv := &http.Server{Addr: listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	admin := &http.Server{Addr: adminListen, Handler: &proxy.Admin{Registry: reg, Key: key}, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second}
	ops := http.NewServeMux()
	ops.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	ops.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ready") })
	ops.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "idp_browser_proxy_requests_total{decision=\"allow\"} %d\nidp_browser_proxy_requests_total{decision=\"deny\"} %d\nidp_browser_proxy_live_renders %d\n",
			p.Allowed.Load(), p.Denied.Load(), reg.Live())
	})
	opsSrv := &http.Server{Addr: metrics, Handler: ops, ReadHeaderTimeout: 10 * time.Second}
	log.Info("idp-browser-proxy listening", "version", version, "addr", listen, "admin", adminListen, "ports", ports, "dialFamily", string(family), "ceiling", ceiling)

	errc := make(chan error, 3)
	for _, s := range []*http.Server{srv, admin, opsSrv} {
		go func() { errc <- s.ListenAndServe() }()
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
