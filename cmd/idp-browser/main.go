// idp-browser: the render pool. idp-web calls it (POST /render) when a page's text is made by JavaScript (ADR-0001).
// Configuration is by environment; keys are read from files, never from the environment. A configuration error is
// written to stderr and the exit status is 2.
//
//	IDP_BROWSER_LISTEN            address of POST /render (default 127.0.0.1:8590); a non-loopback address needs
//	                              IDP_BROWSER_PRIVATE_NETWORK=true (the operator's statement that only idp-web reaches it)
//	IDP_BROWSER_METRICS           address of /healthz /readyz /metrics (default 127.0.0.1:9590)
//	IDP_BROWSER_CALLER_KEYS_FILE  PEM public key(s) of idp-web (P-256): every request must carry its assertion. Required
//	IDP_BROWSER_CALLER_AUDIENCE   the URL idp-web calls, for example http://idp-browser.idp-browser.svc.cluster.local:8590/render. Required
//	IDP_BROWSER_CALLER            the one caller accepted (default idp-web)
//
//	IDP_BROWSER_CHROME            the Chromium executable (default /headless-shell/headless-shell)
//	IDP_BROWSER_POOL              browser processes, so renders at once (default 2)
//	IDP_BROWSER_RECYCLE_AFTER     renders per process before it is replaced (default 50)
//	IDP_BROWSER_RECYCLE_MEMORY_MB a process above this after a render is replaced (default 1024)
//	IDP_BROWSER_RENDER_MEMORY_MB  a render whose process tree passes this is ended as render_failed (default 1536; 0 = off)
//	IDP_BROWSER_NO_SANDBOX        true: start Chromium with --no-sandbox. Refused unless IDP_BROWSER_ISOLATED_BY is set
//	IDP_BROWSER_ISOLATED_BY       gvisor or kata: the operator's statement that the pod runs under that RuntimeClass
//	IDP_BROWSER_PROFILE_DIR       where the profiles of the browsers are made; a tmpfs (default /profile)
//
//	IDP_BROWSER_PROXY             the egress proxy's host:port, as this process reaches it. Required
//	IDP_BROWSER_PROXY_ADMIN       the proxy's admin URL, for example http://idp-browser-proxy.idp-browser-proxy.svc.cluster.local:3129. Required
//	IDP_BROWSER_PROXY_ADMIN_KEY_FILE  the key shared with the proxy (at least 32 bytes). Required
//
//	IDP_BROWSER_TIMEOUT_MS        a render's time when the request names none (default 15000); IDP_BROWSER_MAX_TIMEOUT_MS the most (default 60000)
//	IDP_BROWSER_MAX_BYTES         the HTML cap when the request names none (default 5242880); IDP_BROWSER_MAX_MAX_BYTES the most (default 20971520)
//	IDP_BROWSER_SCROLL            scroll once after the page settles (default true)
//	IDP_BROWSER_SETTLE_MS         the longest wait for the network and the DOM to go quiet after load (default 5000)
//	IDP_BROWSER_QUEUE_WAIT_MS     how long a request waits for a free browser before render_busy (default 2000)
//	IDP_BROWSER_MAX_REQUESTS, IDP_BROWSER_MAX_TOTAL_BYTES, IDP_BROWSER_MAX_RESPONSE_BYTES   budgets asked of the proxy for each render
//	                              (default: the proxy's own, 300, 20 MiB, 10 MiB)
//	IDP_BROWSER_BLOCK_TYPES       resource types not fetched at all, comma-separated (default image,media,font; set and empty: none): they are
//	                              counted as "skipped" in the answer, not against the request budget and not in "blocked"
//	IDP_BROWSER_PORTS             ports a page may be on (default 80,443; the proxy's list must be the same)
//	IDP_BROWSER_USER_AGENT        the User-Agent (default: Chromium's own)
//	IDP_BROWSER_TEST_ORIGINS      for tests only: host:port pairs exempt from the address rules (the proxy has the same list)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"idp-browser/internal/caller"
	"idp-browser/internal/envcfg"
	"idp-browser/internal/render"
	"idp-browser/internal/service"
)

var version = "dev"

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var r envcfg.Reader
	listen := r.String("IDP_BROWSER_LISTEN", "127.0.0.1:8590")
	metrics := r.String("IDP_BROWSER_METRICS", "127.0.0.1:9590")
	private := r.Bool("IDP_BROWSER_PRIVATE_NETWORK", false)
	keys := r.File("IDP_BROWSER_CALLER_KEYS_FILE")
	audience := r.String("IDP_BROWSER_CALLER_AUDIENCE", "")
	subject := r.String("IDP_BROWSER_CALLER", "idp-web")

	cfg := render.DefaultConfig()
	cfg.Log = log
	cfg.ChromePath = r.String("IDP_BROWSER_CHROME", "/headless-shell/headless-shell")
	cfg.Pool = r.Int("IDP_BROWSER_POOL", cfg.Pool, 1, 64)
	cfg.RecycleAfter = r.Int("IDP_BROWSER_RECYCLE_AFTER", cfg.RecycleAfter, 1, 1_000_000)
	cfg.RecycleMemoryMB = r.Int("IDP_BROWSER_RECYCLE_MEMORY_MB", cfg.RecycleMemoryMB, 0, 1<<20)
	cfg.RenderMemoryMB = r.Int("IDP_BROWSER_RENDER_MEMORY_MB", cfg.RenderMemoryMB, 0, 1<<20)
	cfg.NoSandbox = r.Bool("IDP_BROWSER_NO_SANDBOX", false)
	cfg.IsolatedBy = r.String("IDP_BROWSER_ISOLATED_BY", "")
	cfg.ProfileDir = r.String("IDP_BROWSER_PROFILE_DIR", "/profile")
	cfg.ProxyAddr = r.String("IDP_BROWSER_PROXY", "")
	cfg.ProxyAdmin = r.String("IDP_BROWSER_PROXY_ADMIN", "")
	cfg.ProxyAdminKey = r.File("IDP_BROWSER_PROXY_ADMIN_KEY_FILE")
	cfg.DefaultTimeout = time.Duration(r.Int("IDP_BROWSER_TIMEOUT_MS", 15000, 1000, 600000)) * time.Millisecond
	cfg.MaxTimeout = time.Duration(r.Int("IDP_BROWSER_MAX_TIMEOUT_MS", 60000, 1000, 600000)) * time.Millisecond
	cfg.DefaultMaxBytes = r.Int("IDP_BROWSER_MAX_BYTES", cfg.DefaultMaxBytes, 1024, 1<<30)
	cfg.MaxMaxBytes = r.Int("IDP_BROWSER_MAX_MAX_BYTES", cfg.MaxMaxBytes, 1024, 1<<30)
	cfg.Scroll = r.Bool("IDP_BROWSER_SCROLL", cfg.Scroll)
	cfg.Settle = time.Duration(r.Int("IDP_BROWSER_SETTLE_MS", 5000, 0, 60000)) * time.Millisecond
	cfg.QueueWait = time.Duration(r.Int("IDP_BROWSER_QUEUE_WAIT_MS", 2000, 0, 60000)) * time.Millisecond
	cfg.MaxRequests = r.Int("IDP_BROWSER_MAX_REQUESTS", 0, 0, 1_000_000)
	cfg.MaxBytes = r.Int64("IDP_BROWSER_MAX_TOTAL_BYTES", 0, 0, 1<<40)
	cfg.MaxResponseBytes = r.Int64("IDP_BROWSER_MAX_RESPONSE_BYTES", 0, 0, 1<<40)
	cfg.BlockTypes = r.List("IDP_BROWSER_BLOCK_TYPES", cfg.BlockTypes)
	cfg.Ports = r.Ports("IDP_BROWSER_PORTS", nil)
	cfg.UserAgent = r.String("IDP_BROWSER_USER_AGENT", "")
	cfg.TestOrigins = r.Origins("IDP_BROWSER_TEST_ORIGINS")
	if r.Err != nil {
		die("%v", r.Err)
	}
	if !envcfg.Loopback(listen) && !private {
		die("IDP_BROWSER_LISTEN %s is not a loopback address: set IDP_BROWSER_PRIVATE_NETWORK=true to say that only idp-web can reach it (the NetworkPolicy)", listen)
	}
	if len(keys) == 0 || audience == "" {
		die("IDP_BROWSER_CALLER_KEYS_FILE and IDP_BROWSER_CALLER_AUDIENCE are required: the render API answers only to idp-web's signature")
	}
	if len(cfg.TestOrigins) > 0 {
		log.Warn("TEST ORIGINS are set: the address rules do not apply to them. Never in production.", "origins", len(cfg.TestOrigins))
	}
	verifier, err := caller.NewVerifier(keys, audience, subject)
	if err != nil {
		die("IDP_BROWSER_CALLER_KEYS_FILE: %v", err)
	}
	pool, err := render.New(cfg)
	if err != nil {
		die("%v", err)
	}
	defer pool.Close()
	if cfg.NoSandbox {
		log.Warn("Chromium runs with --no-sandbox on the operator's statement that the pod is isolated", "isolatedBy", cfg.IsolatedBy)
	}

	api := &http.Server{Addr: listen, Handler: &service.Server{Renderer: pool, Verifier: verifier, Log: log}, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: cfg.MaxTimeout + 30*time.Second}
	ops := http.NewServeMux()
	ops.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	ops.HandleFunc("/readyz", func(w http.ResponseWriter, req *http.Request) {
		if err := pool.Ready(req.Context()); err != nil {
			http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	ops.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		out := pool.Stats.Snapshot()
		names := make([]string, 0, len(out))
		for k := range out {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Fprintf(w, "idp_browser_renders_total{outcome=%q} %d\n", k, out[k])
		}
		fmt.Fprintf(w, "idp_browser_renders_active %d\nidp_browser_requests_skipped_total %d\nidp_browser_processes %d\nidp_browser_process_starts_total %d\nidp_browser_process_recycles_total %d\n",
			pool.Stats.Active.Load(), pool.Stats.Skipped.Load(), pool.Processes(), pool.Stats.Starts.Load(), pool.Stats.Recycles.Load())
	})
	opsSrv := &http.Server{Addr: metrics, Handler: ops, ReadHeaderTimeout: 10 * time.Second}
	log.Info("idp-browser listening", "version", version, "addr", listen, "ops", metrics, "pool", cfg.Pool, "keys", verifier.KeyIDs(), "caller", subject, "noSandbox", cfg.NoSandbox)

	errc := make(chan error, 2)
	go func() { errc <- api.ListenAndServe() }()
	go func() { errc <- opsSrv.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
			pool.Close()
			os.Exit(1)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = api.Shutdown(ctx)
	_ = opsSrv.Shutdown(ctx)
}
