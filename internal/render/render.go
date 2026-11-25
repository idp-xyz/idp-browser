package render

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/inspector"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"idp-browser/internal/addr"
	"idp-browser/internal/authhop"
	"idp-browser/internal/proxy"
)

// Request is POST /render.
type Request struct {
	URL       string `json:"url"`
	TimeoutMS int    `json:"timeoutMs,omitempty"`
	MaxBytes  int    `json:"maxBytes,omitempty"`
}

// Result is the answer of POST /render.
type Result struct {
	FinalURL string `json:"finalUrl"`
	HTML     string `json:"html"`
	Status   int    `json:"status"`
	Title    string `json:"title"`
	Requests int    `json:"requests"` // requests the page made (the browser's count, or the proxy's if that is more)
	Blocked  int    `json:"blocked"`  // requests refused: by the proxy (address, port, budget) or by the renderer (scheme, budget)
	Skipped  int    `json:"skipped"`  // requests not made because their type (image, media, font by default) is not fetched; not in requests, not in blocked
	Bytes    int64  `json:"bytes"`    // bytes the proxy carried for the render, both directions
	MS       int64  `json:"ms"`
	// Truncated: the DOM was longer than maxBytes and html is its first maxBytes.
	Truncated bool `json:"truncated,omitempty"`
	// Limit is the render budget the page used up, if any: requests, bytes or response (it does not fail the render).
	Limit string `json:"limit,omitempty"`
	// Settled is false when the network or the DOM had not gone quiet when the wait for them ended.
	Settled bool `json:"settled"`
}

var (
	errDeadline = errors.New("deadline")
	errMemory   = errors.New("memory")
	errCrashed  = errors.New("crashed")
)

type captured struct {
	HTML    string `json:"html"`
	HTMLLen int    `json:"htmlLen"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Text    string `json:"text"`
	TextLen int    `json:"textLen"`
}

// check validates a request and returns what the render needs; nothing of a browser is touched.
func (p *Pool) check(req Request) (u string, timeout time.Duration, maxBytes int, err *Error) {
	if req.URL == "" {
		return "", 0, 0, fail(InvalidRequest, "no url")
	}
	if req.TimeoutMS < 0 || req.MaxBytes < 0 {
		return "", 0, 0, fail(InvalidRequest, "timeoutMs and maxBytes may not be negative")
	}
	timeout = p.cfg.DefaultTimeout
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
		if timeout < time.Second || timeout > p.cfg.MaxTimeout {
			return "", 0, 0, fail(InvalidRequest, "timeoutMs must be between 1000 and %d", p.cfg.MaxTimeout.Milliseconds())
		}
	}
	maxBytes = p.cfg.DefaultMaxBytes
	if req.MaxBytes > 0 {
		if req.MaxBytes < 1024 || req.MaxBytes > p.cfg.MaxMaxBytes {
			return "", 0, 0, fail(InvalidRequest, "maxBytes must be between 1024 and %d", p.cfg.MaxMaxBytes)
		}
		maxBytes = req.MaxBytes
	}
	if !utf8.ValidString(req.URL) {
		return "", 0, 0, fail(InvalidRequest, "the url is not UTF-8")
	}
	// The address rules of idp-web (internal/addr): http or https, a name or a public IP literal, the listed ports, no
	// userinfo, no odd IP spelling. The URL is what the browser is told to open, exactly as addr.Target read it.
	a, aerr := addr.TargetWith(req.URL, addr.Options{TestOrigins: p.cfg.TestOrigins, Ports: p.cfg.Ports})
	if aerr != nil {
		return "", 0, 0, fail(NotAllowed, "%v", aerr)
	}
	return a.URL(), timeout, maxBytes, nil
}

// Render renders one page. The error, when there is one, is an *Error with a reason code.
func (p *Pool) Render(ctx context.Context, req Request) (*Result, error) {
	start := time.Now()
	u, timeout, maxBytes, cerr := p.check(req)
	if cerr != nil {
		p.Stats.outcome(cerr.Code)
		return nil, cerr
	}
	s, aerr := p.acquire(ctx)
	if aerr != nil {
		p.Stats.outcome(aerr.(*Error).Code)
		return nil, aerr
	}
	p.Stats.Active.Add(1)
	res, tainted, err := p.run(ctx, s, u, timeout, maxBytes)
	p.Stats.Active.Add(-1)
	p.release(s, tainted)
	if err != nil {
		p.Stats.outcome(err.Code)
		return nil, err
	}
	p.Stats.outcome("ok")
	res.MS = time.Since(start).Milliseconds()
	return res, nil
}

// page-level state gathered from events
type pageState struct {
	mu        sync.Mutex
	inflight  map[network.RequestID]struct{}
	lastNet   time.Time
	requests  int
	blocked   int
	skipped   int
	status    int
	mainFrame cdp.FrameID
	mainHosts map[string]bool
	loaded    chan struct{}
	domReady  chan struct{}
	loadOnce  sync.Once
	domOnce   sync.Once
	pid       int          // the browser process, for the memory baseline
	baseMem   atomic.Int64 // the memory of its tree when the render's context was created (0: not yet)
}

func (st *pageState) init() {
	st.inflight = map[network.RequestID]struct{}{}
	st.mainHosts = map[string]bool{}
	st.loaded = make(chan struct{})
	st.domReady = make(chan struct{})
	st.lastNet = time.Now()
}

func (st *pageState) quiet(d time.Duration) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.inflight) == 0 && time.Since(st.lastNet) >= d
}

func (p *Pool) run(parent context.Context, s *slot, u string, timeout time.Duration, maxBytes int) (res *Result, tainted bool, rerr *Error) {
	if s.proc == nil {
		if err := s.start(); err != nil {
			p.log.Error("browser did not start", "err", err)
			return nil, true, fail(RenderFailed, "the browser did not start")
		}
	}
	id, token := randHex(8), randHex(32)
	life := timeout + 15*time.Second
	lim := proxy.Limits{MaxRequests: p.cfg.MaxRequests, MaxBytes: p.cfg.MaxBytes, MaxResponseBytes: p.cfg.MaxResponseBytes}
	rctx0, rc0 := context.WithTimeout(parent, 5*time.Second)
	err := p.px.register(rctx0, id, token, life, lim)
	rc0()
	if err != nil {
		p.log.Error("the proxy did not take the render", "err", err)
		return nil, false, fail(RenderFailed, "the egress proxy is not available")
	}
	hop, err := authhop.Start(p.cfg.ProxyAddr, id, token, time.Now().Add(life))
	if err != nil {
		_, _ = p.px.finish(context.Background(), id)
		return nil, false, fail(RenderFailed, "the render's proxy hop did not start")
	}

	maxReq := lim.MaxRequests
	if maxReq <= 0 {
		maxReq = proxy.DefaultLimits.MaxRequests
	}
	rctx, rcancel := context.WithCancelCause(s.bctx)
	deadline := time.AfterFunc(timeout, func() { rcancel(errDeadline) })
	stopWatch := make(chan struct{})
	st := &pageState{}
	st.init()
	// The memory watch: the render is judged by the growth of its browser's process tree over the baseline that drive takes once
	// the render's context exists (mem.go); until then there is none, so nothing trips.
	if p.cfg.RenderMemoryMB > 0 && s.proc != nil {
		st.pid = s.proc.Pid
		go func() {
			t := time.NewTicker(250 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopWatch:
					return
				case <-t.C:
					if grewBeyond(st.baseMem.Load(), p.meter.tree(st.pid), int64(p.cfg.RenderMemoryMB)) {
						rcancel(errMemory)
						return
					}
				}
			}
		}()
	}

	paused := make(chan *fetch.EventRequestPaused, 8192)
	var cctx context.Context
	var ccancel context.CancelFunc

	handle := func(ev any) { // runs on the tab's reader: it only records, and hands the rest on
		switch e := ev.(type) {
		case *page.EventLoadEventFired:
			st.loadOnce.Do(func() { close(st.loaded) })
		case *page.EventDomContentEventFired:
			st.domOnce.Do(func() { close(st.domReady) })
		case *inspector.EventTargetCrashed:
			rcancel(errCrashed)
		case *network.EventRequestWillBeSent:
			if e.Type != network.ResourceTypeEventSource && e.Type != network.ResourceTypeWebSocket {
				st.mu.Lock()
				st.inflight[e.RequestID] = struct{}{}
				st.lastNet = time.Now()
				st.mu.Unlock()
			}
		case *network.EventLoadingFinished:
			st.mu.Lock()
			delete(st.inflight, e.RequestID)
			st.lastNet = time.Now()
			st.mu.Unlock()
		case *network.EventLoadingFailed:
			st.mu.Lock()
			delete(st.inflight, e.RequestID)
			st.lastNet = time.Now()
			st.mu.Unlock()
		case *network.EventResponseReceived:
			if e.Type == network.ResourceTypeDocument && e.Response != nil {
				st.mu.Lock()
				if st.mainFrame != "" && e.FrameID == st.mainFrame {
					st.status = int(e.Response.Status)
				}
				st.mu.Unlock()
			}
		case *fetch.EventRequestPaused:
			select {
			case paused <- e:
			default:
				go func() { paused <- e }()
			}
		}
	}
	// the Fetch domain is used for two rules only: a document that is not http or https is refused, and the render's
	// own request count is kept (the proxy cannot count inside a TLS tunnel)
	// A page that retries a failed image in a loop (FedEx's home page made 19,944 requests this way) must not keep the browser
	// and this loop busy until the clock ends: after ten budgets of skipped requests they count as requests.
	skipCap := 10 * maxReq
	skip := map[network.ResourceType]bool{}
	for _, t := range p.cfg.BlockTypes {
		skip[resourceTypeOf(t)] = true
	}
	go func() {
		for {
			select {
			case <-rctx.Done():
				return
			case e := <-paused:
				st.mu.Lock()
				skipIt := skip[e.ResourceType] && st.skipped < skipCap // past the cap a skipped type is an ordinary request, and the budget bounds it
				if skipIt {
					st.skipped++
				}
				st.mu.Unlock()
				if skipIt {
					// a type that is not read: refused here, before the request budget sees it and before the proxy does
					p.Stats.Skipped.Add(1)
					_, _ = chromedp.Call(cctx, fetch.FailRequest, fetch.FailRequestParams{RequestID: e.RequestID, ErrorReason: network.ErrorReasonBlockedByClient})
					continue
				}
				st.mu.Lock()
				st.requests++
				n := st.requests
				st.mu.Unlock()
				reject := false
				if e.ResourceType == network.ResourceTypeDocument {
					if pu, err := url.Parse(e.Request.URL); err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
						reject = true
					} else {
						st.mu.Lock()
						if e.FrameID == st.mainFrame {
							st.mainHosts[hostPortKey(pu)] = true
						}
						st.mu.Unlock()
					}
				}
				if n > maxReq {
					reject = true
				}
				if reject {
					st.mu.Lock()
					st.blocked++
					st.mu.Unlock()
					_, _ = chromedp.Call(cctx, fetch.FailRequest, fetch.FailRequestParams{RequestID: e.RequestID, ErrorReason: network.ErrorReasonBlockedByClient})
				} else {
					_, _ = chromedp.Call(cctx, fetch.ContinueRequest, fetch.ContinueRequestParams{RequestID: e.RequestID})
				}
			}
		}
	}()

	cctx, ccancel = chromedp.NewContext(rctx,
		chromedp.WithNewBrowserContext(func(c *target.CreateBrowserContextParams) {
			c.ProxyServer = "http://" + hop.Addr() // this render's hop, which carries this render's credential
			c.ProxyBypassList = "<-loopback>"
		}),
		chromedp.WithListener(handle))

	var cap captured
	var navErr string
	var settled bool
	var runErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				runErr = errors.New("panic in the render")
			}
		}()
		runErr = p.drive(cctx, st, u, maxBytes, &cap, &navErr, &settled)
	}()
	cause := context.Cause(rctx)

	// end the render: stop the clocks, dispose the context, close the hop, take the proxy's account
	deadline.Stop()
	close(stopWatch)
	ccancel()
	rcancel(nil)
	hop.Close()
	fctx, fc := context.WithTimeout(context.Background(), 5*time.Second)
	usage, uerr := p.px.finish(fctx, id)
	fc()
	if uerr != nil {
		p.log.Warn("the proxy gave no account of the render", "err", uerr)
	}

	if s.baseMem == 0 {
		s.baseMem = st.baseMem.Load() // this process's own baseline, from its first render
	}
	st.mu.Lock()
	requests, blocked, skipped, status := st.requests, st.blocked, st.skipped, st.status
	mainHosts := st.mainHosts
	st.mu.Unlock()

	// a refused address for the page itself is the answer, whatever the browser made of the refusal
	for _, r := range usage.Refused {
		if mainHosts[strings.ToLower(r.Host)+":"+strconv.Itoa(r.Port)] && (r.Reason == "not_public" || r.Reason == "port" || r.Reason == "bad_host") {
			return nil, false, fail(NotAllowed, "the address of the page is not a public one (%s)", r.Reason)
		}
	}
	switch {
	case errors.Is(cause, errDeadline):
		return nil, true, fail(RenderTimeout, "the page did not finish within %s", timeout)
	case errors.Is(cause, errMemory):
		return nil, true, fail(RenderFailed, "the page used more than %d MiB of memory", p.cfg.RenderMemoryMB)
	case errors.Is(cause, errCrashed):
		return nil, true, fail(RenderFailed, "the page crashed")
	case runErr != nil:
		p.log.Info("render failed", "err", runErr)
		if parent.Err() != nil {
			return nil, true, fail(RenderFailed, "the request was cancelled")
		}
		return nil, true, fail(RenderFailed, "the browser failed")
	case navErr == "net::ERR_ABORTED":
		// the browser gave up the navigation because the answer is not a page: a file (PDF, archive) that it would download,
		// and downloads are denied. idp-web reads those itself (its PDF reader)
		return nil, false, fail(RenderFailed, "the address is a file, not a web page (the browser aborted the navigation: net::ERR_ABORTED)")
	case navErr != "":
		return nil, false, fail(RenderFailed, "navigation failed: %s", navErr)
	}
	if !strings.HasPrefix(cap.URL, "http://") && !strings.HasPrefix(cap.URL, "https://") {
		// the navigation ended on the browser's own error page, or on something that is not a web page
		return nil, false, fail(RenderFailed, "the navigation did not end on a web page")
	}
	if cap.Status != 0 {
		status = cap.Status
	}
	html := cap.HTML
	truncated := cap.HTMLLen > len(cap.HTML)
	if len(html) > maxBytes {
		html = html[:maxBytes]
		for len(html) > 0 && !utf8.ValidString(html[len(html)-min(4, len(html)):]) {
			html = html[:len(html)-1] // never end in the middle of a character
		}
		truncated = true
	}
	if signal, blockedPage := Detect(status, cap.Title, cap.HTML, cap.Text); blockedPage {
		p.log.Info("blocked by site", "signal", signal)
		return nil, false, fail(BlockedBySite, "the site answered with a challenge or a refusal (%s)", signal)
	}
	if usage.Requests > requests {
		requests = usage.Requests
	}
	limit := usage.Limit
	if limit == "" && requests > maxReq {
		limit = "requests"
	}
	return &Result{FinalURL: cap.URL, HTML: html, Status: status, Title: cap.Title, Requests: requests, Blocked: blocked + usage.Blocked, Skipped: skipped,
		Bytes: usage.BytesIn + usage.BytesOut, Truncated: truncated, Limit: limit, Settled: settled}, false, nil
}

// drive is everything done with the page: set up, navigate, wait, scroll, read.
func (p *Pool) drive(ctx context.Context, st *pageState, u string, maxBytes int, out *captured, navErr *string, settled *bool) error {
	// the first call creates the render's browser context and its tab; it carries no deadline of its own (the render's clock
	// is on the context)
	tree, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if err != nil {
		return err
	}
	st.mu.Lock()
	st.mainFrame = tree.FrameTree.Frame.ID
	st.mu.Unlock()
	bcid := chromedp.FromContext(ctx).BrowserContextID
	if st.pid != 0 {
		st.baseMem.Store(p.meter.tree(st.pid)) // the baseline of the memory watch: this browser, this context, nothing loaded yet
	}

	_, e1 := chromedp.Call(ctx, page.Enable, page.EnableParams{})
	_, e2 := chromedp.Call(ctx, network.Enable, network.EnableParams{})
	_, e3 := chromedp.Call(ctx, fetch.Enable, fetch.EnableParams{Patterns: []*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}}})
	_, e4 := chromedp.Call(ctx, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{Width: 1280, Height: 1024, DeviceScaleFactor: 1})
	_, e5 := chromedp.CallBrowser(ctx, browser.SetDownloadBehavior, browser.SetDownloadBehaviorParams{Behavior: browser.SetDownloadBehaviorBehaviorDeny, BrowserContextID: bcid})
	_, e6 := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: initScript})
	_, e7 := chromedp.Call(ctx, network.SetBypassServiceWorker, network.SetBypassServiceWorkerParams{Bypass: true})
	for _, e := range []error{e1, e2, e3, e4, e5, e6, e7} {
		if e != nil {
			return e
		}
	}
	for _, name := range deniedPermissions {
		// best effort: a name this Chromium does not know is not an error worth failing a render for
		_, _ = chromedp.CallBrowser(ctx, browser.SetPermission, browser.SetPermissionParams{
			Permission: &browser.PermissionDescriptor{Name: name}, Setting: browser.PermissionSettingDenied, BrowserContextID: bcid})
	}

	nav, err := chromedp.Call(ctx, page.Navigate, page.NavigateParams{URL: u})
	if err != nil {
		return err
	}
	if nav.ErrorText != "" {
		*navErr = nav.ErrorText
		return nil
	}
	// the load event; a page whose load never comes (a tracker that hangs) is read after DOMContentLoaded and a grace period
	grace := time.NewTimer(p.loadGrace(ctx))
	defer grace.Stop()
	select {
	case <-st.loaded:
	case <-grace.C:
		select {
		case <-st.domReady:
		default:
			<-ctx.Done() // nothing has loaded: the render's clock decides
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	*settled = p.settle(ctx, st, p.cfg.Settle)
	if p.cfg.Scroll {
		_, _ = chromedp.Run(ctx, chromedp.Evaluate[chromedp.Void](`window.scrollTo(0, Math.max(document.body ? document.body.scrollHeight : 0, document.documentElement.scrollHeight))`))
		s2 := min(p.cfg.Settle, 2*time.Second)
		*settled = p.settle(ctx, st, s2)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c, err := chromedp.Run(ctx, chromedp.Evaluate[captured](captureScript(maxBytes)))
	if err != nil {
		return err
	}
	*out = c
	return nil
}

// loadGrace: how long to wait for the load event before settling for DOMContentLoaded: 60% of the time left.
func (p *Pool) loadGrace(ctx context.Context) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		return time.Until(d) * 6 / 10
	}
	return p.cfg.DefaultTimeout * 6 / 10
}

// settle waits until the network has been idle for 500 ms and the DOM has not changed for 300 ms, or max has passed.
// It reports whether the page settled. The DOM is read through a mutation counter that initScript keeps; a page whose
// thread is stuck does not answer, which counts as not quiet.
func (p *Pool) settle(ctx context.Context, st *pageState, max time.Duration) bool {
	begin := time.Now()
	lastMut, lastChange := -1, time.Now()
	for time.Since(begin) < max {
		if ctx.Err() != nil {
			return false
		}
		ectx, c := context.WithTimeout(ctx, time.Second)
		n, err := chromedp.Run(ectx, chromedp.Evaluate[int](`window.__idpMut || 0`))
		c()
		if err != nil || n != lastMut {
			lastMut, lastChange = n, time.Now()
		}
		if err == nil && st.quiet(500*time.Millisecond) && time.Since(lastChange) >= 300*time.Millisecond {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
	return false
}

// hostPortKey is "host:port" of a URL, with the default port of its scheme; the proxy's refusals are named the same way.
func hostPortKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// resourceTypeOf is the CDP name of a setting's type: "image" is "Image", "xhr" is "XHR", and so on.
func resourceTypeOf(t string) network.ResourceType {
	switch t {
	case "xhr":
		return network.ResourceTypeXHR
	case "texttrack":
		return network.ResourceTypeTextTrack
	case "eventsource":
		return network.ResourceTypeEventSource
	case "cspviolationreport":
		return network.ResourceTypeCSPViolationReport
	case "signedexchange":
		return network.ResourceTypeSignedExchange
	}
	return network.ResourceType(strings.ToUpper(t[:1]) + t[1:])
}
