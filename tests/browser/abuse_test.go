//go:build browser

package browsertest

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"idp-browser/internal/proxy"
	"idp-browser/internal/render"
)

func (r *rig) okPage() { r.page("/ok", `<html><body>HEALTHY</body></html>`) }

func TestAnInfiniteLoopEndsAsRenderTimeoutAndThePoolStaysHealthy(t *testing.T) {
	r := newRig(t, opts{})
	r.okPage()
	r.page("/loop", `<html><body><script>while (true) {}</script></body></html>`)
	r.page("/loop-later", `<html><body>started<script>window.onload = () => { setTimeout(() => { while (true) {} }, 50); };</script></body></html>`)
	for _, p := range []string{"/loop", "/loop-later"} {
		start := time.Now()
		_, err := r.render(render.Request{URL: r.url(p), TimeoutMS: 3000})
		wantCode(t, err, render.RenderTimeout)
		if took := time.Since(start); took > 12*time.Second {
			t.Errorf("%s: took %v for a 3 s clock", p, took)
		}
	}
	if r.pool.Stats.Recycles.Load() < 2 {
		t.Errorf("the browser that ran the loop was not replaced (recycles %d)", r.pool.Stats.Recycles.Load())
	}
	r.healthy("/ok")
}

func TestAMemoryBombIsEndedAsRenderFailedAndThePoolStaysHealthy(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.RenderMemoryMB = 1000 }})
	r.okPage()
	r.page("/bomb", `<html><body><script>
const keep = [];
function bomb() { for (let i = 0; i < 10; i++) { const b = new ArrayBuffer(64 * 1024 * 1024); new Uint8Array(b).fill(7); keep.push(b); } setTimeout(bomb, 5); }
bomb();</script></body></html>`)
	start := time.Now()
	_, err := r.render(render.Request{URL: r.url("/bomb"), TimeoutMS: 30000})
	wantCode(t, err, render.RenderFailed)
	if !strings.Contains(err.Error(), "memory") {
		t.Errorf("the reason does not say memory: %v", err)
	}
	if took := time.Since(start); took > 25*time.Second {
		t.Errorf("took %v", took)
	}
	r.healthy("/ok")
}

func TestASubresourceStormIsCutAtTheRequestBudget(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.MaxRequests = 100; c.BlockTypes = nil }}) // images are what the storm is made of
	r.okPage()
	r.mux.HandleFunc("/img", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		io.WriteString(w, "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
	})
	r.page("/storm", `<html><body>STORM<script>for (let i = 0; i < 2000; i++) { const im = new Image(); im.src = '/img?i=' + i; document.body.appendChild(im); }</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/storm"), TimeoutMS: 30000})
	if res.Limit != "requests" || res.Blocked < 1500 || res.Requests < 100 {
		t.Errorf("limit %q blocked %d requests %d", res.Limit, res.Blocked, res.Requests)
	}
	if n := r.hitCount("/img"); n > 100 {
		t.Errorf("the origin served %d images against a budget of 100", n)
	}
	r.healthy("/ok")
}

// The proxy counts the requests it sees too (the browser's own count does not cover frames of other sites): a render that
// registers a small budget and makes more requests than that is refused at the proxy.
func TestTheProxyEnforcesTheRequestBudgetAlone(t *testing.T) {
	r := newRig(t, opts{ceil: proxy.Limits{MaxRequests: 30}})
	r.okPage()
	r.mux.HandleFunc("/img", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		io.WriteString(w, "GIF89a")
	})
	r.page("/storm", `<html><body>STORM<script>for (let i = 0; i < 400; i++) { const f = document.createElement('iframe'); f.src = '/img?i=' + i; document.body.appendChild(f); }</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/storm"), TimeoutMS: 30000})
	if res.Limit != "requests" || r.hitCount("/img") > 30 {
		t.Errorf("limit %q, origin served %d", res.Limit, r.hitCount("/img"))
	}
	var denied int
	for _, e := range r.audit.all() {
		if e.Reason == "limit_requests" {
			denied++
		}
	}
	if denied == 0 && res.Blocked == 0 {
		t.Error("nothing was refused")
	}
}

func TestInfiniteRedirectsEndAsRenderFailed(t *testing.T) {
	r := newRig(t, opts{})
	r.okPage()
	r.mux.HandleFunc("/spin", func(w http.ResponseWriter, q *http.Request) {
		http.Redirect(w, q, "/spin?"+fmt.Sprint(time.Now().UnixNano()), http.StatusFound)
	})
	start := time.Now()
	_, err := r.render(render.Request{URL: r.url("/spin"), TimeoutMS: 20000})
	wantCode(t, err, render.RenderFailed)
	if !strings.Contains(err.Error(), "REDIRECT") {
		t.Errorf("%v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Error("too slow")
	}
	r.healthy("/ok")
}

func TestAHugeDOMIsCutAtMaxBytes(t *testing.T) {
	r := newRig(t, opts{})
	r.okPage()
	r.page("/huge", `<html><body><script>
let s = ''; for (let i = 0; i < 120000; i++) s += '<p>paragraph number ' + i + ' of the huge page</p>';
document.body.innerHTML = s;</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/huge"), MaxBytes: 1 << 20, TimeoutMS: 40000})
	if !res.Truncated || len(res.HTML) > 1<<20 || len(res.HTML) < 1<<19 {
		t.Errorf("truncated %v, %d bytes", res.Truncated, len(res.HTML))
	}
	if !strings.Contains(res.HTML, "paragraph number 0 ") {
		t.Error("the cut is not at the end")
	}
	// the default cap too
	res = r.mustRender(render.Request{URL: r.url("/huge"), TimeoutMS: 40000})
	if len(res.HTML) > 5<<20 || !res.Truncated {
		t.Errorf("default cap: truncated %v, %d bytes", res.Truncated, len(res.HTML))
	}
	r.healthy("/ok")
}

func TestAResponseOverTheResponseBudgetIsCut(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.MaxResponseBytes = 2 << 20 }})
	r.okPage()
	r.mux.HandleFunc("/bigjs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		chunk := []byte(strings.Repeat("/* padding */\n", 1000))
		for i := 0; i < 3000; i++ { // 42 MB, no Content-Length
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	r.page("/big", `<html><body>BIG<script src="/bigjs"></script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/big"), TimeoutMS: 30000})
	if res.Limit != "response" || res.Bytes > 8<<20 {
		t.Errorf("limit %q, bytes %d", res.Limit, res.Bytes)
	}
	r.healthy("/ok")
}

func TestTheTotalByteBudgetIsEnforcedAtTheProxy(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.MaxBytes = 3 << 20; c.BlockTypes = nil }})
	r.okPage()
	r.mux.HandleFunc("/chunk", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(make([]byte, 1<<20))
	})
	r.page("/many", `<html><body>MANY<script>for (let i = 0; i < 12; i++) { const im = new Image(); im.src = '/chunk?i=' + i; }</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/many"), TimeoutMS: 30000})
	if res.Limit != "bytes" || res.Bytes > 6<<20 {
		t.Errorf("limit %q, bytes %d", res.Limit, res.Bytes)
	}
	r.healthy("/ok")
}

func TestAPageThatNeverLoadsEndsAsRenderTimeout(t *testing.T) {
	r := newRig(t, opts{})
	r.okPage()
	r.mux.HandleFunc("/hang.js", func(w http.ResponseWriter, q *http.Request) { <-q.Context().Done() })
	r.page("/hang", `<html><body>head<script src="/hang.js"></script></body></html>`)
	start := time.Now()
	_, err := r.render(render.Request{URL: r.url("/hang"), TimeoutMS: 3000})
	wantCode(t, err, render.RenderTimeout)
	if time.Since(start) > 10*time.Second {
		t.Error("too slow")
	}
	r.healthy("/ok")
}

func TestWhenEveryBrowserIsRenderingTheAnswerIsRenderBusy(t *testing.T) {
	r := newRig(t, opts{}) // one browser, no queue
	r.okPage()
	r.mux.HandleFunc("/slow.js", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(3 * time.Second)
		io.WriteString(w, "document.body.append('SLOW-DONE')")
	})
	r.page("/slow", `<html><body>HEALTHY<script src="/slow.js"></script></body></html>`)
	done := make(chan error, 1)
	go func() {
		_, err := r.render(render.Request{URL: r.url("/slow"), TimeoutMS: 20000})
		done <- err
	}()
	deadline := time.Now().Add(15 * time.Second)
	for r.pool.Stats.Active.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	_, err := r.render(render.Request{URL: r.url("/ok")})
	wantCode(t, err, render.RenderBusy)
	if err := <-done; err != nil {
		t.Fatalf("the first render: %v", err)
	}
	r.healthy("/ok")
}

func TestABrowserIsReplacedAfterTheConfiguredNumberOfRenders(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.RecycleAfter = 3 }})
	r.okPage()
	r.mustRender(render.Request{URL: r.url("/ok")})
	first := r.pool.PIDs()
	if len(first) != 1 {
		t.Fatalf("pids %v", first)
	}
	r.mustRender(render.Request{URL: r.url("/ok")})
	if got := r.pool.PIDs(); len(got) != 1 || got[0] != first[0] {
		t.Errorf("replaced early: %v", got)
	}
	r.mustRender(render.Request{URL: r.url("/ok")})
	if r.pool.Processes() != 0 {
		t.Errorf("the process of the third render is still there: %v", r.pool.PIDs())
	}
	r.mustRender(render.Request{URL: r.url("/ok")})
	if got := r.pool.PIDs(); len(got) != 1 || got[0] == first[0] {
		t.Errorf("pids after the fourth render: %v (first %v)", got, first)
	}
	if r.pool.Stats.Starts.Load() != 2 || r.pool.Stats.Recycles.Load() != 1 {
		t.Errorf("starts %d recycles %d", r.pool.Stats.Starts.Load(), r.pool.Stats.Recycles.Load())
	}
}

func TestABrowserAboveTheMemoryThresholdIsReplacedAfterTheRender(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.RecycleMemoryMB = 1 }}) // any browser is above one megabyte
	r.okPage()
	r.mustRender(render.Request{URL: r.url("/ok")})
	if r.pool.Processes() != 0 || r.pool.Stats.Recycles.Load() != 1 {
		t.Errorf("processes %d recycles %d", r.pool.Processes(), r.pool.Stats.Recycles.Load())
	}
}

// Inside one TLS tunnel (HTTP/2) the proxy sees one request however many the page makes: the render's own count is what
// holds the budget there.
func TestAStormOverOneTLSConnectionIsCutByTheRendersOwnCount(t *testing.T) {
	r := newRig(t, opts{tls: true, cfg: func(c *render.Config) { c.MaxRequests = 100; c.BlockTypes = nil }})
	r.okPage()
	r.mux.HandleFunc("/img", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/gif")
		io.WriteString(w, "GIF89a")
	})
	r.page("/storm", `<html><body>STORM<script>for (let i = 0; i < 1000; i++) { const im = new Image(); im.src = '/img?i=' + i; }</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.tls.URL + "/storm", TimeoutMS: 30000})
	if res.Limit != "requests" || res.Blocked < 800 {
		t.Errorf("limit %q blocked %d", res.Limit, res.Blocked)
	}
	if n := r.hitCount("/img"); n > 100 {
		t.Errorf("the origin served %d images over one tunnel against a budget of 100", n)
	}
	var connects int
	for _, e := range r.audit.all() {
		if e.Decision == "allow" {
			connects++
		}
	}
	if connects > 10 {
		t.Errorf("%d tunnels: the test does not show the tunnel hiding the requests", connects)
	}
}

const imagePage = `<html><body><p id="t">THE TEXT OF THE PAGE</p><script>
for (let i = 0; i < 500; i++) { const im = new Image(); im.src = '/img?i=' + i; document.body.appendChild(im); }
const f = document.createElement('style'); f.textContent = '@font-face { font-family: X; src: url(/font.woff2); } p { font-family: X; }'; document.head.appendChild(f);
const v = document.createElement('video'); v.src = '/clip.mp4'; v.preload = 'auto'; document.body.appendChild(v);
</script></body></html>`

// Images, media and fonts are not fetched: skipped, counted apart, outside the request budget, never at the proxy or the origin.
func TestImagesMediaAndFontsAreSkippedAndDoNotUseTheBudget(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.MaxRequests = 100 }})
	r.okPage()
	for _, p := range []string{"/img", "/font.woff2", "/clip.mp4"} {
		r.mux.HandleFunc(p, func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "x") })
	}
	r.page("/images", imagePage)
	res := r.mustRender(render.Request{URL: r.url("/images"), TimeoutMS: 30000})
	if !strings.Contains(res.HTML, "THE TEXT OF THE PAGE") {
		t.Fatalf("the text is missing: %.200q", res.HTML)
	}
	if res.Skipped < 500 || res.Blocked != 0 || res.Limit != "" || res.Requests > 10 {
		t.Errorf("skipped %d blocked %d limit %q requests %d", res.Skipped, res.Blocked, res.Limit, res.Requests)
	}
	if n := r.hitCount("/img") + r.hitCount("/font.woff2") + r.hitCount("/clip.mp4"); n != 0 {
		t.Errorf("the origin served %d images, fonts or media", n)
	}
	if r.pool.Stats.Skipped.Load() < 500 {
		t.Errorf("the metric counts %d", r.pool.Stats.Skipped.Load())
	}
	r.healthy("/ok")
}

// The setting off: the same page uses the budget as before.
func TestWithTheSettingEmptyTheSamePageHitsTheRequestBudget(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.MaxRequests = 100; c.BlockTypes = nil }})
	r.mux.HandleFunc("/img", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "x") })
	r.page("/images", imagePage)
	res := r.mustRender(render.Request{URL: r.url("/images"), TimeoutMS: 30000})
	if res.Skipped != 0 || res.Limit != "requests" || res.Blocked < 300 || !strings.Contains(res.HTML, "THE TEXT OF THE PAGE") {
		t.Errorf("skipped %d blocked %d limit %q", res.Skipped, res.Blocked, res.Limit)
	}
}

// Skipping is not free: past ten budgets of skipped requests the rest count as requests, so a page that retries a refused
// image in a loop meets the budget instead of keeping the renderer busy until the clock.
func TestSkippingIsBoundedByTenBudgets(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.MaxRequests = 20 }})
	r.page("/loop", `<html><body>LOOP<script>let n = 0; function more() { for (let i = 0; i < 100 && n < 5000; i++, n++) { new Image().src = '/img?i=' + n; } if (n < 5000) setTimeout(more, 1); } more();</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/loop"), TimeoutMS: 30000})
	if res.Skipped != 200 || res.Limit != "requests" || res.Blocked < 100 {
		t.Errorf("skipped %d blocked %d limit %q", res.Skipped, res.Blocked, res.Limit)
	}
}
