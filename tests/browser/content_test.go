//go:build browser

package browsertest

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"idp-browser/internal/proxy"
	"idp-browser/internal/render"
)

const okPage = `<!doctype html><html><body>HEALTHY</body></html>`

func TestContentThatAppearsLaterInATimerIsPresent(t *testing.T) {
	r := newRig(t, opts{})
	r.page("/late", `<html><body><p id="p">loading</p><script>setTimeout(() => { document.getElementById('p').textContent = 'TIMER-CONTENT-' + '4410'; }, 800);</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/late")})
	if !strings.Contains(res.HTML, "TIMER-CONTENT-4410") {
		t.Fatalf("the delayed text is missing: %.300q", res.HTML)
	}
}

func TestContentFetchedAfterLoadIsPresent(t *testing.T) {
	r := newRig(t, opts{})
	r.mux.HandleFunc("/api/data", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"text":"FETCHED-TEXT-9921"}`) })
	r.page("/spa", `<html><body><div id="a"></div><script>fetch('/api/data').then(r => r.json()).then(j => { document.getElementById('a').textContent = j.text; });</script></body></html>`)
	if res := r.mustRender(render.Request{URL: r.url("/spa")}); !strings.Contains(res.HTML, "FETCHED-TEXT-9921") {
		t.Fatalf("%.300q", res.HTML)
	}
}

const lazyPage = `<html><body><div style="height:6000px">spacer</div><div id="lazy">not yet</div>
<script>new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { document.getElementById('lazy').textContent = 'LAZY-SECTION-' + 'LOADED'; o.disconnect(); } }).observe(document.getElementById('lazy'));</script></body></html>`

// The scroll is a control: with it the lazy section is read, without it the section is not there.
func TestALazySectionIsLoadedByOneScrollAndOnlyByIt(t *testing.T) {
	on := newRig(t, opts{})
	on.page("/lazy", lazyPage)
	if res := on.mustRender(render.Request{URL: on.url("/lazy")}); !strings.Contains(res.HTML, "LAZY-SECTION-LOADED") {
		t.Fatalf("with the scroll: %.200q", res.HTML)
	}
	off := newRig(t, opts{cfg: func(c *render.Config) { c.Scroll = false }})
	off.page("/lazy", lazyPage)
	if res := off.mustRender(render.Request{URL: off.url("/lazy")}); strings.Contains(res.HTML, "LAZY-SECTION-LOADED") {
		t.Fatal("the lazy section loaded without a scroll: the test does not test the scroll")
	}
}

func TestAnHTTPSPageIsRenderedThroughAConnectTunnel(t *testing.T) {
	r := newRig(t, opts{tls: true})
	r.page("/s", `<html><body><div id="a"></div><script>document.getElementById('a').textContent = 'OVER-TLS-' + '5521';</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.tls.URL + "/s"})
	if !strings.Contains(res.HTML, "OVER-TLS-5521") {
		t.Fatalf("%.300q", res.HTML)
	}
	tlsPort := r.tls.Listener.Addr().String()[strings.LastIndex(r.tls.Listener.Addr().String(), ":")+1:]
	found := false
	for _, e := range r.audit.all() {
		if fmt.Sprint(e.Port) == tlsPort && e.Decision == "allow" && e.Reason == "ok" && e.Bytes > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("no allowed CONNECT of the TLS origin in the audit: %v", r.audit.all())
	}
}

func TestTheStatusAndTheFinalURLAfterRedirectsAreReported(t *testing.T) {
	r := newRig(t, opts{})
	r.mux.HandleFunc("/start", func(w http.ResponseWriter, q *http.Request) { http.Redirect(w, q, "/middle", http.StatusFound) })
	r.mux.HandleFunc("/middle", func(w http.ResponseWriter, q *http.Request) {
		http.Redirect(w, q, "/gone?x=1", http.StatusMovedPermanently)
	})
	r.mux.HandleFunc("/gone", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		io.WriteString(w, "<html><title>Missing</title><body>This page is not here, and this sentence makes it more than a bare error page for the detector to decide on.</body></html>")
	})
	res := r.mustRender(render.Request{URL: r.url("/start")})
	if res.Status != 404 || res.FinalURL != r.url("/gone?x=1") || res.Title != "Missing" {
		t.Errorf("%+v", *res)
	}
}

func TestChallengeAndRefusalPagesAreBlockedBySite(t *testing.T) {
	r := newRig(t, opts{})
	r.page("/cf", `<html><head><title>Just a moment...</title></head><body><script>window._cf_chl_opt={cvId:'3'}</script>Checking your browser</body></html>`)
	r.page("/js-challenge", `<html><body><div id="a"></div><script>setTimeout(()=>{document.getElementById('a').textContent='Please verify you are human'},100)</script></body></html>`)
	// the soft block of Akamai that answers 200 (found at www.fedex.com, 2026-11-23)
	r.page("/akamai", `<html><body><h1>We're sorry, we can't process your request right now.</h1><p>It appears you don't have permission to view this webpage.</p><p>Incident Number: 0.11a6b4d.1795089600.5f2c</p></body></html>`)
	r.mux.HandleFunc("/forbidden", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, "<html><body>Forbidden</body></html>")
	})
	for _, p := range []string{"/cf", "/js-challenge", "/akamai", "/forbidden"} {
		_, err := r.render(render.Request{URL: r.url(p)})
		if re, ok := err.(*render.Error); !ok || re.Code != render.BlockedBySite {
			t.Errorf("%s: %v", p, err)
		}
	}
	r.page("/ok", okPage)
	r.healthy("/ok")
}

func TestAnInvalidOrForbiddenRequestIsRefusedBeforeABrowserIsUsed(t *testing.T) {
	r := newRig(t, opts{})
	for _, tc := range []struct {
		req  render.Request
		code string
	}{
		{render.Request{}, render.InvalidRequest},
		{render.Request{URL: r.url("/x"), TimeoutMS: 10}, render.InvalidRequest},
		{render.Request{URL: r.url("/x"), TimeoutMS: 10_000_000}, render.InvalidRequest},
		{render.Request{URL: r.url("/x"), MaxBytes: 5}, render.InvalidRequest},
		{render.Request{URL: r.url("/x"), MaxBytes: -1}, render.InvalidRequest},
		{render.Request{URL: "file:///etc/passwd"}, render.NotAllowed},
		{render.Request{URL: "chrome://version"}, render.NotAllowed},
		{render.Request{URL: "chrome-error://chromewebdata/"}, render.NotAllowed},
		{render.Request{URL: "data:text/html,<p>hi</p>"}, render.NotAllowed},
		{render.Request{URL: "javascript:alert(1)"}, render.NotAllowed},
		{render.Request{URL: "blob:http://example.com/x"}, render.NotAllowed},
		{render.Request{URL: "ftp://example.com/"}, render.NotAllowed},
		{render.Request{URL: "about:blank"}, render.NotAllowed},
		{render.Request{URL: "http://127.0.0.1:1/"}, render.NotAllowed},
		{render.Request{URL: "http://169.254.169.254/latest/meta-data/"}, render.NotAllowed},
		{render.Request{URL: "http://10.0.0.1/"}, render.NotAllowed},
		{render.Request{URL: "http://[::1]/"}, render.NotAllowed},
		{render.Request{URL: "http://[64:ff9b::7f00:1]/"}, render.NotAllowed},
		{render.Request{URL: "http://2130706433/"}, render.NotAllowed},
		{render.Request{URL: "http://user:pw@example.com/"}, render.NotAllowed},
		{render.Request{URL: "http://example.com:22/"}, render.NotAllowed},
	} {
		_, err := r.render(tc.req)
		re, ok := err.(*render.Error)
		if !ok || re.Code != tc.code {
			t.Errorf("%q %+v: %v, want %s", tc.req.URL, tc.req, err, tc.code)
		}
	}
	if r.pool.Stats.Starts.Load() != 0 || r.pool.Processes() != 0 {
		t.Error("a browser was started for a request that is refused")
	}
}

// A name that resolves privately, and a redirect to a private address, are the page itself being refused: not_allowed,
// whatever the browser made of the proxy's refusal.
func TestAPageOnAPrivateNameOrRedirectedToAPrivateAddressIsNotAllowed(t *testing.T) {
	r := newRig(t, opts{})
	r.mux.HandleFunc("/to-meta", func(w http.ResponseWriter, q *http.Request) {
		http.Redirect(w, q, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	r.mux.HandleFunc("/to-name", func(w http.ResponseWriter, q *http.Request) {
		http.Redirect(w, q, "http://private.test/admin", http.StatusFound)
	})
	r.mux.HandleFunc("/to-file", func(w http.ResponseWriter, q *http.Request) {
		http.Redirect(w, q, "file:///etc/passwd", http.StatusFound)
	})
	for _, u := range []string{"http://private.test/", "http://metadata.test/", "http://loop.test/", "http://mixed.test/", r.url("/to-meta"), r.url("/to-name")} {
		_, err := r.render(render.Request{URL: u, TimeoutMS: 15000})
		if re, ok := err.(*render.Error); !ok || re.Code != render.NotAllowed {
			t.Errorf("%s: %v, want not_allowed", u, err)
		}
	}
	// a redirect to file: is refused by the browser itself; whatever the code, the file is not returned
	res, err := r.render(render.Request{URL: r.url("/to-file")})
	if err == nil && (strings.Contains(res.HTML, "root:") || !strings.HasPrefix(res.FinalURL, "http")) {
		t.Errorf("a redirect to file: gave %+v", res)
	}
	for _, e := range r.audit.all() {
		if e.Host == "169.254.169.254" && e.Decision != "deny" {
			t.Errorf("the metadata address was allowed: %v", e)
		}
	}
	if r.canaryHit.Load() != 0 {
		t.Error("the canary was reached")
	}
}

var _ = proxy.Entry{}
