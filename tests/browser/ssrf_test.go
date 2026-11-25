//go:build browser

package browsertest

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"idp-browser/internal/render"
)

// A page that tries every way a page can make a request, at addresses that must never be reached. Every one is refused
// at the proxy (the audit says so), none is allowed, and a listener on loopback that stands for the inside of the network
// receives nothing.
func TestAPageThatReachesForTheInsideOfTheNetworkGetsNothing(t *testing.T) {
	r := newRig(t, opts{cfg: func(c *render.Config) { c.BlockTypes = nil }}) // <img> is one of the vectors
	cp := r.canaryPort()
	targets := []string{
		"http://127.0.0.1:" + cp + "/canary",
		"http://127.0.0.1/",
		"http://[::1]/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/admin",
		"http://192.168.1.1/",
		"http://private.test/secret",
		"http://metadata.test/",
		"http://loop.test/",
		"http://mixed.test/",
		"http://[::1]:" + cp + "/",
		"http://100.64.0.1/",
	}
	var list []string
	for _, x := range targets {
		list = append(list, fmt.Sprintf("%q", x))
	}
	r.page("/ssrf", `<html><body><script>
const targets = [`+strings.Join(list, ",")+`];
for (const t of targets) {
  try { fetch(t, {mode: 'no-cors'}).catch(() => {}); } catch (e) {}
  try { const x = new XMLHttpRequest(); x.open('GET', t); x.send(); } catch (e) {}
  try { const i = new Image(); i.src = t + '?img'; } catch (e) {}
  try { const f = document.createElement('iframe'); f.src = t + '?frame'; document.body.appendChild(f); } catch (e) {}
  try { new WebSocket(t.replace('http', 'ws')); } catch (e) {}
  try { const s = document.createElement('script'); s.src = t + '?script'; document.head.appendChild(s); } catch (e) {}
  try { const l = document.createElement('link'); l.rel = 'stylesheet'; l.href = t + '?css'; document.head.appendChild(l); } catch (e) {}
  try { navigator.sendBeacon(t + '?beacon', 'x'); } catch (e) {}
  try { const fm = document.createElement('form'); fm.method = 'POST'; fm.action = t + '?form'; fm.target = 'ghost'; document.body.appendChild(fm); } catch (e) {}
  try { new EventSource(t + '?sse'); } catch (e) {}
}
setTimeout(() => { document.body.append('SSRF-PAGE-DONE'); }, 1500);
</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/ssrf"), TimeoutMS: 30000})
	if !strings.Contains(res.HTML, "SSRF-PAGE-DONE") {
		t.Fatalf("the page did not run: %.200q", res.HTML)
	}
	if res.Blocked < len(targets) {
		t.Errorf("blocked %d of at least %d targets", res.Blocked, len(targets))
	}
	hosts := map[string]string{ // the host as the audit has it
		"127.0.0.1": "", "169.254.169.254": "", "10.0.0.5": "", "192.168.1.1": "", "private.test": "", "metadata.test": "", "loop.test": "",
		"mixed.test": "", "::1": "", "100.64.0.1": "",
	}
	for h := range hosts {
		es := r.audit.forHost(h)
		if h == "127.0.0.1" { // the test origin is on 127.0.0.1 too, and allowed: only port 80 and the canary's port count
			var only []string
			for _, e := range es {
				if fmt.Sprint(e.Port) == cp || e.Port == 80 {
					only = append(only, e.Decision+"/"+e.Reason)
				}
			}
			if len(only) == 0 {
				t.Errorf("no audit line for the canary port")
			}
			for _, d := range only {
				if !strings.HasPrefix(d, "deny/") {
					t.Errorf("canary request: %s", d)
				}
			}
			continue
		}
		if len(es) == 0 {
			t.Errorf("%s: no audit line, so nothing shows that the proxy saw it", h)
		}
		for _, e := range es {
			if e.Decision != "deny" || (e.Reason != "not_public" && e.Reason != "bad_host" && e.Reason != "port") {
				t.Errorf("%s: %v", h, e)
			}
		}
	}
	if n := r.canaryHit.Load(); n != 0 {
		t.Errorf("the canary received %d connections", n)
	}
	for _, e := range r.audit.all() {
		if strings.ContainsAny(e.Host, "/?") {
			t.Errorf("a path or query in an audit host: %v", e)
		}
	}
}

// Top-level navigation by the page to file:, chrome:, data: and the like goes nowhere.
func TestAPageCannotNavigateItselfToLocalSchemes(t *testing.T) {
	r := newRig(t, opts{})
	r.mux.HandleFunc("/etc-marker", func(w http.ResponseWriter, _ *http.Request) {})
	for i, target := range []string{"file:///etc/passwd", "file:///etc/hostname", "chrome://version", "chrome://gpu", "data:text/html,<p>DATA-NAV-PWNED</p>",
		"blob:null/x", "view-source:http://example.com/", "about:srcdoc", "ftp://127.0.0.1/", "chrome-error://chromewebdata/"} {
		path := fmt.Sprintf("/nav%d", i)
		r.page(path, `<html><body>NAV-ORIGIN-PAGE<script>setTimeout(() => { try { location.href = `+fmt.Sprintf("%q", target)+`; } catch (e) {} }, 100);
setTimeout(() => { try { window.open(`+fmt.Sprintf("%q", target)+`); } catch (e) {} }, 200);
setTimeout(() => { try { const f = document.createElement('iframe'); f.src = `+fmt.Sprintf("%q", target)+`; document.body.appendChild(f); } catch (e) {} }, 300);
</script><meta http-equiv="refresh" content="1;url=`+target+`"></body></html>`)
		res, err := r.render(render.Request{URL: r.url(path), TimeoutMS: 15000})
		if re, ok := err.(*render.Error); ok && re.Code == render.RenderFailed {
			continue // the browser ended on its own error page for this one, and the render says so
		}
		if err != nil {
			t.Errorf("%s: %v", target, err)
			continue
		}
		if !strings.HasPrefix(res.FinalURL, r.origin.URL) || !strings.Contains(res.HTML, "NAV-ORIGIN-PAGE") {
			t.Errorf("%s: the page ended at %s", target, res.FinalURL)
		}
		// the page's own source holds the target (script, meta, iframe): what must not be there is what the target would show
		shown := regexp.MustCompile(`(?s)<script.*?</script>|<meta[^>]*>|<iframe[^>]*>`).ReplaceAllString(res.HTML, "")
		for _, bad := range []string{"PWNED", "root:x:", "Chromium"} {
			if strings.Contains(shown, bad) {
				t.Errorf("%s: html holds %q", target, bad)
			}
		}
	}
}

// WebRTC may use only the proxy: a STUN server on loopback UDP is never asked.
func TestWebRTCSendsNothingOutsideTheProxy(t *testing.T) {
	r := newRig(t, opts{})
	port := r.udp.LocalAddr().String()
	r.page("/rtc", `<html><body><script>
const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:`+port+`'}]});
pc.createDataChannel('x');
pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => {});
setTimeout(() => { document.body.append('RTC-DONE'); }, 3000);
</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/rtc"), TimeoutMS: 20000})
	if !strings.Contains(res.HTML, "RTC-DONE") {
		t.Fatalf("%.200q", res.HTML)
	}
	if n := r.udpHit.Load(); n != 0 {
		t.Errorf("the STUN canary received %d datagrams", n)
	}
}
