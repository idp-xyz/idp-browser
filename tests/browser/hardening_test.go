//go:build browser

package browsertest

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"idp-browser/internal/render"
)

// Render 1 puts a cookie and every kind of storage on the origin; render 2, in the SAME browser process, finds none of it,
// and the origin sees no cookie from it. The render also has no cache of the one before.
func TestContextsShareNoCookieStorageOrCache(t *testing.T) {
	r := newRig(t, opts{}) // one process: both renders run in it
	var cookies []string
	r.mux.HandleFunc("/cached.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Content-Type", "text/javascript")
		w.Write([]byte("window.cachedLoaded = true;"))
	})
	r.mux.HandleFunc("/set", func(w http.ResponseWriter, q *http.Request) {
		cookies = append(cookies, "set:"+q.Header.Get("Cookie"))
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "secret-session", Path: "/", MaxAge: 3600})
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>one<script src="/cached.js"></script><script>
localStorage.setItem('k', 'ls-value'); sessionStorage.setItem('k', 'ss-value'); document.cookie = 'js=cookie; path=/; max-age=3600';
indexedDB.open('db', 1).onupgradeneeded = e => { e.target.result.createObjectStore('s'); };
</script></body></html>`))
	})
	r.mux.HandleFunc("/get", func(w http.ResponseWriter, q *http.Request) {
		cookies = append(cookies, "get:"+q.Header.Get("Cookie"))
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><pre id="out"></pre><script src="/cached.js"></script><script>
const out = {cookie: document.cookie, ls: localStorage.getItem('k'), ss: sessionStorage.getItem('k'), idb: null};
indexedDB.databases().then(d => { out.idb = d.length; document.getElementById('out').textContent = JSON.stringify(out); });
</script></body></html>`))
	})
	r.mustRender(render.Request{URL: r.url("/set")})
	res := r.mustRender(render.Request{URL: r.url("/get")})
	if r.pool.Stats.Starts.Load() != 1 {
		t.Fatalf("the two renders did not share a process (%d starts): the test proves nothing", r.pool.Stats.Starts.Load())
	}
	m := regexp.MustCompile(`<pre id="out">(.*?)</pre>`).FindStringSubmatch(res.HTML)
	if m == nil {
		t.Fatalf("%.300q", res.HTML)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(strings.ReplaceAll(m[1], "&quot;", `"`), "&amp;", "&")), &out); err != nil {
		t.Fatal(err, m[1])
	}
	if out["cookie"] != "" || out["ls"] != nil || out["ss"] != nil || out["idb"] != float64(0) {
		t.Errorf("state carried over: %v", out)
	}
	if got := cookies[len(cookies)-1]; got != "get:" {
		t.Errorf("the origin saw %q on the second render", got)
	}
	if n := r.hitCount("/cached.js"); n != 2 {
		t.Errorf("the cached script was fetched %d times for two renders", n)
	}
}

func TestBrowserFeaturesThatReachOutOfThePageAreOff(t *testing.T) {
	r := newRig(t, opts{})
	r.mux.HandleFunc("/dl", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="payload.bin"`)
		w.Write([]byte("DOWNLOAD-MARKER-77"))
	})
	r.page("/features", `<html><body><script>
const out = {sw: typeof navigator.serviceWorker, notification: typeof Notification !== 'undefined' ? Notification.permission : 'none'};
const states = {};
for (const n of ['geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read', 'midi']) { navigator.permissions.query({name: n}).then(p => { states[n] = p.state; }, () => { states[n] = 'unknown'; }); }
function fin() { out.perm = states; document.body.setAttribute('data-out', JSON.stringify(out)); }
navigator.geolocation.getCurrentPosition(() => { out.geo = 'granted'; }, e => { out.geo = 'denied'; });
navigator.mediaDevices.getUserMedia({video: true, audio: true}).then(() => { out.media = 'granted'; }, e => { out.media = 'denied:' + e.name; });
navigator.clipboard.readText().then(() => { out.clipboard = 'granted'; }, e => { out.clipboard = 'denied'; });
const a = document.createElement('a'); a.href = '/dl'; a.download = 'payload.bin'; document.body.appendChild(a); a.click();
setTimeout(fin, 600);
</script></body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/features"), TimeoutMS: 20000})
	m := regexp.MustCompile(`data-out="([^"]*)"`).FindStringSubmatch(res.HTML)
	if m == nil {
		t.Fatalf("%.300q", res.HTML)
	}
	out := strings.ReplaceAll(m[1], "&quot;", `"`)
	if strings.Contains(out, "granted") || !strings.Contains(out, `"perm":{`) || !strings.Contains(out, `"sw":"undefined"`) || !(strings.Contains(out, `"notification":"denied"`) || strings.Contains(out, `"notification":"none"`)) {
		t.Errorf("features: %s", out)
	}
	_ = filepath.WalkDir(r.cfg.ProfileDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if d.Name() == "payload.bin" {
				t.Errorf("a download was saved: %s", p)
			}
		}
		return nil
	})
	if m, _ := filepath.Glob("/tmp/payload*"); len(m) > 0 {
		t.Errorf("download in /tmp: %v", m)
	}
	_ = os.Getpid
}
