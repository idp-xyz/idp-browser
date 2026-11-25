//go:build browser

package browsertest

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idp-browser/internal/caller"
	"idp-browser/internal/service"
)

// The whole API over the real pool: requests that are not idp-web's signed ones start no browser at all, and a signed one
// is rendered and answered in the documented shape.
func TestTheAPIStartsNoBrowserForARequestThatIsNotSigned(t *testing.T) {
	r := newRig(t, opts{})
	r.page("/p", `<html><head><title>T</title></head><body><script>document.body.append('API-' + 'OK')</script></body></html>`)
	const aud = "http://idp-browser.test:8590/render"
	priv, pub, _ := caller.GenerateKey()
	signer, _ := caller.NewSigner(priv)
	v, _ := caller.NewVerifier(pub, aud, "idp-web")
	api := httptest.NewServer(&service.Server{Renderer: r.pool, Verifier: v, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	defer api.Close()
	body := `{"url":"` + r.url("/p") + `","timeoutMs":15000}`
	post := func(b, bearer string) (int, []byte) {
		req, _ := http.NewRequest("POST", api.URL+"/render", strings.NewReader(b))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out
	}
	good, _ := signer.Sign(aud, "POST", "/render", []byte(body))
	otherPriv, _, _ := caller.GenerateKey()
	other, _ := caller.NewSigner(otherPriv)
	wrong, _ := other.Sign(aud, "POST", "/render", []byte(body))
	expired, _ := signer.Sign(aud, "POST", "/render", []byte(body))
	signer.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	old, _ := signer.Sign(aud, "POST", "/render", []byte(body))
	for name, bearer := range map[string]string{"unsigned": "", "wrong key": wrong, "expired": old} {
		if code, _ := post(body, bearer); code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
	_ = expired
	if r.pool.Stats.Starts.Load() != 0 || r.pool.Processes() != 0 || len(r.audit.all()) != 0 {
		t.Fatal("a browser or the proxy was used for a request that was refused")
	}
	code, out := post(body, good)
	if code != 200 {
		t.Fatalf("%d %s", code, out)
	}
	var res map[string]any
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"finalUrl", "html", "status", "title", "requests", "blocked", "bytes", "ms"} {
		if _, ok := res[k]; !ok {
			t.Errorf("no %s in %s", k, out)
		}
	}
	if !strings.Contains(res["html"].(string), "API-OK") || res["title"] != "T" {
		t.Errorf("%s", out)
	}
	// replayed
	if code, _ := post(body, good); code != 401 {
		t.Errorf("replay: %d", code)
	}
	// a refused address is an error with a code in the body
	b2 := `{"url":"http://169.254.169.254/"}`
	g2, _ := (func() (string, error) { signer.Now = time.Now; return signer.Sign(aud, "POST", "/render", []byte(b2)) })()
	code, out = post(b2, g2)
	if code != 422 || !strings.Contains(string(out), `"code":"not_allowed"`) {
		t.Errorf("%d %s", code, out)
	}
}
