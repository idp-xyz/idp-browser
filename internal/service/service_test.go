package service

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"idp-browser/internal/caller"
	"idp-browser/internal/render"
)

const aud = "http://idp-browser.test:8590/render"

type fake struct {
	calls atomic.Int64
	res   *render.Result
	err   error
}

func (f *fake) Render(_ context.Context, req render.Request) (*render.Result, error) {
	f.calls.Add(1)
	return f.res, f.err
}

type rig struct {
	f      *fake
	srv    *httptest.Server
	signer *caller.Signer
	now    time.Time
}

func newRig(t *testing.T) *rig {
	priv, pub, _ := caller.GenerateKey()
	signer, _ := caller.NewSigner(priv)
	v, err := caller.NewVerifier(pub, aud, "idp-web")
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{f: &fake{res: &render.Result{FinalURL: "http://x/", HTML: "<p>hi</p>", Status: 200}}, signer: signer, now: time.Now()}
	signer.Now = func() time.Time { return r.now }
	v.SetClock(func() time.Time { return r.now })
	r.srv = httptest.NewServer(&Server{Renderer: r.f, Verifier: v, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) post(t *testing.T, body, auth string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", r.srv.URL+"/render", strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (r *rig) sign(t *testing.T, body string) string {
	a, err := r.signer.Sign(aud, "POST", "/render", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const body = `{"url":"https://example.com/","timeoutMs":15000}`

func TestASignedRequestIsRenderedAndAnswered(t *testing.T) {
	r := newRig(t)
	code, out := r.post(t, body, r.sign(t, body))
	if code != 200 || !strings.Contains(out, `\u003cp\u003ehi`) || r.f.calls.Load() != 1 {
		t.Errorf("%d %s calls %d", code, out, r.f.calls.Load())
	}
}

// Unsigned, wrongly signed, expired, replayed and re-aimed requests are refused before the renderer is asked anything.
func TestRequestsThatAreNotIdpWebsAreRefusedBeforeAnyRender(t *testing.T) {
	r := newRig(t)
	good := r.sign(t, body)
	otherPriv, _, _ := caller.GenerateKey()
	other, _ := caller.NewSigner(otherPriv)
	other.Now = func() time.Time { return r.now }
	wrongKey, _ := other.Sign(aud, "POST", "/render", []byte(body))
	otherAud, _ := r.signer.Sign("http://elsewhere/render", "POST", "/render", []byte(body))
	otherSubject, _ := r.signer.SignRaw(aud, "idp-host", "j1", r.now.Unix(), r.now.Unix()+30, caller.Digest("POST", "/render", []byte(body)))
	for name, tc := range map[string]struct{ body, auth string }{
		"unsigned":         {body, ""},
		"garbage":          {body, "abc.def.ghi"},
		"another key":      {body, wrongKey},
		"another audience": {body, otherAud},
		"another caller":   {body, otherSubject},
		"another body":     {`{"url":"http://169.254.169.254/"}`, good},
	} {
		if code, out := r.post(t, tc.body, tc.auth); code != 401 || strings.Contains(out, "html") {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	// expired
	old := r.sign(t, body)
	r.now = r.now.Add(10 * time.Minute)
	if code, _ := r.post(t, body, old); code != 401 {
		t.Errorf("expired: %d", code)
	}
	r.now = r.now.Add(-10 * time.Minute)
	// replayed: the first use is the only use
	if code, _ := r.post(t, body, good); code != 200 {
		t.Fatalf("the good one: %d", code)
	}
	if code, _ := r.post(t, body, good); code != 401 {
		t.Errorf("replayed: %d", code)
	}
	if n := r.f.calls.Load(); n != 1 {
		t.Errorf("the renderer was asked %d times, want once (the good request)", n)
	}
}

func TestReasonCodesAndStatuses(t *testing.T) {
	for code, want := range map[string]int{render.InvalidRequest: 400, render.NotAllowed: 422, render.RenderBusy: 503, render.RenderTimeout: 504, render.RenderFailed: 502, render.BlockedBySite: 502} {
		r := newRig(t)
		r.f.res, r.f.err = nil, &render.Error{Code: code, Msg: "m"}
		status, out := r.post(t, body, r.sign(t, body))
		if status != want || !strings.Contains(out, `"code":"`+code+`"`) {
			t.Errorf("%s: %d %s", code, status, out)
		}
	}
}

func TestMalformedBodiesAndWrongPathsAndMethods(t *testing.T) {
	r := newRig(t)
	for _, b := range []string{`not json`, `{"url":"x","extra":1}`, `{"url":"x"} {"url":"y"}`, ``} {
		if code, out := r.post(t, b, r.sign(t, b)); code != 400 || !strings.Contains(out, "invalid_request") {
			t.Errorf("%q: %d %s", b, code, out)
		}
	}
	resp, _ := http.Get(r.srv.URL + "/render")
	if resp.StatusCode != 405 {
		t.Errorf("GET: %d", resp.StatusCode)
	}
	resp, _ = http.Post(r.srv.URL+"/other", "application/json", strings.NewReader(body))
	if resp.StatusCode != 404 {
		t.Errorf("/other: %d", resp.StatusCode)
	}
	big := `{"url":"` + strings.Repeat("a", MaxBody) + `"}`
	if code, _ := r.post(t, big, r.sign(t, big)); code != 413 {
		t.Errorf("a large body: %d", code)
	}
	if r.f.calls.Load() != 0 {
		t.Error("the renderer was asked for a malformed request")
	}
}
