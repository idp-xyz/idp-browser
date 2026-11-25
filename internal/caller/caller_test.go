package caller

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate testdata/caller-assertion-v1.json")

const aud = "http://idp-browser.idp-browser.svc.cluster.local:8590/render"

type rig struct {
	s   *Signer
	v   *Verifier
	t0  time.Time
	now time.Time
}

func newRig(t *testing.T) *rig {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(pub, aud, "idp-web")
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{s: s, v: v, t0: time.Unix(1795089600, 0)}
	r.now = r.t0
	s.Now = func() time.Time { return r.t0 }
	v.SetClock(func() time.Time { return r.now })
	return r
}

var body = []byte(`{"url":"https://example.com/","timeoutMs":15000}`)

func TestAGoodAssertionVerifiesOnceAndOnlyOnce(t *testing.T) {
	r := newRig(t)
	a, err := r.s.Sign(aud, "POST", "/render", body)
	if err != nil {
		t.Fatal(err)
	}
	r.now = r.t0.Add(5 * time.Second)
	if err := r.v.Verify(a, "POST", "/render", body); err != nil {
		t.Fatal(err)
	}
	if err := r.v.Verify(a, "POST", "/render", body); err == nil || !strings.Contains(err.Error(), "presented before") {
		t.Errorf("replay: %v", err)
	}
}

func TestEveryWayToBeWrongIsRefused(t *testing.T) {
	r := newRig(t)
	other := newRig(t)
	sign := func(s *Signer, a, sub, jti string, iat, exp int64, req string) string {
		x, err := s.SignRaw(a, sub, jti, iat, exp, req)
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	t0 := r.t0.Unix()
	good := Digest("POST", "/render", body)
	good1, _ := r.s.Sign(aud, "POST", "/render", body)
	parts := strings.Split(good1, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"`+aud+`","iat":`+itoa(t0)+`,"exp":`+itoa(t0+3600)+`,"jti":"x","sub":"idp-web","req":"`+good+`"}`)) + "." + parts[2]
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"idp-caller+jwt"}`))
	for _, tc := range []struct {
		name, assertion, method, path string
		body                          []byte
		at                            time.Time
		want                          string
	}{
		{"no assertion", "", "POST", "/render", body, r.t0, "no assertion"},
		{"not a JWS", "abc", "POST", "/render", body, r.t0, "compact JWS"},
		{"alg none", noneHeader + "." + parts[1] + ".", "POST", "/render", body, r.t0, "header alg"},
		{"claims changed after signing", tampered, "POST", "/render", body, r.t0, "signature does not verify"},
		{"another key (unknown kid)", sign(other.s, aud, "idp-web", "a1", t0, t0+30, good), "POST", "/render", body, r.t0, "does not hold"},
		{"another audience", sign(r.s, "http://elsewhere/render", "idp-web", "a2", t0, t0+30, good), "POST", "/render", body, r.t0, "made for"},
		{"another caller", sign(r.s, aud, "idp-host", "a3", t0, t0+30, good), "POST", "/render", body, r.t0, "only \"idp-web\""},
		{"no caller", sign(r.s, aud, "", "a3b", t0, t0+30, good), "POST", "/render", body, r.t0, "only \"idp-web\""},
		{"expired", sign(r.s, aud, "idp-web", "a4", t0, t0+30, good), "POST", "/render", body, r.t0.Add(30*time.Second + Skew + time.Second), "expired"},
		{"from the future", sign(r.s, aud, "idp-web", "a5", t0+3600, t0+3630, good), "POST", "/render", body, r.t0, "future"},
		{"valid for an hour", sign(r.s, aud, "idp-web", "a6", t0, t0+3600, good), "POST", "/render", body, r.t0, "too long"},
		{"no id", sign(r.s, aud, "idp-web", "", t0, t0+30, good), "POST", "/render", body, r.t0, "no id"},
		{"another body", sign(r.s, aud, "idp-web", "a7", t0, t0+30, good), "POST", "/render", []byte(`{"url":"http://169.254.169.254/"}`), r.t0, "another request"},
		{"another path", sign(r.s, aud, "idp-web", "a8", t0, t0+30, good), "POST", "/other", body, r.t0, "another request"},
		{"another method", sign(r.s, aud, "idp-web", "a9", t0, t0+30, good), "PUT", "/render", body, r.t0, "another request"},
	} {
		r.now = tc.at
		err := r.v.Verify(tc.assertion, tc.method, tc.path, tc.body)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// A key is rotated by holding two: an assertion of either verifies, one of a third key does not.
func TestAKeyIsRotatedByHoldingTwo(t *testing.T) {
	priv1, pub1, _ := GenerateKey()
	priv2, pub2, _ := GenerateKey()
	priv3, _, _ := GenerateKey()
	v, err := NewVerifier(append(append([]byte{}, pub1...), pub2...), aud, "idp-web")
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range [][]byte{priv1, priv2, priv3} {
		s, _ := NewSigner(k)
		a, _ := s.Sign(aud, "POST", "/render", body)
		err := v.Verify(a, "POST", "/render", body)
		if (i < 2) != (err == nil) {
			t.Errorf("key %d: %v", i, err)
		}
	}
}

func TestAFullReplayTableRefusesInsteadOfForgetting(t *testing.T) {
	old := maxSeen
	maxSeen = 256
	defer func() { maxSeen = old }()
	r := newRig(t)
	exp := r.t0.Add(time.Minute).Unix()
	for i := 0; i < maxSeen; i++ {
		if !r.v.first(string(rune(i))+"x"+itoa(int64(i)), exp, r.t0.Unix()) {
			t.Fatalf("id %d refused early", i)
		}
	}
	if r.v.first("one more", exp, r.t0.Unix()) {
		t.Error("a full table of live ids accepted another")
	}
}

// The vectors pin the format idp-web's signer must produce (L1-3 copies the file and verifies it): the digest, the
// header, the claims, the verifier's decisions at a fixed time.
type vectorFile struct {
	Format   string  `json:"format"`
	Audience string  `json:"audience"`
	Subject  string  `json:"subject"`
	Keys     []vKey  `json:"keys"`
	Cases    []vCase `json:"cases"`
}
type vKey struct{ Name, Kid, PEM string }
type vCase struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Steps       []vStep `json:"steps"`
}
type vStep struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Body      string `json:"body"`
	Assertion string `json:"assertion"`
	Now       string `json:"now"`
	Digest    string `json:"digest"`
	Accept    bool   `json:"accept"`
	Reason    string `json:"reason,omitempty"`
}

func TestVectors(t *testing.T) {
	const file = "testdata/caller-assertion-v1.json"
	if *update {
		generateVectors(t, file)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	var pems []byte
	for _, k := range vf.Keys[:1] { // the first key is the one idp-web's key; the second is a stranger
		pems = append(pems, k.PEM...)
	}
	for _, c := range vf.Cases {
		v, err := NewVerifier(pems, vf.Audience, vf.Subject)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range c.Steps {
			now, _ := time.Parse(time.RFC3339, s.Now)
			v.SetClock(func() time.Time { return now })
			if want := Digest(s.Method, s.Path, []byte(s.Body)); want != s.Digest {
				t.Errorf("%s step %d: digest %s, vector says %s", c.Name, i, want, s.Digest)
			}
			err := v.Verify(s.Assertion, s.Method, s.Path, []byte(s.Body))
			if (err == nil) != s.Accept {
				t.Errorf("%s step %d: accept=%v, err %v", c.Name, i, s.Accept, err)
			}
			if err != nil && !strings.Contains(err.Error(), s.Reason) {
				t.Errorf("%s step %d: %q, want it to contain %q", c.Name, i, err, s.Reason)
			}
		}
	}
}

func generateVectors(t *testing.T, file string) {
	priv, pub, _ := GenerateKey()
	privX, pubX, _ := GenerateKey()
	s, _ := NewSigner(priv)
	x, _ := NewSigner(privX)
	t0 := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return t0 }
	x.Now = s.Now
	kid := func(p []byte) string { v, _ := NewVerifier(p, "a", "b"); return v.KeyIDs()[0] }
	vf := vectorFile{Format: "idp.telos.browser-caller-assertion-vectors/v1", Audience: aud, Subject: "idp-web",
		Keys: []vKey{{"idp-web", kid(pub), string(pub)}, {"stranger", kid(pubX), string(pubX)}}}
	bodyS := string(body)
	d := Digest("POST", "/render", body)
	step := func(a string, at time.Time, method, path, b string, accept bool, reason string) vStep {
		return vStep{Method: method, Path: path, Body: b, Assertion: a, Now: at.Format(time.RFC3339), Digest: Digest(method, path, []byte(b)), Accept: accept, Reason: reason}
	}
	good, _ := s.Sign(aud, "POST", "/render", body)
	raw := func(sg *Signer, a, sub, jti string, iat, exp int64) string {
		z, _ := sg.SignRaw(a, sub, jti, iat, exp, d)
		return z
	}
	vf.Cases = []vCase{
		{"good", "What idp-web signs for a render, presented ten seconds later.", []vStep{step(good, t0.Add(10*time.Second), "POST", "/render", bodyS, true, "")}},
		{"replayed", "The same assertion presented twice: the second is refused.", []vStep{step(good, t0.Add(10*time.Second), "POST", "/render", bodyS, true, ""), step(good, t0.Add(11*time.Second), "POST", "/render", bodyS, false, "presented before")}},
		{"expired", "Presented after the lifetime and the allowed skew.", []vStep{step(good, t0.Add(30*time.Second+Skew+time.Second), "POST", "/render", bodyS, false, "expired")}},
		{"another body", "The signature was made for another page.", []vStep{step(good, t0.Add(time.Second), "POST", "/render", `{"url":"http://169.254.169.254/"}`, false, "another request")}},
		{"another key", "Signed by a key the verifier does not hold.", []vStep{step(raw(x, aud, "idp-web", "v1", t0.Unix(), t0.Unix()+30), t0.Add(time.Second), "POST", "/render", bodyS, false, "does not hold")}},
		{"another caller", "Signed by the right key for another subject.", []vStep{step(raw(s, aud, "idp-host", "v2", t0.Unix(), t0.Unix()+30), t0.Add(time.Second), "POST", "/render", bodyS, false, "only")}},
		{"another audience", "Made for another endpoint.", []vStep{step(raw(s, "http://other/render", "idp-web", "v3", t0.Unix(), t0.Unix()+30), t0.Add(time.Second), "POST", "/render", bodyS, false, "made for")}},
		{"too long", "Valid for an hour: not something idp-web signs.", []vStep{step(raw(s, aud, "idp-web", "v4", t0.Unix(), t0.Unix()+3600), t0.Add(time.Second), "POST", "/render", bodyS, false, "too long")}},
	}
	out, _ := json.MarshalIndent(vf, "", "  ")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
