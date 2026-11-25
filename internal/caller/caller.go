// Package caller is the signature idp-web puts on every render request, and the check idp-browser makes before it does
// anything for it (ADR-0001 D8).
//
// It is the platform's caller assertion (idp-mcp ADR-0001 D44, idp-web internal/mcp/assertion.go) in the same form: a
// compact JWS, ES256, typ idp-caller+jwt, kid the RFC 7638 thumbprint of the public key, claims aud (this endpoint),
// sub (the caller), iat, exp, jti and req (a digest of the request). What differs is the signer and the digest. The signer
// is idp-web itself, not the gateway, because the render hop is idp-web to idp-browser and does not pass through the
// gateway. The digest is over the HTTP request, not over an MCP method: sha256 of
//
//	METHOD "\n" PATH "\n" BODY
//
// with the body exactly as sent, so that a signature cannot be moved to another URL or another page. It travels as
// "Authorization: Bearer <jws>".
//
// Only one caller identity is accepted: the verifier holds the public keys and one subject (idp-web), and an assertion
// that verifies but names another subject is refused.
package caller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

var maxSeen = 65536 // replay table size; a variable for the test

const (
	assertionType = "idp-caller+jwt"
	// Skew is how far the two clocks may differ.
	Skew = 30 * time.Second
	// MaxTTL is the longest life an assertion may claim; idp-web signs for 30 seconds.
	MaxTTL       = 2 * time.Minute
	maxAssertion = 4096
)

// ErrAssertion: the request carries no assertion this server accepts. The reason goes to the log, not to the caller.
var ErrAssertion = errors.New("the caller assertion is missing or invalid")

// Digest is what the signer signs about a request.
func Digest(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method + "\n" + path + "\n"))
	h.Write(body)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func keyID(pub *ecdsa.PublicKey) (string, error) {
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil || len(raw) != 65 {
		return "", errors.New("not an uncompressed P-256 point")
	}
	enc := base64.RawURLEncoding.EncodeToString
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + enc(raw[1:33]) + `","y":"` + enc(raw[33:]) + `"}`))
	return enc(sum[:]), nil
}

type claims struct {
	Audience string `json:"aud"`
	Issued   int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	ID       string `json:"jti"`
	Subject  string `json:"sub"`
	Request  string `json:"req"`
}

// Signer makes assertions. idp-web has one; here it is what the tests and the vectors use.
type Signer struct {
	key     *ecdsa.PrivateKey
	kid     string
	Subject string        // default idp-web
	TTL     time.Duration // default 30 s
	Now     func() time.Time
}

// NewSigner reads a P-256 private key (PEM, PKCS#8 or SEC1).
func NewSigner(pemBytes []byte) (*Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		if key, ok = k.(*ecdsa.PrivateKey); !ok {
			return nil, errors.New("the key is not an EC key")
		}
	} else if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		return nil, errors.New("not a PKCS#8 or SEC1 private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("the key is not on P-256")
	}
	kid, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{key: key, kid: kid, Subject: "idp-web", TTL: 30 * time.Second, Now: time.Now}, nil
}

// GenerateKey makes a P-256 key pair as PEM (private PKCS#8, public PKIX), for tests and for the operator's first set-up.
func GenerateKey() (privPEM, pubPEM []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), nil
}

// Sign returns the assertion for one request to audience.
func (s *Signer) Sign(audience, method, path string, body []byte) (string, error) {
	now := s.Now()
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	return s.sign(claims{Audience: audience, Issued: now.Unix(), Expires: now.Add(s.TTL).Unix(), ID: base64.RawURLEncoding.EncodeToString(id),
		Subject: s.Subject, Request: Digest(method, path, body)})
}

func (s *Signer) sign(c claims) (string, error) {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": s.kid, "typ": assertionType})
	p, _ := json.Marshal(c)
	signing := enc(h) + "." + enc(p)
	sum := sha256.Sum256([]byte(signing))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return signing + "." + enc(sig), nil
}

// SignRaw signs arbitrary claims; for the tests that make assertions a correct signer would not.
func (s *Signer) SignRaw(aud, sub, jti string, iat, exp int64, req string) (string, error) {
	return s.sign(claims{Audience: aud, Issued: iat, Expires: exp, ID: jti, Subject: sub, Request: req})
}

// Verifier checks assertions.
type Verifier struct {
	keys     map[string]*ecdsa.PublicKey
	audience string
	subject  string
	now      func() time.Time

	mu   sync.Mutex
	seen map[string]int64
}

// NewVerifier reads one or more PEM public keys (PKIX, P-256). audience is this endpoint, the URL idp-web calls
// (for example http://idp-browser.idp-browser.svc.cluster.local:8590/render); subject is the one caller accepted.
func NewVerifier(pemBytes []byte, audience, subject string) (*Verifier, error) {
	if audience == "" || subject == "" {
		return nil, errors.New("no audience or no subject")
	}
	v := &Verifier{keys: map[string]*ecdsa.PublicKey{}, audience: audience, subject: subject, now: time.Now, seen: map[string]int64{}}
	for rest := pemBytes; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("not a PKIX public key: %w", err)
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("the key is not an EC key on P-256")
		}
		kid, err := keyID(pub)
		if err != nil {
			return nil, err
		}
		v.keys[kid] = pub
	}
	if len(v.keys) == 0 {
		return nil, errors.New("no public key found")
	}
	return v, nil
}

// SetClock replaces the clock (tests and vectors).
func (v *Verifier) SetClock(now func() time.Time) { v.now = now }

// KeyIDs of the accepted keys, for the operator's log.
func (v *Verifier) KeyIDs() []string {
	out := make([]string, 0, len(v.keys))
	for k := range v.keys {
		out = append(out, k)
	}
	return out
}

// Verify checks that idp-web signed assertion for this endpoint and for exactly this request, that it has not
// expired, and that it was not presented before. The error says why not (for the log).
func (v *Verifier) Verify(assertion, method, path string, body []byte) error {
	if assertion == "" {
		return errors.New("no assertion")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || len(assertion) > maxAssertion {
		return errors.New("not a compact JWS")
	}
	dec := base64.RawURLEncoding.DecodeString
	hraw, err1 := dec(parts[0])
	craw, err2 := dec(parts[1])
	sig, err3 := dec(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return errors.New("not base64url")
	}
	var h struct{ Alg, Typ, Kid string }
	var hh map[string]string
	if json.Unmarshal(hraw, &hh) != nil {
		return errors.New("header is not an object")
	}
	h.Alg, h.Typ, h.Kid = hh["alg"], hh["typ"], hh["kid"]
	if h.Alg != "ES256" || h.Typ != assertionType {
		return fmt.Errorf("header alg %q typ %q", h.Alg, h.Typ)
	}
	key := v.keys[h.Kid]
	if key == nil {
		return fmt.Errorf("signed with a key this server does not hold (kid %q)", h.Kid)
	}
	if len(sig) != 64 {
		return errors.New("signature length")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("signature does not verify")
	}
	var c claims
	if err := json.NewDecoder(bytes.NewReader(craw)).Decode(&c); err != nil {
		return errors.New("claims are not an object")
	}
	now := v.now()
	switch {
	case c.Audience != v.audience:
		return fmt.Errorf("made for %q, not for %s", c.Audience, v.audience)
	case c.Expires == 0 || now.After(time.Unix(c.Expires, 0).Add(Skew)):
		return errors.New("expired")
	case c.Issued == 0 || time.Unix(c.Issued, 0).After(now.Add(Skew)):
		return errors.New("issued in the future")
	case c.Expires < c.Issued || c.Expires-c.Issued > int64(MaxTTL/time.Second):
		return errors.New("valid for too long")
	case c.ID == "":
		return errors.New("no id")
	case c.Subject != v.subject:
		return fmt.Errorf("the caller is %q, only %q is accepted", c.Subject, v.subject)
	case c.Request != Digest(method, path, body):
		return errors.New("made for another request")
	}
	if !v.first(c.ID, c.Expires+int64(Skew/time.Second), now.Unix()) {
		return errors.New("presented before")
	}
	return nil
}

// first records id until forget and reports whether it was new. A full table of unexpired ids refuses (fails closed).
func (v *Verifier) first(id string, forget, now int64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.seen[id]; dup {
		return false
	}
	if len(v.seen) >= maxSeen/2 {
		for k, t := range v.seen {
			if t < now {
				delete(v.seen, k)
			}
		}
		if len(v.seen) >= maxSeen {
			return false
		}
	}
	v.seen[id] = forget
	return true
}
