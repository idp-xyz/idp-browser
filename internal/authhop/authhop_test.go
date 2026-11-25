package authhop

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"idp-browser/internal/proxy"
)

// The hop adds the render's credential to what the browser sends, and the proxy behind it accepts that and nothing else.
func TestTheHopCarriesTheRendersCredentialForConnectAndForPlainRequests(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin saw proxy-auth=%q", r.Header.Get("Proxy-Authorization"))
	}))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")
	audit := &lines{}
	reg := &proxy.Registry{}
	px := httptest.NewServer(&proxy.Proxy{Registry: reg, TestOrigins: map[string]bool{host: true}, Audit: audit})
	defer px.Close()
	if err := reg.Register("r1", []byte(strings.Repeat("t", 32)), time.Minute, proxy.Limits{}); err != nil {
		t.Fatal(err)
	}
	h, err := Start(strings.TrimPrefix(px.URL, "http://"), "r1", strings.Repeat("t", 32), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// plain: the browser sends an absolute URI, with no credential
	c, _ := net.Dial("tcp", h.Addr())
	fmt.Fprintf(c, "GET %s/x?q=1 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", origin.URL, host)
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "200 OK") || !strings.Contains(string(b), `origin saw proxy-auth=""`) {
		t.Errorf("plain: %q", b)
	}
	// CONNECT
	c, _ = net.Dial("tcp", h.Addr())
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v %v", resp, err)
	}
	fmt.Fprintf(c, "GET /y HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	b, _ = io.ReadAll(br)
	if !strings.Contains(string(b), "origin saw") {
		t.Errorf("tunnel: %q", b)
	}
	// a credential the browser sends itself is replaced, not trusted
	c, _ = net.Dial("tcp", h.Addr())
	fmt.Fprintf(c, "GET %s/z HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nConnection: close\r\n\r\n", origin.URL, host)
	if b, _ = io.ReadAll(c); !strings.Contains(string(b), "200 OK") {
		t.Errorf("own credential: %q", b)
	}
	for _, e := range audit.get() {
		if e.Render != "r1" || e.Decision != "allow" {
			t.Errorf("audit %v", e)
		}
	}
	if len(audit.get()) != 3 {
		t.Errorf("%d audit lines", len(audit.get()))
	}
	// without the hop the same proxy refuses
	if resp, err := http.Get(px.URL); err == nil && resp.StatusCode != 407 {
		t.Errorf("the proxy without a credential: %d", resp.StatusCode)
	}
}

type lines struct{ es []proxy.Entry }

func (l *lines) Audit(e proxy.Entry) { l.es = append(l.es, e) }
func (l *lines) get() []proxy.Entry  { time.Sleep(50 * time.Millisecond); return l.es }
