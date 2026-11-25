// Package authhop is the hop between a browser and the egress proxy that carries the render's credential.
//
// Chromium takes a proxy as an address; the credential has to be given in answer to a 407, which needs a hook in every
// target that makes requests (frames, workers) and is easy to leave out of one. So the browser's proxy for a render is
// a listener on 127.0.0.1 that belongs to that render, and it adds the Proxy-Authorization header to everything it
// forwards to the egress proxy. The browser never holds the token, a page cannot read it, and no request can go
// without it. The hop decides nothing: it is not a policy point, and the proxy checks every request as before.
package authhop

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Hop is a loopback listener that forwards to the proxy with a credential. One per render.
type Hop struct {
	ln       net.Listener
	upstream string
	auth     string
	deadline time.Time

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// Start listens on 127.0.0.1 (a random port) and forwards to the proxy at upstream ("host:port"), adding the credential.
// Connections are cut at deadline.
func Start(upstream, id, token string, deadline time.Time) (*Hop, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := &Hop{ln: ln, upstream: upstream, auth: "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+token)), deadline: deadline, conns: map[net.Conn]struct{}{}}
	h.wg.Add(1)
	go h.accept()
	return h, nil
}

// Addr is the host:port the browser's proxy setting names.
func (h *Hop) Addr() string { return h.ln.Addr().String() }

// Close stops the listener and cuts every connection.
func (h *Hop) Close() {
	h.mu.Lock()
	h.closed = true
	for c := range h.conns {
		c.Close()
	}
	h.mu.Unlock()
	h.ln.Close()
	h.wg.Wait()
}

func (h *Hop) track(c net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		c.Close()
		return false
	}
	h.conns[c] = struct{}{}
	return true
}

func (h *Hop) untrack(c net.Conn) {
	h.mu.Lock()
	delete(h.conns, c)
	h.mu.Unlock()
	c.Close()
}

func (h *Hop) accept() {
	defer h.wg.Done()
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		if !h.track(c) {
			continue
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer h.untrack(c)
			_ = c.SetDeadline(h.deadline)
			h.serve(c)
		}()
	}
}

func (h *Hop) serve(c net.Conn) {
	br := bufio.NewReader(c)
	var up net.Conn
	var upr *bufio.Reader
	defer func() {
		if up != nil {
			h.untrack(up)
		}
	}()
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.Header.Set("Proxy-Authorization", h.auth)
		if up == nil {
			u, err := net.DialTimeout("tcp", h.upstream, 10*time.Second)
			if err != nil || !h.track(u) {
				io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				return
			}
			_ = u.SetDeadline(h.deadline)
			up, upr = u, bufio.NewReader(u)
		}
		if req.Method == http.MethodConnect {
			h.tunnel(c, br, up, upr, req)
			return
		}
		if err := req.WriteProxy(up); err != nil {
			return
		}
		resp, err := http.ReadResponse(upr, req)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		err = resp.Write(c)
		resp.Body.Close()
		if err != nil || resp.Close || req.Close {
			return
		}
	}
}

// tunnel forwards a CONNECT: the proxy's answer goes back as it is, and when it is a 200 the two sides are joined.
func (h *Hop) tunnel(c net.Conn, br *bufio.Reader, up net.Conn, upr *bufio.Reader, req *http.Request) {
	if err := req.Write(up); err != nil {
		return
	}
	resp, err := http.ReadResponse(upr, req)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	if resp.StatusCode != http.StatusOK {
		resp.Close = true
		_ = resp.Write(c)
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upr); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}
