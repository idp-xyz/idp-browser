package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Limits are what one render may use through the proxy (ADR-0001 D6). Zero values mean the proxy's own defaults.
type Limits struct {
	MaxRequests      int   // CONNECT tunnels and plain-HTTP requests the proxy sees (default 300)
	MaxBytes         int64 // both directions of all of them (default 20 MiB)
	MaxResponseBytes int64 // from the origin, per plain response and per tunnel (default 10 MiB)
}

// DefaultLimits are the limits of the plan (section 3 and D6 of the ADR).
var DefaultLimits = Limits{MaxRequests: 300, MaxBytes: 20 << 20, MaxResponseBytes: 10 << 20}

func (l Limits) orDefault(d Limits) Limits {
	if l.MaxRequests <= 0 {
		l.MaxRequests = d.MaxRequests
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = d.MaxResponseBytes
	}
	return l
}

// clamp lowers l to the ceiling c: a render asks for less than the operator allows, never more.
func (l Limits) clamp(c Limits) Limits {
	l = l.orDefault(c)
	if l.MaxRequests > c.MaxRequests {
		l.MaxRequests = c.MaxRequests
	}
	if l.MaxBytes > c.MaxBytes {
		l.MaxBytes = c.MaxBytes
	}
	if l.MaxResponseBytes > c.MaxResponseBytes {
		l.MaxResponseBytes = c.MaxResponseBytes
	}
	return l
}

// Refusal is a request the proxy refused, as the renderer is told (host and reason, never a path).
type Refusal struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Reason string `json:"reason"`
}

// Usage is what a render used, returned when it is finished.
type Usage struct {
	Requests int   `json:"requests"` // admitted
	Blocked  int   `json:"blocked"`  // refused after the credential was accepted
	BytesIn  int64 `json:"bytesIn"`  // from the origins
	BytesOut int64 `json:"bytesOut"` // to the origins
	// Limit is the first limit the render hit: requests, bytes or response; empty when none.
	Limit string `json:"limit,omitempty"`
	// Refused lists the first distinct refusals (at most maxRefusals).
	Refused []Refusal `json:"refused,omitempty"`
}

const maxRefusals = 32

// Render is a registered render: the credential its browser uses and the budget it has. All methods are safe for
// concurrent use.
type Render struct {
	id       string
	tokenSum [sha256.Size]byte
	deadline time.Time
	limits   Limits
	ctx      context.Context // done at the deadline, at Finish and at a hit limit: every tunnel of the render ends with it
	cancel   context.CancelFunc

	requests atomic.Int64
	blocked  atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	mu      sync.Mutex
	limit   string
	refused []Refusal
}

// ID of the render, as the renderer chose it.
func (r *Render) ID() string { return r.id }

// Context is done when the render may no longer use the proxy.
func (r *Render) Context() context.Context { return r.ctx }

// admit counts one request and says whether the render may make it.
func (r *Render) admit() (bool, string) {
	if r.ctx.Err() != nil {
		if r.limitHit() == "bytes" {
			return false, "limit_bytes"
		}
		return false, "deadline"
	}
	if r.requests.Add(1) > int64(r.limits.MaxRequests) {
		r.requests.Add(-1)
		r.setLimit("requests")
		return false, "limit_requests"
	}
	return true, ""
}

// addBytes counts n bytes (in: from the origin) and reports false when the render's total is used up, which also ends
// every tunnel of the render.
func (r *Render) addBytes(n int, in bool) bool {
	var total int64
	if in {
		r.bytesIn.Add(int64(n))
	} else {
		r.bytesOut.Add(int64(n))
	}
	total = r.bytesIn.Load() + r.bytesOut.Load()
	if total > r.limits.MaxBytes {
		r.setLimit("bytes")
		r.cancel()
		return false
	}
	return true
}

func (r *Render) setLimit(l string) {
	r.mu.Lock()
	if r.limit == "" {
		r.limit = l
	}
	r.mu.Unlock()
}

func (r *Render) limitHit() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.limit
}

func (r *Render) refuse(host string, port int, reason string) {
	r.blocked.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.refused) < maxRefusals {
		f := Refusal{Host: host, Port: port, Reason: reason}
		for _, x := range r.refused {
			if x == f {
				return
			}
		}
		r.refused = append(r.refused, f)
	}
}

func (r *Render) usage() Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Usage{Requests: int(r.requests.Load()), Blocked: int(r.blocked.Load()), BytesIn: r.bytesIn.Load(), BytesOut: r.bytesOut.Load(),
		Limit: r.limit, Refused: append([]Refusal(nil), r.refused...)}
}

// Registry holds the live renders. A render exists from Register until Finish or its deadline; the proxy serves only
// requests that carry the id and the token of a live one.
type Registry struct {
	// Ceiling is the most any render may ask for (the proxy's configured limits).
	Ceiling Limits
	// Max is the most renders that may be live at once (default 256).
	Max int
	// MaxLife is the longest deadline a render may have (default 5 minutes).
	MaxLife time.Duration

	now    func() time.Time
	mu     sync.Mutex
	live   map[string]*Render
	closed map[string]time.Time // finished or expired ids: kept a little, so that a late request is told "expired", not "unknown"
}

// ErrRegistry is wrapped by every refusal of Register.
var ErrRegistry = errors.New("render not registered")

func (g *Registry) init() {
	if g.live == nil {
		g.live = map[string]*Render{}
		g.closed = map[string]time.Time{}
	}
	if g.now == nil {
		g.now = time.Now
	}
	if g.Max == 0 {
		g.Max = 256
	}
	if g.MaxLife == 0 {
		g.MaxLife = 5 * time.Minute
	}
	g.Ceiling = g.Ceiling.orDefault(DefaultLimits)
}

// Register makes a render live until now+life. The token must be at least 16 bytes (the renderer makes 32 random ones).
func (g *Registry) Register(id string, token []byte, life time.Duration, want Limits) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.init()
	if id == "" || len(id) > 64 || len(token) < 16 || life <= 0 || life > g.MaxLife {
		return errors.New("invalid render id, token or lifetime")
	}
	g.sweep()
	if _, dup := g.live[id]; dup {
		return errors.New("the render id is in use")
	}
	if len(g.live) >= g.Max {
		return errors.New("too many live renders")
	}
	ctx, cancel := context.WithDeadline(context.Background(), g.now().Add(life))
	g.live[id] = &Render{id: id, tokenSum: sha256.Sum256(token), deadline: g.now().Add(life), limits: want.clamp(g.Ceiling), ctx: ctx, cancel: cancel}
	return nil
}

// sweep forgets renders whose deadline passed more than a minute ago and ids closed more than ten minutes ago. g.mu held.
func (g *Registry) sweep() {
	now := g.now()
	for id, r := range g.live {
		if now.After(r.deadline.Add(time.Minute)) {
			r.cancel()
			delete(g.live, id)
			g.closed[id] = now
		}
	}
	for id, t := range g.closed {
		if now.Sub(t) > 10*time.Minute {
			delete(g.closed, id)
		}
	}
}

// Lookup finds the live render a credential names. The reason is one of no_credential, unknown_render, bad_token,
// expired.
func (g *Registry) Lookup(id string, token []byte) (*Render, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.init()
	if id == "" && len(token) == 0 {
		return nil, "no_credential"
	}
	r := g.live[id]
	if r == nil {
		if _, was := g.closed[id]; was {
			return nil, "expired"
		}
		return nil, "unknown_render"
	}
	sum := sha256.Sum256(token)
	if subtle.ConstantTimeCompare(sum[:], r.tokenSum[:]) != 1 {
		return nil, "bad_token"
	}
	if !g.now().Before(r.deadline) {
		return nil, "expired"
	}
	return r, ""
}

// Finish ends the render: its tunnels are closed, its token is dead, and what it used is returned.
func (g *Registry) Finish(id string) (Usage, bool) {
	g.mu.Lock()
	r := g.live[id]
	if r != nil {
		delete(g.live, id)
		g.closed[id] = g.now()
	}
	g.mu.Unlock()
	if r == nil {
		return Usage{}, false
	}
	r.cancel()
	return r.usage(), true
}

// Live is the number of live renders.
func (g *Registry) Live() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.init()
	return len(g.live)
}

// IDs of the live renders, for tests and the operator's metrics.
func (g *Registry) IDs() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for id := range g.live {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
