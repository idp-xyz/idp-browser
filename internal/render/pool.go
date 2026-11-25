// Package render is the pool of headless Chromium processes and the one operation they offer: render a public page and
// give back its DOM (ADR-0001 D4, D5, D9).
//
// A process renders one page at a time, in a browser context created for that render alone (no cookie, cache, storage
// or permission of any other render), and the context is disposed when the render ends. A process is replaced after
// RecycleAfter renders, above a memory threshold, and after any render that did not end normally.
package render

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

// Pool is the render pool.
type Pool struct {
	cfg   Config
	log   *slog.Logger
	px    *proxyClient
	free  chan *slot
	slots []*slot

	closed atomic.Bool
	meter  memMeter
	Stats  Stats
}

// Stats are the counters of /metrics.
type Stats struct {
	mu       sync.Mutex
	Outcomes map[string]int64 // by "ok" or a reason code
	Starts   atomic.Int64     // browser processes started
	Recycles atomic.Int64     // processes replaced, whatever the reason
	Active   atomic.Int64     // renders in progress
	Skipped  atomic.Int64     // requests not made because of their type (IDP_BROWSER_BLOCK_TYPES)
}

func (s *Stats) outcome(code string) {
	s.mu.Lock()
	if s.Outcomes == nil {
		s.Outcomes = map[string]int64{}
	}
	s.Outcomes[code]++
	s.mu.Unlock()
}

// Snapshot of the outcome counters.
func (s *Stats) Snapshot() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.Outcomes))
	for k, v := range s.Outcomes {
		out[k] = v
	}
	return out
}

type slot struct {
	idx     int
	gen     int
	pool    *Pool
	bctx    context.Context // the browser's context: it lives as long as the process
	bcancel context.CancelFunc
	proc    *os.Process
	dir     string
	renders int   // renders by this process
	baseMem int64 // the memory of its tree at its first render (mem.go): the recycle is by growth over it
}

// New validates the configuration and makes the pool. No browser is started until the first render.
func New(cfg Config) (*Pool, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if err := os.MkdirAll(cfg.ProfileDir, 0o700); err != nil {
		return nil, err
	}
	// profiles left by a process that was killed with its service
	if old, _ := filepath.Glob(filepath.Join(cfg.ProfileDir, "p*-*")); len(old) > 0 {
		for _, d := range old {
			_ = os.RemoveAll(d)
		}
	}
	p := &Pool{meter: systemMeter(), cfg: cfg, log: cfg.Log, px: newProxyClient(cfg.ProxyAdmin, cfg.ProxyAdminKey), free: make(chan *slot, cfg.Pool)}
	for i := 0; i < cfg.Pool; i++ {
		s := &slot{idx: i, pool: p}
		p.slots = append(p.slots, s)
		p.free <- s
	}
	return p, nil
}

// Config returns the pool's configuration (with the defaults of the caller's choosing already in it).
func (p *Pool) Config() Config { return p.cfg }

// Ready says whether a render could be made: the browser executable is there and the proxy's admin port answers.
func (p *Pool) Ready(ctx context.Context) error {
	if _, err := os.Stat(p.cfg.ChromePath); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return p.px.ping(ctx)
}

// Close stops every browser. Renders in progress end as render_failed.
func (p *Pool) Close() {
	p.closed.Store(true)
	for _, s := range p.slots {
		s.stop()
	}
}

// Processes is the number of browser processes running now (for tests and /metrics).
func (p *Pool) Processes() int {
	n := 0
	for _, s := range p.slots {
		if s.proc != nil {
			n++
		}
	}
	return n
}

// PIDs of the running browser processes; they are read when no render is in progress.
func (p *Pool) PIDs() []int {
	var out []int
	for _, s := range p.slots {
		if s.proc != nil {
			out = append(out, s.proc.Pid)
		}
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// start launches the browser of the slot.
func (s *slot) start() error {
	cfg := &s.pool.cfg
	s.gen++
	s.dir = filepath.Join(cfg.ProfileDir, fmt.Sprintf("p%d-%d", s.idx, s.gen))
	for _, sub := range []string{"", "/config", "/cache", "/tmp"} {
		if err := os.MkdirAll(s.dir+sub, 0o700); err != nil {
			return err
		}
	}
	actx, acancel := chromedp.NewExecAllocator(context.Background(), cfg.chromeOptions(s.dir)...)
	bctx, bcancel := chromedp.NewContext(actx)
	s.bcancel = func() { bcancel(); acancel() }
	s.bctx = bctx
	// the first call starts the process; it carries no timeout of its own, because a timeout on it would stop the browser
	errc := make(chan error, 1)
	go func() {
		_, err := chromedp.CallBrowser(bctx, browser.GetVersion, cdp.Empty{})
		errc <- err
	}()
	select {
	case err := <-errc:
		if err != nil {
			s.stop()
			return fmt.Errorf("starting the browser: %w", err)
		}
	case <-time.After(30 * time.Second):
		s.stop()
		return fmt.Errorf("starting the browser: no answer in 30 s")
	}
	s.proc = chromedp.FromContext(bctx).Browser.Process()
	s.renders = 0
	s.baseMem = 0
	s.pool.Stats.Starts.Add(1)
	return nil
}

// stop kills the process and everything below it and removes its profile.
func (s *slot) stop() {
	if s.bctx == nil {
		return
	}
	if s.proc != nil {
		killTree(s.proc.Pid)
	}
	s.bcancel()
	s.bctx, s.bcancel, s.proc = nil, nil, nil
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
		s.dir = ""
	}
	s.pool.Stats.Recycles.Add(1)
}

// killTree kills pid and its descendants. A renderer stuck in a script does not notice that its browser is gone, so
// the browser's death is not enough.
func killTree(pid int) {
	for _, p := range append(descendants(pid), pid) {
		_ = syscall.Kill(p, syscall.SIGKILL)
	}
}

// acquire takes a free slot, waiting at most QueueWait.
func (p *Pool) acquire(ctx context.Context) (*slot, error) {
	select {
	case s := <-p.free:
		return s, nil
	default:
	}
	if p.cfg.QueueWait <= 0 {
		return nil, fail(RenderBusy, "all %d browsers are rendering", p.cfg.Pool)
	}
	t := time.NewTimer(p.cfg.QueueWait)
	defer t.Stop()
	select {
	case s := <-p.free:
		return s, nil
	case <-t.C:
		return nil, fail(RenderBusy, "all %d browsers are rendering", p.cfg.Pool)
	case <-ctx.Done():
		return nil, fail(RenderFailed, "the request ended while it waited for a browser")
	}
}

// release returns the slot, replacing its process first when it must be.
func (p *Pool) release(s *slot, tainted bool) {
	s.renders++
	switch {
	case s.proc == nil:
	case p.closed.Load() || tainted:
		s.stop()
	case s.renders >= p.cfg.RecycleAfter:
		s.stop()
	case p.memoryRecycle(s):
		p.log.Info("browser recycled", "reason", "memory")
		s.stop()
	}
	p.free <- s
}

// memoryRecycle: the tree of the slot's process has grown by more than RecycleMemoryMB over the baseline of its first render.
func (p *Pool) memoryRecycle(s *slot) bool {
	return s.proc != nil && grewBeyond(s.baseMem, p.meter.tree(s.proc.Pid), int64(p.cfg.RecycleMemoryMB))
}
