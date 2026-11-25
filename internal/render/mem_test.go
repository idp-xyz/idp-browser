package render

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const pgSize = 4096

// fixture writes a /proc of three processes (the browser, its zygote, a renderer) and returns its root.
type proc struct {
	pid, ppid       int
	comm            string
	resident, share int64 // pages, as statm has them
	anonKB          int64 // RssAnon of status; 0: the line is absent (a kernel without it)
}

func fixture(t *testing.T, ps []proc) memMeter {
	t.Helper()
	root := t.TempDir()
	for _, p := range ps {
		write(t, root, p)
	}
	return memMeter{root: root, pageSize: pgSize}
}

func write(t *testing.T, root string, p proc) {
	t.Helper()
	d := filepath.Join(root, fmt.Sprint(p.pid))
	_ = os.MkdirAll(d, 0o755)
	// comm may hold spaces and parentheses: the parent is read after the last ')'
	must(t, os.WriteFile(filepath.Join(d, "stat"), []byte(fmt.Sprintf("%d (%s) S %d 0 0 0 0\n", p.pid, p.comm, p.ppid)), 0o644))
	must(t, os.WriteFile(filepath.Join(d, "statm"), []byte(fmt.Sprintf("1000000 %d %d 1 0 5000 0\n", p.resident, p.share)), 0o644))
	status := "Name:\tx\nVmRSS:\t100 kB\n"
	if p.anonKB > 0 {
		status += fmt.Sprintf("RssAnon:\t%d kB\nRssFile:\t1 kB\n", p.anonKB)
	}
	must(t, os.WriteFile(filepath.Join(d, "status"), []byte(status), 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// pages in a MiB
func mib(n int64) int64 { return n << 20 / pgSize }

// Linux: RssAnon is there, and the libraries (resident, shared) do not count.
func TestMemoryWithAnonymousAccounting(t *testing.T) {
	m := fixture(t, []proc{
		{100, 1, "headless shell", mib(300), mib(200), 100 << 10}, // 100 MiB anonymous
		{101, 100, "chrome (zygote)", mib(250), mib(200), 50 << 10},
		{102, 101, "renderer", mib(400), mib(200), 300 << 10},
		{999, 1, "unrelated", mib(5000), 0, 5000 << 10}, // not in the tree
	})
	if got := m.tree(100); got != 450<<20 {
		t.Errorf("tree %d MiB, want 450", got>>20)
	}
}

// Linux without RssAnon (an older kernel): resident minus shared.
func TestMemoryWithSharedPagesOnly(t *testing.T) {
	m := fixture(t, []proc{
		{100, 1, "headless shell", mib(300), mib(200), 0},
		{101, 100, "zygote", mib(250), mib(200), 0},
		{102, 101, "renderer", mib(400), mib(200), 0},
	})
	if got := m.tree(100); got != (100+50+200)<<20 {
		t.Errorf("tree %d MiB, want 350", got>>20)
	}
}

// gVisor: shared is 0 and there is no RssAnon (statm "13733002 71410 0 0 0 0 0"): the whole resident set, which counts the
// libraries in every process. The absolute number is large; the growth is right.
func TestMemoryUnderGVisorCountsTheResidentSet(t *testing.T) {
	idle := []proc{
		{100, 1, "headless shell", mib(500), 0, 0},
		{101, 100, "zygote", mib(450), 0, 0},
		{102, 101, "renderer", mib(300), 0, 0},
		{103, 101, "renderer", mib(300), 0, 0},
	}
	m := fixture(t, idle)
	base := m.tree(100)
	if base != 1550<<20 {
		t.Fatalf("idle tree %d MiB", base>>20)
	}
	// the stopgap's failure: an idle tree is above RENDER_MEMORY_MB (1536) in absolute terms, and must not trip
	if grewBeyond(base, m.tree(100), 1536) {
		t.Error("an idle tree under shared 0 trips the memory watch")
	}
	// a pgSize that allocates 2 GiB in its renderer does
	write(t, m.root, proc{102, 101, "renderer", mib(300) + mib(2048), 0, 0})
	if !grewBeyond(base, m.tree(100), 1536) {
		t.Error("a 2 GiB bomb under shared 0 is not caught")
	}
	// a pgSize that allocates 500 MiB (and a new renderer process of 300 MiB) does not
	write(t, m.root, proc{102, 101, "renderer", mib(300) + mib(500), 0, 0})
	write(t, m.root, proc{104, 101, "renderer", mib(300), 0, 0})
	if grewBeyond(base, m.tree(100), 1536) {
		t.Error("ordinary growth trips the watch")
	}
	// the recycle: by growth over the process's baseline, not the absolute (1 GiB would recycle after every render)
	if grewBeyond(base, base+(100<<20), 1024) || !grewBeyond(base, base+(1100<<20), 1024) {
		t.Error("recycle threshold")
	}
}

func TestGrowthWithoutABaselineNeverTrips(t *testing.T) {
	if grewBeyond(0, 10<<30, 1536) || grewBeyond(1<<30, 10<<30, 0) {
		t.Error("no baseline or no limit must not trip")
	}
	if grewBeyond(1<<30, 1<<30+1536<<20, 1536) || !grewBeyond(1<<30, 1<<30+1536<<20+1, 1536) {
		t.Error("the limit is a strict bound on growth")
	}
	if got := (memMeter{root: "/nonexistent", pageSize: pgSize}).tree(1); got != 0 {
		t.Errorf("no /proc gave %d", got)
	}
}

func TestStatusAnonAndStatmBytes(t *testing.T) {
	if v, ok := statusAnon("RssAnon:\t   2048 kB\nRssFile: 1 kB\n"); !ok || v != 2<<20 {
		t.Errorf("%d %v", v, ok)
	}
	for _, s := range []string{"VmRSS: 5 kB\n", "RssAnon:\t0 kB\n", "RssAnon: x kB\n", ""} {
		if _, ok := statusAnon(s); ok {
			t.Errorf("%q has no usable RssAnon", s)
		}
	}
	if statmBytes("100000 20000 8000 1 0 5000 0", 4096) != 12000*4096 || statmBytes("13733002 71410 0 0 0 0 0", 4096) != 71410*4096 || statmBytes("garbage", 4096) != 0 {
		t.Error("statm")
	}
	if got := descendantsIn(fixture(t, []proc{{100, 1, "a b) (c", 1, 0, 0}, {101, 100, "x", 1, 0, 0}}).root, 100); len(got) != 1 || got[0] != 101 {
		t.Errorf("descendants %v", got)
	}
}

// The recycle decision, on fixtures of both accountings: an idle browser is never replaced for being large, a grown one is.
func TestTheRecycleDecisionIsByGrowthOverTheProcessBaseline(t *testing.T) {
	for name, anon := range map[string]int64{"anonymous accounting": 0, "gvisor accounting": 1} {
		m := fixture(t, []proc{{100, 1, "headless shell", mib(900), 0, 0}, {101, 100, "renderer", mib(900), 0, 0}}) // 1.8 GiB resident
		if anon == 0 {                                                                                              // the same tree as Linux reports it: RssAnon is what counts
			m = fixture(t, []proc{{100, 1, "headless shell", mib(900), mib(800), 100 << 10}, {101, 100, "renderer", mib(900), mib(800), 150 << 10}})
		}
		p := &Pool{meter: m, cfg: Config{RecycleMemoryMB: 1024}}
		s := &slot{pool: p, proc: &os.Process{Pid: 100}}
		s.baseMem = m.tree(100)
		if p.memoryRecycle(s) {
			t.Errorf("%s: an idle browser is replaced", name)
		}
		write(t, m.root, proc{101, 100, "renderer", mib(900) + mib(1500), 0, 0})
		if anon == 0 {
			write(t, m.root, proc{101, 100, "renderer", mib(900), mib(800), (150 + 1500) << 10})
		}
		if !p.memoryRecycle(s) {
			t.Errorf("%s: a browser that grew by 1.5 GiB is kept", name)
		}
		s.baseMem = 0 // no baseline (the first render failed before it was taken): never replaced for memory
		if p.memoryRecycle(s) {
			t.Errorf("%s: no baseline, yet replaced", name)
		}
	}
}
