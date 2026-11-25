package render

import (
	"os"
	"strconv"
	"strings"
)

// Memory of a browser's process tree, and how a render is judged by it (ADR-0001 D11).
//
// The absolute number depends on what /proc says, and /proc does not say the same everywhere: on Linux, status has RssAnon (the
// anonymous pages: heap, ArrayBuffers, what a page allocates; not the shared libraries) and statm says which resident pages are
// shared; under gVisor statm's "shared" column is 0 and an idle headless-shell tree measures about 1.6 GiB, because every
// process is counted with its libraries. So no absolute threshold can be right on both. The renders are judged by GROWTH over a
// baseline taken, with the same reading, when the render's context has been created (and the recycle by growth over the first
// baseline of the process): a constant in the reading cancels, and what a page allocates does not.

// memMeter reads /proc under root (a directory of fixtures in the tests).
type memMeter struct {
	root     string
	pageSize int64
}

func systemMeter() memMeter { return memMeter{root: "/proc", pageSize: int64(os.Getpagesize())} }

// tree is the memory, in bytes, of the process pid and everything below it. 0 where there is no /proc to read.
func (m memMeter) tree(pid int) int64 {
	var total int64
	for _, p := range append(descendantsIn(m.root, pid), pid) {
		total += m.process(p)
	}
	return total
}

// process: RssAnon of /proc/<pid>/status when the kernel reports it (the anonymous memory: what a page allocates), else the
// private part of statm (resident minus shared) when statm reports shared pages, else the whole resident set.
func (m memMeter) process(pid int) int64 {
	dir := m.root + "/" + strconv.Itoa(pid)
	if b, err := os.ReadFile(dir + "/status"); err == nil {
		if anon, ok := statusAnon(string(b)); ok {
			return anon
		}
	}
	b, err := os.ReadFile(dir + "/statm")
	if err != nil {
		return 0
	}
	return statmBytes(string(b), m.pageSize)
}

// statusAnon is RssAnon of a /proc/<pid>/status text, in bytes. ok is false when the field is absent or 0 (a kernel that has
// no such accounting says 0 or says nothing).
func statusAnon(status string) (int64, bool) {
	for _, line := range strings.Split(status, "\n") {
		if v, found := strings.CutPrefix(line, "RssAnon:"); found {
			f := strings.Fields(v)
			if len(f) >= 1 {
				if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil && kb > 0 {
					return kb * 1024, true
				}
			}
			return 0, false
		}
	}
	return 0, false
}

// statmBytes of one /proc/<pid>/statm line: resident minus shared when it has shared pages, else resident.
func statmBytes(line string, pageSize int64) int64 {
	f := strings.Fields(line)
	if len(f) < 3 {
		return 0
	}
	res, err1 := strconv.ParseInt(f[1], 10, 64)
	shr, err2 := strconv.ParseInt(f[2], 10, 64)
	if err1 != nil || err2 != nil || res < 0 {
		return 0
	}
	if shr > 0 && res > shr {
		res -= shr
	}
	return res * pageSize
}

// grewBeyond reports whether now is more than limitMB above base. A baseline of 0 (not taken, or no /proc) never trips it.
func grewBeyond(base, now, limitMB int64) bool {
	return limitMB > 0 && base > 0 && now-base > limitMB<<20
}

// descendantsIn of pid, by a scan of root.
func descendantsIn(root string, pid int) []int {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	children := map[int][]int{}
	for _, e := range entries {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(root + "/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')') // the name may hold spaces and parentheses
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		if pp, err := strconv.Atoi(f[1]); err == nil {
			children[pp] = append(children[pp], p)
		}
	}
	var out []int
	stack := []int{pid}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range children[p] {
			out = append(out, c)
			stack = append(stack, c)
		}
	}
	return out
}

// descendants of pid in the real /proc.
func descendants(pid int) []int { return descendantsIn("/proc", pid) }
