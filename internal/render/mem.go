package render

import (
	"os"
	"strconv"
	"strings"
)

// treeRSS is the private resident memory, in bytes, of the process pid and everything below it: Chromium's renderers, its GPU
// and network processes are children of the browser process (through the zygote). It reads /proc and returns 0 where
// there is none, which turns the memory watch off rather than failing a render.
func treeRSS(pid int) int64 {
	var total int64
	for _, p := range append(descendants(pid), pid) {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(p) + "/statm")
		if err != nil {
			continue
		}
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			// resident minus shared: the pages of the shared libraries are in every process of the tree, and counting them
			// for each would put a browser with a dozen processes at a gigabyte before it holds anything
			res, err1 := strconv.ParseInt(f[1], 10, 64)
			shr, err2 := strconv.ParseInt(f[2], 10, 64)
			if err1 == nil && err2 == nil && res > shr {
				total += (res - shr) * int64(os.Getpagesize())
			}
		}
	}
	return total
}

// descendants of pid, by the same /proc scan.
func descendants(pid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	children := map[int][]int{}
	for _, e := range entries {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
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
