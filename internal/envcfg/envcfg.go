// Package envcfg reads the settings of the two binaries from the environment. A setting that is present and wrong is an
// error, never a silent default: the services exit with status 2 and say which one.
package envcfg

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Reader collects the first error so that main can report all the settings in one pass.
type Reader struct{ Err error }

func (r *Reader) fail(name, format string, args ...any) {
	if r.Err == nil {
		r.Err = fmt.Errorf("%s: %s", name, fmt.Sprintf(format, args...))
	}
}

// String of the variable, or def.
func (r *Reader) String(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

// Int of the variable, or def; it must be within [min, max].
func (r *Reader) Int(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		r.fail(name, "%q is not a number from %d to %d", v, min, max)
		return def
	}
	return n
}

// Int64 is Int for byte counts.
func (r *Reader) Int64(name string, def, min, max int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < min || n > max {
		r.fail(name, "%q is not a number from %d to %d", v, min, max)
		return def
	}
	return n
}

// Bool of the variable: "true" or "false".
func (r *Reader) Bool(name string, def bool) bool {
	switch v := os.Getenv(name); v {
	case "":
		return def
	case "true":
		return true
	case "false":
		return false
	default:
		r.fail(name, "%q is not true or false", v)
		return def
	}
}

// File reads the file the variable names (a secret is never in the environment itself). Empty if unset.
func (r *Reader) File(name string) []byte {
	p := os.Getenv(name)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		r.fail(name, "%v", err)
		return nil
	}
	return []byte(strings.TrimSpace(string(b)))
}

// Ports reads "80,443"; the default is used when unset.
func (r *Reader) Ports(name string, def []int) []int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	var out []int
	for _, f := range strings.Split(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 || n > 65535 {
			r.fail(name, "%q is not a list of ports", v)
			return def
		}
		out = append(out, n)
	}
	return out
}

// Origins reads the test origins: "host:port,host:port".
func (r *Reader) Origins(name string) map[string]bool {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	out := map[string]bool{}
	for _, f := range strings.Split(v, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if _, _, err := net.SplitHostPort(f); err != nil {
			r.fail(name, "%q is not host:port", f)
			continue
		}
		out[f] = true
	}
	return out
}

// Loopback reports whether a listen address is on the loopback interface only.
func Loopback(listen string) bool {
	h, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// List reads a comma-separated list; a variable that is set and empty is the empty list (not the default).
func (r *Reader) List(name string, def []string) []string {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.ToLower(strings.TrimSpace(f)); f != "" {
			out = append(out, f)
		}
	}
	return out
}
