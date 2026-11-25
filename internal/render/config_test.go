package render

import (
	"strings"
	"testing"
)

func valid() Config {
	c := DefaultConfig()
	c.ChromePath = "/x"
	c.ProfileDir = "/p"
	c.ProxyAddr = "proxy:3128"
	c.ProxyAdmin = "http://proxy:3129"
	c.ProxyAdminKey = []byte(strings.Repeat("k", 32))
	return c
}

// --no-sandbox only on the operator's statement that the pod runs under gVisor or Kata.
func TestNoSandboxIsRefusedWithoutTheIsolationStatement(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.NoSandbox = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "gVisor or Kata") {
		t.Errorf("no statement: %v", err)
	}
	for _, by := range []string{"gvisor", "kata"} {
		c.IsolatedBy = by
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", by, err)
		}
	}
	c.IsolatedBy = "docker"
	if err := c.Validate(); err == nil {
		t.Error("an unknown runtime was accepted")
	}
	// the statement without --no-sandbox is harmless, and the flag is not on the command line
	c.NoSandbox, c.IsolatedBy = false, "gvisor"
	if err := c.Validate(); err != nil {
		t.Error(err)
	}
	if strings.Contains(strings.Join(argsOf(c), " "), "no-sandbox") {
		t.Error("--no-sandbox is on the command line without the setting")
	}
	c.NoSandbox = true
	if !strings.Contains(strings.Join(argsOf(c), " "), "no-sandbox") {
		t.Error("the setting does not reach the command line")
	}
}

func argsOf(c Config) []string {
	var out []string
	for _, f := range (&c).chromeFlags("/p") {
		out = append(out, f.name)
	}
	return out
}

// The command line of the plan's section 2, flag by flag.
func TestTheCommandLineHasTheHardeningTheADRPromises(t *testing.T) {
	flags := map[string]any{}
	v := valid()
	for _, f := range v.chromeFlags("/p") {
		flags[f.name] = f.value
	}
	for name, want := range map[string]any{
		"proxy-server": failClosedProxy, "disable-quic": true, "webrtc-ip-handling-policy": "disable_non_proxied_udp",
		"force-webrtc-ip-handling-policy": "disable_non_proxied_udp", "host-resolver-rules": "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
		"disable-extensions": true, "deny-permission-prompts": true, "disable-notifications": true, "proxy-bypass-list": "<-loopback>",
	} {
		if flags[name] != want {
			t.Errorf("--%s = %v, want %v", name, flags[name], want)
		}
	}
	if _, ok := flags["no-sandbox"]; ok {
		t.Error("--no-sandbox by default")
	}
	if !strings.Contains(flags["disable-features"].(string), "DnsOverHttps") {
		t.Error("DNS over HTTPS is not disabled")
	}
	if _, ok := flags["ignore-certificate-errors-spki-list"]; ok {
		t.Error("a certificate exception without the test setting")
	}
}

func TestOtherConfigurationErrors(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"no chrome":      func(c *Config) { c.ChromePath = "" },
		"no proxy":       func(c *Config) { c.ProxyAddr = "" },
		"no admin":       func(c *Config) { c.ProxyAdmin = "" },
		"short key":      func(c *Config) { c.ProxyAdminKey = []byte("short") },
		"empty pool":     func(c *Config) { c.Pool = 0 },
		"no profile dir": func(c *Config) { c.ProfileDir = "" },
		"timeouts":       func(c *Config) { c.MaxTimeout = c.DefaultTimeout - 1 },
	} {
		c := valid()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRequestChecks(t *testing.T) {
	p := &Pool{cfg: valid()}
	for _, tc := range []struct {
		req  Request
		code string
	}{
		{Request{URL: "https://example.com/a?b=1#frag"}, ""},
		{Request{URL: "http://93.184.216.34/"}, ""},
		{Request{URL: "https://example.com/", TimeoutMS: 1000, MaxBytes: 1024}, ""},
		{Request{}, InvalidRequest},
		{Request{URL: "https://example.com/", TimeoutMS: 999}, InvalidRequest},
		{Request{URL: "https://example.com/", TimeoutMS: 60001}, InvalidRequest},
		{Request{URL: "https://example.com/", MaxBytes: 1023}, InvalidRequest},
		{Request{URL: "https://example.com/", MaxBytes: 21 << 20}, InvalidRequest},
		{Request{URL: "https://example.com/\xff"}, InvalidRequest},
		{Request{URL: "file:///etc/passwd"}, NotAllowed},
		{Request{URL: "http://localhost:8080/"}, NotAllowed},
		{Request{URL: "http://127.0.0.1/"}, NotAllowed},
		{Request{URL: "http://[::ffff:7f00:1]/"}, NotAllowed},
		{Request{URL: "http://0x7f.1/"}, NotAllowed},
		{Request{URL: "https://example.com:8443/"}, NotAllowed},
	} {
		_, _, _, err := p.check(tc.req)
		got := ""
		if err != nil {
			got = err.Code
		}
		if got != tc.code {
			t.Errorf("%+v: %q, want %q", tc.req, got, tc.code)
		}
	}
}

func TestBlockTypesMustBeTypesThatMayBeRefused(t *testing.T) {
	c := valid()
	if len(c.BlockTypes) != 3 {
		t.Errorf("default %v", c.BlockTypes)
	}
	for _, ok := range [][]string{nil, {"image"}, {"image", "media", "font", "stylesheet", "xhr"}} {
		c.BlockTypes = ok
		if err := c.Validate(); err != nil {
			t.Errorf("%v: %v", ok, err)
		}
	}
	for _, bad := range []string{"document", "websocket", "images", ""} {
		c.BlockTypes = []string{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for in, want := range map[string]string{"image": "Image", "xhr": "XHR", "font": "Font", "texttrack": "TextTrack", "eventsource": "EventSource"} {
		if got := string(resourceTypeOf(in)); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}
