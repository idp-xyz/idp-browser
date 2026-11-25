package render

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Config is everything the renderer is told. Defaults are the ones of the plan (section 3) and the ADR (D4, D5).
type Config struct {
	// ChromePath is the headless Chromium executable (the image has /headless-shell/headless-shell).
	ChromePath string
	// Pool is the number of browser processes, and so of renders at once (default 2). A process renders one page at a
	// time: no two renders ever share a process.
	Pool int
	// RecycleAfter renders, a process is replaced (default 50); RecycleMemoryMB: a process whose tree has grown by more than this (over its first render's baseline, mem.go)
	// after a render is replaced (default 1024). A process after any failed render is replaced whatever these say.
	RecycleAfter    int
	RecycleMemoryMB int
	// RenderMemoryMB is the most the tree of a process may GROW while it renders, over the baseline taken when the render's context
	// was created (default 1536; growth, not an absolute, because /proc does not account the same everywhere: mem.go); above it the render is
	// ended as render_failed and the process is killed. Zero disables the watch.
	RenderMemoryMB int

	// NoSandbox starts Chromium with --no-sandbox, which is allowed only when IsolatedBy says the pod runs under gVisor
	// or Kata: inside them the container is the sandbox (ADR-0001 D9). Otherwise Chromium's own sandbox is used.
	NoSandbox  bool
	IsolatedBy string // "gvisor" or "kata"

	// ProfileDir holds the per-process profile directories; the image mounts a tmpfs there.
	ProfileDir string

	// ProxyAddr is the egress proxy's CONNECT port as the renderer reaches it (host:port); ProxyAdmin its admin base URL;
	// ProxyAdminKey the key they share.
	ProxyAddr     string
	ProxyAdmin    string
	ProxyAdminKey []byte

	// Scroll: scroll to the bottom once after the page settles, to start lazy loading (default true: see DefaultConfig).
	Scroll bool
	// DefaultTimeout is a render's time when the request names none (15 s); MaxTimeout the most a request may ask (60 s).
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	// DefaultMaxBytes caps the HTML (5 MiB); MaxMaxBytes the most a request may ask (20 MiB).
	DefaultMaxBytes int
	MaxMaxBytes     int
	// Settle is the longest the renderer waits, after the page has loaded, for the network and the DOM to go quiet (5 s).
	Settle time.Duration
	// QueueWait is how long a request waits for a free browser before it is answered render_busy (default 2 s).
	QueueWait time.Duration

	// BlockTypes are the resource types the renderer refuses to fetch at all (CDP resource types, lower case; default image,
	// media, font): a text read does not need them, and they are most of a modern page's requests and bytes. They are counted
	// as Skipped, not as Blocked, and not against the request budget. Empty: none is refused.
	BlockTypes []string

	// Limits the proxy is asked to enforce for each render; zero is the proxy's own.
	MaxRequests      int
	MaxBytes         int64
	MaxResponseBytes int64

	// TestOrigins exempts exact host:port pairs from the address rules, for the renderer's check of the URL. The proxy has
	// the same list. Acceptance only (ADR-0001 D13).
	TestOrigins map[string]bool
	Ports       []int // the ports a URL may name; must be the proxy's list (default 80, 443)

	// TestTrustSPKI lists base64 SHA-256 hashes of public keys whose certificates Chromium accepts although no authority
	// signed them (--ignore-certificate-errors-spki-list), so that a test can render an HTTPS origin of its own. Tests only:
	// the services' environment has no setting for it.
	TestTrustSPKI []string

	UserAgent string // empty: Chromium's own
	Log       *slog.Logger
}

// DefaultConfig is the configuration with every default filled in.
func DefaultConfig() Config {
	return Config{
		Pool: 2, RecycleAfter: 50, RecycleMemoryMB: 1024, RenderMemoryMB: 1536,
		Scroll: true, BlockTypes: []string{"image", "media", "font"}, DefaultTimeout: 15 * time.Second, MaxTimeout: 60 * time.Second,
		DefaultMaxBytes: 5 << 20, MaxMaxBytes: 20 << 20, Settle: 5 * time.Second, QueueWait: 2 * time.Second,
	}
}

// Validate refuses a configuration the service must not start with. In particular it refuses --no-sandbox without the
// statement that the pod is isolated by gVisor or Kata (ADR-0001 D9).
func (c *Config) Validate() error {
	if c.NoSandbox {
		switch c.IsolatedBy {
		case "gvisor", "kata":
		case "":
			return errors.New("--no-sandbox is refused: Chromium's own sandbox is switched off only in a pod that runs under gVisor or Kata; set IDP_BROWSER_ISOLATED_BY=gvisor or kata to say it does")
		default:
			return fmt.Errorf("IDP_BROWSER_ISOLATED_BY %q is not gvisor or kata", c.IsolatedBy)
		}
	} else if c.IsolatedBy != "" && c.IsolatedBy != "gvisor" && c.IsolatedBy != "kata" {
		return fmt.Errorf("IDP_BROWSER_ISOLATED_BY %q is not gvisor or kata", c.IsolatedBy)
	}
	switch {
	case c.ChromePath == "":
		return errors.New("no Chromium executable (IDP_BROWSER_CHROME)")
	case c.Pool < 1 || c.Pool > 64:
		return errors.New("the pool must have 1 to 64 browsers")
	case c.RecycleAfter < 1:
		return errors.New("a browser must render at least once before it is replaced")
	case c.ProxyAddr == "" || c.ProxyAdmin == "":
		return errors.New("no egress proxy (IDP_BROWSER_PROXY, IDP_BROWSER_PROXY_ADMIN): the browser has no other way out")
	case len(c.ProxyAdminKey) < 32:
		return errors.New("the proxy admin key must be at least 32 bytes")
	case c.DefaultTimeout <= 0 || c.MaxTimeout < c.DefaultTimeout:
		return errors.New("timeouts: the default must be positive and not above the maximum")
	case c.DefaultMaxBytes <= 0 || c.MaxMaxBytes < c.DefaultMaxBytes:
		return errors.New("byte limits: the default must be positive and not above the maximum")
	case c.blockTypesError() != "":
		return errors.New(c.blockTypesError())
	case c.ProfileDir == "":
		return errors.New("no profile directory (IDP_BROWSER_PROFILE_DIR; a tmpfs)")
	}
	return nil
}

// resourceTypes are the CDP resource types a setting may name. "document" is not one: refusing documents would refuse the page.
var resourceTypes = map[string]bool{"stylesheet": true, "image": true, "media": true, "font": true, "script": true, "texttrack": true, "xhr": true,
	"fetch": true, "prefetch": true, "eventsource": true, "manifest": true, "signedexchange": true, "ping": true, "cspviolationreport": true,
	"preflight": true, "other": true}

func (c *Config) blockTypesError() string {
	for _, t := range c.BlockTypes {
		if !resourceTypes[t] {
			return "IDP_BROWSER_BLOCK_TYPES: " + t + " is not a resource type that may be refused (document and websocket are never; see internal/render/config.go)"
		}
	}
	return ""
}
