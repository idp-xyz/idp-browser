package render

import (
	"strconv"
	"strings"

	"github.com/chromedp/chromedp"
)

// failClosedProxy is the proxy of every part of a browser that does not have a render's own: nothing listens there, so
// whatever is not a render's request (the default context, a component update the flags did not stop) goes nowhere.
const failClosedProxy = "http://127.0.0.1:9"

// disabledFeatures: features that would send requests of their own, upgrade a page's scheme, or resolve names through the
// browser's own resolver (ADR-0001 D9).
var disabledFeatures = []string{
	"Translate", "MediaRouter", "OptimizationHints", "AutofillServerCommunication", "CertificateTransparencyComponentUpdater",
	"HttpsUpgrades", "HttpsFirstBalancedModeAutoEnable", // an http page stays http: the egress rules judge the address, not the scheme
	"UseDnsHttpsSvcb", "DnsOverHttps", // no name is resolved here at all
	"NetworkTimeServiceQuerying", "InterestFeedContentSuggestions", "PrivacySandboxSettings4", "ThirdPartyStoragePartitioning",
}

type kv struct {
	name  string
	value any
}

// chromeFlags is the command line of one browser process (ADR-0001 D9), as data so that a test can read it.
func (c *Config) chromeFlags(dir string) []kv {
	f := []kv{
		{"user-data-dir", dir},
		{"headless", true}, {"hide-scrollbars", true}, {"mute-audio", true},
		{"no-first-run", true}, {"no-default-browser-check", true},
		{"window-size", "1280,1024"},

		// Every byte goes through the egress proxy. The context of a render has its own proxy (its credential); this is the
		// default for anything else, and it goes nowhere. Loopback is not exempt: a page asking for 127.0.0.1 reaches the
		// proxy, which refuses it and writes it to the audit.
		{"proxy-server", failClosedProxy},
		{"proxy-bypass-list", "<-loopback>"},
		// The browser resolves no name itself: with an HTTP proxy the proxy does, and this rule makes any lookup the
		// browser might still make fail; only the render's own hop, a loopback literal, is excluded.
		{"host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"},
		// UDP does not go through an HTTP proxy: no QUIC and HTTP/3, and WebRTC may use only the proxy (that is, nothing).
		{"disable-quic", true},
		{"webrtc-ip-handling-policy", "disable_non_proxied_udp"},
		{"force-webrtc-ip-handling-policy", "disable_non_proxied_udp"},
		{"enforce-webrtc-ip-permission-check", true},

		{"disable-features", strings.Join(disabledFeatures, ",")},
		{"disable-extensions", true},
		{"disable-component-extensions-with-background-pages", true},
		{"disable-background-networking", true},
		{"disable-component-update", true},
		{"disable-sync", true},
		{"disable-default-apps", true},
		{"disable-domain-reliability", true},
		{"disable-client-side-phishing-detection", true},
		{"safebrowsing-disable-auto-update", true},
		{"disable-breakpad", true},
		{"disable-crash-reporter", true},
		{"no-pings", true},
		{"metrics-recording-only", true},
		{"disable-print-preview", true},
		{"disable-notifications", true},
		{"deny-permission-prompts", true},
		{"autoplay-policy", "user-gesture-required"},
		{"disable-dev-shm-usage", true}, // the profile directory is a tmpfs; /dev/shm is small in a container
		{"js-flags", "--max-old-space-size=1024"},
	}
	if c.NoSandbox {
		f = append(f, kv{"no-sandbox", true})
	}
	if len(c.TestTrustSPKI) > 0 {
		f = append(f, kv{"ignore-certificate-errors-spki-list", strings.Join(c.TestTrustSPKI, ",")})
	}
	if c.UserAgent != "" {
		f = append(f, kv{"user-agent", c.UserAgent})
	}
	return f
}

// chromeOptions turns chromeFlags into the allocator's options. Nothing of the Go process's environment is passed on.
func (c *Config) chromeOptions(dir string) []chromedp.ExecAllocatorOption {
	o := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(c.ChromePath),
		chromedp.NoInheritEnv,
		chromedp.Env("HOME="+dir, "XDG_CONFIG_HOME="+dir+"/config", "XDG_CACHE_HOME="+dir+"/cache", "TMPDIR="+dir+"/tmp", "LANG=en_US.UTF-8", "PATH=/headless-shell:/usr/bin"),
	}
	for _, f := range c.chromeFlags(dir) {
		o = append(o, chromedp.Flag(f.name, f.value))
	}
	return o
}

// deniedPermissions are overridden to denied in every render's context, besides the flag that denies the prompts.
var deniedPermissions = []string{"geolocation", "notifications", "push", "midi", "camera", "microphone", "audioCapture", "videoCapture",
	"clipboardReadWrite", "clipboardSanitizedWrite", "backgroundSync", "persistentStorage", "idleDetection", "displayCapture", "sensors"}

// initScript runs in every document before its own scripts: a MutationObserver that the settle wait reads, and the
// APIs of service workers removed from the page's view. The last is a second layer, not a boundary (the first is that
// everything a worker could fetch goes through the proxy too).
const initScript = `(() => {
  try {
    window.__idpMut = 0;
    new MutationObserver(r => { window.__idpMut += r.length; }).observe(document, {subtree: true, childList: true, attributes: true, characterData: true});
  } catch (e) {}
  try { Object.defineProperty(Navigator.prototype, 'serviceWorker', {get: () => undefined, configurable: true}); } catch (e) {}
})();`

func captureScript(maxBytes int) string {
	return `(() => {
  const de = document.documentElement;
  let html = de ? de.outerHTML : "";
  if (document.doctype) { try { html = new XMLSerializer().serializeToString(document.doctype) + html; } catch (e) {} }
  const nav = performance.getEntriesByType("navigation")[0];
  const text = (document.body && document.body.innerText) || "";
  return {html: html.slice(0, ` + strconv.Itoa(maxBytes) + `), htmlLen: html.length, title: document.title || "", url: location.href,
          status: nav ? (nav.responseStatus || 0) : 0, text: text.slice(0, 4000), textLen: text.length};
})()`
}
