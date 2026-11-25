package render

import (
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	long := strings.Repeat("This is a long article about web security and CAPTCHAs, access denied errors and more. ", 40)
	for _, tc := range []struct {
		name          string
		status        int
		title, html   string
		text          string
		blocked       bool
		signalContain string
	}{
		{"cloudflare managed challenge", 200, "Just a moment...", `<html><script>window._cf_chl_opt={}</script>`, "Verify you are human", true, "S1"},
		{"cloudflare block page", 403, "Attention Required! | Cloudflare", "<html>", "Sorry, you have been blocked", true, "S2"},
		{"aws waf", 200, "", "<script>AwsWafCookieDomainList=[]</script>", "", true, "S1"},
		{"datadome", 200, "x", `<iframe src="https://geo.captcha-delivery.com/captcha/">`, "", true, "S1"},
		{"akamai errors page (HTTP 200)", 200, "Access Denied", `<html>Reference #18.4a3d1c02.1795089600.abc123</html>`, "Access Denied You don't have permission to access \"http://x/\" on this server. Reference #18.4a3d1c02.1795089600.abc123", true, "S"},
		{"fedex soft block (HTTP 200)", 200, "", "<html>", "We're sorry, we can't process your request right now. It appears you don't have permission to view this webpage. Incident Number: 0.11a6b4d.1795089600.5f2c", true, "S4"},
		{"imperva", 200, "", "<html>", "Request unsuccessful. Incapsula incident ID: 1234-5678", true, "S4"},
		{"chinese security check", 200, "", "<html>", "正在进行安全检测", true, "S3"},
		{"a bare 403", 403, "", "<html>", "Forbidden", true, "S5"},
		{"a bare 429", 429, "", "<html>", "Too many requests", true, "S5"},
		{"a captcha prompt only", 200, "Verify", "<html>", "Please complete the CAPTCHA to continue", true, "S3"},

		// near misses: the same words on a page that is a page
		{"a long article about captchas", 200, "How CAPTCHAs work", "<html>", long, false, ""},
		{"a long article that quotes the akamai message", 200, "Debugging 403s", "<html>", long + " You don't have permission to access this on this server. Reference #18.4a3d1c02.1795089600.abc123", false, ""},
		{"a long page of a site that runs a bot script", 200, "Shop", `<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>`, long, false, ""},
		{"a 403 page that has real content", 403, "Forbidden", "<html>", long, false, ""},
		{"a normal short page", 200, "Hello", "<html><p>Hello</p>", "Hello, world. This page is short and fine.", false, ""},
		{"a 404 is not a block", 404, "Not found", "<html>", "Not found", false, ""},
		{"an empty page", 200, "", "<html></html>", "", false, ""},
	} {
		sig, got := Detect(tc.status, tc.title, tc.html, tc.text)
		if got != tc.blocked {
			t.Errorf("%s: blocked=%v (%s), want %v", tc.name, got, sig, tc.blocked)
		}
		if got && !strings.Contains(sig, tc.signalContain) {
			t.Errorf("%s: signal %q, want it to contain %q", tc.name, sig, tc.signalContain)
		}
	}
}
