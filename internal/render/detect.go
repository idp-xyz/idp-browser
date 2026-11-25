package render

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// blocked_by_site: what the renderer reports instead of a page when the site answered with a challenge or a refusal
// (plan section 3: "遇到验证码或反爬页面 → 报 blocked_by_site，不重试、不绕过"; ADR-0001 D4). The signals are simple on
// purpose and are the ones idp-web already uses for its own reads (idp-web internal/fetch/botcheck.go, ADR-0001 D12),
// plus the soft blocks that answer 200: the rule that keeps a real page safe is the same, a marker counts only on a
// page with little visible text.
//
// A page is blocked_by_site when ANY of these holds (the visible text is document.body.innerText, in characters):
//
//  1. S1 html marker: the source holds a marker of a known challenge (htmlMarkers), and the page has at most
//     maxChallengeText characters of visible text.
//  2. S2 title: the whole title is one of titleMarkers (Cloudflare's "Just a moment...", "Access Denied" and others).
//  3. S3 text marker: the visible text holds a phrase of textMarkers and the page has at most maxPromptText characters.
//  4. S4 refusal text: the visible text holds a phrase of refusalMarkers (an access-denied page that says so in words:
//     Akamai's "Reference #...", FedEx's "we can't process your request right now ... Incident Number", Imperva's
//     "Incapsula incident ID") and the page has at most maxChallengeText characters. This is the soft block that comes
//     with HTTP 200.
//  5. S5 status: the status is 403 or 429 and the page has at most maxPromptText characters of visible text. A real
//     "forbidden" page of a site that is working says more than that, and a bare one is a refusal.
//
// Each rule is tested in detect_test.go with a page that must be reported and a near miss (the same words in a long
// article) that must not.
const (
	maxChallengeText = 1000
	maxPromptText    = 300
)

var htmlMarkers = []string{
	"_cf_chl_opt",             // Cloudflare managed challenge
	"cf-chl-",                 // Cloudflare challenge form and widgets
	"cf-browser-verification", // Cloudflare's older interstitial
	"challenge-platform",      // Cloudflare challenge script path
	"awswafcookiedomainlist",  // AWS WAF JavaScript challenge
	"gokuprops",               // AWS WAF challenge
	"px-captcha",              // HUMAN (PerimeterX) press-and-hold
	"captcha-delivery.com",    // DataDome
	"/_incapsula_resource",    // Imperva Incapsula
	"errors.edgesuite.net",    // Akamai's error pages: "Reference #18.xxxx", served with 200 or 403
	"_____tmd_____",           // Alibaba Cloud WAF slider
	"geetest",                 // GeeTest slider
}

var titleMarkers = []string{
	"just a moment...", "just a moment…", "attention required! | cloudflare",
	"please wait...", // ByteDance and Volcano Engine's security check
	"access denied", "pardon our interruption", "robot check", "are you a robot?", "security check", "403 forbidden", "error 403",
	"访问被拒绝", "安全验证", "人机验证",
}

var textMarkers = []string{
	"正在进行安全检测", "verify you are human", "verify you're human", "verifying you are human", "are you a robot", "i'm not a robot",
	"captcha", "unusual traffic from your computer", "人机验证", "请完成安全验证", "press & hold", "slide to verify", "滑动验证", "拖动滑块",
}

var refusalMarkers = []string{
	"it appears you don't have permission to view this webpage", // FedEx, behind Akamai: HTTP 200 (found 2026-11-23)
	"you don't have permission to access",                       // Akamai: "You don't have permission to access ... on this server. Reference #"
	"we can't process your request right now",
	"your request has been blocked",
	"request unsuccessful. incapsula incident id",
	"access to this page has been denied",
	"automated access to", "automated queries",
	"访问过于频繁", "请求被拦截", "访问被拒绝", "您的访问行为异常",
}

var akamaiRef = regexp.MustCompile(`reference #\d+\.[0-9a-f]+\.\d+`)

// foldText lower-cases text and makes the quotes and the white space of a refusal page comparable with the markers: curly
// and modifier apostrophes and primes become ', curly double quotes become ", runs of white space one space. A site that
// writes "don’t" with U+2019 is the same refusal. The same function is in idp-web (internal/fetch/blocked.go); keep them identical.
func foldText(s string) string {
	s = strings.NewReplacer("\u2019", "'", "\u2018", "'", "\u02bc", "'", "\u2032", "'", "\u201c", "\"", "\u201d", "\"").Replace(strings.ToLower(s))
	return strings.Join(strings.Fields(s), " ")
}

// Detect reports whether a rendered page is a block, and which rule says so. html is the rendered source, text the
// visible text.
func Detect(status int, title, html, text string) (string, bool) {
	n := utf8.RuneCountInString(strings.TrimSpace(text))
	lowerText := strings.ToLower(text)
	if n <= maxChallengeText {
		lowerHTML := strings.ToLower(html)
		for _, m := range htmlMarkers {
			if strings.Contains(lowerHTML, m) {
				return "S1 html marker " + m, true
			}
		}
		folded := foldText(text)
		for _, m := range refusalMarkers {
			if strings.Contains(folded, m) {
				return "S4 refusal text " + m, true
			}
		}
		if akamaiRef.MatchString(folded) {
			return "S4 refusal text Akamai reference", true
		}
	}
	t := strings.ToLower(strings.TrimSpace(title))
	for _, m := range titleMarkers {
		if t == m && n <= maxChallengeText {
			return "S2 title " + m, true
		}
	}
	if n <= maxPromptText {
		for _, m := range textMarkers {
			if strings.Contains(lowerText, m) {
				return "S3 text marker " + m, true
			}
		}
		if status == 403 || status == 429 {
			return "S5 status", true
		}
	}
	return "", false
}
