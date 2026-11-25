package render

import "fmt"

// Reason codes of a failed render (ADR-0001 D4). They are the whole vocabulary idp-web gets; the message is for the log
// and for an operator, never an instruction to the caller.
const (
	RenderTimeout  = "render_timeout"  // the page did not load, or did not answer, in the time given
	RenderFailed   = "render_failed"   // the browser, the network or the page failed (crash, memory, a navigation error, a limit)
	BlockedBySite  = "blocked_by_site" // a captcha, an anti-bot interstitial or an access-denied page instead of the page
	RenderBusy     = "render_busy"     // every browser of the pool is rendering
	InvalidRequest = "invalid_request" // the request is not valid (no url, a field out of range, not JSON)
	NotAllowed     = "not_allowed"     // the address is not a public http or https one
)

// Error is a failed render.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func fail(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Codes lists every reason code, for the tests and the metrics.
var Codes = []string{RenderTimeout, RenderFailed, BlockedBySite, RenderBusy, InvalidRequest, NotAllowed}
