//go:build browser

package browsertest

import (
	"strings"
	"testing"

	"idp-browser/internal/render"
)

func TestTextMadeByJavaScriptIsInTheHTML(t *testing.T) {
	r := newRig(t, opts{})
	r.page("/spa", `<!doctype html><html><head><title>SPA shell</title></head><body><div id="app"></div>
<script>document.getElementById('app').innerHTML = '<article><h1>Rendered headline</h1><p>The body exists only after JavaScript ran: ZEBRA-' + '7731.</p></article>'; document.title = 'Rendered ' + 'title';</script>
</body></html>`)
	res := r.mustRender(render.Request{URL: r.url("/spa")})
	if !strings.Contains(res.HTML, "ZEBRA-7731") || !strings.Contains(res.HTML, "Rendered headline") {
		t.Fatalf("html: %.300q", res.HTML)
	}
	if res.Title != "Rendered title" || res.Status != 200 || res.FinalURL != r.url("/spa") || res.Requests < 1 || res.MS <= 0 {
		t.Errorf("result %+v", *res)
	}
}
