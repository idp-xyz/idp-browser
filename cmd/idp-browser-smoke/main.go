// idp-browser-smoke: the helper of `make smoke-real` (deploy/smoke-real.sh). It is not part of the service.
//
//	idp-browser-smoke keygen DIR                      writes caller.key, caller.pub (P-256, PKCS#8 and PKIX) and admin.key into DIR
//	idp-browser-smoke render -base URL -ops URL -audience URL -key FILE URL
//	                                                  waits for the renderer's /readyz, signs one request the way idp-web will
//	                                                  (internal/caller), posts it and prints a summary
//	idp-browser-smoke probe HOST:PORT...              tries a TCP connection to each, 5 s, and says whether it got through
//	idp-browser-smoke audit                           reads the proxy's JSON log on stdin and prints what it audited
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"idp-browser/internal/caller"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: idp-browser-smoke keygen|render|audit")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "render":
		render(os.Args[2:])
	case "probe":
		probe(os.Args[2:])
	case "audit":
		audit(os.Stdin)
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

func keygen(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "keygen DIR")
		os.Exit(2)
	}
	priv, pub, err := caller.GenerateKey()
	if err != nil {
		panic(err)
	}
	admin := make([]byte, 32)
	_, _ = rand.Read(admin)
	// readable by the unprivileged users of the containers; the files live in a throwaway directory
	for name, b := range map[string][]byte{"caller.key": priv, "caller.pub": pub, "admin.key": []byte(hex.EncodeToString(admin))} {
		if err := os.WriteFile(filepath.Join(args[0], name), b, 0o644); err != nil {
			panic(err)
		}
	}
}

func render(args []string) {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	base := fs.String("base", "", "the renderer's API base URL, for example http://renderer:8590")
	ops := fs.String("ops", "", "the renderer's ops base URL (waited on: /readyz)")
	aud := fs.String("audience", "", "the audience the renderer was told")
	keyFile := fs.String("key", "", "idp-web's private key")
	timeout := fs.Int("timeout-ms", 30000, "timeoutMs of the request")
	_ = fs.Parse(args)
	if fs.NArg() != 1 || *base == "" || *aud == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "render -base URL -audience URL -key FILE [-ops URL] URL")
		os.Exit(2)
	}
	kb, err := os.ReadFile(*keyFile)
	if err != nil {
		panic(err)
	}
	signer, err := caller.NewSigner(kb)
	if err != nil {
		panic(err)
	}
	if *ops != "" {
		deadline := time.Now().Add(90 * time.Second)
		for {
			resp, err := http.Get(*ops + "/readyz")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					break
				}
			}
			if time.Now().After(deadline) {
				fmt.Println("the renderer did not become ready in 90 s")
				os.Exit(1)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	body, _ := json.Marshal(map[string]any{"url": fs.Arg(0), "timeoutMs": *timeout})
	assertion, err := signer.Sign(*aud, "POST", "/render", body)
	if err != nil {
		panic(err)
	}
	req, _ := http.NewRequest("POST", *base+"/render", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+assertion)
	start := time.Now()
	resp, err := (&http.Client{Timeout: time.Duration(*timeout)*time.Millisecond + 60*time.Second}).Do(req)
	if err != nil {
		fmt.Println("request failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	fmt.Printf("render answer     HTTP %d in %s\n", resp.StatusCode, time.Since(start).Round(time.Millisecond))
	var ok struct {
		FinalURL string                          `json:"finalUrl"`
		HTML     string                          `json:"html"`
		Status   int                             `json:"status"`
		Title    string                          `json:"title"`
		Requests int                             `json:"requests"`
		Blocked  int                             `json:"blocked"`
		Skipped  int                             `json:"skipped"`
		Bytes    int64                           `json:"bytes"`
		MS       int64                           `json:"ms"`
		Settled  bool                            `json:"settled"`
		Trunc    bool                            `json:"truncated"`
		Limit    string                          `json:"limit"`
		Error    *struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(raw, &ok); err != nil {
		fmt.Printf("answer is not JSON: %.200q\n", raw)
		os.Exit(1)
	}
	if ok.Error != nil {
		fmt.Printf("error code        %s\nmessage           %s\n", ok.Error.Code, ok.Error.Message)
		return
	}
	fmt.Printf("finalUrl          %s\npage status       %d\ntitle             %q\nrequests          %d\nblocked           %d\nskipped           %d\nbytes             %d\nms                %d\nsettled           %v\nhtml bytes        %d (truncated: %v, limit: %q)\n",
		ok.FinalURL, ok.Status, ok.Title, ok.Requests, ok.Blocked, ok.Skipped, ok.Bytes, ok.MS, ok.Settled, len(ok.HTML), ok.Trunc, ok.Limit)
	fmt.Printf("visible text      %q\n", visibleText(ok.HTML, 300))
}

var (
	dropBlocks = regexp.MustCompile(`(?is)<(script|style|noscript|template)\b.*?</\s*(script|style|noscript|template)\s*>`)
	tags       = regexp.MustCompile(`(?s)<[^>]*>`)
	space      = regexp.MustCompile(`\s+`)
)

// visibleText is a rough reading of the rendered HTML for the summary: not what idp-web's extraction will give.
func visibleText(html string, n int) string {
	t := dropBlocks.ReplaceAllString(html, " ")
	t = tags.ReplaceAllString(t, " ")
	t = strings.NewReplacer("&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'").Replace(t)
	t = strings.TrimSpace(space.ReplaceAllString(t, " "))
	if utf8.RuneCountInString(t) > n {
		return string([]rune(t)[:n])
	}
	return t
}

func probe(addrs []string) {
	bad := false
	for _, a := range addrs {
		c, err := net.DialTimeout("tcp", a, 5*time.Second)
		if err == nil {
			c.Close()
			fmt.Printf("  REACHED     %s\n", a)
			bad = true
		} else {
			fmt.Printf("  unreachable %s\n", a)
		}
	}
	if bad {
		os.Exit(1)
	}
}

func audit(r io.Reader) {
	type key struct{ host, port, decision, reason string }
	counts := map[key]int{}
	bytesBy := map[key]int64{}
	total := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l map[string]any
		if json.Unmarshal(sc.Bytes(), &l) != nil || l["msg"] != "egress" {
			continue
		}
		k := key{fmt.Sprint(l["host"]), fmt.Sprint(l["port"]), fmt.Sprint(l["decision"]), fmt.Sprint(l["reason"])}
		counts[k]++
		if b, ok := l["bytes"].(float64); ok {
			bytesBy[k] += int64(b)
		}
		total++
	}
	fmt.Printf("proxy audit       %d request lines\n", total)
	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i].host < keys[j].host
	})
	for _, k := range keys {
		fmt.Printf("  %-6s %-14s %5d x  %s:%s  bytes %d\n", k.decision, k.reason, counts[k], k.host, k.port, bytesBy[k])
	}
}
