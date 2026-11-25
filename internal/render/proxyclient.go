package render

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"idp-browser/internal/proxy"
)

// proxyClient makes a render live at the egress proxy and ends it (internal/proxy/admin.go).
type proxyClient struct {
	base string
	key  []byte
	http *http.Client
}

func newProxyClient(base string, key []byte) *proxyClient {
	return &proxyClient{base: base, key: key, http: &http.Client{Timeout: 5 * time.Second}}
}

func (c *proxyClient) do(ctx context.Context, method, id string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/v1/renders/"+url.PathEscape(id), r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(c.key))
	return c.http.Do(req)
}

func (c *proxyClient) register(ctx context.Context, id, token string, life time.Duration, lim proxy.Limits) error {
	resp, err := c.do(ctx, http.MethodPut, id, map[string]any{"token": token, "lifetimeMs": life.Milliseconds(),
		"maxRequests": lim.MaxRequests, "maxBytes": lim.MaxBytes, "maxResponseBytes": lim.MaxResponseBytes})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("the proxy refused the render: %d %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}

func (c *proxyClient) finish(ctx context.Context, id string) (proxy.Usage, error) {
	resp, err := c.do(ctx, http.MethodDelete, id, nil)
	if err != nil {
		return proxy.Usage{}, err
	}
	defer resp.Body.Close()
	var u proxy.Usage
	if resp.StatusCode != http.StatusOK {
		return u, fmt.Errorf("the proxy has no such render: %d", resp.StatusCode)
	}
	return u, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u)
}

// ping says whether the proxy's admin port answers.
func (c *proxyClient) ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/healthz", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("proxy admin: %d", resp.StatusCode)
	}
	return nil
}
