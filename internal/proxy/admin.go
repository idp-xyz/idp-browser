package proxy

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Admin is the renderer's way to make a render live and to end it (ADR-0001 D5). It is on a port of its own, behind a
// key file that the renderer and the proxy share, and nothing the browser can reach is on it:
//
//	PUT    /v1/renders/{id}  {"token": "<base64 or hex, at least 16 bytes>", "lifetimeMs": 20000, "maxRequests": 300, ...}  -> 204
//	DELETE /v1/renders/{id}  -> 200 {"requests": ..., "blocked": ..., "bytesIn": ..., "bytesOut": ..., "limit": ..., "refused": [...]}
//
// The limits are optional and are lowered to the proxy's own ceiling when they are larger.
type Admin struct {
	Registry *Registry
	Key      []byte // the bearer secret, at least 32 bytes
}

type registration struct {
	Token            string `json:"token"`
	LifetimeMs       int64  `json:"lifetimeMs"`
	MaxRequests      int    `json:"maxRequests"`
	MaxBytes         int64  `json:"maxBytes"`
	MaxResponseBytes int64  `json:"maxResponseBytes"`
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" { // no key: it says nothing but that the process runs
		io.WriteString(w, "ok\n")
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(a.Key) < 32 || subtle.ConstantTimeCompare([]byte(got), a.Key) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, "/v1/renders/")
	if !ok || id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var reg registration
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil || json.Unmarshal(body, &reg) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		err = a.Registry.Register(id, []byte(reg.Token), time.Duration(reg.LifetimeMs)*time.Millisecond,
			Limits{MaxRequests: reg.MaxRequests, MaxBytes: reg.MaxBytes, MaxResponseBytes: reg.MaxResponseBytes})
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		u, ok := a.Registry.Finish(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(u)
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
