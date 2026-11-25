// Package service is the HTTP API of the renderer: POST /render, from idp-web only (ADR-0001 D7, D8).
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"idp-browser/internal/caller"
	"idp-browser/internal/render"
)

// MaxBody is the largest request body read (a URL and two numbers).
const MaxBody = 16 << 10

// Renderer is what the service needs of the pool.
type Renderer interface {
	Render(ctx context.Context, req render.Request) (*render.Result, error)
}

// Server is the handler of the API port.
type Server struct {
	Renderer Renderer
	Verifier *caller.Verifier
	Log      *slog.Logger
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message,omitempty"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var b errorBody
	b.Error.Code, b.Error.Message = code, msg
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(b)
}

// statusOf maps a reason code to the HTTP status; idp-web reads the code in the body, the status is for the humans and proxies.
func statusOf(code string) int {
	switch code {
	case render.InvalidRequest:
		return http.StatusBadRequest
	case render.NotAllowed:
		return http.StatusUnprocessableEntity
	case render.RenderBusy:
		return http.StatusServiceUnavailable
	case render.RenderTimeout:
		return http.StatusGatewayTimeout
	default: // render_failed, blocked_by_site
		return http.StatusBadGateway
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/render" || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, render.InvalidRequest, "POST only")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, render.InvalidRequest, "the body is too large")
		return
	}
	// Who is asking comes before everything else, and what the request says is not looked at until it is known: an
	// unsigned, wrongly signed, expired or replayed request ends here, before any browser work (ADR-0001 D8).
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		bearer = ""
	}
	if err := s.Verifier.Verify(bearer, r.Method, r.URL.Path, body); err != nil {
		s.Log.Warn("caller assertion refused", "why", err.Error(), "client", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "unauthorized", "")
		return
	}
	var req render.Request
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeError(w, http.StatusBadRequest, render.InvalidRequest, "the body is not a render request")
		return
	}
	res, err := s.Renderer.Render(r.Context(), req)
	if err != nil {
		var re *render.Error
		if !errors.As(err, &re) {
			re = &render.Error{Code: render.RenderFailed, Msg: "the render failed"}
		}
		s.Log.Info("render refused or failed", "code", re.Code, "msg", re.Msg)
		writeError(w, statusOf(re.Code), re.Code, re.Msg)
		return
	}
	s.Log.Info("render", "status", res.Status, "requests", res.Requests, "blocked", res.Blocked, "bytes", res.Bytes, "ms", res.MS, "truncated", res.Truncated)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}
