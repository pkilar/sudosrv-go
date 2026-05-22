// SPDX-License-Identifier: Apache-2.0

// Package api implements the optional management HTTP API for sudosrv. It
// exposes read-only endpoints for enumerating active sessions and querying
// per-session metadata. Authentication is a static bearer token loaded from
// configuration; transport security is provided by an optional TLS listener.
package api

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sudosrv/internal/config"
	"sudosrv/internal/sessions"
	"time"
)

// Server owns the management HTTP server. Construct with NewServer, then call
// Listen synchronously to bind the address (so port-in-use and TLS load
// errors surface at startup), and finally Serve to begin handling requests.
// Shutdown stops Serve cleanly.
type Server struct {
	cfg      config.APIConfig
	registry *sessions.Registry
	httpSrv  *http.Server
	listener net.Listener
	token    string
}

// NewServer validates the configuration, loads the bearer token, and prepares
// an *http.Server. The server is not yet listening when this returns; call
// Listen to bind synchronously, then Serve to begin handling requests.
func NewServer(cfg config.APIConfig, registry *sessions.Registry) (*Server, error) {
	if cfg.ListenAddress == "" {
		return nil, errors.New("api: ListenAddress is required")
	}
	if registry == nil {
		return nil, errors.New("api: registry is required")
	}
	token, err := loadToken(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, registry: registry, token: token}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/sessions", s.authMW(s.handleList))
	mux.HandleFunc("GET /api/v1/sessions/{id}", s.authMW(s.handleGet))

	s.httpSrv = &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s, nil
}

// Listen synchronously binds the configured address and, if TLS is configured,
// loads and validates the certificate pair. Bind failures (e.g. port already
// in use) and TLS-load failures are returned here so callers can detect them
// at startup rather than discover the API silently absent.
func (s *Server) Listen() error {
	if s.listener != nil {
		return errors.New("api: Listen called more than once")
	}
	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("api: load tls keypair: %w", err)
		}
		ln, err := tls.Listen("tcp", s.cfg.ListenAddress, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			return fmt.Errorf("api: listen on %s: %w", s.cfg.ListenAddress, err)
		}
		s.listener = ln
		return nil
	}
	ln, err := net.Listen("tcp", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("api: listen on %s: %w", s.cfg.ListenAddress, err)
	}
	s.listener = ln
	return nil
}

// Serve handles HTTP requests on the listener bound by Listen. It blocks
// until Shutdown is called and returns http.ErrServerClosed in that case.
func (s *Server) Serve() error {
	if s.listener == nil {
		return errors.New("api: Serve called before Listen")
	}
	return s.httpSrv.Serve(s.listener)
}

// Addr returns the bound listener's address. Useful in tests where the
// configured address may use port 0.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Shutdown gracefully stops the HTTP server. In-flight requests are allowed
// to finish until ctx is cancelled, after which they are forcibly closed.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// loadToken returns the configured bearer token, preferring AuthTokenFile over
// AuthToken. The file's contents are trimmed of surrounding whitespace.
func loadToken(cfg config.APIConfig) (string, error) {
	if cfg.AuthTokenFile != "" {
		b, err := os.ReadFile(cfg.AuthTokenFile)
		if err != nil {
			return "", fmt.Errorf("api: read auth_token_file %q: %w", cfg.AuthTokenFile, err)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			return "", fmt.Errorf("api: auth_token_file %q is empty", cfg.AuthTokenFile)
		}
		return token, nil
	}
	if cfg.AuthToken != "" {
		return cfg.AuthToken, nil
	}
	return "", errors.New("api: no auth_token or auth_token_file configured")
}

// authMW enforces a constant-time bearer-token check on every request.
func (s *Server) authMW(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, prefix) {
			writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		provided := h[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	}
}

// handleList responds with a summary of every active session, sorted newest-first.
func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	sessionsSnap := s.registry.Snapshot()
	out := struct {
		Count    int              `json:"count"`
		Sessions []sessionSummary `json:"sessions"`
	}{
		Count:    len(sessionsSnap),
		Sessions: make([]sessionSummary, 0, len(sessionsSnap)),
	}
	for _, info := range sessionsSnap {
		out.Sessions = append(out.Sessions, summarize(info))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGet responds with the full metadata for a single session, looked up by
// session_id (UUID) or server_log_id (base64).
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	info, ok := s.registry.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, detail(info))
}

// sessionSummary is the per-session record returned by the list endpoint. It
// pulls a small subset of fields out of the InfoMsgs map for at-a-glance
// triage; clients needing every field should call the per-session endpoint.
type sessionSummary struct {
	SessionID        string    `json:"session_id"`
	ServerLogID      string    `json:"server_log_id,omitempty"`
	Mode             string    `json:"mode"`
	SubmitUser       string    `json:"submituser,omitempty"`
	SubmitHost       string    `json:"submithost,omitempty"`
	RunUser          string    `json:"runuser,omitempty"`
	Command          string    `json:"command,omitempty"`
	TTYName          string    `json:"ttyname,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	SubmitTime       time.Time `json:"submit_time,omitzero"`
	RemoteAddr       string    `json:"remote_addr,omitempty"`
	MessagesReceived int64     `json:"messages_received"`
	LastActivity     time.Time `json:"last_activity,omitzero"`
}

// sessionDetail is the full per-session record returned by the GET endpoint.
type sessionDetail struct {
	SessionID    string         `json:"session_id"`
	ServerLogID  string         `json:"server_log_id,omitempty"`
	Mode         string         `json:"mode"`
	RemoteAddr   string         `json:"remote_addr,omitempty"`
	StartedAt    time.Time      `json:"started_at"`
	SubmitTime   time.Time      `json:"submit_time,omitzero"`
	ExpectIobufs bool           `json:"expect_iobufs"`
	Info         map[string]any `json:"info"`
	Live         liveStats      `json:"live"`
}

type liveStats struct {
	MessagesReceived int64     `json:"messages_received"`
	BytesReceived    int64     `json:"bytes_received"`
	LastActivity     time.Time `json:"last_activity,omitzero"`
	SessionDir       string    `json:"session_dir,omitempty"`
	CacheFile        string    `json:"cache_file,omitempty"`
	Phase            string    `json:"phase,omitempty"`
}

func summarize(info sessions.SessionInfo) sessionSummary {
	// The string-typed assertion shorthand returns "" on miss, which is what
	// the omitempty tags on these fields expect anyway, so no explicit ok-check
	// is needed.
	out := sessionSummary{
		SessionID:   info.SessionID,
		ServerLogID: info.ServerLogID,
		Mode:        info.Mode,
		StartedAt:   info.StartedAt,
		SubmitTime:  info.SubmitTime,
		RemoteAddr:  info.RemoteAddr,
	}
	out.SubmitUser, _ = info.Info["submituser"].(string)
	out.SubmitHost, _ = info.Info["submithost"].(string)
	out.RunUser, _ = info.Info["runuser"].(string)
	out.Command, _ = info.Info["command"].(string)
	out.TTYName, _ = info.Info["ttyname"].(string)

	if info.Provider != nil {
		stats := info.Provider.LiveStats()
		out.MessagesReceived = stats.MessagesReceived
		out.LastActivity = stats.LastActivity
	}
	return out
}

func detail(info sessions.SessionInfo) sessionDetail {
	out := sessionDetail{
		SessionID:    info.SessionID,
		ServerLogID:  info.ServerLogID,
		Mode:         info.Mode,
		RemoteAddr:   info.RemoteAddr,
		StartedAt:    info.StartedAt,
		SubmitTime:   info.SubmitTime,
		ExpectIobufs: info.ExpectIobufs,
		Info:         info.Info,
	}
	if info.Provider != nil {
		s := info.Provider.LiveStats()
		out.Live = liveStats{
			MessagesReceived: s.MessagesReceived,
			BytesReceived:    s.BytesReceived,
			LastActivity:     s.LastActivity,
			SessionDir:       s.SessionDir,
			CacheFile:        s.CacheFile,
			Phase:            s.Phase,
		}
	}
	return out
}

// writeJSON marshals body into a buffer first so an encoding failure can
// produce a 500 response instead of a 200 with truncated JSON. Once
// WriteHeader has fired, the status is locked and the client will see
// whatever we already wrote.
func writeJSON(w http.ResponseWriter, status int, body any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		slog.Error("api: failed to encode JSON response", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(buf.Bytes()); err != nil {
		slog.Error("api: failed to write JSON response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
