// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	"sudosrv/internal/sessions"
	"testing"
	"time"

	"github.com/google/uuid"
)

type stubProvider struct {
	stats sessions.LiveStats
}

func (s *stubProvider) LiveStats() sessions.LiveStats { return s.stats }

func newTestServer(t *testing.T, token string) (*Server, *sessions.Registry) {
	t.Helper()
	reg := sessions.NewRegistry()
	srv, err := NewServer(config.APIConfig{
		ListenAddress: "127.0.0.1:0",
		AuthToken:     token,
	}, reg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, reg
}

func registerSample(reg *sessions.Registry, sessionID, mode string, info map[string]any, stats sessions.LiveStats) sessions.SessionInfo {
	si := sessions.SessionInfo{
		SessionID:    sessionID,
		ServerLogID:  "logid-" + sessionID,
		SessionUUID:  uuid.MustParse("11111111-2222-3333-4444-555555555555"),
		Mode:         mode,
		RemoteAddr:   "10.0.0.5:54321",
		StartedAt:    time.Date(2026, 4, 30, 14, 22, 11, 0, time.UTC),
		SubmitTime:   time.Date(2026, 4, 30, 14, 22, 10, 0, time.UTC),
		ExpectIobufs: true,
		Info:         info,
		Provider:     &stubProvider{stats: stats},
	}
	reg.Register(si)
	return si
}

// withTestServer wires the API server's mux into an httptest.Server so the
// tests do not have to bind a real port.
func withTestServer(t *testing.T, srv *Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(srv.httpSrv.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestNewServer_Validates(t *testing.T) {
	reg := sessions.NewRegistry()
	if _, err := NewServer(config.APIConfig{}, reg); err == nil {
		t.Fatal("expected error for empty ListenAddress")
	}
	if _, err := NewServer(config.APIConfig{ListenAddress: "127.0.0.1:0"}, nil); err == nil {
		t.Fatal("expected error for nil registry")
	}
	if _, err := NewServer(config.APIConfig{ListenAddress: "127.0.0.1:0"}, reg); err == nil {
		t.Fatal("expected error when no token is configured")
	}
}

func TestLoadToken_FromFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("  the-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	got, err := loadToken(config.APIConfig{AuthTokenFile: tokenPath})
	if err != nil {
		t.Fatalf("loadToken: %v", err)
	}
	if got != "the-token" {
		t.Fatalf("loadToken = %q, want %q", got, "the-token")
	}
}

func TestLoadToken_EmptyFileRejected(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("   \n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if _, err := loadToken(config.APIConfig{AuthTokenFile: tokenPath}); err == nil {
		t.Fatal("expected error for empty token file")
	}
}

func TestLoadToken_FilePreferredOverInline(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("from-file"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	got, err := loadToken(config.APIConfig{AuthTokenFile: tokenPath, AuthToken: "inline"})
	if err != nil {
		t.Fatalf("loadToken: %v", err)
	}
	if got != "from-file" {
		t.Fatalf("loadToken = %q, want file value", got)
	}
}

func TestAuth_RejectsMissingHeader(t *testing.T) {
	srv, _ := newTestServer(t, "secret")
	ts := withTestServer(t, srv)

	resp, err := http.Get(ts.URL + "/api/v1/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body["error"], "Authorization") {
		t.Fatalf("error = %q, want contains \"Authorization\"", body["error"])
	}
}

func TestAuth_RejectsWrongScheme(t *testing.T) {
	srv, _ := newTestServer(t, "secret")
	ts := withTestServer(t, srv)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAuth_RejectsWrongToken(t *testing.T) {
	// Covers two cases: a different-length wrong token (the easy case the
	// constant-time compare's length check short-circuits) AND a same-length
	// wrong token (which exercises the equal-length compare path). A future
	// "optimization" that replaces the constant-time compare with == would
	// still pass the former; the latter is what catches that regression.
	cases := []struct {
		name    string
		token   string
	}{
		{"different length", "wrong"},
		{"same length, single char differs", "sxcret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newTestServer(t, "secret")
			ts := withTestServer(t, srv)

			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/sessions", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

func TestAuth_AcceptsCorrectToken(t *testing.T) {
	srv, _ := newTestServer(t, "secret")
	ts := withTestServer(t, srv)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestList_EmptyRegistry(t *testing.T) {
	srv, _ := newTestServer(t, "tok")
	ts := withTestServer(t, srv)

	body := authedGet(t, ts.URL+"/api/v1/sessions", "tok")
	var out struct {
		Count    int              `json:"count"`
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Count != 0 {
		t.Fatalf("count = %d, want 0", out.Count)
	}
	if out.Sessions == nil {
		t.Fatal("sessions field must be a JSON array, even when empty")
	}
}

func TestList_PopulatedRegistry(t *testing.T) {
	srv, reg := newTestServer(t, "tok")
	ts := withTestServer(t, srv)

	registerSample(reg, "sess-A", "local", map[string]any{
		"submituser": "alice",
		"submithost": "host01",
		"runuser":    "root",
		"command":    "/usr/bin/vim",
		"ttyname":    "/dev/pts/3",
	}, sessions.LiveStats{MessagesReceived: 12, LastActivity: time.Date(2026, 4, 30, 14, 22, 18, 0, time.UTC)})

	body := authedGet(t, ts.URL+"/api/v1/sessions", "tok")
	var out struct {
		Count    int              `json:"count"`
		Sessions []sessionSummary `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, body)
	}
	if out.Count != 1 || len(out.Sessions) != 1 {
		t.Fatalf("count=%d sessions=%d, want 1/1", out.Count, len(out.Sessions))
	}
	got := out.Sessions[0]
	if got.SessionID != "sess-A" || got.SubmitUser != "alice" || got.Command != "/usr/bin/vim" {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if got.MessagesReceived != 12 {
		t.Fatalf("MessagesReceived = %d, want 12", got.MessagesReceived)
	}
}

func TestGet_ByUUID(t *testing.T) {
	srv, reg := newTestServer(t, "tok")
	ts := withTestServer(t, srv)

	registerSample(reg, "sess-A", "local", map[string]any{
		"submituser": "alice",
		"runargv":    []string{"vim", "/etc/hosts"},
	}, sessions.LiveStats{MessagesReceived: 7, BytesReceived: 1024, SessionDir: "/var/log/x"})

	body := authedGet(t, ts.URL+"/api/v1/sessions/sess-A", "tok")
	var out sessionDetail
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, body)
	}
	if out.SessionID != "sess-A" {
		t.Fatalf("SessionID = %q", out.SessionID)
	}
	if out.Live.MessagesReceived != 7 || out.Live.BytesReceived != 1024 || out.Live.SessionDir != "/var/log/x" {
		t.Fatalf("live = %+v", out.Live)
	}
	// runargv survives as a JSON array of strings even though the source map
	// uses []string; the test asserts json round-tripping does not lose shape.
	got, ok := out.Info["runargv"].([]any)
	if !ok || len(got) != 2 {
		t.Fatalf("runargv = %v", out.Info["runargv"])
	}
}

func TestGet_ByServerLogID(t *testing.T) {
	srv, reg := newTestServer(t, "tok")
	ts := withTestServer(t, srv)

	registerSample(reg, "sess-A", "relay", map[string]any{}, sessions.LiveStats{})

	body := authedGet(t, ts.URL+"/api/v1/sessions/logid-sess-A", "tok")
	var out sessionDetail
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, body)
	}
	if out.SessionID != "sess-A" {
		t.Fatalf("SessionID = %q, want sess-A (lookup by ServerLogID)", out.SessionID)
	}
}

func TestGet_NotFound(t *testing.T) {
	srv, _ := newTestServer(t, "tok")
	ts := withTestServer(t, srv)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/sessions/missing", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "session not found" {
		t.Fatalf("error = %q, want \"session not found\"", body["error"])
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv, _ := newTestServer(t, "tok")
	ts := withTestServer(t, srv)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+"/api/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func authedGet(t *testing.T, url, token string) []byte {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d body=%s", url, resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}
