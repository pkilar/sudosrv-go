package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"
	"time"
)

// TestAPI_EndToEnd starts a real server with both the protocol listener and
// the management API enabled, drives an AcceptMessage through the protocol
// path, queries the API to see the session, then closes the client connection
// and asserts the session is gone.
func TestAPI_EndToEnd(t *testing.T) {
	apiAddr := freeAddr(t)
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:          "local",
			ListenAddress: "127.0.0.1:0",
			IdleTimeout:   30 * time.Second,
		},
		LocalStorage: config.LocalStorageConfig{
			LogDirectory:    t.TempDir(),
			DirPermissions:  0750,
			FilePermissions: 0640,
		},
		API: config.APIConfig{
			ListenAddress: apiAddr,
			AuthToken:     "secret",
		},
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { shutdown(srv) })

	if srv.apiServer == nil {
		t.Fatal("apiServer is nil after Start with API config")
	}

	// Wait for the API listener to actually bind. The API server's Start runs
	// asynchronously; poll briefly until a 401 (auth failure) round-trips.
	apiURL := "http://" + apiAddr
	if err := waitForAPI(apiURL); err != nil {
		t.Fatalf("API not ready: %v", err)
	}

	// Open a protocol-level connection and drive a full AcceptMessage through.
	protoAddr := srv.listeners[0].Addr().String()
	conn, err := net.Dial("tcp", protoAddr)
	if err != nil {
		t.Fatalf("Dial protocol: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	proc := protocol.NewProcessorWithCloser(conn, conn, conn)

	// Step 1: ClientHello
	if err := proc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "e2e-test"}},
	}); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	resp, err := proc.ReadServerMessage()
	if err != nil {
		t.Fatalf("read ServerHello: %v", err)
	}
	if resp.GetHello() == nil {
		t.Fatalf("expected ServerHello, got %T", resp.GetType())
	}

	// Step 2: AcceptMessage with the minimum required InfoMsgs.
	acceptMsg := &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix()},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			strInfo("submituser", "alice"),
			strInfo("submithost", "host01"),
			strInfo("runuser", "root"),
			strInfo("command", "/usr/bin/vim"),
			strInfo("ttyname", "/dev/pts/3"),
			strInfo("submitcwd", "/home/alice"),
		},
	}
	if err := proc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg},
	}); err != nil {
		t.Fatalf("write AcceptMessage: %v", err)
	}
	resp, err = proc.ReadServerMessage()
	if err != nil {
		t.Fatalf("read LogId response: %v", err)
	}
	logID := resp.GetLogId()
	if logID == "" {
		t.Fatalf("expected LogId response, got %T", resp.GetType())
	}

	// Step 3: Hit the API and verify the session shows up.
	sessions := listSessionsViaAPI(t, apiURL+"/api/v1/sessions", "secret")
	if len(sessions) != 1 {
		t.Fatalf("expected 1 active session, got %d: %+v", len(sessions), sessions)
	}
	got := sessions[0]
	if got["mode"] != "local" {
		t.Errorf("mode = %v, want local", got["mode"])
	}
	if got["submituser"] != "alice" {
		t.Errorf("submituser = %v, want alice", got["submituser"])
	}
	if got["command"] != "/usr/bin/vim" {
		t.Errorf("command = %v, want /usr/bin/vim", got["command"])
	}
	if got["server_log_id"] != logID {
		t.Errorf("server_log_id = %v, want %q", got["server_log_id"], logID)
	}

	// Step 4: GET by session_id should also work.
	sessionID, _ := got["session_id"].(string)
	if sessionID == "" {
		t.Fatal("session_id missing in API response")
	}
	detail := getSessionViaAPI(t, apiURL+"/api/v1/sessions/"+sessionID, "secret")
	if detail["session_id"] != sessionID {
		t.Errorf("detail session_id = %v, want %q", detail["session_id"], sessionID)
	}

	// Step 5: GET by server_log_id should also work. The base64 log_id may
	// contain "/" so the URL segment must be escaped before issuing the request.
	detail2 := getSessionViaAPI(t, apiURL+"/api/v1/sessions/"+url.PathEscape(logID), "secret")
	if detail2["session_id"] != sessionID {
		t.Errorf("lookup by ServerLogID: session_id = %v, want %q", detail2["session_id"], sessionID)
	}

	// Step 6: Close the client connection. The server-side Handle() defer
	// deregisters the session.
	_ = conn.Close()

	// Wait briefly for the deregister to land. We retry rather than sleep a
	// fixed duration so the test stays fast on healthy systems.
	if err := waitFor(func() bool {
		return len(listSessionsViaAPI(t, apiURL+"/api/v1/sessions", "secret")) == 0
	}, 2*time.Second); err != nil {
		t.Fatalf("session was not deregistered: %v", err)
	}

	// Step 7: GET on a now-vanished session should return 404.
	resp404 := apiRequest(t, apiURL+"/api/v1/sessions/"+sessionID, "secret")
	if resp404.StatusCode != http.StatusNotFound {
		t.Errorf("after deregister: GET status = %d, want 404", resp404.StatusCode)
	}
	resp404.Body.Close()
}

// TestAPI_RelayVisibleDuringFlush asserts that a relay session whose client
// connection has closed remains visible in the management API while its
// background goroutine is still attempting upstream flushes. Hiding it on
// disconnect would defeat the API's purpose for relay-mode operators trying
// to diagnose store-and-forward backlogs.
func TestAPI_RelayVisibleDuringFlush(t *testing.T) {
	apiAddr := freeAddr(t)
	// Pick a free port for the upstream and immediately close the listener so
	// dial attempts get a connection-refused error. The relay session will
	// enter the flushing phase and retry with exponential backoff.
	upstreamAddr := freeAddr(t)

	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:          "relay",
			ListenAddress: "127.0.0.1:0",
			IdleTimeout:   30 * time.Second,
		},
		Relay: config.RelayConfig{
			UpstreamHost:         upstreamAddr,
			ConnectTimeout:       500 * time.Millisecond,
			RelayCacheDirectory:  t.TempDir(),
			ReconnectAttempts:    -1,             // infinite — we cancel via shutdown
			MaxReconnectInterval: 5 * time.Second,
		},
		API: config.APIConfig{
			ListenAddress: apiAddr,
			AuthToken:     "secret",
		},
	})

	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { shutdown(srv) })

	apiURL := "http://" + apiAddr
	if err := waitForAPI(apiURL); err != nil {
		t.Fatalf("API not ready: %v", err)
	}

	// Drive a full relay session: ClientHello, AcceptMessage, ExitMessage.
	conn, err := net.Dial("tcp", srv.listeners[0].Addr().String())
	if err != nil {
		t.Fatalf("Dial protocol: %v", err)
	}
	proc := protocol.NewProcessorWithCloser(conn, conn, conn)

	if err := proc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "e2e-relay"}},
	}); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	if _, err := proc.ReadServerMessage(); err != nil {
		t.Fatalf("read ServerHello: %v", err)
	}

	acceptMsg := &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix()},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			strInfo("submituser", "alice"),
			strInfo("submithost", "host01"),
			strInfo("runuser", "root"),
			strInfo("command", "/usr/bin/vim"),
			strInfo("submitcwd", "/home/alice"),
		},
	}
	if err := proc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg},
	}); err != nil {
		t.Fatalf("write AcceptMessage: %v", err)
	}
	if _, err := proc.ReadServerMessage(); err != nil {
		t.Fatalf("read LogId response: %v", err)
	}

	// Send ExitMessage so the relay session moves into the flush phase.
	if err := proc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	}); err != nil {
		t.Fatalf("write ExitMessage: %v", err)
	}
	// Close the connection. The relay session's background goroutine keeps
	// running because the upstream is unreachable.
	_ = conn.Close()

	// Wait for the session to enter the flushing phase. The connection's
	// teardown does not deregister relay sessions, so the entry must remain.
	if err := waitFor(func() bool {
		ss := listSessionsViaAPI(t, apiURL+"/api/v1/sessions", "secret")
		if len(ss) != 1 {
			return false
		}
		s, _ := ss[0]["session_id"].(string)
		if s == "" {
			return false
		}
		got := getSessionViaAPI(t, apiURL+"/api/v1/sessions/"+s, "secret")
		live, _ := got["live"].(map[string]any)
		phase, _ := live["phase"].(string)
		return phase == "flushing"
	}, 5*time.Second); err != nil {
		t.Fatalf("relay session never reached phase=flushing in API: %v", err)
	}

	// Confirm the summary call also shows the session with mode=relay.
	ss := listSessionsViaAPI(t, apiURL+"/api/v1/sessions", "secret")
	if len(ss) != 1 {
		t.Fatalf("expected 1 active session in flushing phase, got %d", len(ss))
	}
	if ss[0]["mode"] != "relay" {
		t.Errorf("mode = %v, want relay", ss[0]["mode"])
	}

	// shutdown() cancels the server context, which propagates into the relay
	// session's run() and unblocks its retry loop. onDone then deregisters.
}

// TestAPI_DisabledByDefault confirms that an empty APIConfig produces no API
// listener and no extra goroutines.
func TestAPI_DisabledByDefault(t *testing.T) {
	srv := newTestServer(t, &config.Config{
		Server: config.ServerConfig{
			Mode:          "local",
			ListenAddress: "127.0.0.1:0",
		},
		LocalStorage: config.LocalStorageConfig{
			LogDirectory:    t.TempDir(),
			DirPermissions:  0750,
			FilePermissions: 0640,
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer shutdown(srv)
	if srv.apiServer != nil {
		t.Fatal("apiServer is non-nil when APIConfig is empty")
	}
}

func strInfo(key, val string) *pb.InfoMessage {
	return &pb.InfoMessage{Key: key, Value: &pb.InfoMessage_Strval{Strval: val}}
}

// freeAddr asks the kernel for a free TCP port and immediately closes the
// listener. There is a small race window where another process can bind the
// same port before we do, but the API server's bind error would surface in
// the test as an explicit failure.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitForAPI(url string) error {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/api/v1/sessions")
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("API never accepted connections at %s", url)
}

func waitFor(cond func() bool, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("condition not met within %s", timeout)
}

func apiRequest(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func listSessionsViaAPI(t *testing.T, url, token string) []map[string]any {
	t.Helper()
	resp := apiRequest(t, url, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d body=%s", url, resp.StatusCode, body)
	}
	var out struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Sessions
}

func getSessionViaAPI(t *testing.T, url, token string) map[string]any {
	t.Helper()
	resp := apiRequest(t, url, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d body=%s", url, resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}
