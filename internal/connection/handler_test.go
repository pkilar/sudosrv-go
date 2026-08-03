// SPDX-License-Identifier: Apache-2.0
// Filename: internal/connection/handler_test.go
package connection

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	"sudosrv/internal/sessions"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mockSessionHandler is a mock implementation of the SessionHandler interface for testing.
type mockSessionHandler struct {
	t              *testing.T
	HandleClientFn func(msg *pb.ClientMessage) (*pb.ServerMessage, error)
	CloseFn        func() error
}

func (m *mockSessionHandler) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	if m.HandleClientFn != nil {
		return m.HandleClientFn(msg)
	}
	m.t.Fatal("HandleClientMessage called unexpectedly")
	return nil, nil
}

func (m *mockSessionHandler) Close() error {
	if m.CloseFn != nil {
		return m.CloseFn()
	}
	return nil
}

func TestConnectionHandler(t *testing.T) {
	// Default test config
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "local",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
		LocalStorage: config.LocalStorageConfig{}, // Needed for function signature
	}

	t.Run("ClientHelloFlow", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		handler := NewHandler(serverConn, cfg)
		var wg sync.WaitGroup
		wg.Go(handler.Handle)

		clientProc := protocol.NewProcessor(clientConn, clientConn)

		// Client sends Hello
		helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "test-harness"}}}
		if err := clientProc.WriteClientMessage(helloMsg); err != nil {
			t.Fatalf("Client failed to write Hello: %v", err)
		}

		// Client reads server response
		serverResponse, err := clientProc.ReadServerMessage()
		if err != nil {
			t.Fatalf("Client failed to read server response: %v", err)
		}

		if serverHello := serverResponse.GetHello(); serverHello == nil {
			t.Fatal("Expected ServerHello response, got something else")
		}

		serverConn.Close()
		wg.Wait()
	})

	t.Run("AcceptMessageStartsLocalStorageSession", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		handler := NewHandler(serverConn, cfg)
		sessionClosed := make(chan bool, 1)

		// Override the session factory on the handler instance to return our mock
		handler.sessionFactories.newLocalStorageSession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error) {
			return &mockSessionHandler{
				t: t,
				HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
					return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: sessionUUID.String()}}, nil
				},
				CloseFn: func() error {
					sessionClosed <- true
					return nil
				},
			}, nil
		}

		go handler.Handle()

		clientProc := protocol.NewProcessor(clientConn, clientConn)

		// Client sends Accept (with required fields)
		acceptMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
			ExpectIobufs: true,
			SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix(), TvNsec: 0},
			InfoMsgs: []*pb.InfoMessage{
				{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
				{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "testhost"}},
				{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
				{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"}},
			},
		}}}
		clientProc.WriteClientMessage(acceptMsg)
		clientProc.ReadServerMessage()

		serverConn.Close()

		select {
		case <-sessionClosed:
		case <-time.After(1 * time.Second):
			t.Fatal("Session Close() was not called on connection termination")
		}
	})

}

// mockConn implements net.Conn for testing runcwd fallback logic
type mockConnForRuncwd struct {
	net.Conn
}

func (m *mockConnForRuncwd) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

// Helper function to create a test handler for runcwd tests
func createTestHandlerForRuncwd() *Handler {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:                      "local",
			ServerID:                  "test-server",
			IdleTimeout:               0,
			ServerOperationalLogLevel: "info",
		},
	}
	return NewHandler(&mockConnForRuncwd{}, cfg)
}

// Helper function to create AcceptMessage with given info messages for runcwd tests
func createAcceptMessageForRuncwd(infoMsgs []*pb.InfoMessage) *pb.AcceptMessage {
	return &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 1234567890, TvNsec: 0},
		ExpectIobufs: true,
		InfoMsgs:     infoMsgs,
	}
}

// Helper function to find info message value by key
func findInfoValue(acceptMsg *pb.AcceptMessage, key string) string {
	for _, info := range acceptMsg.InfoMsgs {
		if info.GetKey() == key {
			return info.GetStrval()
		}
	}
	return ""
}

func TestApplyRuncwdFallback_Tier1_ExplicitRuncwd(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: explicit runcwd is set and valid
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "runcwd", Value: &pb.InfoMessage_Strval{Strval: "/explicit/path"}},
		{Key: "submitcwd", Value: &pb.InfoMessage_Strval{Strval: "/submit/cwd"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
		{Key: "login_shell", Value: &pb.InfoMessage_Strval{Strval: "true"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/explicit/path" {
		t.Errorf("Expected runcwd to remain '/explicit/path', got '%s'", result)
	}
}

func TestApplyRuncwdFallback_Tier1_WildcardRuncwd(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: runcwd is set to "*" (should trigger fallback)
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "runcwd", Value: &pb.InfoMessage_Strval{Strval: "*"}},
		{Key: "submitcwd", Value: &pb.InfoMessage_Strval{Strval: "/submit/cwd"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
		{Key: "login_shell", Value: &pb.InfoMessage_Strval{Strval: "true"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/home/runuser" {
		t.Errorf("Expected runcwd to be '/home/runuser' (tier 2), got '%s'", result)
	}
}

func TestApplyRuncwdFallback_Tier2_LoginShell(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: no explicit runcwd, but login shell mode with runhome
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "submitcwd", Value: &pb.InfoMessage_Strval{Strval: "/submit/cwd"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
		{Key: "login_shell", Value: &pb.InfoMessage_Strval{Strval: "true"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/home/runuser" {
		t.Errorf("Expected runcwd to be '/home/runuser' (tier 2), got '%s'", result)
	}
}

func TestApplyRuncwdFallback_Tier2_LoginShellNumeric(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: login_shell as "1" (numeric true)
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "submitcwd", Value: &pb.InfoMessage_Strval{Strval: "/submit/cwd"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
		{Key: "login_shell", Value: &pb.InfoMessage_Strval{Strval: "1"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/home/runuser" {
		t.Errorf("Expected runcwd to be '/home/runuser' (tier 2), got '%s'", result)
	}
}

func TestApplyRuncwdFallback_Tier3_SubmitCwd(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: no explicit runcwd, not login shell, fall back to submitcwd
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "submitcwd", Value: &pb.InfoMessage_Strval{Strval: "/submit/cwd"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
		{Key: "login_shell", Value: &pb.InfoMessage_Strval{Strval: "false"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/submit/cwd" {
		t.Errorf("Expected runcwd to be '/submit/cwd' (tier 3), got '%s'", result)
	}
}

func TestApplyRuncwdFallback_Tier3_Cwd(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: fall back to "cwd" if "submitcwd" is not available
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "cwd", Value: &pb.InfoMessage_Strval{Strval: "/current/working/dir"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/current/working/dir" {
		t.Errorf("Expected runcwd to be '/current/working/dir' (tier 3), got '%s'", result)
	}
}

func TestApplyRuncwdFallback_NoLoginShellWithRunhome(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: runhome exists but not login shell, should use submitcwd
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "submitcwd", Value: &pb.InfoMessage_Strval{Strval: "/submit/cwd"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
		// no login_shell field or false
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/submit/cwd" {
		t.Errorf("Expected runcwd to be '/submit/cwd' (tier 3), got '%s'", result)
	}
}

func TestApplyRuncwdFallback_EmptyRuncwd(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: empty runcwd should trigger fallback
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "runcwd", Value: &pb.InfoMessage_Strval{Strval: ""}},
		{Key: "submitcwd", Value: &pb.InfoMessage_Strval{Strval: "/submit/cwd"}},
		{Key: "runhome", Value: &pb.InfoMessage_Strval{Strval: "/home/runuser"}},
		{Key: "login_shell", Value: &pb.InfoMessage_Strval{Strval: "true"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "/home/runuser" {
		t.Errorf("Expected runcwd to be '/home/runuser' (tier 2), got '%s'", result)
	}
}

func TestApplyRuncwdFallback_NoFallbackData(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	// Test case: no fallback data available
	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "somekey", Value: &pb.InfoMessage_Strval{Strval: "somevalue"}},
	})

	handler.applyRuncwdFallback(acceptMsg)

	result := findInfoValue(acceptMsg, "runcwd")
	if result != "" {
		t.Errorf("Expected runcwd to remain empty, got '%s'", result)
	}
}

func TestSetOrUpdateInfoMessage_NewMessage(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "existing", Value: &pb.InfoMessage_Strval{Strval: "value"}},
	})

	handler.setOrUpdateInfoMessage(acceptMsg, "newkey", "newvalue")

	result := findInfoValue(acceptMsg, "newkey")
	if result != "newvalue" {
		t.Errorf("Expected new info message to be added with value 'newvalue', got '%s'", result)
	}

	// Ensure existing message is unchanged
	existing := findInfoValue(acceptMsg, "existing")
	if existing != "value" {
		t.Errorf("Expected existing message to remain 'value', got '%s'", existing)
	}
}

func TestPreSessionAlertMessage(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "local",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
	}

	handler := NewHandler(serverConn, cfg)
	go handler.Handle()

	clientProc := protocol.NewProcessor(clientConn, clientConn)

	// Send an AlertMessage before any session
	alertMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_AlertMsg{
			AlertMsg: &pb.AlertMessage{
				AlertTime: &pb.TimeSpec{TvSec: 1700000000, TvNsec: 0},
				Reason:    "test alert",
			},
		},
	}
	if err := clientProc.WriteClientMessage(alertMsg); err != nil {
		t.Fatalf("Client failed to write AlertMsg: %v", err)
	}

	// No response expected — send another message to verify connection is alive
	helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "test"}}}
	if err := clientProc.WriteClientMessage(helloMsg); err != nil {
		t.Fatalf("Client failed to write Hello after alert: %v", err)
	}

	resp, err := clientProc.ReadServerMessage()
	if err != nil {
		t.Fatalf("Client failed to read response after alert: %v", err)
	}
	if resp.GetHello() == nil {
		t.Fatal("Expected ServerHello after alert, got something else")
	}

	serverConn.Close()
}

func TestPreSessionRejectEventLogging(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	tmpDir := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "local",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
		LocalStorage: config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		},
	}

	handler := NewHandler(serverConn, cfg)
	go handler.Handle()

	clientProc := protocol.NewProcessor(clientConn, clientConn)

	// Send a RejectMessage
	rejectMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_RejectMsg{
			RejectMsg: &pb.RejectMessage{
				SubmitTime: &pb.TimeSpec{TvSec: 1700000000, TvNsec: 0},
				Reason:     "command not allowed",
				InfoMsgs: []*pb.InfoMessage{
					{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/usr/sbin/reboot"}},
					{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "eviluser"}},
					{Key: "event_type", Value: &pb.InfoMessage_Strval{Strval: "accept"}},
					{Key: "reason", Value: &pb.InfoMessage_Strval{Strval: "attacker override"}},
					{Key: "submit_time", Value: &pb.InfoMessage_Strval{Strval: "attacker time"}},
				},
			},
		},
	}
	if err := clientProc.WriteClientMessage(rejectMsg); err != nil {
		t.Fatalf("Client failed to write RejectMsg: %v", err)
	}

	// No response expected — verify connection is still alive
	helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "test"}}}
	if err := clientProc.WriteClientMessage(helloMsg); err != nil {
		t.Fatalf("Client failed to write Hello after reject: %v", err)
	}

	resp, err := clientProc.ReadServerMessage()
	if err != nil {
		t.Fatalf("Client failed to read response after reject: %v", err)
	}
	if resp.GetHello() == nil {
		t.Fatal("Expected ServerHello after reject, got something else")
	}

	serverConn.Close()

	// Verify a log.json file was created somewhere in tmpDir
	found := false
	filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Name() == "log.json" {
			found = true
			data, _ := os.ReadFile(path)
			var eventRecord map[string]any
			if err := json.Unmarshal(data, &eventRecord); err != nil {
				t.Errorf("Failed to unmarshal reject event log: %v", err)
				return nil
			}
			if eventRecord["event_type"] != "reject" {
				t.Errorf("Expected event_type 'reject', got '%v'", eventRecord["event_type"])
			}
			if eventRecord["reason"] != "command not allowed" {
				t.Errorf("Expected reason 'command not allowed', got '%v'", eventRecord["reason"])
			}
			expectedSubmitTime := time.Unix(1700000000, 0).UTC().Format(time.RFC3339Nano)
			if eventRecord["submit_time"] != expectedSubmitTime {
				t.Errorf("Expected submit_time '%s', got '%v'", expectedSubmitTime, eventRecord["submit_time"])
			}
			if eventRecord["command"] != "/usr/sbin/reboot" {
				t.Errorf("Expected command '/usr/sbin/reboot', got '%v'", eventRecord["command"])
			}
		}
		return nil
	})

	if !found {
		t.Error("No log.json reject event file was created")
	}
}

func TestEventOnlyAcceptLocalLogging(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	tmpDir := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "local",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
		LocalStorage: config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			IologDir:        "%{LIVEDIR}/%{user}",
			IologFile:       "%{seq}",
			DirPermissions:  0755,
			FilePermissions: 0644,
		},
	}

	handler := NewHandler(serverConn, cfg)
	var wg sync.WaitGroup
	wg.Go(handler.Handle)

	clientProc := protocol.NewProcessor(clientConn, clientConn)
	acceptMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{
			AcceptMsg: &pb.AcceptMessage{
				SubmitTime:   &pb.TimeSpec{TvSec: 1700000000, TvNsec: 0},
				ExpectIobufs: false,
				InfoMsgs: []*pb.InfoMessage{
					{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
					{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "testhost"}},
					{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
					{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/id"}},
				},
			},
		},
	}
	if err := clientProc.WriteClientMessage(acceptMsg); err != nil {
		t.Fatalf("Client failed to write event-only AcceptMsg: %v", err)
	}
	if err := clientProc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 7}},
	}); err != nil {
		t.Fatalf("Client failed to write event-only ExitMsg: %v", err)
	}

	clientConn.Close()
	wg.Wait()

	var eventRecord map[string]any
	filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.Name() != "log.json" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("ReadFile(%s): %v", path, readErr)
			return nil
		}
		if err := json.Unmarshal(data, &eventRecord); err != nil {
			t.Errorf("Failed to unmarshal event-only log: %v", err)
		}
		return nil
	})
	if eventRecord == nil {
		t.Fatal("No log.json event-only accept file was created")
	}
	if eventRecord["event_type"] != "accept" {
		t.Errorf("Expected event_type 'accept', got %v", eventRecord["event_type"])
	}
	if eventRecord["command"] != "/bin/id" {
		t.Errorf("Expected command '/bin/id', got %v", eventRecord["command"])
	}
	if eventRecord["exit_value"] != float64(7) {
		t.Errorf("Expected exit_value 7, got %v", eventRecord["exit_value"])
	}
}

func TestEventOnlyAcceptRelayRoutesExitWithoutLogIDResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "relay",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
		Relay: config.RelayConfig{
			UpstreamHost:        "127.0.0.1:30344",
			RelayCacheDirectory: t.TempDir(),
		},
	}

	handler := NewHandler(serverConn, cfg)
	exitRouted := make(chan struct{}, 1)
	handler.sessionFactories.newRelaySession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, relayCfg *config.RelayConfig) (SessionHandler, error) {
		return &mockSessionHandler{
			t: t,
			HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
				if msg.GetExitMsg() != nil {
					exitRouted <- struct{}{}
				}
				return nil, nil
			},
			CloseFn: func() error { return nil },
		}, nil
	}

	var wg sync.WaitGroup
	wg.Go(handler.Handle)

	clientProc := protocol.NewProcessor(clientConn, clientConn)
	if err := clientProc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{
			AcceptMsg: &pb.AcceptMessage{
				SubmitTime:   &pb.TimeSpec{TvSec: 1700000000, TvNsec: 0},
				ExpectIobufs: false,
				InfoMsgs: []*pb.InfoMessage{
					{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
					{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "testhost"}},
					{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
					{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/id"}},
				},
			},
		},
	}); err != nil {
		t.Fatalf("Client failed to write event-only AcceptMsg: %v", err)
	}
	if err := clientProc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	}); err != nil {
		t.Fatalf("Client failed to write event-only ExitMsg: %v", err)
	}

	select {
	case <-exitRouted:
	case <-time.After(time.Second):
		t.Fatal("event-only ExitMsg was not routed to relay session")
	}

	serverConn.Close()
	wg.Wait()
}

func TestRestartMessageStartsSession(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "local",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
	}

	handler := NewHandler(serverConn, cfg)
	restartCalled := false

	// Override the restart factory to use a mock
	handler.sessionFactories.newLocalRestartSession = func(restartMsg *pb.RestartMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
		restartCalled = true
		return &mockSessionHandler{
			t: t,
			HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
				return nil, nil
			},
			CloseFn: func() error { return nil },
		}, nil
	}

	go handler.Handle()

	clientProc := protocol.NewProcessor(clientConn, clientConn)

	// Send a RestartMessage
	restartMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_RestartMsg{
			RestartMsg: &pb.RestartMessage{
				LogId:       "dGVzdC1sb2ctaWQ=", // base64("test-log-id")
				ResumePoint: &pb.TimeSpec{TvSec: 5, TvNsec: 0},
			},
		},
	}
	if err := clientProc.WriteClientMessage(restartMsg); err != nil {
		t.Fatalf("Client failed to write RestartMsg: %v", err)
	}

	resp, err := clientProc.ReadServerMessage()
	if err != nil {
		t.Fatalf("Client failed to read response: %v", err)
	}

	if resp.GetLogId() == "" {
		t.Fatal("Expected log_id in response to RestartMessage")
	}

	if !restartCalled {
		t.Error("Expected restart session factory to be called")
	}

	serverConn.Close()
}

func TestSubCommandRoutingToActiveSession(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "local",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
	}

	handler := NewHandler(serverConn, cfg)
	var mu sync.Mutex
	messagesReceived := make([]string, 0)
	// Signals each silent (no-response) message the mock processes.
	silentProcessed := make(chan struct{}, 4)

	// Override session factory to track messages
	handler.sessionFactories.newLocalStorageSession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error) {
		return &mockSessionHandler{
			t: t,
			HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
				mu.Lock()
				defer mu.Unlock()
				switch msg.Type.(type) {
				case *pb.ClientMessage_AcceptMsg:
					messagesReceived = append(messagesReceived, "accept")
					return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: "test-id"}}, nil
				case *pb.ClientMessage_RejectMsg:
					messagesReceived = append(messagesReceived, "reject")
					silentProcessed <- struct{}{}
					return nil, nil
				case *pb.ClientMessage_AlertMsg:
					messagesReceived = append(messagesReceived, "alert")
					silentProcessed <- struct{}{}
					return nil, nil
				default:
					return nil, nil
				}
			},
			CloseFn: func() error { return nil },
		}, nil
	}

	var wg sync.WaitGroup
	wg.Go(handler.Handle)

	clientProc := protocol.NewProcessor(clientConn, clientConn)

	// Start a session with AcceptMessage (must include required fields)
	acceptMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		ExpectIobufs: true,
		SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix(), TvNsec: 0},
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
			{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "testhost"}},
			{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"}},
		},
	}}}
	clientProc.WriteClientMessage(acceptMsg)
	clientProc.ReadServerMessage() // Read log_id

	// Now send a sub-command accept (should be routed to session)
	subAcceptMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{
			AcceptMsg: &pb.AcceptMessage{
				SubmitTime: &pb.TimeSpec{TvSec: 1700000000, TvNsec: 0},
			},
		},
	}
	clientProc.WriteClientMessage(subAcceptMsg)
	clientProc.ReadServerMessage() // Read sub-command response

	// Send a sub-command reject (should be routed to session)
	subRejectMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_RejectMsg{
			RejectMsg: &pb.RejectMessage{
				Reason: "denied",
			},
		},
	}
	clientProc.WriteClientMessage(subRejectMsg)
	<-silentProcessed

	// Send an alert (should be routed to session)
	alertMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_AlertMsg{
			AlertMsg: &pb.AlertMessage{
				Reason: "test alert",
			},
		},
	}
	clientProc.WriteClientMessage(alertMsg)
	<-silentProcessed

	serverConn.Close()
	wg.Wait()

	// Verify all messages were routed to the active session
	// First accept is the initial session setup, second is the sub-command
	mu.Lock()
	received := make([]string, len(messagesReceived))
	copy(received, messagesReceived)
	mu.Unlock()

	expectedMessages := []string{"accept", "accept", "reject", "alert"}
	if len(received) != len(expectedMessages) {
		t.Fatalf("Expected %d messages routed to session, got %d: %v", len(expectedMessages), len(received), received)
	}
	for i, expected := range expectedMessages {
		if received[i] != expected {
			t.Errorf("Message %d: expected '%s', got '%s'", i, expected, received[i])
		}
	}
}

func TestClientHelloValidation(t *testing.T) {
	t.Run("EmptyClientIdRejected", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:        "local",
				IdleTimeout: 1 * time.Second,
				ServerID:    "TestSrv",
			},
		}

		handler := NewHandler(serverConn, cfg)
		go handler.Handle()

		clientProc := protocol.NewProcessor(clientConn, clientConn)

		// Send ClientHello with empty client_id
		helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: ""}}}
		if err := clientProc.WriteClientMessage(helloMsg); err != nil {
			t.Fatalf("Client failed to write Hello: %v", err)
		}

		// Should receive an error response
		resp, err := clientProc.ReadServerMessage()
		if err != nil {
			t.Fatalf("Client failed to read response: %v", err)
		}
		if resp.GetError() == "" {
			t.Fatal("Expected error response for empty client_id, got non-error")
		}

		serverConn.Close()
	})

	t.Run("ValidClientIdAccepted", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:        "local",
				IdleTimeout: 1 * time.Second,
				ServerID:    "TestSrv",
			},
		}

		handler := NewHandler(serverConn, cfg)
		go handler.Handle()

		clientProc := protocol.NewProcessor(clientConn, clientConn)

		// Send ClientHello with valid client_id
		helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "sudo 1.9.14p2"}}}
		if err := clientProc.WriteClientMessage(helloMsg); err != nil {
			t.Fatalf("Client failed to write Hello: %v", err)
		}

		resp, err := clientProc.ReadServerMessage()
		if err != nil {
			t.Fatalf("Client failed to read response: %v", err)
		}
		if resp.GetHello() == nil {
			t.Fatal("Expected ServerHello response")
		}

		serverConn.Close()
	})
}

func TestRequiredFieldValidation(t *testing.T) {
	requiredFields := []string{"submituser", "submithost", "runuser", "command"}

	for _, missingField := range requiredFields {
		t.Run("Missing_"+missingField, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()

			tmpDir := t.TempDir()
			cfg := &config.Config{
				Server: config.ServerConfig{
					Mode:        "local",
					IdleTimeout: 1 * time.Second,
					ServerID:    "TestSrv",
				},
				LocalStorage: config.LocalStorageConfig{
					LogDirectory:    tmpDir,
					DirPermissions:  0755,
					FilePermissions: 0644,
				},
			}

			handler := NewHandler(serverConn, cfg)
			go handler.Handle()

			clientProc := protocol.NewProcessor(clientConn, clientConn)

			// Build InfoMsgs with one required field missing
			allFields := map[string]string{
				"submituser": "testuser",
				"submithost": "testhost",
				"runuser":    "root",
				"command":    "/bin/ls",
			}

			var infoMsgs []*pb.InfoMessage
			for key, val := range allFields {
				if key == missingField {
					continue // Skip the one we're testing
				}
				infoMsgs = append(infoMsgs, &pb.InfoMessage{
					Key:   key,
					Value: &pb.InfoMessage_Strval{Strval: val},
				})
			}

			acceptMsg := &pb.ClientMessage{
				Type: &pb.ClientMessage_AcceptMsg{
					AcceptMsg: &pb.AcceptMessage{
						SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix(), TvNsec: 0},
						ExpectIobufs: true,
						InfoMsgs:     infoMsgs,
					},
				},
			}
			if err := clientProc.WriteClientMessage(acceptMsg); err != nil {
				t.Fatalf("Client failed to write AcceptMsg: %v", err)
			}

			// Should receive an error response
			resp, err := clientProc.ReadServerMessage()
			if err != nil {
				t.Fatalf("Client failed to read response: %v", err)
			}
			if resp.GetError() == "" {
				t.Fatalf("Expected error response for missing %s, got non-error", missingField)
			}

			serverConn.Close()
		})
	}

	t.Run("AllRequiredFieldsPresent", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		tmpDir := t.TempDir()
		cfg := &config.Config{
			Server: config.ServerConfig{
				Mode:        "local",
				IdleTimeout: 1 * time.Second,
				ServerID:    "TestSrv",
			},
			LocalStorage: config.LocalStorageConfig{
				LogDirectory:    tmpDir,
				DirPermissions:  0755,
				FilePermissions: 0644,
			},
		}

		handler := NewHandler(serverConn, cfg)

		// Use a mock so we don't need real file I/O
		handler.sessionFactories.newLocalStorageSession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
			return &mockSessionHandler{
				t: t,
				HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
					return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: "test-id"}}, nil
				},
				CloseFn: func() error { return nil },
			}, nil
		}

		go handler.Handle()

		clientProc := protocol.NewProcessor(clientConn, clientConn)

		acceptMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_AcceptMsg{
				AcceptMsg: &pb.AcceptMessage{
					SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix(), TvNsec: 0},
					ExpectIobufs: true,
					InfoMsgs: []*pb.InfoMessage{
						{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
						{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "testhost"}},
						{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
						{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"}},
					},
				},
			},
		}
		if err := clientProc.WriteClientMessage(acceptMsg); err != nil {
			t.Fatalf("Client failed to write AcceptMsg: %v", err)
		}

		resp, err := clientProc.ReadServerMessage()
		if err != nil {
			t.Fatalf("Client failed to read response: %v", err)
		}
		if resp.GetLogId() == "" {
			t.Fatal("Expected log_id response for valid AcceptMessage")
		}

		serverConn.Close()
	})
}

func TestSetOrUpdateInfoMessage_UpdateExisting(t *testing.T) {
	handler := createTestHandlerForRuncwd()

	acceptMsg := createAcceptMessageForRuncwd([]*pb.InfoMessage{
		{Key: "existing", Value: &pb.InfoMessage_Strval{Strval: "oldvalue"}},
	})

	handler.setOrUpdateInfoMessage(acceptMsg, "existing", "newvalue")

	result := findInfoValue(acceptMsg, "existing")
	if result != "newvalue" {
		t.Errorf("Expected existing message to be updated to 'newvalue', got '%s'", result)
	}

	// Ensure we didn't add a duplicate
	count := 0
	for _, info := range acceptMsg.InfoMsgs {
		if info.GetKey() == "existing" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected exactly 1 'existing' info message, got %d", count)
	}
}

// fakeDoneRelaySession implements SessionHandler plus the doneNotifier and
// logIDProvider markers. It pretends to be a relay session whose background
// runner has already exited (IsDone returns true) and has already fired its
// onDone callback before the connection handler called registerSession.
type fakeDoneRelaySession struct{}

func (fakeDoneRelaySession) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	if msg.GetAcceptMsg() != nil {
		return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: "fake-log-id"}}, nil
	}
	return nil, nil
}
func (fakeDoneRelaySession) Close() error  { return nil }
func (fakeDoneRelaySession) IsDone() bool  { return true }
func (fakeDoneRelaySession) LogID() string { return "fake-log-id" }

// TestRelay_DoneBeforeRegisterDoesNotOrphan reproduces the race the codex
// adversarial review flagged: a relay session's background runner exits and
// fires onDone before registerSession adds the entry, leaving an orphan
// registry record that the connection-close path then never cleans up
// (because relay sessions are skipped by the disconnect-time deregister).
// The fix detects an already-done session immediately after register and
// removes the entry inside registerSession.
func TestRelay_DoneBeforeRegisterDoesNotOrphan(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "relay",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
		Relay: config.RelayConfig{
			UpstreamHost:        "127.0.0.1:0",
			RelayCacheDirectory: t.TempDir(),
		},
	}

	registry := sessions.NewRegistry()
	handler := NewHandlerWithContext(t.Context(), serverConn, cfg, registry)
	handler.sessionFactories.newRelaySession = func(sessionUUID uuid.UUID, _ *pb.AcceptMessage, _ *config.RelayConfig) (SessionHandler, error) {
		// Simulate the race: the runner finished and called Deregister
		// before registerSession had a chance to add the entry. The
		// Deregister here is a no-op because the entry does not yet
		// exist — this is exactly the orphan-producing situation.
		registry.Deregister(sessionUUID.String())
		return fakeDoneRelaySession{}, nil
	}

	var wg sync.WaitGroup
	wg.Go(handler.Handle)

	clientProc := protocol.NewProcessor(clientConn, clientConn)
	if err := clientProc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{
			AcceptMsg: &pb.AcceptMessage{
				SubmitTime:   &pb.TimeSpec{TvSec: 1700000000, TvNsec: 0},
				ExpectIobufs: true,
				InfoMsgs: []*pb.InfoMessage{
					{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "alice"}},
					{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "host01"}},
					{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
					{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/id"}},
				},
			},
		},
	}); err != nil {
		t.Fatalf("client write AcceptMsg: %v", err)
	}
	// Wait for the LogId response. By the time it arrives, registerSession
	// has finished (it runs before HandleClientMessage in handleAccept).
	if _, err := clientProc.ReadServerMessage(); err != nil {
		t.Fatalf("client read LogId: %v", err)
	}

	if got := registry.Len(); got != 0 {
		t.Fatalf("registry should be empty after done-before-register cleanup; len=%d", got)
	}

	serverConn.Close()
	wg.Wait()
}

// TestWaitForRateToken verifies that exceeding the per-connection rate limit
// applies back-pressure (blocks until a token refills) instead of terminating
// the connection — the reference C sudo_logsrvd has no such limit, and a
// legitimate high-throughput session must not be severed. It also verifies the
// wait is abortable via context so shutdown is never pinned by a slow client.
func TestWaitForRateToken(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: "local", IdleTimeout: time.Second, ServerID: "t"},
	}
	_, serverConn := net.Pipe()
	defer serverConn.Close()
	h := NewHandler(serverConn, cfg)

	// The initial burst (rateBurst tokens) drains effectively instantly.
	start := time.Now()
	for range int(rateBurst) {
		if err := h.waitForRateToken(context.Background()); err != nil {
			t.Fatalf("unexpected error draining burst: %v", err)
		}
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("draining the burst took %s, expected near-instant", d)
	}

	// With the bucket empty the next token must BLOCK and then SUCCEED — never
	// return an error (which the caller turns into a connection teardown). It
	// should take roughly one refill interval (1/rateRefillPerSec).
	start = time.Now()
	if err := h.waitForRateToken(context.Background()); err != nil {
		t.Fatalf("expected back-pressure (block then succeed), got error: %v", err)
	}
	if d := time.Since(start); d < 5*time.Millisecond {
		t.Errorf("expected throttle delay ~%v, got %s (was it actually throttled?)", time.Second/time.Duration(rateRefillPerSec), d)
	}

	// Force the bucket empty, then a cancelled context must abort the wait
	// promptly rather than blocking forever.
	h.rateLimitMutex.Lock()
	h.rateTokens = 0
	h.rateLastRefill = time.Now()
	h.rateLimitMutex.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.waitForRateToken(ctx); err == nil {
		t.Error("expected cancellation error while rate-limited, got nil")
	}
}

// deadlineRecorderConn wraps a net.Conn and records SetReadDeadline calls so a
// test can assert whether the handler armed a per-message idle read deadline.
type deadlineRecorderConn struct {
	net.Conn
	mu           sync.Mutex
	setCalls     int
	lastDeadline time.Time
}

func (c *deadlineRecorderConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.setCalls++
	c.lastDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineRecorderConn) calls() (int, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setCalls, c.lastDeadline
}

// TestNoMessagesAcceptedAfterExit checks that the server stops reading once the
// client has sent its ExitMessage.
//
// C deletes the read event outright in handle_exit (sudo_ev_del(evbase,
// read_ev)) and moves to EXITED/FINISHED, so a post-Exit message is never even
// parsed; anything arriving in those states is a state machine error that kills
// the connection. Go kept the loop running and handed every later message to the
// session. In relay mode those extra records land in a cache file whose Exit has
// already been written, so the flush replays a session that ends mid-stream and
// then keeps going -- delivering a truncated duplicate upstream, or looping on
// an unacknowledgeable replay. One crafted message from an unauthenticated peer
// was enough.
//
// Conformance: docs/logsrvd-reference/ ARCH-036.
func TestNoMessagesAcceptedAfterExit(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{
		Mode: "local", ServerID: "t", ServerTimeout: 5 * time.Second,
	}}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	h := NewHandler(serverConn, cfg)
	// A mock session keeps this focused on the handler's state machine rather
	// than on local-storage path expansion.
	h.sessionFactories.newLocalStorageSession = func(id uuid.UUID, _ *pb.AcceptMessage, _ *config.LocalStorageConfig) (SessionHandler, error) {
		return &mockSessionHandler{t: t, HandleClientFn: func(m *pb.ClientMessage) (*pb.ServerMessage, error) {
			if m.GetExitMsg() != nil {
				return &pb.ServerMessage{Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{TvSec: 1}}}, nil
			}
			return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: id.String()}}, nil
		}}, nil
	}
	done := make(chan struct{})
	go func() { h.Handle(); close(done) }()

	cp := protocol.NewProcessor(clientConn, clientConn)
	write := func(m *pb.ClientMessage) error { return cp.WriteClientMessage(m) }

	if err := write(&pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "x"}}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, err := cp.ReadServerMessage(); err != nil {
		t.Fatalf("read ServerHello: %v", err)
	}
	if err := write(&pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 1},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "u"}},
			{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "h"}},
			{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"}},
		},
	}}}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	acceptResp, err := cp.ReadServerMessage()
	if err != nil {
		t.Fatalf("read log_id: %v", err)
	}
	if acceptResp.GetLogId() == "" {
		t.Fatalf("accept was not acknowledged with a log_id, got %T (%v)", acceptResp.Type, acceptResp)
	}
	if err := write(&pb.ClientMessage{Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{}}}); err != nil {
		t.Fatalf("exit: %v", err)
	}
	if _, err := cp.ReadServerMessage(); err != nil {
		t.Fatalf("read final commit point: %v", err)
	}

	// The server must be finished with this connection now.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler kept reading after the ExitMessage; post-Exit records would " +
			"be appended to an already-terminated session")
	}
}

// TestWriteTimeoutBoundsUnresponsivePeer checks that a peer which completes the
// handshake and then stops reading cannot pin a handler goroutine forever.
//
// This is the other half of the idle_timeout change. Removing the idle read
// deadline was correct — C never disconnects an idle client — but C is not
// unbounded: it arms its *write* events with [server] timeout (default 30s,
// DEFAULT_SOCKET_TIMEOUT_SEC), so a client that stops draining the socket is cut
// loose. Without an equivalent, one silent peer holds a goroutine, its session
// files and one of max_connections slots until the process exits, and repeating
// that wedges the server.
//
// net.Pipe is unbuffered, so the server's reply blocks until someone reads it —
// exactly the condition being tested.
//
// Conformance: docs/logsrvd-reference/ ARCH-032, ARCH-045, TLS-022.
func TestWriteTimeoutBoundsUnresponsivePeer(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{
		Mode:          "local",
		ServerID:      "t",
		ServerTimeout: 200 * time.Millisecond,
	}}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	h := NewHandler(serverConn, cfg)
	done := make(chan struct{})
	go func() {
		h.Handle()
		close(done)
	}()

	// Send a ClientHello and then never read the ServerHello reply.
	clientProc := protocol.NewProcessor(clientConn, clientConn)
	if err := clientProc.WriteClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "silent"}},
	}); err != nil {
		t.Fatalf("client write Hello: %v", err)
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler never returned: a peer that stops reading pins the goroutine " +
			"and its connection slot indefinitely")
	}
}

// TestIdleReadDeadlineOptOut verifies that a non-positive idle_timeout disables
// the per-message read deadline (matching C sudo_logsrvd's NULL read timeout),
// while a positive value still arms it.
func TestIdleReadDeadlineOptOut(t *testing.T) {
	exchangeHello := func(t *testing.T, idle time.Duration) *deadlineRecorderConn {
		t.Helper()
		cfg := &config.Config{Server: config.ServerConfig{Mode: "local", IdleTimeout: idle, ServerID: "t"}}
		clientConn, serverConn := net.Pipe()
		rec := &deadlineRecorderConn{Conn: serverConn}
		h := NewHandler(rec, cfg)
		var wg sync.WaitGroup
		wg.Go(h.Handle)

		clientProc := protocol.NewProcessor(clientConn, clientConn)
		if err := clientProc.WriteClientMessage(&pb.ClientMessage{
			Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "x"}},
		}); err != nil {
			t.Fatalf("client write Hello: %v", err)
		}
		if _, err := clientProc.ReadServerMessage(); err != nil {
			t.Fatalf("client read ServerHello: %v", err)
		}
		// The loop has processed one message and is back at the top of the next
		// iteration (where the deadline is armed) before blocking on read.
		clientConn.Close()
		serverConn.Close()
		wg.Wait()
		return rec
	}

	t.Run("NegativeDisablesReadDeadline", func(t *testing.T) {
		rec := exchangeHello(t, -1*time.Second)
		if n, _ := rec.calls(); n != 0 {
			t.Errorf("expected 0 SetReadDeadline calls with idle_timeout<=0, got %d", n)
		}
	})

	t.Run("PositiveArmsReadDeadline", func(t *testing.T) {
		rec := exchangeHello(t, 30*time.Second)
		n, last := rec.calls()
		if n == 0 {
			t.Error("expected SetReadDeadline to be armed with a positive idle_timeout")
		}
		if !last.After(time.Now()) {
			t.Errorf("expected a future read deadline, got %v", last)
		}
	})

	// The regression guard that matters: not "the opt-out works" but "the
	// shipped default IS the opt-out". This drives a config through the real
	// LoadConfig path rather than hand-building a struct, so re-introducing a
	// finite default in internal/config fails here too.
	//
	// Conformance: docs/logsrvd-reference/ ARCH-024, ARCH-045, CONF-025.
	t.Run("ShippedDefaultArmsNoReadDeadline", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(tmpFile, []byte("server:\n  mode: \"local\"\n"), 0600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}
		cfg, err := config.LoadConfig(tmpFile)
		if err != nil {
			t.Fatalf("LoadConfig() error: %v", err)
		}

		clientConn, serverConn := net.Pipe()
		rec := &deadlineRecorderConn{Conn: serverConn}
		h := NewHandler(rec, cfg)
		var wg sync.WaitGroup
		wg.Go(h.Handle)

		clientProc := protocol.NewProcessor(clientConn, clientConn)
		if err := clientProc.WriteClientMessage(&pb.ClientMessage{
			Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "x"}},
		}); err != nil {
			t.Fatalf("client write Hello: %v", err)
		}
		if _, err := clientProc.ReadServerMessage(); err != nil {
			t.Fatalf("client read ServerHello: %v", err)
		}
		clientConn.Close()
		serverConn.Close()
		wg.Wait()

		if n, _ := rec.calls(); n != 0 {
			t.Errorf("shipped defaults armed %d read deadline(s); an idle sudo session "+
				"must never be disconnected by the server, because the client responds "+
				"by killing the user's command (log_client.c:1919)", n)
		}
	})
}

// startIoBufferSession brings a local-mode handler up to the RUNNING state and
// returns the client-side processor, the log directory and a channel closed when
// the handler goroutine exits.
func startIoBufferSession(t *testing.T) (protocol.Processor, string, <-chan struct{}) {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: "local", ServerID: "t", ServerTimeout: 5 * time.Second},
		LocalStorage: config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		},
	}
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })

	h := NewHandler(serverConn, cfg)
	done := make(chan struct{})
	go func() { h.Handle(); close(done) }()

	cp := protocol.NewProcessor(clientConn, clientConn)
	if err := cp.WriteClientMessage(&pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{
		HelloMsg: &pb.ClientHello{ClientId: "x"},
	}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if _, err := cp.ReadServerMessage(); err != nil {
		t.Fatalf("read ServerHello: %v", err)
	}
	if err := cp.WriteClientMessage(&pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 1},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "u"}},
			{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "h"}},
			{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"}},
		},
	}}}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	resp, err := cp.ReadServerMessage()
	if err != nil {
		t.Fatalf("read log_id: %v", err)
	}
	if resp.GetLogId() == "" {
		t.Fatalf("accept was not acknowledged with a log_id, got %T", resp.Type)
	}
	return cp, tmpDir, done
}

// readTimingFile returns the contents of the single session timing file below
// logDir, or "" when the session never wrote one.
func readTimingFile(t *testing.T, logDir string) string {
	t.Helper()
	var content string
	err := filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "timing" {
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			content = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", logDir, err)
	}
	return content
}

// TestIoBufferValidation checks that an IoBuffer whose delay is not a normalised
// non-negative timespec, or whose data is empty, is rejected instead of being
// written to the timing file.
//
// C sudo_logsrvd applies valid_timespec() plus a data.len != 0 check in
// handle_iobuf (logsrvd/logsrvd.c:756-760) and drops the connection with
// "invalid IoBuffer". Without it a negative tv_nsec renders as "0.-00000005",
// which sudoreplay cannot parse: it stops at that line, so every record written
// after it is on disk but unreplayable.
//
// Conformance: docs/logsrvd-reference/ PROTO-027.
func TestIoBufferValidation(t *testing.T) {
	invalid := []struct {
		name string
		buf  *pb.IoBuffer
	}{
		{"NegativeNanoseconds", &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: 0, TvNsec: -5}, Data: []byte("hello")}},
		{"NanosecondsNotNormalised", &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 1000000000}, Data: []byte("hello")}},
		{"NegativeSeconds", &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: -1, TvNsec: 0}, Data: []byte("hello")}},
		{"MissingDelay", &pb.IoBuffer{Data: []byte("hello")}},
		{"EmptyData", &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 1000}}},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			cp, logDir, done := startIoBufferSession(t)

			if err := cp.WriteClientMessage(&pb.ClientMessage{
				Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: tc.buf},
			}); err != nil {
				t.Fatalf("write IoBuffer: %v", err)
			}

			resp, err := cp.ReadServerMessage()
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if resp.GetError() == "" {
				t.Fatalf("invalid IoBuffer was accepted; got %T (%v)", resp.Type, resp)
			}

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("handler kept the connection open after an invalid IoBuffer")
			}

			if timing := readTimingFile(t, logDir); timing != "" {
				t.Fatalf("invalid IoBuffer was recorded in the timing file: %q", timing)
			}
		})
	}

	t.Run("ValidBufferAccepted", func(t *testing.T) {
		cp, logDir, done := startIoBufferSession(t)

		if err := cp.WriteClientMessage(&pb.ClientMessage{
			Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 999999999},
				Data:  []byte("hello"),
			}},
		}); err != nil {
			t.Fatalf("write IoBuffer: %v", err)
		}
		resp, err := cp.ReadServerMessage()
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.GetError() != "" {
			t.Fatalf("valid IoBuffer was rejected: %v", resp.GetError())
		}
		if err := cp.WriteClientMessage(&pb.ClientMessage{
			Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{}},
		}); err != nil {
			t.Fatalf("exit: %v", err)
		}
		if _, err := cp.ReadServerMessage(); err != nil {
			t.Fatalf("read final commit point: %v", err)
		}
		<-done

		if timing := readTimingFile(t, logDir); timing != "4 1.999999999 5\n" {
			t.Fatalf("unexpected timing record %q", timing)
		}
	})
}
