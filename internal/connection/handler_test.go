// SPDX-License-Identifier: Apache-2.0
// Filename: internal/connection/handler_test.go
package connection

import (
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
