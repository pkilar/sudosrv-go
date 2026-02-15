// Filename: internal/connection/handler_test.go
package connection

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
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

// mockUpstreamServer simulates a real sudo_logsrvd server for testing the relay.
type mockUpstreamServer struct {
	listener     net.Listener
	wg           sync.WaitGroup
	receivedMsgs chan *pb.ClientMessage
	t            *testing.T
}

func newMockUpstreamServer(t *testing.T, addr string) (*mockUpstreamServer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &mockUpstreamServer{
		listener:     l,
		receivedMsgs: make(chan *pb.ClientMessage, 100),
		t:            t,
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

func (s *mockUpstreamServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // Listener was closed
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConnection(c)
		}(conn)
	}
}

// handleConnection now robustly handles the full handshake and subsequent message flush.
func (s *mockUpstreamServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	proc := protocol.NewProcessor(conn, conn)

	// 1. Handle handshake from connectToUpstream
	if _, err := proc.ReadClientMessage(); err != nil { // Read ClientHello
		s.t.Logf("Mock server: failed to read ClientHello: %v", err)
		return
	}
	if err := proc.WriteServerMessage(&pb.ServerMessage{Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{}}}); err != nil {
		s.t.Logf("Mock server: failed to write ServerHello: %v", err)
		return
	}

	// 2. Handle the flush from flushFile.
	// This will receive all messages from the cache file, starting with the AcceptMessage.
	for {
		msg, err := proc.ReadClientMessage()
		if err != nil {
			if err == io.EOF {
				return // Expected when the flushing client disconnects.
			}
			s.t.Logf("mock upstream server read error: %v", err)
			return
		}

		// Send to channel in a non-blocking way to avoid deadlock
		select {
		case s.receivedMsgs <- msg:
		default:
			s.t.Logf("Mock server: receivedMsgs channel full, dropping message")
		}

		// Respond like a real server would to keep the client happy.
		switch msg.Type.(type) {
		case *pb.ClientMessage_AcceptMsg:
			if err := proc.WriteServerMessage(&pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: "mock-log-id"}}); err != nil {
				s.t.Logf("Mock server: failed to write LogId response: %v", err)
				return
			}
		case *pb.ClientMessage_ExitMsg:
			return // Exit after processing exit message
		}
	}
}

func (s *mockUpstreamServer) Close() {
	s.listener.Close()
	s.wg.Wait()
	close(s.receivedMsgs)
}

func (s *mockUpstreamServer) Addr() string {
	return s.listener.Addr().String()
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			handler.Handle()
		}()

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

		// Client sends Accept
		acceptMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{ExpectIobufs: true}}}
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
			var eventRecord map[string]interface{}
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
		}
		return nil
	})

	if !found {
		t.Error("No log.json reject event file was created")
	}
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
	messagesReceived := make([]string, 0)

	// Override session factory to track messages
	handler.sessionFactories.newLocalStorageSession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error) {
		return &mockSessionHandler{
			t: t,
			HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
				switch msg.Type.(type) {
				case *pb.ClientMessage_AcceptMsg:
					messagesReceived = append(messagesReceived, "accept")
					return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: "test-id"}}, nil
				case *pb.ClientMessage_RejectMsg:
					messagesReceived = append(messagesReceived, "reject")
					return nil, nil
				case *pb.ClientMessage_AlertMsg:
					messagesReceived = append(messagesReceived, "alert")
					return nil, nil
				default:
					return nil, nil
				}
			},
			CloseFn: func() error { return nil },
		}, nil
	}

	go handler.Handle()

	clientProc := protocol.NewProcessor(clientConn, clientConn)

	// Start a session with AcceptMessage
	acceptMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{ExpectIobufs: true}}}
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
	// No response for reject, send another message to confirm processing
	time.Sleep(50 * time.Millisecond) // Small delay to ensure processing

	// Send an alert (should be routed to session)
	alertMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_AlertMsg{
			AlertMsg: &pb.AlertMessage{
				Reason: "test alert",
			},
		},
	}
	clientProc.WriteClientMessage(alertMsg)
	time.Sleep(50 * time.Millisecond) // Small delay to ensure processing

	serverConn.Close()
	time.Sleep(100 * time.Millisecond) // Allow handler to process

	// Verify all messages were routed to the active session
	// First accept is the initial session setup, second is the sub-command
	expectedMessages := []string{"accept", "accept", "reject", "alert"}
	if len(messagesReceived) != len(expectedMessages) {
		t.Fatalf("Expected %d messages routed to session, got %d: %v", len(expectedMessages), len(messagesReceived), messagesReceived)
	}
	for i, expected := range expectedMessages {
		if messagesReceived[i] != expected {
			t.Errorf("Message %d: expected '%s', got '%s'", i, expected, messagesReceived[i])
		}
	}
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
