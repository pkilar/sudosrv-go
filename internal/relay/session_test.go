// Filename: internal/relay/session_test.go
package relay

import (
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

// Helper to create a standard AcceptMessage for tests
func createTestAcceptMessage() *pb.AcceptMessage {
	return &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix(), TvNsec: 0},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "relayuser"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/usr/bin/top"}},
		},
	}
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
			if !s.isClosing() {
				s.t.Logf("Accept error: %v", err)
			}
			return // Listener was closed
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConnection(c)
		}(conn)
	}
}

func (s *mockUpstreamServer) isClosing() bool {
	// Check if listener is closed by trying to get the file descriptor
	if tcpListener, ok := s.listener.(*net.TCPListener); ok {
		file, err := tcpListener.File()
		if err != nil {
			return true // Likely closed
		}
		file.Close()
	}
	return false
}

// handleConnection now robustly handles the full handshake and subsequent message flush.
func (s *mockUpstreamServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	proc := protocol.NewProcessor(conn, conn)
	s.t.Logf("Mock server: new connection from %s", conn.RemoteAddr())

	// 1. Handle handshake from connectToUpstream
	helloMsg, err := proc.ReadClientMessage() // Read ClientHello
	if err != nil {
		s.t.Logf("Mock server: failed to read ClientHello: %v", err)
		return
	}
	s.t.Logf("Mock server: received ClientHello: %v", helloMsg.GetHelloMsg())

	if err := proc.WriteServerMessage(&pb.ServerMessage{Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{}}}); err != nil {
		s.t.Logf("Mock server: failed to write ServerHello: %v", err)
		return
	}
	s.t.Logf("Mock server: sent ServerHello")

	// 2. Handle the flush from flushFile.
	// This will receive all messages from the cache file, starting with the AcceptMessage.
	messageCount := 0
	for {
		msg, err := proc.ReadClientMessage()
		if err != nil {
			if err == io.EOF {
				s.t.Logf("Mock server: client disconnected (EOF) after %d messages", messageCount)
				return // Expected when the flushing client disconnects.
			}
			s.t.Logf("mock upstream server read error: %v", err)
			return
		}
		messageCount++
		s.t.Logf("Mock server: received message %d type %T", messageCount, msg.Type)

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
			s.t.Logf("Mock server: sent LogId response")
		case *pb.ClientMessage_ExitMsg:
			s.t.Logf("Mock server: received ExitMsg, ending session")
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

func TestRelaySession_CacheAndFlush(t *testing.T) {
	// 1. Start a mock upstream server
	mockServer, err := newMockUpstreamServer(t, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock upstream server: %v", err)
	}
	defer mockServer.Close()

	// Give the mock server a moment to start listening
	time.Sleep(50 * time.Millisecond)

	// 2. Setup config for the relay session
	tmpDir := t.TempDir()
	relayCfg := &config.RelayConfig{
		RelayCacheDirectory:  tmpDir,
		ReconnectAttempts:    5,                      // Try a few times
		MaxReconnectInterval: 100 * time.Millisecond, // Fast retry for tests
		ConnectTimeout:       2 * time.Second,
		UpstreamHost:         mockServer.Addr(),
	}

	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	acceptMsg := createTestAcceptMessage()

	// 3. Create a new relay session
	session, err := NewSession(sessionUUID, acceptMsg, relayCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}

	// 4. Send some messages to the session, which will be cached locally
	session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{Data: []byte("output1")}},
	})
	session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{Data: []byte("output2")}},
	})
	// Send the final exit message, which completes the client-facing part of the session
	session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	})

	// 5. Close the "client" connection to the relay session.
	// This signals the messageWriter to finish, allowing the background flusher to proceed.
	session.Close()

	// 6. Wait for the session's background goroutine to finish with a timeout
	done := make(chan struct{})
	go func() {
		session.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Session completed successfully
	case <-time.After(10 * time.Second):
		t.Fatal("Session goroutine did not complete within timeout")
	}

	// 7. Verify the upstream server received the messages
	expectedMsgCount := 4 // Accept, Ttyout1, Ttyout2, Exit
	receivedCount := 0

	timeout := time.After(5 * time.Second)
	var allMsgs []*pb.ClientMessage

	for receivedCount < expectedMsgCount {
		select {
		case msg, ok := <-mockServer.receivedMsgs:
			if !ok {
				t.Fatalf("Mock server channel closed prematurely. Received %d of %d", receivedCount, expectedMsgCount)
			}
			allMsgs = append(allMsgs, msg)
			receivedCount++
		case <-timeout:
			t.Fatalf("timed out waiting for messages from upstream server. Received %d of %d", receivedCount, expectedMsgCount)
		}
	}

	// Check message types
	if allMsgs[0].GetAcceptMsg() == nil {
		t.Errorf("Expected first flushed message to be AcceptMsg, but it was %T", allMsgs[0].Type)
	}
	if allMsgs[1].GetTtyoutBuf() == nil {
		t.Errorf("Expected second flushed message to be TtyoutBuf, but it was %T", allMsgs[1].Type)
	}
	if allMsgs[2].GetTtyoutBuf() == nil {
		t.Errorf("Expected third flushed message to be TtyoutBuf, but it was %T", allMsgs[2].Type)
	}
	if allMsgs[3].GetExitMsg() == nil {
		t.Errorf("Expected last flushed message to be ExitMsg, but it was %T", allMsgs[3].Type)
	}

	// 8. Verify the cache file was deleted (uses UUID string for filename)
	cacheFilePath := filepath.Join(tmpDir, sessionUUID.String()+".log")
	if _, err := os.Stat(cacheFilePath); !os.IsNotExist(err) {
		t.Errorf("Expected cache file %s to be deleted after successful flush, but it still exists", cacheFilePath)
	}
}

func TestRelayCommitPoints(t *testing.T) {
	tmpDir := t.TempDir()
	relayCfg := &config.RelayConfig{
		RelayCacheDirectory:  tmpDir,
		ReconnectAttempts:    0,
		MaxReconnectInterval: 100 * time.Millisecond,
		ConnectTimeout:       time.Second,
		UpstreamHost:         "127.0.0.1:0", // Won't actually connect; we only test HandleClientMessage
	}

	sessionUUID := uuid.MustParse("b2c3d4e5-f6a7-4b2c-9d3e-0f1a2b3c4d5e")
	acceptMsg := createTestAcceptMessage()

	session, err := NewSession(sessionUUID, acceptMsg, relayCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}

	// AcceptMsg should return log_id
	resp, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg},
	})
	if err != nil {
		t.Fatalf("HandleClientMessage(AcceptMsg) failed: %v", err)
	}
	if resp == nil || resp.GetLogId() == "" {
		t.Fatal("Expected log_id response for AcceptMsg")
	}

	// First I/O event should return a commit point (zero-value lastCommitTime)
	resp, err = session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{
			TtyoutBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 500000000},
				Data:  []byte("hello"),
			},
		},
	})
	if err != nil {
		t.Fatalf("HandleClientMessage(TtyoutBuf) failed: %v", err)
	}
	if resp == nil || resp.GetCommitPoint() == nil {
		t.Fatal("Expected commit point for first I/O event in relay mode")
	}

	// Verify commit point values
	cp := resp.GetCommitPoint()
	if cp.TvSec != 1 || cp.TvNsec != 500000000 {
		t.Errorf("Commit point mismatch: expected 1.5s, got %d.%09d", cp.TvSec, cp.TvNsec)
	}

	// Non-I/O events should not return commit points
	resp, err = session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_WinsizeEvent{
			WinsizeEvent: &pb.ChangeWindowSize{
				Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 100000000},
				Rows:  25, Cols: 80,
			},
		},
	})
	if err != nil {
		t.Fatalf("HandleClientMessage(WinsizeEvent) failed: %v", err)
	}
	if resp != nil {
		t.Errorf("Expected nil response for non-I/O event, got %v", resp)
	}

	// Clean up: send exit and close
	session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	})
	session.Close()
}

func TestRelayCommitPointThrottling(t *testing.T) {
	tmpDir := t.TempDir()
	relayCfg := &config.RelayConfig{
		RelayCacheDirectory:  tmpDir,
		ReconnectAttempts:    0,
		MaxReconnectInterval: 100 * time.Millisecond,
		ConnectTimeout:       time.Second,
		UpstreamHost:         "127.0.0.1:0",
	}

	sessionUUID := uuid.MustParse("c3d4e5f6-a7b8-4c3d-ae4f-1a2b3c4d5e6f")
	acceptMsg := createTestAcceptMessage()

	session, err := NewSession(sessionUUID, acceptMsg, relayCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}

	makeIoMsg := func() *pb.ClientMessage {
		return &pb.ClientMessage{
			Type: &pb.ClientMessage_StdoutBuf{
				StdoutBuf: &pb.IoBuffer{
					Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 50000000}, // 50ms
					Data:  []byte("x"),
				},
			},
		}
	}

	// First I/O event: commit point expected
	resp, err := session.HandleClientMessage(makeIoMsg())
	if err != nil {
		t.Fatalf("First I/O event failed: %v", err)
	}
	if resp == nil || resp.GetCommitPoint() == nil {
		t.Fatal("Expected commit point on first relay I/O event")
	}

	// Subsequent events within throttle window: no commit point
	for i := 0; i < 3; i++ {
		resp, err = session.HandleClientMessage(makeIoMsg())
		if err != nil {
			t.Fatalf("I/O event %d failed: %v", i+2, err)
		}
		if resp != nil {
			t.Fatalf("Expected nil for I/O event %d within throttle window, got commit point", i+2)
		}
	}

	// Backdate lastCommitTime to simulate time passing
	session.lastCommitTime = time.Now().Add(-commitPointInterval - time.Second)

	// Next event should return a commit point
	resp, err = session.HandleClientMessage(makeIoMsg())
	if err != nil {
		t.Fatalf("I/O event after interval failed: %v", err)
	}
	if resp == nil || resp.GetCommitPoint() == nil {
		t.Fatal("Expected commit point after throttle interval elapsed")
	}

	// Clean up
	session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	})
	session.Close()
}
