// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/session_test.go
package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"sync/atomic"
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
	closing      atomic.Bool // set true before listener.Close so acceptLoop suppresses the expected "use of closed network connection" log
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
			if !s.closing.Load() {
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
			if errors.Is(err, io.EOF) {
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
	s.closing.Store(true)
	s.listener.Close()
	s.wg.Wait()
	close(s.receivedMsgs)
}

func (s *mockUpstreamServer) Addr() string {
	return s.listener.Addr().String()
}

func waitRelaySession(t *testing.T, session *Session, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		session.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("relay session did not finish within %s", timeout)
	}
}

func TestRelaySession_CacheAndFlush(t *testing.T) {
	// 1. Start a mock upstream server
	mockServer, err := newMockUpstreamServer(t, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock upstream server: %v", err)
	}
	defer mockServer.Close()

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
	session, err := NewSession(t.Context(), sessionUUID, acceptMsg, relayCfg, nil)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}

	// 4. Send some messages to the session, which will be cached locally.
	// Errors here indicate a regression in HandleClientMessage (e.g. timeout,
	// channel closed); failing loudly beats a silent miscount downstream.
	if _, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{Data: []byte("output1")}},
	}); err != nil {
		t.Fatalf("HandleClientMessage(output1): %v", err)
	}
	if _, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{Data: []byte("output2")}},
	}); err != nil {
		t.Fatalf("HandleClientMessage(output2): %v", err)
	}
	// Send the final exit message, which completes the client-facing part of the session
	if _, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	}); err != nil {
		t.Fatalf("HandleClientMessage(exit): %v", err)
	}

	// 5. Close the "client" connection to the relay session.
	// This signals the messageWriter to finish, allowing the background flusher to proceed.
	session.Close()

	// 6. Wait for the session's background goroutine to finish with a timeout
	waitRelaySession(t, session, 10*time.Second)

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

	session, err := NewSession(t.Context(), sessionUUID, acceptMsg, relayCfg, nil)
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
	if _, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	}); err != nil {
		t.Fatalf("HandleClientMessage(exit) during cleanup: %v", err)
	}
	session.Close()
	waitRelaySession(t, session, 2*time.Second)
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

	session, err := NewSession(t.Context(), sessionUUID, acceptMsg, relayCfg, nil)
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
	for i := range 3 {
		resp, err = session.HandleClientMessage(makeIoMsg())
		if err != nil {
			t.Fatalf("I/O event %d failed: %v", i+2, err)
		}
		if resp != nil {
			t.Fatalf("Expected nil for I/O event %d within throttle window, got commit point", i+2)
		}
	}

	// Backdate lastCommitTime to simulate time passing
	session.mu.Lock()
	session.lastCommitTime = time.Now().Add(-commitPointInterval - time.Second)
	session.mu.Unlock()

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
	waitRelaySession(t, session, 2*time.Second)
}

func TestRelaySession_CloseDoesNotWaitForFlush(t *testing.T) {
	tmpDir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	relayCfg := &config.RelayConfig{
		RelayCacheDirectory:  tmpDir,
		ReconnectAttempts:    -1,
		MaxReconnectInterval: time.Second,
		ConnectTimeout:       50 * time.Millisecond,
		UpstreamHost:         "127.0.0.1:1",
	}

	sessionUUID := uuid.MustParse("d4e5f6a7-b8c9-4d5e-af60-2b3c4d5e6f70")
	session, err := NewSession(ctx, sessionUUID, createTestAcceptMessage(), relayCfg, nil)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}

	if _, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	}); err != nil {
		t.Fatalf("HandleClientMessage(ExitMsg) failed: %v", err)
	}

	start := time.Now()
	if err := session.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Close() waited for relay flush: elapsed=%s", elapsed)
	}

	cancel()
	waitRelaySession(t, session, 2*time.Second)
}

// TestRelaySession_NoMessageLossUnderCloseRace asserts the invariant Codex's
// adversarial review flagged: if HandleClientMessage returns nil error, the
// message MUST end up durably cached. The previous Close/send synchronization
// (separate `closed` chan signal + open data channel) could let a sender
// commit to the buffer after the writer goroutine had already exited via the
// closed-signal arm, silently losing audit data.
//
// To exercise the race, we use a starting barrier so a wave of senders all
// hit the channel right when Close runs, maximising the chance that a send
// commits to the buffer concurrently with Close closing the channel. The
// test asserts the invariant on every iteration of an inner loop so a single
// run gives many race attempts; combine with `-race -count=N` for stress.
func TestRelaySession_NoMessageLossUnderCloseRace(t *testing.T) {
	const (
		iterations = 25
		senders    = 500
	)
	for iter := range iterations {
		t.Run(fmt.Sprintf("iter-%02d", iter), func(t *testing.T) {
			tmpDir := t.TempDir()
			relayCfg := &config.RelayConfig{
				RelayCacheDirectory:  tmpDir,
				ReconnectAttempts:    0, // skip phase 2; leaves the *.log cache file in place
				MaxReconnectInterval: 50 * time.Millisecond,
				ConnectTimeout:       50 * time.Millisecond,
				UpstreamHost:         "127.0.0.1:1", // unreachable
			}

			sessionUUID := uuid.New()
			session, err := NewSession(t.Context(), sessionUUID, createTestAcceptMessage(), relayCfg, nil)
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}

			var (
				startBarrier = make(chan struct{})
				wg           sync.WaitGroup
				mu           sync.Mutex
				acked        = make(map[uint32]struct{}, senders)
			)
			wg.Add(senders)
			for i := range senders {
				go func(i int) {
					defer wg.Done()
					payload := make([]byte, 4)
					binary.BigEndian.PutUint32(payload, uint32(i))
					msg := &pb.ClientMessage{Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{
						Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 0},
						Data:  payload,
					}}}
					<-startBarrier
					if _, err := session.HandleClientMessage(msg); err == nil {
						mu.Lock()
						acked[uint32(i)] = struct{}{}
						mu.Unlock()
					}
				}(i)
			}
			// Release the senders, then Close almost immediately. This
			// maximises the chance that some sends are still committing
			// when Close closes the channel.
			close(startBarrier)
			if err := session.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			wg.Wait()
			waitRelaySession(t, session, 5*time.Second)

			cachePath := filepath.Join(tmpDir, sessionUUID.String()+".log")
			cached, err := readCachedPayloads(cachePath)
			if err != nil {
				t.Fatalf("read cache: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			for idx := range acked {
				if _, ok := cached[idx]; !ok {
					t.Fatalf("data loss: sender %d returned nil error but its payload is absent from cache (ack=%d cached=%d)",
						idx, len(acked), len(cached))
				}
			}
		})
	}
}

// readCachedPayloads opens the relay cache file and returns the set of
// TtyoutBuf payload sender-indices it contains. Non-Ttyout messages
// (AcceptMsg from session init) are skipped.
func readCachedPayloads(path string) (map[uint32]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[uint32]struct{})
	for {
		msg, err := readProtoMessage(f)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		buf := msg.GetTtyoutBuf()
		if buf == nil {
			continue
		}
		data := buf.GetData()
		if len(data) != 4 {
			continue
		}
		out[binary.BigEndian.Uint32(data)] = struct{}{}
	}
}
