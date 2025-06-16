// Filename: internal/connection/handler_test.go
package connection

import (
	"io"
	"net"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"testing"
	"time"
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
		handler.sessionFactories.newLocalStorageSession = func(logID string, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error) {
			return &mockSessionHandler{
				t: t,
				HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
					return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: logID}}, nil
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
