// Filename: internal/connection/handler_test.go
package connection

import (
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

func TestConnectionHandler(t *testing.T) {
	// Default test config
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:        "local",
			IdleTimeout: 1 * time.Second,
			ServerID:    "TestSrv",
		},
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
		helloMsg := &pb.ClientMessage{Event: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "test-harness"}}}
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
		} else if serverHello.GetServerId() != cfg.Server.ServerID {
			t.Errorf("Expected server ID '%s', got '%s'", cfg.Server.ServerID, serverHello.GetServerId())
		}

		serverConn.Close() // Close connection to stop the handler
		wg.Wait()
	})

	t.Run("AcceptMessageStartsSession", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		// Override NewSession to inject our mock
		originalNewSession := storage.NewSession
		defer func() { storage.NewSession = originalNewSession }()

		sessionClosed := make(chan bool, 1)

		storage.NewSession = func(logID string, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (storage.SessionHandler, error) {
			return &mockSessionHandler{
				t: t,
				HandleClientFn: func(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
					// This is the first call with the AcceptMsg
					if msg.GetAcceptMsg() == nil {
						t.Error("First message to session should be AcceptMsg")
					}
					// Respond with log_id
					return &pb.ServerMessage{Event: &pb.ServerMessage_LogId{LogId: logID}}, nil
				},
				CloseFn: func() error {
					sessionClosed <- true
					return nil
				},
			}, nil
		}

		handler := NewHandler(serverConn, cfg)
		go handler.Handle()

		clientProc := protocol.NewProcessor(clientConn, clientConn)

		// Client sends Accept
		acceptMsg := &pb.ClientMessage{Event: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{ExpectIobufs: true}}}
		if err := clientProc.WriteClientMessage(acceptMsg); err != nil {
			t.Fatalf("Client failed to write Accept: %v", err)
		}

		// Client reads log_id response
		response, err := clientProc.ReadServerMessage()
		if err != nil {
			t.Fatalf("Client failed to read response to Accept: %v", err)
		}

		if response.GetLogId() == "" {
			t.Fatal("Expected log_id response, got something else")
		}

		// Closing the connection should trigger the session's Close() method
		serverConn.Close()

		select {
		case <-sessionClosed:
			// Success
		case <-time.After(1 * time.Second):
			t.Fatal("Session Close() was not called on connection termination")
		}
	})
}
