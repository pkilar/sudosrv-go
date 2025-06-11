// Filename: internal/relay/session.go
package relay

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"time"
)

const (
	maxReconnectInterval     = time.Minute
	initialReconnectInterval = time.Second
)

// Session handles relaying I/O logs for one session to an upstream server.
type Session struct {
	logID            string
	config           *config.RelayConfig
	initialAcceptMsg *pb.AcceptMessage
	upstreamConn     net.Conn
	upstreamProc     protocol.Processor
	toClientChan     chan *pb.ServerMessage
	fromClientChan   chan *pb.ClientMessage
	done             chan struct{}
	connMux          sync.Mutex
	wg               sync.WaitGroup
}

// NewSession creates a new relay session handler.
func NewSession(logID string, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig) (*Session, error) {
	s := &Session{
		logID:            logID,
		config:           cfg,
		initialAcceptMsg: acceptMsg,
		toClientChan:     make(chan *pb.ServerMessage),
		fromClientChan:   make(chan *pb.ClientMessage, 100), // Buffer to hold messages during reconnect
		done:             make(chan struct{}),
	}

	s.wg.Add(1)
	go s.manager()

	return s, nil
}

// manager is the core goroutine that manages the connection lifecycle.
func (s *Session) manager() {
	defer s.wg.Done()

	reconnectAttempts := 0
	for {
		slog.Info("Attempting to connect to upstream server", "log_id", s.logID, "attempt", reconnectAttempts+1)
		err := s.connectToUpstream()
		if err != nil {
			slog.Error("Failed to connect to upstream", "log_id", s.logID, "error", err)

			select {
			case <-s.done:
				slog.Info("Manager shutting down during reconnect backoff.", "log_id", s.logID)
				return // Abort on shutdown signal
			case <-time.After(s.calculateBackoff(reconnectAttempts)):
				reconnectAttempts++
				continue
			}
		}

		slog.Info("Successfully connected to upstream server", "log_id", s.logID)
		reconnectAttempts = 0 // Reset on successful connection

		// Start reader and writer for the new connection
		var localWg sync.WaitGroup
		localWg.Add(2)

		connDone := make(chan struct{})

		go func() {
			defer localWg.Done()
			s.upstreamWriter(connDone)
		}()
		go func() {
			defer localWg.Done()
			s.upstreamReader(connDone)
		}()

		localWg.Wait() // Wait for reader/writer to exit, indicating connection loss
		slog.Warn("Connection to upstream lost. Will attempt to reconnect.", "log_id", s.logID)

		// Check if we should exit permanently
		select {
		case <-s.done:
			slog.Info("Manager shutting down permanently.", "log_id", s.logID)
			return
		default:
			// Continue to reconnect loop
		}
	}
}

func (s *Session) calculateBackoff(attempts int) time.Duration {
	if attempts == 0 {
		return initialReconnectInterval
	}
	backoff := float64(initialReconnectInterval) * math.Pow(2, float64(attempts))
	if backoff > float64(maxReconnectInterval) {
		return maxReconnectInterval
	}
	return time.Duration(backoff)
}

// connectToUpstream dials the upstream server and performs the initial handshake.
func (s *Session) connectToUpstream() error {
	s.connMux.Lock()
	defer s.connMux.Unlock()

	dialer := &net.Dialer{Timeout: s.config.ConnectTimeout}
	var conn net.Conn
	var err error

	if s.config.UseTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", s.config.UpstreamHost, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", s.config.UpstreamHost)
	}

	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}

	s.upstreamConn = conn
	s.upstreamProc = protocol.NewProcessor(s.upstreamConn, s.upstreamConn)

	// Perform handshake
	// 1. Send ClientHello
	helloMsg := &pb.ClientMessage{Event: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "GoSudoLogSrv-Relay/1.0"}}}
	if err := s.upstreamProc.WriteClientMessage(helloMsg); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send ClientHello to upstream: %w", err)
	}

	// 2. Read ServerHello
	_, err = s.upstreamProc.ReadServerMessage() // We don't do much with the response, just ensure it's valid
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive ServerHello from upstream: %w", err)
	}

	// 3. Send the original AcceptMessage to start the log session
	acceptMsg := &pb.ClientMessage{Event: &pb.ClientMessage_AcceptMsg{AcceptMsg: s.initialAcceptMsg}}
	if err := s.upstreamProc.WriteClientMessage(acceptMsg); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send AcceptMessage to upstream: %w", err)
	}

	// 4. Read the log_id response
	logIDResponse, err := s.upstreamProc.ReadServerMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive log_id from upstream: %w", err)
	}
	if logIDResponse.GetLogId() == "" {
		conn.Close()
		return fmt.Errorf("upstream did not respond with a valid log_id")
	}

	return nil
}

// HandleClientMessage queues a message to be sent to the upstream server.
func (s *Session) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	// Don't forward the initial AcceptMsg as it's handled by the connect logic.
	if _, ok := msg.Event.(*pb.ClientMessage_AcceptMsg); ok {
		// We expect the first response to be the log_id from the handshake.
		// This is a bit of a simplification; a more robust implementation might
		// use a different channel for the very first response.
	} else {
		select {
		case s.fromClientChan <- msg:
		case <-s.done:
			return nil, fmt.Errorf("relay session is closed")
		}
	}

	// Wait for a response from the reader goroutine
	select {
	case serverMsg, ok := <-s.toClientChan:
		if !ok {
			return nil, fmt.Errorf("relay session closed while waiting for response")
		}
		return serverMsg, nil
	case <-s.done:
		return nil, fmt.Errorf("relay session closed while waiting for response")
	}
}

// upstreamReader reads messages from the upstream server and sends them to the client handler.
func (s *Session) upstreamReader(connDone chan struct{}) {
	defer close(connDone) // Signal writer and manager that this connection is dead

	for {
		s.connMux.Lock()
		proc := s.upstreamProc
		s.connMux.Unlock()

		if proc == nil {
			time.Sleep(100 * time.Millisecond) // Wait for connection
			continue
		}

		serverMsg, err := proc.ReadServerMessage()
		if err != nil {
			slog.Debug("Upstream read failed, closing reader.", "log_id", s.logID, "error", err)
			s.closeCurrentConnection()
			return
		}

		select {
		case s.toClientChan <- serverMsg:
		case <-s.done:
			return
		}
	}
}

// upstreamWriter writes messages from the client to the upstream server.
func (s *Session) upstreamWriter(connDone chan struct{}) {
	for {
		select {
		case clientMsg := <-s.fromClientChan:
			s.connMux.Lock()
			proc := s.upstreamProc
			s.connMux.Unlock()

			if proc == nil {
				slog.Warn("Upstream writer has message but no connection, message may be delayed.", "log_id", s.logID)
				// Re-queue the message, this is not ideal. A better queue is needed for production.
				// For now, this will likely block until a reconnect happens, which is acceptable.
				s.fromClientChan <- clientMsg
				time.Sleep(time.Second)
				continue
			}

			if err := proc.WriteClientMessage(clientMsg); err != nil {
				slog.Debug("Upstream write failed, closing writer.", "log_id", s.logID, "error", err)
				s.closeCurrentConnection()
				// Do not return here, let the reader's failure trigger the reconnect logic
			}
		case <-connDone: // Fired by reader when it exits
			return
		case <-s.done:
			return
		}
	}
}

// closeCurrentConnection safely closes the current upstream connection.
func (s *Session) closeCurrentConnection() {
	s.connMux.Lock()
	defer s.connMux.Unlock()
	if s.upstreamConn != nil {
		s.upstreamConn.Close()
		s.upstreamConn = nil
		s.upstreamProc = nil
	}
}

// Close terminates the relay session permanently.
func (s *Session) Close() error {
	slog.Info("Permanently closing relay session", "log_id", s.logID)
	close(s.done)
	s.closeCurrentConnection()
	s.wg.Wait() // Wait for manager to finish
	close(s.fromClientChan)
	close(s.toClientChan)
	return nil
}
