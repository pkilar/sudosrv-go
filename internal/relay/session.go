// Filename: internal/relay/session.go
package relay

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

const (
	maxReconnectInterval     = time.Minute
	initialReconnectInterval = time.Second
	relayCacheDir            = "/var/log/gosudo-relay-cache" // Directory for storing logs when disconnected
)

type relayState int

const (
	stateConnected relayState = iota
	stateDisconnected
	stateFlushing
)

// String returns a string representation of the relayState.
func (rs relayState) String() string {
	switch rs {
	case stateConnected:
		return "Connected"
	case stateDisconnected:
		return "Disconnected"
	case stateFlushing:
		return "Flushing"
	default:
		return "Unknown"
	}
}

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
	state            relayState
	cacheFile        *os.File
	cacheFileName    string
}

// NewSession creates a new relay session handler.
func NewSession(logID string, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig) (*Session, error) {
	if err := os.MkdirAll(relayCacheDir, 0750); err != nil {
		return nil, fmt.Errorf("could not create relay cache directory %s: %w", relayCacheDir, err)
	}

	s := &Session{
		logID:            logID,
		config:           cfg,
		initialAcceptMsg: acceptMsg,
		toClientChan:     make(chan *pb.ServerMessage),
		fromClientChan:   make(chan *pb.ClientMessage, 100),
		done:             make(chan struct{}),
		state:            stateDisconnected,
		cacheFileName:    filepath.Join(relayCacheDir, fmt.Sprintf("%s.log", logID)),
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
		select {
		case <-s.done:
			slog.Info("Manager shutting down permanently.", "log_id", s.logID)
			return
		default:
		}

		slog.Info("Attempting to connect to upstream server", "log_id", s.logID, "attempt", reconnectAttempts+1)
		err := s.connectToUpstream()
		if err != nil {
			slog.Error("Failed to connect to upstream", "log_id", s.logID, "error", err)
			s.setState(stateDisconnected)
			backoffDuration := s.calculateBackoff(reconnectAttempts)
			slog.Info("Waiting before next reconnect attempt", "log_id", s.logID, "duration", backoffDuration)
			select {
			case <-s.done:
				slog.Info("Manager shutting down during reconnect backoff.", "log_id", s.logID)
				return
			case <-time.After(backoffDuration):
				reconnectAttempts++
				continue
			}
		}

		slog.Info("Successfully connected to upstream server", "log_id", s.logID)
		reconnectAttempts = 0

		s.flushCache() // Flush any cached logs

		s.setState(stateConnected) // Switch to real-time relaying

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
		localWg.Wait()

		slog.Warn("Connection to upstream lost. Will attempt to reconnect.", "log_id", s.logID)
		s.setState(stateDisconnected)
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

func (s *Session) connectToUpstream() error {
	s.connMux.Lock()
	defer s.connMux.Unlock()

	dialer := &net.Dialer{Timeout: s.config.ConnectTimeout}
	var conn net.Conn
	var err error

	slog.Debug("Dialing upstream", "host", s.config.UpstreamHost, "use_tls", s.config.UseTLS)
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

	slog.Debug("Starting handshake with upstream", "log_id", s.logID)
	// 1. Send ClientHello
	helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "GoSudoLogSrv-Relay/1.0"}}}
	if err := s.upstreamProc.WriteClientMessage(helloMsg); err != nil {
		conn.Close()
		return fmt.Errorf("failed to send ClientHello to upstream: %w", err)
	}

	// 2. Read ServerHello
	if _, err = s.upstreamProc.ReadServerMessage(); err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive ServerHello from upstream: %w", err)
	}

	// 3. Send the original AcceptMessage to start the log session
	acceptMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: s.initialAcceptMsg}}
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
	slog.Debug("Upstream handshake complete", "log_id", s.logID, "upstream_log_id", logIDResponse.GetLogId())
	return nil
}

func (s *Session) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	if _, ok := msg.Type.(*pb.ClientMessage_AcceptMsg); !ok {
		select {
		case s.fromClientChan <- msg:
		case <-s.done:
			return nil, fmt.Errorf("relay session is closed")
		}
	}

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

func (s *Session) upstreamReader(connDone chan struct{}) {
	defer close(connDone)

	for {
		proc := s.getProcessor()
		if proc == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		serverMsg, err := proc.ReadServerMessage()
		if err != nil {
			slog.Debug("Upstream read failed, closing reader.", "log_id", s.logID, "error", err)
			s.closeCurrentConnection()
			return
		}
		slog.Debug("Relay received message from upstream", "log_id", s.logID, "message_type", fmt.Sprintf("%T", serverMsg.Type))

		select {
		case s.toClientChan <- serverMsg:
		case <-s.done:
			return
		}
	}
}

func (s *Session) upstreamWriter(connDone chan struct{}) {
	for {
		select {
		case clientMsg := <-s.fromClientChan:
			s.connMux.Lock()
			currentState := s.state
			s.connMux.Unlock()

			if currentState == stateConnected {
				proc := s.getProcessor()
				if proc == nil {
					// Connection likely just dropped, requeue and let manager handle it
					s.fromClientChan <- clientMsg
					time.Sleep(100 * time.Millisecond)
					continue
				}
				slog.Debug("Relay sending message to upstream", "log_id", s.logID, "message_type", fmt.Sprintf("%T", clientMsg.Type))
				if err := proc.WriteClientMessage(clientMsg); err != nil {
					slog.Debug("Upstream write failed.", "log_id", s.logID, "error", err)
					s.closeCurrentConnection()
				}
			} else {
				// State is disconnected or flushing, cache the message to disk
				if err := s.writeToCache(clientMsg); err != nil {
					slog.Error("Failed to write to relay cache", "log_id", s.logID, "error", err)
				}
			}
		case <-connDone:
			return
		case <-s.done:
			return
		}
	}
}

func (s *Session) setState(newState relayState) {
	s.connMux.Lock()
	defer s.connMux.Unlock()

	if s.state == newState {
		return
	}

	slog.Info("Relay session changing state", "log_id", s.logID, "from", s.state, "to", newState)
	s.state = newState

	// Handle cache file on state transitions
	if newState == stateDisconnected && s.cacheFile == nil {
		var err error
		s.cacheFile, err = os.OpenFile(s.cacheFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			slog.Error("Failed to open relay cache file for writing", "log_id", s.logID, "path", s.cacheFileName, "error", err)
		}
	} else if (newState == stateConnected || newState == stateFlushing) && s.cacheFile != nil {
		s.cacheFile.Close()
		s.cacheFile = nil
	}
}

func (s *Session) writeToCache(msg *pb.ClientMessage) error {
	s.connMux.Lock()
	defer s.connMux.Unlock()
	if s.cacheFile == nil {
		return fmt.Errorf("cache file is not open")
	}

	slog.Debug("Caching message to disk", "log_id", s.logID, "message_type", fmt.Sprintf("%T", msg.Type))
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message for cache: %w", err)
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	if _, err := s.cacheFile.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length prefix to cache: %w", err)
	}
	if _, err := s.cacheFile.Write(data); err != nil {
		return fmt.Errorf("failed to write payload to cache: %w", err)
	}
	return nil
}

func (s *Session) flushCache() {
	s.setState(stateFlushing)
	slog.Info("Starting to flush relay cache from disk", "log_id", s.logID, "path", s.cacheFileName)

	f, err := os.Open(s.cacheFileName)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("No cache file to flush.", "log_id", s.logID)
			return // Nothing to do
		}
		slog.Error("Failed to open cache file for flushing", "log_id", s.logID, "error", err)
		return
	}
	defer f.Close()

	lenBuf := make([]byte, 4)
	for {
		// Read message from cache file
		_, err := io.ReadFull(f, lenBuf)
		if err == io.EOF {
			break // End of file
		}
		if err != nil {
			slog.Error("Failed to read length prefix from cache during flush", "log_id", s.logID, "error", err)
			return
		}
		msgLen := binary.BigEndian.Uint32(lenBuf)
		data := make([]byte, msgLen)
		if _, err := io.ReadFull(f, data); err != nil {
			slog.Error("Failed to read payload from cache during flush", "log_id", s.logID, "error", err)
			return
		}

		msg := &pb.ClientMessage{}
		if err := proto.Unmarshal(data, msg); err != nil {
			slog.Error("Failed to unmarshal message from cache during flush", "log_id", s.logID, "error", err)
			continue
		}

		// Send message to upstream
		slog.Debug("Flushing cached message to upstream", "log_id", s.logID, "message_type", fmt.Sprintf("%T", msg.Type))
		if err := s.getProcessor().WriteClientMessage(msg); err != nil {
			slog.Error("Failed to send flushed message to upstream, aborting flush", "log_id", s.logID, "error", err)
			s.closeCurrentConnection() // Connection is dead
			return
		}
	}

	slog.Info("Finished flushing relay cache", "log_id", s.logID)
	// Truncate and remove the cache file now that it's empty
	f.Close()
	if err := os.Remove(s.cacheFileName); err != nil {
		slog.Error("Failed to remove flushed cache file", "log_id", s.logID, "error", err)
	}
}

func (s *Session) getProcessor() protocol.Processor {
	s.connMux.Lock()
	defer s.connMux.Unlock()
	return s.upstreamProc
}

func (s *Session) closeCurrentConnection() {
	s.connMux.Lock()
	defer s.connMux.Unlock()
	if s.upstreamConn != nil {
		s.upstreamConn.Close()
		s.upstreamConn = nil
		s.upstreamProc = nil
	}
}

func (s *Session) Close() error {
	slog.Info("Permanently closing relay session", "log_id", s.logID)
	close(s.done)
	s.closeCurrentConnection()
	s.wg.Wait()
	close(s.fromClientChan)
	close(s.toClientChan)

	// Clean up cache file if it exists
	s.connMux.Lock()
	if s.cacheFile != nil {
		s.cacheFile.Close()
	}
	s.connMux.Unlock()
	return nil
}
