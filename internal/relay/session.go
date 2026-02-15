// Filename: internal/relay/session.go
package relay

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	initialReconnectInterval = time.Second
	flushingSuffix           = ".flushing"
)

// Session handles the entire lifecycle of a relay session. It is a durable,
// background process independent of the client connection that created it.
type Session struct {
	logID            string
	config           *config.RelayConfig
	initialAcceptMsg *pb.AcceptMessage
	fromClientChan   chan *pb.ClientMessage
	wg               sync.WaitGroup
	cacheFileName    string
	ctx              context.Context
	cancel           context.CancelFunc
}

// NewSession creates a new relay session handler.
func NewSession(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig) (*Session, error) {
	if err := os.MkdirAll(cfg.RelayCacheDirectory, 0750); err != nil {
		return nil, fmt.Errorf("could not create relay cache directory %s: %w", cfg.RelayCacheDirectory, err)
	}

	// Use UUID string for cache file naming (safe for filenames).
	cacheFileName := filepath.Join(cfg.RelayCacheDirectory, fmt.Sprintf("%s.log", sessionUUID.String()))

	// Generate log_id matching C sudo_logsrvd format: base64(UUID bytes).
	// Relay has no local path, matching journal mode behavior (empty path).
	logID := base64.StdEncoding.EncodeToString(sessionUUID[:])

	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		logID:            logID,
		config:           cfg,
		initialAcceptMsg: acceptMsg,
		fromClientChan:   make(chan *pb.ClientMessage, 1000), // Buffered channel for client messages
		cacheFileName:    cacheFileName,
		ctx:              ctx,
		cancel:           cancel,
	}

	s.wg.Add(1)
	go s.run() // Start the single, durable goroutine for this session.

	return s, nil
}

// run is the core goroutine for a session. It first writes all messages from the
// client to a local cache file. Once the session is complete (ExitMessage),
// it proceeds to persistently try to flush that file to the upstream server.
func (s *Session) run() {
	defer s.wg.Done()
	slog.Debug("Relay session runner started", "log_id", s.logID)

	// Phase 1: Write all incoming messages to the local cache file.
	sessionCompleted := s.writeMessagesToCache()

	if !sessionCompleted {
		slog.Warn("Relay session ended without a final ExitMessage. The cached log will be flushed by the next server startup.", "log_id", s.logID)
		return
	}

	// Phase 2: The client session is complete. Now, persistently try to flush the file.
	slog.Info("Client session complete, beginning persistent flush attempts.", "log_id", s.logID, "file", s.cacheFileName)
	for attempt := 0; s.config.ReconnectAttempts == -1 || attempt < s.config.ReconnectAttempts; attempt++ {
		select {
		case <-s.ctx.Done():
			slog.Info("Relay session cancelled, stopping flush attempts", "log_id", s.logID)
			return
		default:
		}

		proc, err := connectToUpstream(s.config)
		if err != nil {
			slog.Warn("Upstream connection attempt failed", "log_id", s.logID, "error", err)
			backoff := s.calculateBackoff(attempt)
			slog.Info("Waiting before next reconnect attempt", "log_id", s.logID, "duration", backoff)

			// Respect context cancellation during backoff
			select {
			case <-s.ctx.Done():
				slog.Info("Relay session cancelled during backoff", "log_id", s.logID)
				return
			case <-time.After(backoff):
				continue
			}
		}

		// Connection successful, now flush the file.
		slog.Info("Upstream connection successful, flushing cache.", "log_id", s.logID, "file", s.cacheFileName)
		err = flushFile(proc, s.cacheFileName)
		proc.Close() // Always close the connection after flush attempt
		if err != nil {
			slog.Error("Failed during cache flush, will retry.", "log_id", s.logID, "error", err)
		} else {
			slog.Info("Cache flush successful. Relay session finished.", "log_id", s.logID)
			return
		}
	}

	if s.config.ReconnectAttempts != -1 {
		slog.Error("Relay session has exhausted all reconnect attempts. The cached log remains on disk.", "log_id", s.logID, "attempts", s.config.ReconnectAttempts)
	}
}

// writeMessagesToCache opens the cache file and writes all received messages until an ExitMessage.
func (s *Session) writeMessagesToCache() (completed bool) {
	file, err := os.OpenFile(s.cacheFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		slog.Error("CRITICAL: could not open cache file. Relay data for this session will be lost.", "log_id", s.logID, "error", err)
		return
	}
	defer file.Close()

	// Write the essential AcceptMessage first to ensure the cache file is valid for flushing.
	if err := writeProtoMessage(file, &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: s.initialAcceptMsg}}); err != nil {
		slog.Error("Failed to write initial accept message to cache", "log_id", s.logID, "error", err)
		return
	}

	// This loop continues until the client disconnects and the HandleClientMessage channel is closed by its owner.
	for msg := range s.fromClientChan {
		if err := writeProtoMessage(file, msg); err != nil {
			slog.Error("Failed to write message to relay cache", "log_id", s.logID, "error", err)
		}
		if _, ok := msg.Type.(*pb.ClientMessage_ExitMsg); ok {
			slog.Debug("ExitMessage received and cached. Ending write phase.", "log_id", s.logID)
			return true
		}
	}
	// The channel was closed, meaning the client connection handler terminated.
	return false
}

func (s *Session) calculateBackoff(attempts int) time.Duration {
	maxInterval := s.config.MaxReconnectInterval
	if maxInterval <= 0 {
		maxInterval = time.Minute // Fallback to default if not configured or invalid
	}
	backoff := float64(initialReconnectInterval) * math.Pow(2, float64(attempts))
	if backoff > float64(maxInterval) {
		return maxInterval
	}
	return time.Duration(backoff)
}

func (s *Session) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	// Don't process the initial AcceptMsg again, it was handled in NewSession.
	if _, ok := msg.Type.(*pb.ClientMessage_AcceptMsg); ok {
		// For relay mode, we return a log ID immediately to satisfy the client
		return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: s.logID}}, nil
	}

	// Use a timeout to prevent indefinite blocking
	select {
	case s.fromClientChan <- msg:
		return nil, nil
	case <-time.After(5 * time.Second):
		slog.Warn("Relay session message channel timeout", "log_id", s.logID)
		return nil, fmt.Errorf("relay session message channel timeout")
	case <-s.ctx.Done():
		return nil, fmt.Errorf("relay session cancelled")
	}
}

// Close is called by the connection handler when the client disconnects.
// It signals the messageWriter to stop accepting new messages.
func (s *Session) Close() error {
	slog.Info("Client connection closed. Relay session writer will now complete.", "log_id", s.logID)
	close(s.fromClientChan) // Signal the messageWriter loop to terminate.

	// Wait for goroutine to finish, but don't cancel context yet to allow natural completion
	s.wg.Wait()

	// Now cancel context for cleanup
	s.cancel()
	return nil
}

// ---- Standalone Flusher for Orphaned Files ----

// FlushOrphanedFile connects to upstream and sends the content of a single file.
func FlushOrphanedFile(filePath string, cfg *config.RelayConfig) {
	slog.Info("Found orphaned relay file, attempting to flush", "path", filePath)

	// Rename file to prevent another process from picking it up
	flushingFileName := filePath + flushingSuffix
	if err := os.Rename(filePath, flushingFileName); err != nil {
		slog.Error("Could not rename orphaned file for flushing", "path", filePath, "error", err)
		return
	}

	proc, err := connectToUpstream(cfg)
	if err != nil {
		slog.Error("Failed to connect to upstream for orphaned file flush", "path", flushingFileName, "error", err)
		os.Rename(flushingFileName, filePath)
		return
	}

	err = flushFile(proc, flushingFileName)
	proc.Close() // Always close the connection after flush attempt
	if err != nil {
		slog.Error("Failed to flush orphaned file, renaming back", "path", flushingFileName, "error", err)
		os.Rename(flushingFileName, filePath)
		return
	}
	slog.Info("Successfully flushed orphaned relay file", "path", flushingFileName)
}

func flushFile(proc protocol.Processor, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open cache file for flushing: %w", err)
	}
	defer func() {
		f.Close()
		if err := os.Remove(filePath); err != nil {
			slog.Error("Failed to remove flushed cache file", "path", filePath, "error", err)
		}
	}()

	// The first message (AcceptMsg) must be sent to initiate the session upstream.
	// Since connectToUpstream now handles this, we can just read and send all messages from the file.
	for {
		msg, err := readProtoMessage(f)
		if err == io.EOF {
			return nil // Success
		}
		if err != nil {
			return fmt.Errorf("error reading message from cache during flush: %w", err)
		}

		// The first message sent by this loop will be the AcceptMessage.
		if err := proc.WriteClientMessage(msg); err != nil {
			return fmt.Errorf("failed to send flushed message to upstream: %w", err)
		}

		// Wait for response after sending AcceptMsg
		if msg.GetAcceptMsg() != nil {
			if _, err := proc.ReadServerMessage(); err != nil {
				return fmt.Errorf("did not get log_id response from upstream: %w", err)
			}
		}
	}
}

func connectToUpstream(cfg *config.RelayConfig) (protocol.Processor, error) {
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout}
	var conn net.Conn
	var err error

	slog.Debug("Dialing upstream", "host", cfg.UpstreamHost, "use_tls", cfg.UseTLS, "tls_skip_verify", cfg.TLSSkipVerify)
	if cfg.UseTLS {
		tlsConfig := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify}
		conn, err = tls.DialWithDialer(dialer, "tcp", cfg.UpstreamHost, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", cfg.UpstreamHost)
	}

	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	proc := protocol.NewProcessorWithCloser(conn, conn, conn)
	slog.Debug("Starting handshake with upstream")
	helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "GoSudoLogSrv-Relay/1.0"}}}
	if err := proc.WriteClientMessage(helloMsg); err != nil {
		proc.Close()
		return nil, fmt.Errorf("failed to send ClientHello to upstream: %w", err)
	}
	if _, err = proc.ReadServerMessage(); err != nil {
		proc.Close()
		return nil, fmt.Errorf("failed to receive ServerHello from upstream: %w", err)
	}
	return proc, nil
}

// writeProtoMessage serializes and writes a single protobuf message with its length prefix.
func writeProtoMessage(w io.Writer, msg *pb.ClientMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// readProtoMessage reads a single length-prefixed protobuf message.
func readProtoMessage(r io.Reader) (*pb.ClientMessage, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	data := make([]byte, msgLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	msg := &pb.ClientMessage{}
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
