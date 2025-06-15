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
	// The 'done' channel is used to signal shutdown from the main server process.
	// In this revised model, we assume the session lives until its work is done
	// or the entire server process terminates.
	wg sync.WaitGroup

	cacheFileName string
}

// NewSession creates a new relay session handler.
func NewSession(logID string, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig) (*Session, error) {
	if err := os.MkdirAll(cfg.RelayCacheDirectory, 0750); err != nil {
		return nil, fmt.Errorf("could not create relay cache directory %s: %w", cfg.RelayCacheDirectory, err)
	}

	cacheFileName := filepath.Join(cfg.RelayCacheDirectory, fmt.Sprintf("%s.log", logID))

	s := &Session{
		logID:            logID,
		config:           cfg,
		initialAcceptMsg: acceptMsg,
		fromClientChan:   make(chan *pb.ClientMessage, 100), // Buffered channel for client messages
		cacheFileName:    cacheFileName,
	}

	s.wg.Add(1)
	go s.run() // Start the single, durable goroutine for this session.

	return s, nil
}

// run is the core goroutine for a session. It first writes all messages from the
// client to a local cache file. Once the client session is complete (ExitMessage),
// it proceeds to persistently try to flush that file to the upstream server.
func (s *Session) run() {
	defer s.wg.Done()
	slog.Debug("Relay session runner started", "log_id", s.logID)

	// Phase 1: Write all incoming messages to the local cache file.
	// This phase completes when an ExitMessage is received and written.
	sessionCompleted := s.writeMessagesToCache()

	if !sessionCompleted {
		slog.Warn("Relay session ended without a final ExitMessage. The cached log will be flushed by the next server startup.", "log_id", s.logID)
		return
	}

	// Phase 2: The client session is complete. Now, persistently try to flush the file.
	slog.Info("Client session complete, beginning persistent flush attempts.", "log_id", s.logID, "file", s.cacheFileName)
	for attempt := 0; s.config.ReconnectAttempts == -1 || attempt < s.config.ReconnectAttempts; attempt++ {
		proc, err := connectToUpstream(s.config, s.initialAcceptMsg)
		if err != nil {
			slog.Warn("Upstream connection attempt failed", "log_id", s.logID, "error", err)
			backoff := s.calculateBackoff(attempt)
			slog.Info("Waiting before next reconnect attempt", "log_id", s.logID, "duration", backoff)
			time.Sleep(backoff) // Simple sleep, as this goroutine has no other tasks.
			continue
		}

		// Connection successful, now flush the file.
		slog.Info("Upstream connection successful, flushing cache.", "log_id", s.logID, "file", s.cacheFileName)
		err = flushFile(proc, s.cacheFileName)
		if err != nil {
			slog.Error("Failed during cache flush, will retry.", "log_id", s.logID, "error", err)
			// The connection is likely dead, so loop to retry the whole process.
		} else {
			slog.Info("Cache flush successful. Relay session finished.", "log_id", s.logID)
			return // Success! The goroutine can exit.
		}
	}

	if s.config.ReconnectAttempts != -1 {
		slog.Warn("Relay session has exhausted all reconnect attempts. The cached log remains on disk.", "log_id", s.logID, "attempts", s.config.ReconnectAttempts)
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
			return true // Session completed normally.
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
		return nil, nil
	}
	s.fromClientChan <- msg
	return nil, nil
}

// Close is called by the connection handler when the client disconnects.
// It signals the messageWriter to stop accepting new messages.
func (s *Session) Close() error {
	slog.Info("Client connection closed. Relay session writer will now complete.", "log_id", s.logID)
	close(s.fromClientChan) // Signal the messageWriter loop to terminate.
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

	f, err := os.Open(flushingFileName)
	if err != nil {
		slog.Error("Failed to open renamed orphaned file for flushing", "path", flushingFileName, "error", err)
		return
	}
	defer f.Close()

	// Read the first message to get the AcceptMessage
	firstMsg, err := readProtoMessage(f)
	if err != nil {
		slog.Error("Could not read initial message from orphaned file", "path", flushingFileName, "error", err)
		return
	}

	acceptMsg := firstMsg.GetAcceptMsg()
	if acceptMsg == nil {
		slog.Error("First message in orphaned file is not AcceptMessage, cannot flush", "path", flushingFileName)
		return
	}

	// Attempt to connect and flush persistently
	for attempt := 0; cfg.ReconnectAttempts == -1 || attempt < cfg.ReconnectAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(initialReconnectInterval) // Simple backoff for orphaned files
		}

		proc, err := connectToUpstream(cfg, acceptMsg)
		if err != nil {
			slog.Warn("Failed to connect to upstream for orphaned file flush", "path", flushingFileName, "error", err)
			continue
		}

		if err := flushFile(proc, flushingFileName, f); err != nil {
			slog.Error("Failed to flush orphaned file, will retry", "path", flushingFileName, "error", err)
			continue // Try again
		}

		slog.Info("Successfully flushed orphaned relay file", "path", flushingFileName)
		return // Success
	}

	slog.Error("Exhausted all attempts to flush orphaned file. Renaming it back.", "path", flushingFileName)
	os.Rename(flushingFileName, filePath) // Rename back on persistent failure
}

// flushFile reads a cache file message-by-message and sends it via the processor.
func flushFile(proc protocol.Processor, filePath string, file ...*os.File) error {
	var f *os.File
	var err error

	isReusedHandle := len(file) > 0 && file[0] != nil
	if isReusedHandle {
		f = file[0]
		if _, err := f.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek to start of cache file: %w", err)
		}
	} else {
		f, err = os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open cache file for flushing: %w", err)
		}
		defer f.Close()
	}

	// The first message (AcceptMsg) must be sent to initiate the session upstream.
	// Since connectToUpstream now handles this, we can just read and send all messages from the file.
	for {
		msg, err := readProtoMessage(f)
		if err == io.EOF {
			break // Successfully read all messages
		}
		if err != nil {
			return fmt.Errorf("error reading message from cache during flush: %w", err)
		}

		// The first message sent by this loop will be the AcceptMessage.
		if err := proc.WriteClientMessage(msg); err != nil {
			return fmt.Errorf("failed to send flushed message to upstream: %w", err)
		}
	}

	if !isReusedHandle {
		f.Close() // Explicitly close if we opened it here
	}
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to remove flushed cache file: %w", err)
	}

	return nil
}

// connectToUpstream is a helper to establish and handshake with an upstream server.
func connectToUpstream(cfg *config.RelayConfig, initialAcceptMsg *pb.AcceptMessage) (protocol.Processor, error) {
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout}
	var conn net.Conn
	var err error

	slog.Debug("Dialing upstream", "host", cfg.UpstreamHost, "use_tls", cfg.UseTLS)
	if cfg.UseTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", cfg.UpstreamHost, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", cfg.UpstreamHost)
	}

	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	proc := protocol.NewProcessor(conn, conn)

	slog.Debug("Starting handshake with upstream")
	helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "GoSudoLogSrv-Relay/1.0"}}}
	if err := proc.WriteClientMessage(helloMsg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send ClientHello to upstream: %w", err)
	}

	if _, err = proc.ReadServerMessage(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to receive ServerHello from upstream: %w", err)
	}
	return proc, nil
}

// writeProtoMessage serializes and writes a single protobuf message with its length prefix.
func writeProtoMessage(w io.Writer, msg *pb.ClientMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message for cache: %w", err)
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length prefix to cache: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write payload to cache: %w", err)
	}
	return nil
}

// readProtoMessage reads a single length-prefixed protobuf message.
func readProtoMessage(r io.Reader) (*pb.ClientMessage, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err // Can be io.EOF
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
