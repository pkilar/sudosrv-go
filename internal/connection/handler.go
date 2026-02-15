// Filename: internal/connection/handler.go
package connection

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/metrics"
	"sudosrv/internal/protocol"
	"sudosrv/internal/relay"
	"sudosrv/internal/storage"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Handler manages a single client connection.
type Handler struct {
	ctx       context.Context
	conn      net.Conn
	config    *config.Config
	processor protocol.Processor
	logID     string
	session   SessionHandler
	isTLS     bool
	// Rate limiting
	messageCount    int64
	lastMessageTime time.Time
	rateLimitMutex  sync.Mutex
	// sessionFactories allows for injecting mock session creators during tests.
	sessionFactories struct {
		newLocalStorageSession func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error)
		newRelaySession        func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig) (SessionHandler, error)
		newLocalRestartSession func(restartMsg *pb.RestartMessage, cfg *config.LocalStorageConfig) (SessionHandler, error)
	}
}

// SessionHandler defines the interface for handling session data (either locally or by relay).
type SessionHandler interface {
	HandleClientMessage(*pb.ClientMessage) (*pb.ServerMessage, error)
	Close() error
}

// NewHandler creates a new handler for a connection.
func NewHandler(conn net.Conn, cfg *config.Config) *Handler {
	return NewHandlerWithContext(context.Background(), conn, cfg)
}

// NewHandlerWithContext creates a new handler for a connection with context support.
func NewHandlerWithContext(ctx context.Context, conn net.Conn, cfg *config.Config) *Handler {
	_, isTLS := conn.(*tls.Conn)
	h := &Handler{
		ctx:             ctx,
		conn:            conn,
		config:          cfg,
		processor:       protocol.NewProcessorWithCloser(conn, conn, conn),
		isTLS:           isTLS,
		lastMessageTime: time.Now(),
	}

	// Initialize factories to point to the real session creation functions.
	h.sessionFactories.newLocalStorageSession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
		return storage.NewSession(sessionUUID, acceptMsg, localCfg)
	}
	h.sessionFactories.newRelaySession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, relayCfg *config.RelayConfig) (SessionHandler, error) {
		return relay.NewSession(sessionUUID, acceptMsg, relayCfg)
	}
	h.sessionFactories.newLocalRestartSession = func(restartMsg *pb.RestartMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
		return storage.NewRestartSession(restartMsg, localCfg)
	}
	return h
}

// Handle runs the message processing loop for the connection.
func (h *Handler) Handle() {
	defer func() {
		if h.session != nil {
			metrics.Global.DecrementActiveSessions()
			if err := h.session.Close(); err != nil {
				slog.Error("Failed to close session", "error", err, "remote_addr", h.conn.RemoteAddr())
			}
		}
		if err := h.processor.Close(); err != nil {
			slog.Error("Failed to close processor", "error", err, "remote_addr", h.conn.RemoteAddr())
		}
		slog.Info("Connection closed", "remote_addr", h.conn.RemoteAddr(),
			"active_connections", metrics.Global.GetActiveConnections(), "active_sessions", metrics.Global.GetActiveSessions())
	}()

	// Main message loop
	for {
		// Check if context is cancelled
		select {
		case <-h.ctx.Done():
			slog.Info("Connection handler stopping due to context cancellation", "remote_addr", h.conn.RemoteAddr())
			return
		default:
		}

		if err := h.conn.SetReadDeadline(time.Now().Add(h.config.Server.IdleTimeout)); err != nil {
			slog.Error("Failed to set read deadline", "error", err)
			return
		}

		clientMsg, err := h.processor.ReadClientMessage()
		if err != nil {
			// Check if the error is due to context cancellation
			select {
			case <-h.ctx.Done():
				slog.Info("Connection handler stopping due to context cancellation during read", "remote_addr", h.conn.RemoteAddr())
				return
			default:
				slog.Debug("Failed to read client message", "error", err, "remote_addr", h.conn.RemoteAddr())
				return
			}
		}

		// Apply rate limiting to prevent memory exhaustion
		if !h.checkRateLimit() {
			slog.Warn("Rate limit exceeded, closing connection", "remote_addr", h.conn.RemoteAddr())
			errMsg := &pb.ServerMessage{Type: &pb.ServerMessage_Error{Error: "Rate limit exceeded"}}
			_ = h.processor.WriteServerMessage(errMsg)
			return
		}

		serverMsg, err := h.processMessage(clientMsg)
		if err != nil {
			metrics.Global.IncrementMessageErrors()
			slog.Error("Error processing message", "error", err, "remote_addr", h.conn.RemoteAddr(),
				"message_errors", metrics.Global.GetMessageErrors())
			// Attempt to send a fatal error to the client
			errMsg := &pb.ServerMessage{Type: &pb.ServerMessage_Error{Error: "Internal Server Error"}}
			_ = h.processor.WriteServerMessage(errMsg)
			return
		}

		metrics.Global.IncrementMessagesProcessed()

		if serverMsg != nil {
			if err := h.processor.WriteServerMessage(serverMsg); err != nil {
				slog.Error("Failed to write server message", "error", err, "remote_addr", h.conn.RemoteAddr())
				return
			}
		}
	}
}

// processMessage contains the main state machine for the protocol.
func (h *Handler) processMessage(clientMsg *pb.ClientMessage) (*pb.ServerMessage, error) {
	// If a session (relay or local) is active, pass the message to it.
	if h.session != nil {
		return h.session.HandleClientMessage(clientMsg)
	}

	// Handle pre-session messages
	switch event := clientMsg.Type.(type) {
	case *pb.ClientMessage_HelloMsg:
		slog.Info("Received ClientHello", "client_id", event.HelloMsg.ClientId, "remote_addr", h.conn.RemoteAddr())
		return h.handleHello()

	case *pb.ClientMessage_AcceptMsg:
		slog.Info("Received AcceptMessage", "expect_io", event.AcceptMsg.ExpectIobufs, "remote_addr", h.conn.RemoteAddr())
		return h.handleAccept(event.AcceptMsg)

	case *pb.ClientMessage_AlertMsg:
		slog.Info("Received pre-session AlertMessage",
			"reason", event.AlertMsg.GetReason(),
			"remote_addr", h.conn.RemoteAddr())
		if alertTime := event.AlertMsg.GetAlertTime(); alertTime != nil {
			slog.Info("Alert details", "alert_time", time.Unix(alertTime.TvSec, int64(alertTime.TvNsec)).UTC())
		}
		for _, info := range event.AlertMsg.GetInfoMsgs() {
			slog.Info("Alert info", "key", info.GetKey(), "value", info.GetStrval())
		}
		return nil, nil // No response needed for alerts

	case *pb.ClientMessage_RejectMsg:
		slog.Info("Received RejectMessage", "reason", event.RejectMsg.Reason, "remote_addr", h.conn.RemoteAddr())
		return h.handleReject(event.RejectMsg)

	case *pb.ClientMessage_RestartMsg:
		slog.Info("Received RestartMessage", "log_id", event.RestartMsg.GetLogId(), "remote_addr", h.conn.RemoteAddr())
		return h.handleRestart(event.RestartMsg)

	case *pb.ClientMessage_ExitMsg:
		// This can happen if a command is run without I/O logging.
		slog.Info("Received ExitMessage for a non-I/O-logged session", "remote_addr", h.conn.RemoteAddr())
		return nil, nil

	default:
		// If we have a session handler, it will take care of other message types.
		// If not, it's a protocol error to receive other messages.
		slog.Warn("Received unexpected message before session start", "type", fmt.Sprintf("%T", event), "remote_addr", h.conn.RemoteAddr())
		return &pb.ServerMessage{Type: &pb.ServerMessage_Error{Error: "Protocol error: unexpected message"}}, nil
	}
}

// handleHello responds to a ClientHello.
func (h *Handler) handleHello() (*pb.ServerMessage, error) {
	helloResponse := &pb.ServerHello{
		ServerId:    h.config.Server.ServerID,
		Subcommands: true,
	}
	return &pb.ServerMessage{Type: &pb.ServerMessage_Hello{Hello: helloResponse}}, nil
}

// checkRateLimit implements simple rate limiting to prevent memory exhaustion attacks.
// Limits to 100 messages per second per connection.
func (h *Handler) checkRateLimit() bool {
	h.rateLimitMutex.Lock()
	defer h.rateLimitMutex.Unlock()

	now := time.Now()
	timeDiff := now.Sub(h.lastMessageTime)

	// Reset counter if more than 1 second has passed
	if timeDiff >= time.Second {
		h.messageCount = 1
		h.lastMessageTime = now
		return true
	}

	h.messageCount++

	// Allow up to 100 messages per second
	const maxMessagesPerSecond = 100
	if h.messageCount > maxMessagesPerSecond {
		return false
	}

	return true
}

// applyRuncwdFallback implements the three-tier fallback logic for runcwd as per sudo logging.c:1008-1014.
// Tier 1: Use def_runcwd if configured (and not "*")
// Tier 2: Use runas user's home directory if login shell mode
// Tier 3: Use submitting user's current working directory
func (h *Handler) applyRuncwdFallback(acceptMsg *pb.AcceptMessage) {
	// Create a map for quick lookups of info messages
	infoMap := make(map[string]string)
	for _, info := range acceptMsg.InfoMsgs {
		if strval := info.GetStrval(); strval != "" {
			infoMap[info.GetKey()] = strval
		}
	}

	// Check if runcwd is already set and valid (Tier 1)
	if runcwd, exists := infoMap["runcwd"]; exists && runcwd != "" && runcwd != "*" {
		// Tier 1: Explicit runcwd is configured and valid, use it as-is
		slog.Debug("Using explicit runcwd", "runcwd", runcwd)
		return
	}

	// Tier 2: Check for login shell mode
	loginShell := infoMap["login_shell"] == "true" || infoMap["login_shell"] == "1"
	if loginShell {
		if runhome := infoMap["runhome"]; runhome != "" {
			// Use runas user's home directory for login shells
			h.setOrUpdateInfoMessage(acceptMsg, "runcwd", runhome)
			slog.Debug("Applied runcwd fallback tier 2 (login shell)", "runcwd", runhome)
			return
		}
	}

	// Tier 3: Fall back to submitting user's current working directory
	if submitcwd := infoMap["submitcwd"]; submitcwd != "" {
		h.setOrUpdateInfoMessage(acceptMsg, "runcwd", submitcwd)
		slog.Debug("Applied runcwd fallback tier 3 (submit cwd)", "runcwd", submitcwd)
	} else if cwd := infoMap["cwd"]; cwd != "" {
		// Some clients might send "cwd" instead of "submitcwd"
		h.setOrUpdateInfoMessage(acceptMsg, "runcwd", cwd)
		slog.Debug("Applied runcwd fallback tier 3 (cwd)", "runcwd", cwd)
	}
}

// setOrUpdateInfoMessage adds or updates an InfoMessage in the AcceptMessage.
func (h *Handler) setOrUpdateInfoMessage(acceptMsg *pb.AcceptMessage, key, value string) {
	// First try to find existing message to update
	for _, info := range acceptMsg.InfoMsgs {
		if info.GetKey() == key {
			info.Value = &pb.InfoMessage_Strval{Strval: value}
			return
		}
	}

	// If not found, add new InfoMessage
	acceptMsg.InfoMsgs = append(acceptMsg.InfoMsgs, &pb.InfoMessage{
		Key:   key,
		Value: &pb.InfoMessage_Strval{Strval: value},
	})
}

// handleReject logs a rejected command event. In local mode, it persists a
// log.json event record to disk. In relay mode, it only logs via slog.
func (h *Handler) handleReject(rejectMsg *pb.RejectMessage) (*pb.ServerMessage, error) {
	if h.config.Server.Mode != "local" {
		slog.Info("Reject event in non-local mode, logging only", "reason", rejectMsg.GetReason())
		return nil, nil
	}

	// Generate a UUID-based path for the reject event log
	rejectUUID := uuid.New()
	uuidStr := rejectUUID.String()
	sessID := uuidStr[:6]
	rejectDir := filepath.Join(h.config.LocalStorage.LogDirectory, sessID[:2], sessID[2:4], sessID[4:6])

	if err := os.MkdirAll(rejectDir, os.FileMode(h.config.LocalStorage.DirPermissions)); err != nil {
		slog.Error("Failed to create reject event directory", "error", err, "path", rejectDir)
		return nil, nil // Non-fatal
	}

	// Build the event record
	eventRecord := map[string]interface{}{
		"event_type": "reject",
		"reason":     rejectMsg.GetReason(),
	}
	if st := rejectMsg.GetSubmitTime(); st != nil {
		eventRecord["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	// Extract info messages
	infoMap := make(map[string]interface{})
	for _, info := range rejectMsg.GetInfoMsgs() {
		key := info.GetKey()
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			infoMap[key] = v.Strval
		case *pb.InfoMessage_Numval:
			infoMap[key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			infoMap[key] = v.Strlistval.GetStrings()
		}
	}
	if len(infoMap) > 0 {
		for k, v := range infoMap {
			// Preserve authoritative fields already set by the server.
			if _, exists := eventRecord[k]; exists {
				continue
			}
			eventRecord[k] = v
		}
	}

	data, err := json.MarshalIndent(eventRecord, "", "  ")
	if err != nil {
		slog.Error("Failed to marshal reject event", "error", err)
		return nil, nil // Non-fatal
	}

	logJSONPath := filepath.Join(rejectDir, "log.json")
	if err := os.WriteFile(logJSONPath, data, os.FileMode(h.config.LocalStorage.FilePermissions)); err != nil {
		slog.Error("Failed to write reject event log", "error", err, "path", logJSONPath)
		return nil, nil // Non-fatal
	}

	slog.Info("Wrote reject event log", "path", logJSONPath, "reason", rejectMsg.GetReason())
	return nil, nil
}

// handleRestart resumes an existing session from a RestartMessage.
func (h *Handler) handleRestart(restartMsg *pb.RestartMessage) (*pb.ServerMessage, error) {
	if h.config.Server.Mode != "local" {
		return nil, fmt.Errorf("restart not supported in %s mode", h.config.Server.Mode)
	}

	session, err := h.sessionFactories.newLocalRestartSession(restartMsg, &h.config.LocalStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to create restart session: %w", err)
	}

	h.session = session
	h.logID = restartMsg.GetLogId()
	metrics.Global.IncrementSessions()
	metrics.Global.IncrementLocalSessions()
	slog.Info("Resumed local storage session via restart",
		"log_id", h.logID,
		"total_sessions", metrics.Global.GetTotalSessions())

	return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: restartMsg.GetLogId()}}, nil
}

// handleAccept sets up a session for an accepted command.
func (h *Handler) handleAccept(acceptMsg *pb.AcceptMessage) (*pb.ServerMessage, error) {
	if !acceptMsg.ExpectIobufs {
		// Event-only logging, no session needed.
		slog.Info("Handling event-only log (no I/O buffers expected)", "remote_addr", h.conn.RemoteAddr())
		return nil, nil // No server response required for event-only logs
	}

	// Apply the three-tier runcwd fallback logic before processing
	h.applyRuncwdFallback(acceptMsg)

	sessionUUID := uuid.New()
	h.logID = sessionUUID.String() // Store UUID string for logging
	var err error

	// Initialize the correct session handler based on server mode
	switch h.config.Server.Mode {
	case "local":
		h.session, err = h.sessionFactories.newLocalStorageSession(sessionUUID, acceptMsg, &h.config.LocalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create local storage session: %w", err)
		}
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementLocalSessions()
		slog.Info("Started local storage session", "log_id", h.logID,
			"total_sessions", metrics.Global.GetTotalSessions(), "local_sessions", metrics.Global.GetLocalSessions())

	case "relay":
		h.session, err = h.sessionFactories.newRelaySession(sessionUUID, acceptMsg, &h.config.Relay)
		if err != nil {
			return nil, fmt.Errorf("failed to create relay session: %w", err)
		}
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementRelaySessions()
		slog.Info("Started relay session", "log_id", h.logID, "upstream", h.config.Relay.UpstreamHost,
			"total_sessions", metrics.Global.GetTotalSessions(), "relay_sessions", metrics.Global.GetRelaySessions())

	default:
		return nil, fmt.Errorf("unknown server mode: %s", h.config.Server.Mode)
	}

	// The first message to the session handler is the AcceptMessage itself
	// to allow it to initialize and send back the initial log_id.
	return h.session.HandleClientMessage(&pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg}})
}
