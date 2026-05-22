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
	"sudosrv/internal/sessions"
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
	sessionID string // registry key; matches sessionUUID.String() for new sessions
	session   SessionHandler
	registry  *sessions.Registry // optional; nil when the management API is disabled
	startedAt time.Time          // server-side connection start time
	isTLS     bool
	// Rate limiting: token bucket refilled at rateRefillPerSec up to rateBurst.
	rateTokens     float64
	rateLastRefill time.Time
	rateLimitMutex sync.Mutex
	// sessionFactories allows for injecting mock session creators during tests.
	sessionFactories struct {
		newLocalStorageSession func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error)
		newLocalEventSession   func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error)
		newRelaySession        func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig) (SessionHandler, error)
		newLocalRestartSession func(restartMsg *pb.RestartMessage, cfg *config.LocalStorageConfig) (SessionHandler, error)
	}
}

// logIDProvider exposes a session's stable base64 log_id for the management
// registry. storage.Session, storage.EventSession, and relay.Session all
// implement it; sessions that do not are registered with an empty ServerLogID.
type logIDProvider interface {
	LogID() string
}

// doneNotifier marks a session whose lifecycle outlives the client connection
// (currently relay sessions, which keep flushing upstream after the client
// disconnects). Implementers handle their own deregistration via an onDone
// callback fired from a background goroutine; the connection handler must
// therefore not deregister them on disconnect, and must guard against the
// race where IsDone() returns true before registerSession has added the
// session to the registry — in that case onDone's Deregister was a no-op
// and the handler must clean up.
type doneNotifier interface {
	IsDone() bool
}

// Rate limiter parameters. A single client connection is allowed to sustain
// rateRefillPerSec messages per second with room for a short burst of rateBurst.
const (
	rateRefillPerSec = 100.0
	rateBurst        = 100.0
)

// SessionHandler defines the interface for handling session data (either locally or by relay).
type SessionHandler interface {
	HandleClientMessage(*pb.ClientMessage) (*pb.ServerMessage, error)
	Close() error
}

// NewHandler creates a new handler for a connection. The session registry is
// nil; tests and callers that don't need management-API integration can use
// this form.
func NewHandler(conn net.Conn, cfg *config.Config) *Handler {
	return NewHandlerWithContext(context.Background(), conn, cfg, nil)
}

// NewHandlerWithContext creates a new handler for a connection with context
// support. Pass a non-nil registry to make the connection's session visible to
// the management API; pass nil to disable that integration.
func NewHandlerWithContext(ctx context.Context, conn net.Conn, cfg *config.Config, registry *sessions.Registry) *Handler {
	_, isTLS := conn.(*tls.Conn)
	h := &Handler{
		ctx:            ctx,
		conn:           conn,
		config:         cfg,
		processor:      protocol.NewProcessorWithCloser(conn, conn, conn),
		registry:       registry,
		startedAt:      time.Now(),
		isTLS:          isTLS,
		rateTokens:     rateBurst,
		rateLastRefill: time.Now(),
	}

	// Initialize factories to point to the real session creation functions.
	h.sessionFactories.newLocalStorageSession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
		return storage.NewSession(sessionUUID, acceptMsg, localCfg)
	}
	h.sessionFactories.newLocalEventSession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
		return storage.NewEventSession(sessionUUID, acceptMsg, localCfg)
	}
	h.sessionFactories.newRelaySession = func(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, relayCfg *config.RelayConfig) (SessionHandler, error) {
		// onDone is invoked from the relay's background runner goroutine
		// after it finishes (including any upstream-flush retries) — not
		// here at construction time. The connection-side defer skips
		// deregistering relay sessions for this reason; deregister via
		// onDone so "phase: flushing" stays visible in the management API
		// until the flush truly completes.
		sid := sessionUUID.String()
		onDone := func() { h.registry.Deregister(sid) }
		return relay.NewSession(h.ctx, sessionUUID, acceptMsg, relayCfg, onDone)
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
			// Local sessions are fully closed by Close(); deregister now.
			// Self-deregistering sessions (relay) own the registry entry's
			// lifetime via their onDone callback, which fires when their
			// background flusher exits — possibly long after the connection
			// closes. Hiding the "phase: flushing" record on disconnect
			// would defeat the management API's purpose.
			if _, selfDeregistering := h.session.(doneNotifier); !selfDeregistering && h.registry != nil {
				h.registry.Deregister(h.sessionID)
			}
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

		// Apply rate limiting to prevent memory exhaustion.
		// All writes below use h.ctx so a stalled client can't pin the handler
		// past shutdown — see Server.Wait's bounded grace period.
		if !h.checkRateLimit() {
			slog.Warn("Rate limit exceeded, closing connection", "remote_addr", h.conn.RemoteAddr())
			errMsg := &pb.ServerMessage{Type: &pb.ServerMessage_Error{Error: "Rate limit exceeded"}}
			_ = h.processor.WriteServerMessageContext(h.ctx, errMsg)
			return
		}

		serverMsg, err := h.processMessage(clientMsg)
		if err != nil {
			metrics.Global.IncrementMessageErrors()
			slog.Error("Error processing message", "error", err, "remote_addr", h.conn.RemoteAddr(),
				"message_errors", metrics.Global.GetMessageErrors())
			// Attempt to send a fatal error to the client
			errMsg := &pb.ServerMessage{Type: &pb.ServerMessage_Error{Error: "Internal Server Error"}}
			_ = h.processor.WriteServerMessageContext(h.ctx, errMsg)
			return
		}

		metrics.Global.IncrementMessagesProcessed()

		if serverMsg != nil {
			if err := h.processor.WriteServerMessageContext(h.ctx, serverMsg); err != nil {
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
		if event.HelloMsg.ClientId == "" {
			return nil, fmt.Errorf("ClientHello missing required client_id")
		}
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

// registerSession adds the just-created session to the registry, if one is
// configured. Static fields are populated from the AcceptMessage; the live
// MetadataProvider hook is set when the session implements it. ServerLogID is
// pulled from the session at register time via the optional logIDProvider
// interface, so the registered record is complete before any concurrent API
// reader can observe it.
func (h *Handler) registerSession(sessionUUID uuid.UUID, mode string, acceptMsg *pb.AcceptMessage) {
	if h.registry == nil || h.session == nil {
		return
	}
	h.sessionID = sessionUUID.String()
	info := sessions.SessionInfo{
		SessionID:    h.sessionID,
		SessionUUID:  sessionUUID,
		Mode:         mode,
		RemoteAddr:   h.conn.RemoteAddr().String(),
		StartedAt:    h.startedAt,
		ExpectIobufs: acceptMsg.GetExpectIobufs(),
		Info:         protocol.InfoMsgsToMap(acceptMsg.GetInfoMsgs()),
	}
	if st := acceptMsg.GetSubmitTime(); st != nil {
		info.SubmitTime = time.Unix(st.TvSec, int64(st.TvNsec)).UTC()
	}
	if l, ok := h.session.(logIDProvider); ok {
		info.ServerLogID = l.LogID()
	}
	if p, ok := h.session.(sessions.MetadataProvider); ok {
		info.Provider = p
	}
	h.registry.Register(info)
	// Race protection: if a self-deregistering session's background runner
	// finished before we registered (e.g. relay cache write failed in
	// NewSession's goroutine), its onDone callback's Deregister was a no-op
	// because the registry entry did not yet exist. Detect that and
	// deregister our just-added entry now.
	if d, ok := h.session.(doneNotifier); ok && d.IsDone() {
		h.registry.Deregister(h.sessionID)
	}
}

// registerRestartSession is the restart-path equivalent of registerSession.
// Restart sessions resume an existing log, so the base64 log_id is provided
// up-front by the client and used as the registry key directly.
func (h *Handler) registerRestartSession(restartMsg *pb.RestartMessage) {
	if h.registry == nil || h.session == nil {
		return
	}
	h.sessionID = restartMsg.GetLogId()
	info := sessions.SessionInfo{
		SessionID:   h.sessionID,
		ServerLogID: restartMsg.GetLogId(),
		Mode:        "local",
		RemoteAddr:  h.conn.RemoteAddr().String(),
		StartedAt:   h.startedAt,
		Info:        map[string]any{"event_type": "restart"},
	}
	if rt := restartMsg.GetResumePoint(); rt != nil {
		info.Info["resume_point"] = time.Unix(rt.TvSec, int64(rt.TvNsec)).UTC().Format(time.RFC3339Nano)
	}
	if p, ok := h.session.(sessions.MetadataProvider); ok {
		info.Provider = p
	}
	h.registry.Register(info)
}

// refreshLogIDFromSession overwrites h.logID with the session's authoritative
// base64-encoded server log_id. Until the session is created, h.logID holds the
// raw UUID string for early diagnostic logging. Once the session exists, the
// log_id used by storage on disk, by the management API, and returned to the
// client is the base64 form — slog must use the same form so operators can
// correlate log entries with sessions.
func (h *Handler) refreshLogIDFromSession() {
	if lp, ok := h.session.(logIDProvider); ok {
		h.logID = lp.LogID()
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

// checkRateLimit implements token-bucket rate limiting to prevent memory
// exhaustion attacks. Each connection is refilled at rateRefillPerSec tokens/sec
// up to rateBurst; each processed message consumes one token. Unlike a simple
// windowed counter, this correctly smooths bursts that straddle second boundaries.
func (h *Handler) checkRateLimit() bool {
	h.rateLimitMutex.Lock()
	defer h.rateLimitMutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(h.rateLastRefill).Seconds()
	if elapsed > 0 {
		h.rateTokens += elapsed * rateRefillPerSec
		if h.rateTokens > rateBurst {
			h.rateTokens = rateBurst
		}
		h.rateLastRefill = now
	}

	if h.rateTokens < 1 {
		return false
	}
	h.rateTokens--
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
//
// Errors during directory creation, JSON marshaling, or file writing are
// logged and counted as message errors, but return (nil, nil) to avoid
// tearing down the connection. Reject logging is best-effort — the client
// has already been denied, so a server-side persistence failure should not
// escalate into a protocol error.
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
		metrics.Global.IncrementMessageErrors()
		return nil, nil
	}

	// Build the event record
	eventRecord := map[string]any{
		"event_type": "reject",
		"reason":     rejectMsg.GetReason(),
	}
	if st := rejectMsg.GetSubmitTime(); st != nil {
		eventRecord["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	// Merge client-supplied info messages into the record, but never let them
	// overwrite the authoritative fields (event_type, reason, submit_time) we
	// already set above.
	for k, v := range protocol.InfoMsgsToMap(rejectMsg.GetInfoMsgs()) {
		if _, exists := eventRecord[k]; exists {
			continue
		}
		eventRecord[k] = v
	}

	data, err := json.MarshalIndent(eventRecord, "", "  ")
	if err != nil {
		slog.Error("Failed to marshal reject event", "error", err)
		metrics.Global.IncrementMessageErrors()
		return nil, nil
	}

	logJSONPath := filepath.Join(rejectDir, "log.json")
	if err := os.WriteFile(logJSONPath, data, os.FileMode(h.config.LocalStorage.FilePermissions)); err != nil {
		slog.Error("Failed to write reject event log", "error", err, "path", logJSONPath)
		metrics.Global.IncrementMessageErrors()
		return nil, nil
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
	h.registerRestartSession(restartMsg)
	metrics.Global.IncrementSessions()
	metrics.Global.IncrementLocalSessions()
	slog.Info("Resumed local storage session via restart",
		"log_id", h.logID,
		"total_sessions", metrics.Global.GetTotalSessions())

	return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: restartMsg.GetLogId()}}, nil
}

// handleAccept sets up a session for an accepted command.
func (h *Handler) handleAccept(acceptMsg *pb.AcceptMessage) (*pb.ServerMessage, error) {
	// Apply the three-tier runcwd fallback logic before processing
	h.applyRuncwdFallback(acceptMsg)

	// Validate required fields, matching C sudo_logsrvd behavior.
	infoMap := make(map[string]string)
	for _, info := range acceptMsg.InfoMsgs {
		if strval := info.GetStrval(); strval != "" {
			infoMap[info.GetKey()] = strval
		}
	}
	for _, field := range []string{"submituser", "submithost", "runuser", "command"} {
		if infoMap[field] == "" {
			return nil, fmt.Errorf("AcceptMessage missing required field: %s", field)
		}
	}

	sessionUUID := uuid.New()
	h.logID = sessionUUID.String() // Store UUID string for logging
	var err error

	if !acceptMsg.ExpectIobufs {
		return h.handleEventOnlyAccept(sessionUUID, acceptMsg)
	}

	// Initialize the correct session handler based on server mode
	switch h.config.Server.Mode {
	case "local":
		h.session, err = h.sessionFactories.newLocalStorageSession(sessionUUID, acceptMsg, &h.config.LocalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create local storage session: %w", err)
		}
		h.refreshLogIDFromSession()
		h.registerSession(sessionUUID, "local", acceptMsg)
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementLocalSessions()
		slog.Info("Started local storage session", "log_id", h.logID,
			"total_sessions", metrics.Global.GetTotalSessions(), "local_sessions", metrics.Global.GetLocalSessions())

	case "relay":
		h.session, err = h.sessionFactories.newRelaySession(sessionUUID, acceptMsg, &h.config.Relay)
		if err != nil {
			return nil, fmt.Errorf("failed to create relay session: %w", err)
		}
		h.refreshLogIDFromSession()
		h.registerSession(sessionUUID, "relay", acceptMsg)
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementRelaySessions()
		slog.Info("Started relay session", "log_id", h.logID, "upstream", h.config.Relay.UpstreamHost,
			"total_sessions", metrics.Global.GetTotalSessions(), "relay_sessions", metrics.Global.GetRelaySessions())

	default:
		return nil, fmt.Errorf("unknown server mode: %s", h.config.Server.Mode)
	}

	// The first message to the session handler is the AcceptMessage itself
	// to allow it to initialize and send back the initial log_id. The log_id
	// is also captured at registerSession time via the logIDProvider getter,
	// so we don't need to update the registry on the response.
	return h.session.HandleClientMessage(&pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg}})
}

func (h *Handler) handleEventOnlyAccept(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage) (*pb.ServerMessage, error) {
	slog.Info("Handling event-only log (no I/O buffers expected)", "remote_addr", h.conn.RemoteAddr())

	var err error
	switch h.config.Server.Mode {
	case "local":
		h.session, err = h.sessionFactories.newLocalEventSession(sessionUUID, acceptMsg, &h.config.LocalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create local event-only session: %w", err)
		}
		h.refreshLogIDFromSession()
		h.registerSession(sessionUUID, "local", acceptMsg)
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementLocalSessions()
		slog.Info("Started local event-only session", "log_id", h.logID,
			"total_sessions", metrics.Global.GetTotalSessions(), "local_sessions", metrics.Global.GetLocalSessions())
	case "relay":
		h.session, err = h.sessionFactories.newRelaySession(sessionUUID, acceptMsg, &h.config.Relay)
		if err != nil {
			return nil, fmt.Errorf("failed to create relay event-only session: %w", err)
		}
		h.refreshLogIDFromSession()
		h.registerSession(sessionUUID, "relay", acceptMsg)
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementRelaySessions()
		slog.Info("Started relay event-only session", "log_id", h.logID, "upstream", h.config.Relay.UpstreamHost,
			"total_sessions", metrics.Global.GetTotalSessions(), "relay_sessions", metrics.Global.GetRelaySessions())
	default:
		return nil, fmt.Errorf("unknown server mode: %s", h.config.Server.Mode)
	}

	// sudo clients do not expect a log_id response for event-only accepts.
	return nil, nil
}
