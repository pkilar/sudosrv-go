// Filename: internal/connection/handler.go
package connection

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	"sudosrv/internal/relay"
	"sudosrv/internal/storage"
	pb "sudosrv/pkg/sudosrv_proto"
	"time"

	"github.com/google/uuid"
)

// Handler manages a single client connection.
type Handler struct {
	conn      net.Conn
	config    *config.Config
	processor protocol.Processor
	logID     string
	session   SessionHandler
	isTLS     bool
	// sessionFactories allows for injecting mock session creators during tests.
	sessionFactories struct {
		newLocalStorageSession func(logID string, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (SessionHandler, error)
		newRelaySession        func(logID string, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig) (SessionHandler, error)
	}
}

// SessionHandler defines the interface for handling session data (either locally or by relay).
type SessionHandler interface {
	HandleClientMessage(*pb.ClientMessage) (*pb.ServerMessage, error)
	Close() error
}

// NewHandler creates a new handler for a connection.
func NewHandler(conn net.Conn, cfg *config.Config) *Handler {
	_, isTLS := conn.(*tls.Conn)
	h := &Handler{
		conn:      conn,
		config:    cfg,
		processor: protocol.NewProcessorWithCloser(conn, conn, conn),
		isTLS:     isTLS,
	}

	// Initialize factories to point to the real session creation functions.
	h.sessionFactories.newLocalStorageSession = func(logID string, acceptMsg *pb.AcceptMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
		return storage.NewSession(logID, acceptMsg, localCfg)
	}
	h.sessionFactories.newRelaySession = func(logID string, acceptMsg *pb.AcceptMessage, relayCfg *config.RelayConfig) (SessionHandler, error) {
		return relay.NewSession(logID, acceptMsg, relayCfg)
	}
	return h
}

// Handle runs the message processing loop for the connection.
func (h *Handler) Handle() {
	defer func() {
		if h.session != nil {
			if err := h.session.Close(); err != nil {
				slog.Error("Failed to close session", "error", err, "remote_addr", h.conn.RemoteAddr())
			}
		}
		if err := h.processor.Close(); err != nil {
			slog.Error("Failed to close processor", "error", err, "remote_addr", h.conn.RemoteAddr())
		}
		slog.Info("Connection closed", "remote_addr", h.conn.RemoteAddr())
	}()

	// Main message loop
	for {
		if err := h.conn.SetReadDeadline(time.Now().Add(h.config.Server.IdleTimeout)); err != nil {
			slog.Error("Failed to set read deadline", "error", err)
			return
		}

		clientMsg, err := h.processor.ReadClientMessage()
		if err != nil {
			slog.Debug("Failed to read client message", "error", err, "remote_addr", h.conn.RemoteAddr())
			return
		}

		serverMsg, err := h.processMessage(clientMsg)
		if err != nil {
			slog.Error("Error processing message", "error", err, "remote_addr", h.conn.RemoteAddr())
			// Attempt to send a fatal error to the client
			errMsg := &pb.ServerMessage{Type: &pb.ServerMessage_Error{Error: "Internal Server Error"}}
			_ = h.processor.WriteServerMessage(errMsg)
			return
		}

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

	case *pb.ClientMessage_RejectMsg:
		slog.Info("Received RejectMessage", "reason", event.RejectMsg.Reason, "remote_addr", h.conn.RemoteAddr())
		// For now, we just log this and take no further action.
		// A more advanced server might write an event log.
		return nil, nil // No response needed

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
		ServerId: h.config.Server.ServerID,
	}
	return &pb.ServerMessage{Type: &pb.ServerMessage_Hello{Hello: helloResponse}}, nil
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

// handleAccept sets up a session for an accepted command.
func (h *Handler) handleAccept(acceptMsg *pb.AcceptMessage) (*pb.ServerMessage, error) {
	if !acceptMsg.ExpectIobufs {
		// Event-only logging, no session needed.
		slog.Info("Handling event-only log (no I/O buffers expected)", "remote_addr", h.conn.RemoteAddr())
		return nil, nil // No server response required for event-only logs
	}

	// Apply the three-tier runcwd fallback logic before processing
	h.applyRuncwdFallback(acceptMsg)

	h.logID = uuid.New().String()
	var err error

	// Initialize the correct session handler based on server mode
	switch h.config.Server.Mode {
	case "local":
		h.session, err = h.sessionFactories.newLocalStorageSession(h.logID, acceptMsg, &h.config.LocalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create local storage session: %w", err)
		}
		slog.Info("Started local storage session", "log_id", h.logID)

	case "relay":
		h.session, err = h.sessionFactories.newRelaySession(h.logID, acceptMsg, &h.config.Relay)
		if err != nil {
			return nil, fmt.Errorf("failed to create relay session: %w", err)
		}
		slog.Info("Started relay session", "log_id", h.logID, "upstream", h.config.Relay.UpstreamHost)

	default:
		return nil, fmt.Errorf("unknown server mode: %s", h.config.Server.Mode)
	}

	// The first message to the session handler is the AcceptMessage itself
	// to allow it to initialize and send back the initial log_id.
	return h.session.HandleClientMessage(&pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg}})
}
