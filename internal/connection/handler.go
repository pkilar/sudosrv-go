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
}

// SessionHandler defines the interface for handling session data (either locally or by relay).
type SessionHandler interface {
	HandleClientMessage(*pb.ClientMessage) (*pb.ServerMessage, error)
	Close() error
}

// NewHandler creates a new handler for a connection.
func NewHandler(conn net.Conn, cfg *config.Config) *Handler {
	_, isTLS := conn.(*tls.Conn)
	return &Handler{
		conn:      conn,
		config:    cfg,
		processor: protocol.NewProcessor(conn, conn),
		isTLS:     isTLS,
	}
}

// Handle runs the message processing loop for the connection.
func (h *Handler) Handle() {
	defer h.conn.Close()
	defer func() {
		if h.session != nil {
			h.session.Close()
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
			errMsg := &pb.ServerMessage{Event: &pb.ServerMessage_Error{Error: "Internal Server Error"}}
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
	switch event := clientMsg.Event.(type) {
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
		return &pb.ServerMessage{Event: &pb.ServerMessage_Error{Error: "Protocol error: unexpected message"}}, nil
	}
}

// handleHello responds to a ClientHello.
func (h *Handler) handleHello() (*pb.ServerMessage, error) {
	helloResponse := &pb.ServerHello{
		ServerId: h.config.Server.ServerID,
	}
	return &pb.ServerMessage{Event: &pb.ServerMessage_Hello{Hello: helloResponse}}, nil
}

// handleAccept sets up a session for an accepted command.
func (h *Handler) handleAccept(acceptMsg *pb.AcceptMessage) (*pb.ServerMessage, error) {
	if !acceptMsg.ExpectIobufs {
		// Event-only logging, no session needed.
		slog.Info("Handling event-only log (no I/O buffers expected)", "remote_addr", h.conn.RemoteAddr())
		return nil, nil // No server response required for event-only logs
	}

	h.logID = uuid.New().String()
	var err error

	// Initialize the correct session handler based on server mode
	switch h.config.Server.Mode {
	case "local":
		h.session, err = storage.NewSession(h.logID, acceptMsg, &h.config.LocalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create local storage session: %w", err)
		}
		slog.Info("Started local storage session", "log_id", h.logID)

	case "relay":
		h.session, err = relay.NewSession(h.logID, acceptMsg, &h.config.Relay)
		if err != nil {
			return nil, fmt.Errorf("failed to create relay session: %w", err)
		}
		slog.Info("Started relay session", "log_id", h.logID, "upstream", h.config.Relay.UpstreamHost)

	default:
		return nil, fmt.Errorf("unknown server mode: %s", h.config.Server.Mode)
	}

	// The first message to the session handler is the AcceptMessage itself
	// to allow it to initialize and send back the initial log_id.
	return h.session.HandleClientMessage(&pb.ClientMessage{Event: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg}})
}
