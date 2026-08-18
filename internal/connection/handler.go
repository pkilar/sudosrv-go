// SPDX-License-Identifier: Apache-2.0
// Filename: internal/connection/handler.go
package connection

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/eventlog"
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
	// acceptInfo is the accepted command's info_msgs, kept so the ExitMessage --
	// which carries only a run time and an exit value -- can be logged against
	// the command it belongs to. Written once at accept, read on exit, both from
	// this connection's single goroutine.
	acceptInfo map[string]string
	registry   *sessions.Registry // optional; nil when the management API is disabled
	startedAt  time.Time          // server-side connection start time
	isTLS      bool
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
		newRelayRestartSession func(restartMsg *pb.RestartMessage, cfg *config.RelayConfig) (SessionHandler, error)
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
//
// These are a guard against pathological message spam, NOT a traffic shaper.
// They were 100/sec, which is below what an ordinary terminal session produces
// and corrupted every recording that exceeded it: a pty delivers output in
// small reads, so `seq 1 20000` -- 130KB, over in a fraction of a second --
// arrives as 1744 separate ttyout buffers. At 100/sec that session needed 17
// seconds to reach the server.
//
// The damage is worse than slowness, because the throttle is invisible to the
// person being recorded. logsh writes the user's terminal BEFORE handing the
// buffer to the recorder, so output still appears instantly while delivery
// falls behind; the stall is then charged to whatever event comes next and
// written into the timing file as elapsed session time. A replay shows a
// multi-second pause between a keystroke and its output that never happened,
// which makes the transcript actively misleading rather than merely late. The
// same backlog also delays logout, since the exit waits for the server to
// commit the session.
//
// The ceiling below is set an order of magnitude above any rate a real terminal
// produces. Note what does and does not bound resource use here: this limit
// bounds messages, while the 2MB cap in internal/protocol bounds each message
// and max_connections bounds concurrency. A message-rate limit alone never
// bounded bytes -- 100 x 2MB/sec was always permitted -- so raising it does not
// give up a byte-rate guarantee that existed.
const (
	rateRefillPerSec = 50000.0
	rateBurst        = 50000.0
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
//
// The supplied cfg is captured by value for the lifetime of the connection:
// SIGHUP-driven config changes (notably Server.IdleTimeout) only affect
// connections accepted *after* the reload. The server's reload path explicitly
// rejects listener/mode changes for that reason; numeric tuning knobs like
// IdleTimeout become effective per-connection at next accept.
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
		// until the flush truly completes. The active-sessions metric is
		// decremented here for the same reason: until the flush finishes
		// the session is still consuming server resources (cache file +
		// flush goroutine), so it should count as active.
		sid := sessionUUID.String()
		onDone := func() {
			h.registry.Deregister(sid)
			metrics.Global.DecrementActiveSessions()
		}
		return relay.NewSession(h.ctx, sessionUUID, acceptMsg, relayCfg, onDone)
	}
	h.sessionFactories.newLocalRestartSession = func(restartMsg *pb.RestartMessage, localCfg *config.LocalStorageConfig) (SessionHandler, error) {
		return storage.NewRestartSession(restartMsg, localCfg)
	}
	h.sessionFactories.newRelayRestartSession = func(restartMsg *pb.RestartMessage, relayCfg *config.RelayConfig) (SessionHandler, error) {
		// Like newRelaySession, the relay restart session self-deregisters when
		// its background flusher exits. The registry key is the restart log_id,
		// matching registerRestartSession's h.sessionID.
		logID := restartMsg.GetLogId()
		onDone := func() {
			if h.registry != nil {
				h.registry.Deregister(logID)
			}
			metrics.Global.DecrementActiveSessions()
		}
		return relay.NewRestartSession(h.ctx, restartMsg, relayCfg, onDone)
	}
	return h
}

// Handle runs the message processing loop for the connection.
func (h *Handler) Handle() {
	defer func() {
		if h.session != nil {
			// Local sessions are fully closed by Close(); deregister and
			// decrement the active count now. Self-deregistering sessions
			// (relay) own the registry entry's lifetime — and the
			// active-sessions metric — via their onDone callback, which
			// fires when their background flusher exits, possibly long
			// after the connection closes. Hiding "phase: flushing"
			// records or decrementing the metric on disconnect would
			// defeat the management API's purpose.
			if _, selfDeregistering := h.session.(doneNotifier); !selfDeregistering {
				if h.registry != nil {
					h.registry.Deregister(h.sessionID)
				}
				metrics.Global.DecrementActiveSessions()
			}
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

	// Force the TLS handshake to complete under server_timeout. crypto/tls
	// otherwise performs it lazily inside the first Read, where no deadline
	// applies now that idle_timeout defaults to off — a peer could complete the
	// TCP connection, send nothing, and hold this goroutine and one of
	// max_connections slots forever. C bounds the handshake with the same
	// [server] timeout it uses for writes. Conformance: TLS-022, ARCH-032.
	if err := h.handshakeTLS(); err != nil {
		slog.Warn("TLS handshake failed", "error", err, "remote_addr", h.conn.RemoteAddr())
		metrics.Global.IncrementFailedConnections()
		return
	}

	// Main message loop
	for {
		// Check if context is cancelled
		select {
		case <-h.ctx.Done():
			slog.Info("Connection handler stopping due to context cancellation", "remote_addr", h.conn.RemoteAddr())
			return
		default:
		}

		// Arm a per-message idle read deadline ONLY if the operator asked for one.
		// IdleTimeout <= 0 (the default) means no deadline, matching the reference
		// C sudo_logsrvd, which adds its steady-state read event with a NULL
		// timeout: "No read timeout, client messages may happen at arbitrary
		// times" (logsrvd/logsrvd.c:1372).
		//
		// Do not "helpfully" arm a fallback deadline when IdleTimeout <= 0, and do
		// not reintroduce a finite default in internal/config. Disconnecting an
		// idle client does not merely truncate its log — sudo's
		// def_ignore_iolog_errors is false by default (plugins/sudoers/defaults.c:610),
		// so the client answers a dropped log connection by killing the command it
		// is running (plugins/sudoers/log_client.c:1919 → terminate_command). An
		// interactive `sudo -s` sitting at a prompt would be SIGKILLed out from
		// under the user.
		//
		// Dead (as opposed to idle) peers are reaped by TCP keepalive, and the
		// blast radius of a stalled peer is bounded by max_connections.
		//
		// Conformance: docs/logsrvd-reference/ ARCH-024, ARCH-045, CONF-025 (breaking).
		// Guarded by TestIdleReadDeadlineOptOut (this package) and
		// TestIdleTimeoutDefaultsToDisabled (internal/config).
		if h.config.Server.IdleTimeout > 0 {
			if err := h.conn.SetReadDeadline(time.Now().Add(h.config.Server.IdleTimeout)); err != nil {
				slog.Error("Failed to set read deadline", "error", err)
				return
			}
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

		// Apply rate limiting as back-pressure: this blocks until a token is
		// available rather than closing the connection, so a legitimate
		// high-throughput session is throttled, not severed. It returns early
		// only on context cancellation (shutdown), so a stalled client can't pin
		// the handler past shutdown — see Server.Wait's bounded grace period.
		if err := h.waitForRateToken(h.ctx); err != nil {
			slog.Debug("Connection handler stopping while rate-limited", "remote_addr", h.conn.RemoteAddr(), "error", err)
			return
		}

		serverMsg, err := h.processMessage(clientMsg)
		if err != nil {
			metrics.Global.IncrementMessageErrors()
			slog.Error("Error processing message", "error", err, "remote_addr", h.conn.RemoteAddr(),
				"message_errors", metrics.Global.GetMessageErrors())
			// Attempt to send a fatal error to the client. A state-machine
			// violation carries C's own wire text so the peer is told what it
			// did wrong instead of being blamed for a server fault; anything
			// else is an internal failure.
			errText := "Internal Server Error"
			var violation *stateMachineViolation
			if errors.As(err, &violation) {
				errText = stateMachineErrorText
			}
			errMsg := &pb.ServerMessage{Type: &pb.ServerMessage_Error{Error: errText}}
			_ = h.writeServerMessage(errMsg)
			return
		}

		metrics.Global.IncrementMessagesProcessed()

		if serverMsg != nil {
			if err := h.writeServerMessage(serverMsg); err != nil {
				slog.Error("Failed to write server message", "error", err, "remote_addr", h.conn.RemoteAddr())
				return
			}
		}

		// The ExitMessage ends the session; stop reading, exactly as C does by
		// deleting the read event in handle_exit (sudo_ev_del(evbase, read_ev))
		// and moving to EXITED/FINISHED, where any further message is a state
		// machine error that closes the connection.
		//
		// Continuing to read appended post-Exit records to an already-terminated
		// session. In relay mode they land in a cache file whose ExitMessage has
		// already been written, so the flush replays a session that ends
		// mid-stream and then keeps going -- delivering a truncated duplicate
		// upstream, or looping on a replay the upstream will never acknowledge.
		// One crafted message from an unauthenticated peer was enough to trigger
		// it. The response above (the final commit_point) has already been sent,
		// so a well-behaved client loses nothing.
		//
		// Conformance: docs/logsrvd-reference/ ARCH-036.
		if _, isExit := clientMsg.Type.(*pb.ClientMessage_ExitMsg); isExit {
			slog.Debug("ExitMessage processed; closing connection",
				"remote_addr", h.conn.RemoteAddr())
			return
		}
	}
}

// serverTimeoutContext derives a context bounded by server_timeout. A
// non-positive server_timeout disables the bound, matching C's "A value of 0
// will disable the timeout". The returned cancel must always be called.
func (h *Handler) serverTimeoutContext() (context.Context, context.CancelFunc) {
	if t := h.config.Server.ServerTimeout; t > 0 {
		return context.WithTimeout(h.ctx, t)
	}
	return context.WithCancel(h.ctx)
}

// writeServerMessage writes one ServerMessage, bounded by server_timeout.
//
// Without a bound a client that completes the handshake and then stops reading
// blocks this goroutine inside write(2) once the socket buffer fills, holding
// its session and one of max_connections slots until the process exits. C arms
// its write events with [server] timeout for exactly this reason
// (logsrvd/logsrvd.c, sudo_ev_add(..., logsrvd_conf_server_timeout(), ...)).
//
// Conformance: docs/logsrvd-reference/ ARCH-032, ARCH-045.
func (h *Handler) writeServerMessage(msg *pb.ServerMessage) error {
	ctx, cancel := h.serverTimeoutContext()
	defer cancel()
	return h.processor.WriteServerMessageContext(ctx, msg)
}

// handshakeTLS completes the TLS handshake under server_timeout, or returns nil
// immediately for a plaintext connection.
//
// crypto/tls would otherwise run the handshake lazily inside the first Read.
// With idle_timeout off by default that read has no deadline, so a peer that
// opens a TCP connection to the TLS port and then says nothing would pin a
// goroutine indefinitely. Doing it explicitly here also means handshake
// failures are reported as such instead of surfacing as a confusing protocol
// read error.
//
// Conformance: docs/logsrvd-reference/ TLS-022, ARCH-032.
func (h *Handler) handshakeTLS() error {
	tlsConn, ok := h.conn.(*tls.Conn)
	if !ok {
		return nil
	}
	ctx, cancel := h.serverTimeoutContext()
	defer cancel()
	return tlsConn.HandshakeContext(ctx)
}

// validTimeSpec reports whether ts is a delay the protocol permits: present,
// non-negative and with nanoseconds normalised into [0, 1e9).
//
// Mirrors C's valid_timespec() macro (logsrvd/logsrvd.h:49-50).
func validTimeSpec(ts *pb.TimeSpec) bool {
	return ts != nil && ts.GetTvSec() >= 0 && ts.GetTvNsec() >= 0 && ts.GetTvNsec() < 1000000000
}

// validateIoBuffer rejects an IoBuffer whose delay is not a normalised
// non-negative timespec or whose data is empty. Non-IoBuffer messages pass
// through untouched.
//
// C sudo_logsrvd does this in handle_iobuf before handing the buffer to either
// the local or the relay store, and drops the connection with "invalid IoBuffer"
// (logsrvd/logsrvd.c:756-760). Without the check the delay reaches the timing
// file verbatim: a negative tv_nsec is formatted as "0.-00000005", which
// iolog_parse_delay cannot parse (lib/iolog/iolog_timing.c:216-232 scans digits
// only), so sudoreplay reports "invalid timing file line" and stops there —
// every record written afterwards is on disk but permanently unreplayable. In
// relay mode the poisoned record is cached and then rejected by the upstream
// server on every flush attempt, so the cache file is retried forever.
//
// Conformance: docs/logsrvd-reference/ PROTO-027.
func validateIoBuffer(msg *pb.ClientMessage) error {
	var buf *pb.IoBuffer
	switch event := msg.Type.(type) {
	case *pb.ClientMessage_TtyinBuf:
		buf = event.TtyinBuf
	case *pb.ClientMessage_TtyoutBuf:
		buf = event.TtyoutBuf
	case *pb.ClientMessage_StdinBuf:
		buf = event.StdinBuf
	case *pb.ClientMessage_StdoutBuf:
		buf = event.StdoutBuf
	case *pb.ClientMessage_StderrBuf:
		buf = event.StderrBuf
	default:
		return nil
	}
	if buf == nil || len(buf.GetData()) == 0 || !validTimeSpec(buf.GetDelay()) {
		return fmt.Errorf("invalid IoBuffer")
	}
	return nil
}

// stateMachineErrorText is the error string C sudo_logsrvd puts on the wire for
// every state-guard failure (logsrvd/logsrvd.c:525, :562, :595, :667, :746,
// :794, :830, :875).
const stateMachineErrorText = "state machine error"

// stateMachineViolation marks a message that arrived in a state where the
// protocol does not allow it. It is fatal: Handle sends exactly one error
// message and closes the connection, mirroring C, where the failing handler
// sets closure->errstr and client_msg_cb jumps to send_error, which stops
// reading and closes the connection once the error has been written
// (logsrvd/logsrvd.c:1274-1280, :473-508).
//
// Answering and reading on is not a harmless nicety. In relay mode the
// offending message is cached and replayed upstream, where a C sudo_logsrvd
// refuses it for exactly this reason; the flush then fails forever, so one
// bogus message from any peer that can reach the listener pins that session's
// cache file and re-delivers the Accept plus all preceding I/O to the upstream
// on every retry. It also breaks C's one-error-per-connection contract.
//
// Conformance: docs/logsrvd-reference/ PROTO-042, PROTO-043.
// Guarded by TestOutOfOrderMessageIsFatal.
type stateMachineViolation struct{ detail string }

func (e *stateMachineViolation) Error() string { return e.detail }

// processMessage contains the main state machine for the protocol.
func (h *Handler) processMessage(clientMsg *pb.ClientMessage) (*pb.ServerMessage, error) {
	// If a session (relay or local) is active, pass the message to it.
	if h.session != nil {
		// ClientHello and RestartMessage are valid only in INITIAL, so with a
		// session already running they are state-machine errors, not payload
		// for the store (logsrvd/logsrvd.c:665-669, :873-877). Reject them here
		// so they never reach a session — in relay mode reaching the session
		// means being cached and replayed upstream forever.
		switch clientMsg.Type.(type) {
		case *pb.ClientMessage_HelloMsg, *pb.ClientMessage_RestartMsg:
			return nil, &stateMachineViolation{
				detail: fmt.Sprintf("%T received during an active session", clientMsg.Type),
			}
		}
		if err := validateIoBuffer(clientMsg); err != nil {
			return nil, err
		}
		if exit, ok := clientMsg.Type.(*pb.ClientMessage_ExitMsg); ok {
			h.emitExitEvent(exit.ExitMsg)
		}
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
		h.emitEvent(eventlog.Alert, infoStrings(protocol.InfoMsgsToMap(event.AlertMsg.GetInfoMsgs())),
			event.AlertMsg.GetReason())
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
		// I/O buffers, window-size and suspend events are valid only in
		// RUNNING, so before any Accept they are state-machine errors. C
		// answers with one error and closes (logsrvd/logsrvd.c:744-748,
		// :794-796, :830-832 → :1274-1280); so must we, or an unauthenticated
		// peer keeps a connection slot and can keep provoking error replies.
		return nil, &stateMachineViolation{
			detail: fmt.Sprintf("%T received before session start", event),
		}
	}
}

// infoStrings narrows an info_msgs map to its string-valued entries. The
// protocol carries ints and string lists too, but every field the event log
// names (submituser, command, ttyname, ...) is a plain string.
func infoStrings(info map[string]any) map[string]string {
	out := make(map[string]string, len(info))
	for k, v := range info {
		if sv, ok := v.(string); ok {
			out[k] = sv
		}
	}
	return out
}

// emitEvent writes one record to the process-wide event log. It is a no-op when
// no sink is configured, so call sites need no guard.
//
// This is sudo's EVENT log -- the audit line naming who ran what -- and not the
// daemon's operational slog output. Conformance: docs/logsrvd-reference/ CONF-058.
func (h *Handler) emitEvent(t eventlog.EventType, info map[string]string, reason string) {
	e := eventlog.FromInfoMap(t, info)
	e.Reason = reason
	e.TSID = h.logID
	eventlog.Global.Log(e)
}

// emitExitEvent records a command's completion. The ExitMessage identifies
// nothing by itself, so the command is recovered from the accept that opened
// this connection; without one there is nothing meaningful to log.
func (h *Handler) emitExitEvent(exitMsg *pb.ExitMessage) {
	if h.acceptInfo == nil {
		return
	}
	e := eventlog.FromInfoMap(eventlog.Exit, h.acceptInfo)
	e.TSID = h.logID
	e.ExitValue = fmt.Sprintf("%d", exitMsg.GetExitValue())
	e.Signal = exitMsg.GetSignal()
	eventlog.Global.Log(e)
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
func (h *Handler) registerRestartSession(restartMsg *pb.RestartMessage, mode string) {
	if h.registry == nil || h.session == nil {
		return
	}
	h.sessionID = restartMsg.GetLogId()
	info := sessions.SessionInfo{
		SessionID:   h.sessionID,
		ServerLogID: restartMsg.GetLogId(),
		Mode:        mode,
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
	// Same race guard as registerSession: a self-deregistering (relay) session
	// whose runner finished before we registered would have had its onDone
	// Deregister no-op; detect that and remove our just-added entry.
	if d, ok := h.session.(doneNotifier); ok && d.IsDone() {
		h.registry.Deregister(h.sessionID)
	}
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

// handleHello responds to a ClientHello immediately, from local configuration,
// in BOTH server modes.
//
// This is deliberate, and it is the visible half of relay mode being
// unconditionally store-and-forward (see RelayConfig in internal/config and
// "A note on relay mode" in README.md). C's *streaming* relay defers the
// downstream ServerHello: connect_relay() runs first and start_protocol() —
// which formats the greeting — is reached only after the upstream's own
// ServerHello arrives (logsrvd/logsrvd.c:1550-1558,1650-1658 →
// logsrvd/logsrvd_relay.c:709-711). C's store_first relay does what we do here,
// greeting the client up front because no upstream connection exists yet
// (logsrvd/logsrvd.c:209-212 selects cms_journal and skips connect_relay).
//
// The consequence to accept: a client cannot infer an upstream outage from a
// delayed or absent greeting. Its command proceeds and the session is spooled.
// Sites that need the outage to block the command set require_upstream, which
// dials the upstream at Accept time instead.
//
// Conformance: docs/logsrvd-reference/ RELAY-003, CONF-043.
func (h *Handler) handleHello() (*pb.ServerMessage, error) {
	helloResponse := &pb.ServerHello{
		ServerId:    h.config.Server.ServerID,
		Subcommands: true,
	}
	return &pb.ServerMessage{Type: &pb.ServerMessage_Hello{Hello: helloResponse}}, nil
}

// waitForRateToken implements token-bucket rate limiting to bound the rate at
// which a single connection's messages are processed. Each connection is
// refilled at rateRefillPerSec tokens/sec up to rateBurst; each processed
// message consumes one token. The token-bucket smooths bursts that straddle
// second boundaries.
//
// When the bucket is empty this BLOCKS until the next token refills (returning
// only on context cancellation) rather than terminating the connection. This is
// deliberate: the reference C sudo_logsrvd imposes no application-level rate
// limit, and a legitimate high-throughput session (a verbose build, `yes`, a
// large `cat`) routinely emits hundreds of ttyout buffers in a sub-second burst.
// Closing the connection on excess would truncate such a session and make the
// stock client report a fatal log error. Blocking instead applies back-pressure:
// the handler stops reading, TCP flow control slows the client, and no audit
// data is lost. Memory stays bounded because at most one message is held in
// flight while we wait.
func (h *Handler) waitForRateToken(ctx context.Context) error {
	for {
		h.rateLimitMutex.Lock()
		now := time.Now()
		elapsed := now.Sub(h.rateLastRefill).Seconds()
		if elapsed > 0 {
			h.rateTokens += elapsed * rateRefillPerSec
			if h.rateTokens > rateBurst {
				h.rateTokens = rateBurst
			}
			h.rateLastRefill = now
		}
		if h.rateTokens >= 1 {
			h.rateTokens--
			h.rateLimitMutex.Unlock()
			return nil
		}
		// Bucket empty: compute how long until one token refills, then sleep
		// (without holding the mutex) before re-checking. The deficit is < 1
		// token, so the wait is at most 1/rateRefillPerSec seconds.
		wait := time.Duration((1 - h.rateTokens) / rateRefillPerSec * float64(time.Second))
		h.rateLimitMutex.Unlock()
		if wait <= 0 {
			wait = time.Millisecond // floor to avoid a busy spin on rounding
		}

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
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
	// Emitted before the mode check: a refused command is an audit event in
	// every mode, and only local mode writes the metadata-only log.json below.
	h.emitEvent(eventlog.Reject, infoStrings(protocol.InfoMsgsToMap(rejectMsg.GetInfoMsgs())), rejectMsg.GetReason())

	if h.config.Server.Mode != "local" {
		slog.Info("Reject event in non-local mode, logging only", "reason", rejectMsg.GetReason())
		return nil, nil
	}

	// A reject record uses the same UUID hierarchy a session would, so the two
	// land side by side. It deliberately does NOT go through
	// storage.buildSessionPath: an iolog_dir template can reference %{command}
	// and %{runuser}, and a rejected command has no run identity to expand them
	// from. Sharing the layout while not sharing the templating is the point.
	rejectUUID := uuid.New()
	rejectDir := storage.UUIDHierarchyPath(h.config.LocalStorage.LogDirectory, rejectUUID)

	if err := os.MkdirAll(rejectDir, os.FileMode(h.config.LocalStorage.EffectiveDirMode())); err != nil {
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
	if err := os.WriteFile(logJSONPath, data, os.FileMode(h.config.LocalStorage.EffectiveFileMode())); err != nil {
		slog.Error("Failed to write reject event log", "error", err, "path", logJSONPath)
		metrics.Global.IncrementMessageErrors()
		return nil, nil
	}

	slog.Info("Wrote reject event log", "path", logJSONPath, "reason", rejectMsg.GetReason())
	return nil, nil
}

// handleRestart resumes an existing session from a RestartMessage.
func (h *Handler) handleRestart(restartMsg *pb.RestartMessage) (*pb.ServerMessage, error) {
	switch h.config.Server.Mode {
	case "local":
		session, err := h.sessionFactories.newLocalRestartSession(restartMsg, &h.config.LocalStorage)
		if err != nil {
			return nil, fmt.Errorf("failed to create restart session: %w", err)
		}
		h.session = session
		h.logID = restartMsg.GetLogId()
		h.registerRestartSession(restartMsg, "local")
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementLocalSessions()
		slog.Info("Resumed local storage session via restart",
			"log_id", h.logID, "total_sessions", metrics.Global.GetTotalSessions())
		return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: restartMsg.GetLogId()}}, nil

	case "relay":
		// Resume locally by appending to the still-cached session (see
		// relay.NewRestartSession). Go's batch relay cannot forward the restart
		// upstream the way C does, because the upstream never saw the original
		// session and the client holds a relay-local log_id.
		session, err := h.sessionFactories.newRelayRestartSession(restartMsg, &h.config.Relay)
		if err != nil {
			return nil, fmt.Errorf("failed to resume relay session: %w", err)
		}
		h.session = session
		h.logID = restartMsg.GetLogId()
		h.registerRestartSession(restartMsg, "relay")
		metrics.Global.IncrementSessions()
		metrics.Global.IncrementRelaySessions()
		slog.Info("Resumed relay session via restart",
			"log_id", h.logID, "upstream", h.config.Relay.UpstreamHost,
			"total_sessions", metrics.Global.GetTotalSessions())
		// The client transitions straight to SEND_IO after a RestartMessage and
		// does not await a reply, so we send none (avoiding an extra log_id msg).
		return nil, nil

	default:
		return nil, fmt.Errorf("restart not supported in %s mode", h.config.Server.Mode)
	}
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
	// Retained so the ExitMessage, which carries no identifying fields of its
	// own, can be logged against the command it belongs to.
	h.acceptInfo = infoMap
	var err error

	if !acceptMsg.ExpectIobufs {
		resp, evErr := h.handleEventOnlyAccept(sessionUUID, acceptMsg)
		if evErr == nil {
			h.emitEvent(eventlog.Accept, infoMap, "")
		}
		return resp, evErr
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
			// A fail-closed refusal is a policy outcome, not a server fault, so
			// tell the client specifically why its command is being denied
			// instead of collapsing it into "Internal Server Error". sudo relays
			// this text to the user. Conformance: RELAY-010.
			if errors.Is(err, relay.ErrUpstreamUnreachable) {
				slog.Warn("Refusing command: no auditable path to the upstream log server",
					"remote_addr", h.conn.RemoteAddr())
				return &pb.ServerMessage{Type: &pb.ServerMessage_Error{
					Error: "unable to reach upstream log server; command refused (require_upstream is set)",
				}}, nil
			}
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

	// Emitted here rather than at the top of handleAccept so TSID carries the
	// session's real log ID, which is what ties an audit line to its transcript.
	h.emitEvent(eventlog.Accept, infoMap, "")

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
			// Same fail-closed refusal as the I/O path in handleAccept: an
			// event-only session is still a privileged command, so tell the
			// client why it is being denied rather than reporting a server
			// fault. Conformance: RELAY-010.
			if errors.Is(err, relay.ErrUpstreamUnreachable) {
				slog.Warn("Refusing command: no auditable path to the upstream log server",
					"remote_addr", h.conn.RemoteAddr())
				return &pb.ServerMessage{Type: &pb.ServerMessage_Error{
					Error: "unable to reach upstream log server; command refused (require_upstream is set)",
				}}, nil
			}
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
