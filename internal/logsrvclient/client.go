// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logsrvclient/client.go

// Package logsrvclient is the client half of the sudo_logsrv protocol: dialling
// a log server, completing the ClientHello/ServerHello handshake, framing
// messages for a local journal, and interpreting a server's acknowledgement.
//
// It was extracted from internal/relay, which had accumulated a complete and
// well-tested client while nominally being a server component. Two callers now
// share it:
//
//   - internal/relay, forwarding journalled sessions to an upstream log server.
//   - cmd/logsh, the recording login shell, originating sessions of its own.
//
// The package deliberately owns no session state, no retry loop, and no disk
// layout. Those belong to the caller, because relay and logsh disagree about
// all three: relay always journals then flushes, while logsh streams when it
// can and journals only when it must.
package logsrvclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"time"
)

// DefaultResponseTimeout bounds a single message exchange when Config leaves
// ResponseTimeout unset. It matches C's [relay] timeout default
// (logsrvd/logsrvd_conf.c:827-841,1639).
const DefaultResponseTimeout = 30 * time.Second

// ErrUpstreamRejected reports that the server answered with an error or abort
// ServerMessage. It is distinguished from every other failure because it is the
// one that will never succeed on retry: the server parsed the session and said
// no, so the next attempt gets the same answer. Callers use it to terminate a
// retry loop and dead-letter the session rather than spinning on it.
//
// C has no such distinction and no dead-letter path at all. A rejected journal
// there is left in outgoing/ and retried on every subsequent daemon start,
// forever (logsrvd/logsrvd_relay.c:638-661 tears the connection down with the
// state still RUNNING, which is neither FINISHED nor CONNECTING, so the file is
// neither unlinked nor re-queued). Conformance: docs/logsrvd-reference/ RELAY-049.
var ErrUpstreamRejected = errors.New("upstream rejected the session")

// Config holds everything Connect needs to reach one log server. It is a plain
// value type rather than a pointer into internal/config so that callers with
// unrelated configuration shapes -- a relay section, a logsh YAML file -- can
// each build one without depending on the other's schema.
type Config struct {
	// ClientID is announced in the ClientHello. Servers log it, so it should
	// name the component and its version.
	ClientID string

	UpstreamHost string
	UseTLS       bool

	// TLSSkipVerify disables chain and hostname verification of the server
	// certificate. It defaults to FALSE, i.e. the server IS verified -- a
	// deliberate divergence from C, which does not verify by default:
	// tls_checkpeer is initialised to false (logsrvd/logsrvd_conf.c:1688) and
	// tls_client_setup only installs SSL_CTX_set_verify when check_peer is set
	// (logsrvd/tls_client.c:251-256). Stock sudo_logsrvd therefore relays
	// complete transcripts of privileged sessions to any peer that completes a
	// handshake. Conformance: docs/logsrvd-reference/ TLS-027.
	TLSSkipVerify bool
	TLSMinVersion string // "1.2" or "1.3" (empty means 1.3)

	TLSCertFile   string // client cert presented to the server
	TLSKeyFile    string // key for TLSCertFile
	TLSCACertFile string // CA bundle used to verify the server

	ConnectTimeout time.Duration

	// ResponseTimeout bounds each message exchange AFTER the connection is
	// established, mirroring C's [relay] timeout. It is deliberately a separate
	// knob from ConnectTimeout: the dial budget is a latency figure, while this
	// is how long a busy server may take to fsync a session and answer.
	//
	// Reusing a 5s ConnectTimeout here made a server that acknowledged a session
	// in more than 5s fail the flush, so the journal was kept and the entire
	// session replayed on the next attempt -- the same transcript stored twice
	// under two log IDs. Conformance: docs/logsrvd-reference/ CONF-039.
	ResponseTimeout time.Duration
}

// OperationTimeout is the post-connect exchange budget, falling back to
// DefaultResponseTimeout. Do not fold this back together with ConnectTimeout;
// see the ResponseTimeout field comment for the duplicate-audit-record bug that
// caused.
func (c Config) OperationTimeout() time.Duration {
	if c.ResponseTimeout > 0 {
		return c.ResponseTimeout
	}
	return DefaultResponseTimeout
}

// WithTimeout runs fn under a context bounded by OperationTimeout.
func (c Config) WithTimeout(parent context.Context, fn func(context.Context) error) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, c.OperationTimeout())
	defer cancel()
	return fn(ctx)
}

// Connect dials the log server, completes the ClientHello/ServerHello
// handshake, and returns a Processor positioned to send session messages.
// The caller owns the returned Processor and must Close it.
func Connect(ctx context.Context, cfg Config) (protocol.Processor, error) {
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout}
	var conn net.Conn
	var err error

	slog.Debug("Dialing log server", "host", cfg.UpstreamHost, "use_tls", cfg.UseTLS, "tls_skip_verify", cfg.TLSSkipVerify)
	if cfg.UseTLS {
		tlsConfig, tlsErr := buildTLSConfig(cfg)
		if tlsErr != nil {
			return nil, tlsErr
		}
		tlsDialer := tls.Dialer{NetDialer: dialer, Config: tlsConfig}
		conn, err = tlsDialer.DialContext(ctx, "tcp", cfg.UpstreamHost)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", cfg.UpstreamHost)
	}

	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	proc := protocol.NewProcessorWithCloser(conn, conn, conn)
	slog.Debug("Starting handshake with log server")
	helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: cfg.ClientID}}}
	if err := cfg.WithTimeout(ctx, func(opCtx context.Context) error {
		return proc.WriteClientMessageContext(opCtx, helloMsg)
	}); err != nil {
		_ = proc.Close()
		return nil, fmt.Errorf("failed to send ClientHello: %w", err)
	}
	if err := cfg.WithTimeout(ctx, func(opCtx context.Context) error {
		_, err = proc.ReadServerMessageContext(opCtx)
		return err
	}); err != nil {
		_ = proc.Close()
		return nil, fmt.Errorf("failed to receive ServerHello: %w", err)
	}
	return proc, nil
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	minVer, err := config.TLSVersion(cfg.TLSMinVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid tls_min_version: %w", err)
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify, MinVersion: minVer}

	// Present a client certificate when one is configured, so a server running
	// with tls_checkpeer accepts us. Without this, such a server rejects every
	// flush at the handshake and the journal directory grows without bound --
	// and for a store-and-forward caller the failure is silent, because the
	// session was already acknowledged downstream.
	// Conformance: docs/logsrvd-reference/ TLS-025, CONF-045.
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, certErr := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if certErr != nil {
			return nil, fmt.Errorf("load client certificate: %w", certErr)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// A named CA bundle replaces the platform trust store for this server only,
	// which is how a private-CA server is trusted without installing its root
	// system-wide. An unreadable or empty bundle is fatal rather than a silent
	// fall back to the system store: a typo'd path would otherwise trust the
	// public web PKI instead of the one CA that was meant.
	// Conformance: docs/logsrvd-reference/ TLS-007.
	if cfg.TLSCACertFile != "" {
		pem, readErr := os.ReadFile(cfg.TLSCACertFile)
		if readErr != nil {
			return nil, fmt.Errorf("read CA bundle %s: %w", cfg.TLSCACertFile, readErr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA bundle %s contains no usable PEM certificates", cfg.TLSCACertFile)
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}

// ReadAck consumes server messages until the session is acknowledged.
//
// waitCommit selects WHICH acknowledgement counts, and getting it wrong loses
// audit data. An I/O session is only durable once the server sends its FINAL
// commit_point, so waitCommit must be true there: accepting the log_id (or an
// interim commit_point) as proof of delivery means a caller can retire the
// journal -- often the only remaining copy -- while the server is still writing,
// so the session ends up nowhere with no retry scheduled.
//
// Event-only sessions are never acknowledged at all, so callers must not call
// this function for them; blocking on a reply that is never coming hangs the
// caller forever.
//
// An error or abort from the server is always a failure, and always
// ErrUpstreamRejected.
func ReadAck(ctx context.Context, proc protocol.Processor, cfg Config, waitCommit bool) error {
	for {
		var srvMsg *pb.ServerMessage
		err := cfg.WithTimeout(ctx, func(opCtx context.Context) error {
			var readErr error
			srvMsg, readErr = proc.ReadServerMessageContext(opCtx)
			return readErr
		})
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("server closed the connection before acknowledging the session: %w", err)
		}
		if err != nil {
			return err
		}

		switch m := srvMsg.Type.(type) {
		case *pb.ServerMessage_Error:
			// A definitive refusal, not a failure to be reached: the server
			// parsed this session and said no, so every retry gets the same
			// answer. ErrUpstreamRejected routes it to the dead-letter path
			// instead of the retry loop. Conformance: RELAY-049.
			return fmt.Errorf("%w: %s", ErrUpstreamRejected, m.Error)
		case *pb.ServerMessage_Abort:
			return fmt.Errorf("%w (abort): %s", ErrUpstreamRejected, m.Abort)
		case *pb.ServerMessage_CommitPoint:
			return nil
		}
		if !waitCommit {
			return nil
		}
	}
}
