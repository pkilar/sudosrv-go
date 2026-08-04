// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/session.go
package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	"sudosrv/internal/sessions"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const (
	initialReconnectInterval = time.Second
	// FlushingSuffix is appended to a cache file while it is being flushed upstream.
	// Exported so startup orphan recovery can identify mid-flush files.
	FlushingSuffix = ".flushing"
	// DeliveredSuffix is appended to a cache file whose contents have been
	// flushed upstream but which we could not Remove (e.g. permission or IO
	// error). Orphan recovery globs *.log and *.log.flushing, so files with
	// this suffix are invisible to it — preventing the duplicate-upstream
	// hazard that would arise from re-flushing already-delivered messages.
	DeliveredSuffix = ".delivered"
	// commitPointInterval matches C sudo_logsrvd's ACK_FREQUENCY (10 seconds).
	commitPointInterval = 10 * time.Second
)

// Phase strings exposed via Session.LiveStats. Stored as package-level vars
// because atomic.Pointer[string] requires a pointer; using `const` here would
// not let us take an address.
var (
	phaseWriting  = "writing"
	phaseFlushing = "flushing"
)

// Session handles the entire lifecycle of a relay session. It is a durable,
// background process independent of the client connection that created it.
//
// Relay mode is ALWAYS store-and-forward, by design: the session is journalled
// to {relay_cache_directory}/{uuid}.log as messages arrive (the write phase) and
// forwarded upstream only once the client's ExitMessage lands (the flush phase).
// There is no streaming path and no store_first knob to select one, because
// there is nothing to select between — this is C's store_first mode made
// unconditional (logsrvd/logsrvd.c:209-212, which swaps in cms_journal and skips
// connect_relay; the default cms_relay streams each message as it arrives).
//
// The two costs of that, accepted knowingly and documented for operators under
// "A note on relay mode" in README.md:
//
//   - The upstream never sees a session in progress, so it cannot offer a live
//     view of a running command. The management API on this server can.
//   - A client that dies without sending ExitMessage leaves its journal in the
//     cache until the daemon next starts and orphan recovery claims it
//     (see RecoverOrphans). The record arrives late, not never.
//
// A third follows in the connection layer: the downstream ServerHello is
// answered immediately rather than deferred behind an upstream connect. See
// connection.Handler.handleHello.
//
// Conformance: docs/logsrvd-reference/ CONF-043, RELAY-002, RELAY-003.
type Session struct {
	logID            string
	config           *config.RelayConfig
	initialAcceptMsg *pb.AcceptMessage
	// resume is true for a session created via NewRestartSession: it appends the
	// resumed I/O to an existing cache file (which already begins with the
	// original AcceptMessage) instead of writing a fresh AcceptMessage opener.
	resume bool
	// initialAcceptSeen distinguishes the session's own AcceptMessage — which
	// handleAccept replays through HandleClientMessage purely to obtain the
	// log_id response, and which the write phase already caches from
	// initialAcceptMsg — from later sub-command accepts, which must be cached
	// and relayed. Pre-set for resumed sessions: their accept belonged to the
	// original session, so the first accept a restart sees is already a
	// sub-command. Also pre-set for event-only sessions, which get no replay
	// at all. See NewSession and HandleClientMessage.
	initialAcceptSeen atomic.Bool
	fromClientChan    chan *pb.ClientMessage
	// sendMu serializes Close against in-flight HandleClientMessage calls.
	// HandleClientMessage holds RLock for its entire critical section
	// (closed check + channel send); Close takes the exclusive Lock so it
	// waits for every admitted send to commit to the channel before
	// flipping the closed flag and closing the channel. Without this,
	// a sender that passed the closed check could still write to a buffer
	// the writer goroutine has already abandoned, silently losing audit data.
	sendMu          sync.RWMutex
	closed          atomic.Bool // mutated under sendMu.Lock; read under sendMu.RLock
	wg              sync.WaitGroup
	closeOnce       sync.Once
	cacheFileName   string
	mu              sync.Mutex    // Protects cumulativeDelay and lastCommitTime
	cumulativeDelay time.Duration // Single elapsed clock summed across all I/O, winsize, and suspend delays (mirrors C closure->elapsed_time)
	lastCommitTime  time.Time     // When last commit point was sent to client
	ctx             context.Context
	cancel          context.CancelFunc
	// onDone is invoked exactly once after the background runner exits — i.e.
	// after both the cache-write phase and any upstream-flush phase finish.
	// Connection-side bookkeeping that needs to outlive the client connection
	// (such as session-registry deregistration) hooks into this.
	onDone func()
	// done is set to true before onDone fires so callers racing with the
	// runner can detect a "done before I got here" outcome and run any
	// cleanup that onDone could not (because the resource it would clean
	// up did not yet exist when onDone ran).
	done atomic.Bool
	// Live stats exposed to the management API.
	msgCount      atomic.Int64
	bytesReceived atomic.Int64
	lastActivity  atomic.Pointer[time.Time]
	phase         atomic.Pointer[string] // "writing" -> "flushing"
}

// Compile-time check that Session satisfies sessions.MetadataProvider.
var _ sessions.MetadataProvider = (*Session)(nil)

// IsDone reports whether the background runner has finished. Once true the
// session will never call its onDone callback again; any registry or other
// state that was added after onDone fired must be cleaned up by the caller.
func (s *Session) IsDone() bool { return s.done.Load() }

// NewSession creates a new relay session handler.
// The provided ctx is used as the parent context; cancelling it will stop the
// session's background goroutine after the current operation completes.
//
// onDone (if non-nil) is invoked exactly once after the background runner
// finishes, including any upstream-flush retries. This lets callers tie
// resources whose lifecycle exceeds the client connection (e.g. management
// API registry entries) to the actual end of the session rather than the end
// of the connection.
// ErrUpstreamUnreachable is returned by NewSession when require_upstream is set
// and the upstream cannot be reached. Callers should surface a specific error to
// the client rather than a generic failure, so the operator can tell a refused
// command from a server fault.
var ErrUpstreamUnreachable = errors.New("relay upstream is unreachable and require_upstream is set")

func NewSession(ctx context.Context, sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig, onDone func()) (*Session, error) {
	// Fail-closed check, before anything is created on disk: if the operator
	// requires an auditable path to exist, prove one does before letting the
	// command run. Full connect (including TLS) rather than a bare TCP dial, so
	// a broken certificate or a wrong port is caught here too.
	// Conformance: docs/logsrvd-reference/ RELAY-010.
	if cfg.RequireUpstream {
		probe, err := connectToUpstream(ctx, cfg)
		if err != nil {
			slog.Error("Refusing session: require_upstream is set and the upstream is unreachable",
				"upstream", cfg.UpstreamHost, "error", err)
			return nil, fmt.Errorf("%w: %w", ErrUpstreamUnreachable, err)
		}
		_ = probe.Close()
	}

	// 0700: cache files and the directory carry raw sudo I/O (keystrokes,
	// command output, sometimes passwords — the storage password filter
	// does not apply to the relay cache writer). Group/other must not read.
	if err := os.MkdirAll(cfg.RelayCacheDirectory, 0700); err != nil {
		return nil, fmt.Errorf("could not create relay cache directory %s: %w", cfg.RelayCacheDirectory, err)
	}

	// Use UUID string for cache file naming (safe for filenames).
	cacheFileName := filepath.Join(cfg.RelayCacheDirectory, fmt.Sprintf("%s.log", sessionUUID.String()))

	// Generate log_id matching C sudo_logsrvd format: base64(UUID bytes).
	// Relay has no local path, matching journal mode behavior (empty path).
	logID := base64.StdEncoding.EncodeToString(sessionUUID[:])

	ctx, cancel := context.WithCancel(ctx)
	s := &Session{
		logID:            logID,
		config:           cfg,
		initialAcceptMsg: acceptMsg,
		fromClientChan:   make(chan *pb.ClientMessage, 1000), // Buffered channel for client messages
		cacheFileName:    cacheFileName,
		ctx:              ctx,
		cancel:           cancel,
		onDone:           onDone,
	}
	// Only an I/O session's accept is replayed through HandleClientMessage (by
	// handleAccept, to produce the log_id the client waits for). An event-only
	// accept — expect_iobufs=false — is dispatched to handleEventOnlyAccept
	// instead, which returns without that replay because sudo expects no log_id
	// when I/O logging is off (C: logsrvd/logsrvd_journal.c:571 calls
	// fmt_log_id_message only when msg->expect_iobufs). So consume the flag here:
	// otherwise the FIRST sub-command accept of an event-only session would be
	// mistaken for the session's own, answered with an unsolicited log_id, and
	// returned before reaching the cache writer — i.e. never journalled. C
	// journals every accept unconditionally (journal_accept), so a user running
	// sudo with intercept/log_subcmds and I/O logging disabled would see the
	// upstream audit trail silently lose the first intercepted command.
	// Conformance: PROTO-015.
	s.initialAcceptSeen.Store(!acceptMsg.GetExpectIobufs())
	s.phase.Store(&phaseWriting)

	s.wg.Go(s.run) // Start the single, durable goroutine for this session.

	return s, nil
}

// NewRestartSession resumes a relay session interrupted earlier on this server.
//
// Go's relay is store-and-forward: it caches a session to {uuid}.log and only
// flushes upstream after the client's ExitMessage, so the client was handed a
// LOCAL log_id (base64(uuid)) and the upstream never saw the original session.
// C's relay forwards the RestartMessage upstream, which cannot work here because
// the upstream has no log to resume. Instead we resume LOCALLY: decode the uuid
// from the client's log_id, reopen that still-cached file, and append the
// resumed I/O so the upstream eventually receives one continuous session
// (Accept + original I/O + resumed I/O + Exit). The RestartMessage itself is
// consumed here and not cached/forwarded.
//
// resume_point is advisory here: any I/O cached past it (cached but not yet
// flushed, then re-sent by the client) is appended, so the overlap region can
// be duplicated — the same narrow window that exists whenever a client resends
// already-stored I/O. If the cache file is gone (already flushed upstream, or
// an unknown log_id) the session cannot be resumed and an error is returned.
func NewRestartSession(ctx context.Context, restartMsg *pb.RestartMessage, cfg *config.RelayConfig, onDone func()) (*Session, error) {
	decoded, err := base64.StdEncoding.DecodeString(restartMsg.GetLogId())
	if err != nil || len(decoded) < 16 {
		return nil, fmt.Errorf("relay restart: invalid log_id %q", restartMsg.GetLogId())
	}
	var sessionUUID uuid.UUID
	copy(sessionUUID[:], decoded[:16])

	cacheFileName := filepath.Join(cfg.RelayCacheDirectory, fmt.Sprintf("%s.log", sessionUUID.String()))
	if info, statErr := os.Stat(cacheFileName); statErr != nil {
		return nil, fmt.Errorf("relay restart: no cached session for log_id %s (cannot resume): %w", restartMsg.GetLogId(), statErr)
	} else if info.IsDir() {
		return nil, fmt.Errorf("relay restart: cache path %s is a directory", cacheFileName)
	}

	ctx, cancel := context.WithCancel(ctx)
	s := &Session{
		logID:          restartMsg.GetLogId(),
		config:         cfg,
		resume:         true,
		fromClientChan: make(chan *pb.ClientMessage, 1000),
		cacheFileName:  cacheFileName,
		ctx:            ctx,
		cancel:         cancel,
		onDone:         onDone,
	}
	// A resumed session's own accept was consumed by the ORIGINAL session, and
	// handleRestart does not replay one. Any accept this session sees is
	// therefore already a sub-command and must be cached.
	s.initialAcceptSeen.Store(true)
	// Restore the single elapsed clock from resume_point so the synthesized
	// commit points continue from where the interrupted session left off.
	if rp := restartMsg.GetResumePoint(); rp != nil {
		s.cumulativeDelay = durationFromTimeSpec(rp)
	}
	s.phase.Store(&phaseWriting)

	s.wg.Go(s.run)

	return s, nil
}

// run is the core goroutine for a session. It first writes all messages from the
// client to a local cache file. Once the session is complete (ExitMessage),
// it proceeds to persistently try to flush that file to the upstream server.
func (s *Session) run() {
	// Done is owned by the wg.Go that launched this goroutine.
	defer s.cancel()
	defer func() {
		// Set done=true before firing onDone so any caller that observes
		// IsDone() returning true after we have called onDone can rely on
		// onDone having already run (i.e. its Deregister either happened or
		// was a no-op because the registry entry did not yet exist).
		s.done.Store(true)
		if s.onDone != nil {
			s.onDone()
		}
	}()
	slog.Debug("Relay session runner started", "log_id", s.logID)

	// Phase 1: Write all incoming messages to the local cache file.
	sessionCompleted := s.writeMessagesToCache()

	if !sessionCompleted {
		slog.Warn("Relay session ended without a final ExitMessage. The cached log will be flushed by the next server startup.", "log_id", s.logID)
		return
	}

	// Phase 2: The client session is complete. Now, persistently try to flush the file.
	s.phase.Store(&phaseFlushing)
	slog.Info("Client session complete, beginning persistent flush attempts.", "log_id", s.logID, "file", s.cacheFileName)
	// Pre-connect splay (0–1s) so many concurrently-completing sessions don't
	// all hit the upstream in lockstep when it comes back online. Per-session
	// backoff already jitters; this addresses synchronized first attempts.
	if err := sleepWithContext(s.ctx, time.Duration(rand.Int64N(int64(time.Second)))); err != nil {
		return
	}
	for attempt := 0; s.config.ReconnectAttempts == -1 || attempt < s.config.ReconnectAttempts; attempt++ {
		select {
		case <-s.ctx.Done():
			slog.Info("Relay session cancelled, stopping flush attempts", "log_id", s.logID)
			return
		default:
		}

		proc, err := connectToUpstream(s.ctx, s.config)
		if err != nil {
			slog.Warn("Upstream connection attempt failed", "log_id", s.logID, "error", err)
			if !s.waitBeforeRetry(attempt) {
				return
			}
			continue
		}

		// Connection successful, now flush the file. Protocol operations use
		// context-aware reads/writes, so shutdown can interrupt stalled upstream I/O.
		slog.Info("Upstream connection successful, flushing cache.", "log_id", s.logID, "file", s.cacheFileName)
		err = flushFile(s.ctx, proc, s.cacheFileName, s.config)
		_ = proc.Close()
		if err != nil {
			// If ctx was cancelled, the error is expected (we closed the conn).
			if s.ctx.Err() != nil {
				slog.Info("Relay flush aborted due to session cancellation", "log_id", s.logID)
				return
			}
			slog.Error("Failed during cache flush, will retry.", "log_id", s.logID, "error", err)
			// Back off here too, not only on the connect branch. A flush that
			// fails after the connect succeeded — upstream error or abort, a
			// mid-replay EOF, an operation timeout, or the cache file failing to
			// open — is just as permanent as a refused connect, and with the
			// default reconnect_attempts of -1 this loop never ends. Falling
			// straight through re-connected and re-sent the entire session as
			// fast as the round trip allowed: hundreds of upstream connections
			// and full replays per second, one slog.Error each, until the local
			// disk filled. C never does this. A post-connect failure there is
			// not even re-queued in the running process (logsrvd/logsrvd.c:
			// 108-111 re-queues only from CONNECTING), and anything that is
			// re-queued waits relay.retry_interval — 30s by default
			// (logsrvd/logsrvd_queue.c:194-196, logsrvd/logsrvd_conf.c:1642).
			// Conformance: docs/logsrvd-reference/ RELAY-044, RELAY-049.
			if !s.waitBeforeRetry(attempt) {
				return
			}
			continue
		}
		slog.Info("Cache flush successful. Relay session finished.", "log_id", s.logID)
		return
	}

	if s.config.ReconnectAttempts != -1 {
		slog.Error("Relay session has exhausted all reconnect attempts. The cached log remains on disk.", "log_id", s.logID, "attempts", s.config.ReconnectAttempts)
	}
}

// writeMessagesToCache opens the cache file and writes all received messages until an ExitMessage.
func (s *Session) writeMessagesToCache() (completed bool) {
	// 0600: cache files carry raw sudo I/O, sometimes including passwords
	// (the storage password filter is not applied to the relay write path).
	file, err := os.OpenFile(s.cacheFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		slog.Error("CRITICAL: could not open cache file. Relay data for this session will be lost.", "log_id", s.logID, "error", err)
		return
	}
	defer func() {
		// Sync surfaces fsync-time errors; Close surfaces flush errors that
		// only manifest at close (e.g. NFS or disk-full). Drop neither — a
		// cache file that fails to close cleanly is a data-loss signal.
		if err := file.Sync(); err != nil {
			slog.Error("Failed to fsync relay cache file", "log_id", s.logID, "error", err)
		}
		if err := file.Close(); err != nil {
			slog.Error("Failed to close relay cache file", "log_id", s.logID, "error", err)
		}
	}()

	// Write the essential AcceptMessage first to ensure the cache file is valid
	// for flushing. On a resume (restart), the existing cache file already opens
	// with the original AcceptMessage, so we append the resumed I/O directly and
	// the upstream ultimately receives one continuous session.
	if !s.resume {
		if err := writeProtoMessage(file, &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: s.initialAcceptMsg}}); err != nil {
			slog.Error("Failed to write initial accept message to cache", "log_id", s.logID, "error", err)
			return
		}
	}

	// Loop until the session context is cancelled (server shutdown), Close()
	// closes fromClientChan, or an ExitMessage arrives. Close() guarantees
	// that every admitted send has committed to the channel before close()
	// fires, so the ok=false signal here implies "the buffer has been fully
	// drained" — no messages are lost on disconnect races.
	for {
		select {
		case msg, ok := <-s.fromClientChan:
			if !ok {
				// Channel closed by Close(); all buffered messages drained.
				return false
			}
			if err := writeProtoMessage(file, msg); err != nil {
				slog.Error("Failed to write message to relay cache, aborting write phase", "log_id", s.logID, "error", err)
				return false
			}
			if _, ok := msg.Type.(*pb.ClientMessage_ExitMsg); ok {
				slog.Debug("ExitMessage received and cached. Ending write phase.", "log_id", s.logID)
				return true
			}
		case <-s.ctx.Done():
			slog.Info("Relay session write phase cancelled by context", "log_id", s.logID)
			return false
		}
	}
}

// maxBackoffExponent caps the math.Pow(2, n) input to keep backoff from
// overflowing float64 into +Inf during infinite-reconnect runs. 2^62ns is
// already ~146 years — well past any realistic maxInterval.
const maxBackoffExponent = 62

// sleepWithContext sleeps for d or returns ctx.Err() if cancellation arrives
// first. Used for jitter splays that must respect server shutdown.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitBeforeRetry sleeps for the backoff belonging to the attempt that just
// failed, and reports whether the caller should try again. It returns false only
// when the session context was cancelled during the wait (server shutdown), in
// which case the caller must stop — the cache file stays on disk for startup
// orphan recovery.
//
// Every failed flush attempt goes through here, whatever it failed at, so no
// error path can re-loop without a delay. See the RELAY-044 note in run().
func (s *Session) waitBeforeRetry(attempt int) bool {
	backoff := s.calculateBackoff(attempt)
	slog.Info("Waiting before next upstream attempt", "log_id", s.logID, "duration", backoff)
	select {
	case <-s.ctx.Done():
		slog.Info("Relay session cancelled during backoff", "log_id", s.logID)
		return false
	case <-time.After(backoff):
		return true
	}
}

func (s *Session) calculateBackoff(attempts int) time.Duration {
	maxInterval := s.config.MaxReconnectInterval
	if maxInterval <= 0 {
		maxInterval = time.Minute
	}
	exp := min(attempts, maxBackoffExponent)
	backoff := min(
		float64(initialReconnectInterval)*math.Pow(2, float64(exp)),
		float64(maxInterval),
	)
	// Apply equal jitter to prevent thundering herd: base/2 + rand(0, base/2).
	// math/rand/v2 is auto-seeded per-process and safe for concurrent use.
	half := time.Duration(backoff) / 2
	if half > 0 {
		return half + time.Duration(rand.Int64N(int64(half)))
	}
	return time.Duration(backoff)
}

// extractIoDelay returns the stream name and delay for I/O buffer messages.
// Returns ("", nil) for non-I/O messages; the empty stream name is the "not
// applicable" signal — no separate ok bool is needed.
func extractIoDelay(msg *pb.ClientMessage) (string, *pb.TimeSpec) {
	switch event := msg.Type.(type) {
	case *pb.ClientMessage_TtyinBuf:
		return "ttyin", event.TtyinBuf.GetDelay()
	case *pb.ClientMessage_TtyoutBuf:
		return "ttyout", event.TtyoutBuf.GetDelay()
	case *pb.ClientMessage_StdinBuf:
		return "stdin", event.StdinBuf.GetDelay()
	case *pb.ClientMessage_StdoutBuf:
		return "stdout", event.StdoutBuf.GetDelay()
	case *pb.ClientMessage_StderrBuf:
		return "stderr", event.StderrBuf.GetDelay()
	default:
		return "", nil
	}
}

// messageDelay returns the delay of any event that advances sudo's elapsed-time
// clock: the five I/O buffers plus winsize and suspend. Returns nil for messages
// that carry no delay (Accept/Reject/Restart/Alert/Exit). Mirrors the set of
// update_elapsed_time call sites in C sudo_logsrvd.
func messageDelay(msg *pb.ClientMessage) *pb.TimeSpec {
	switch event := msg.Type.(type) {
	case *pb.ClientMessage_TtyinBuf:
		return event.TtyinBuf.GetDelay()
	case *pb.ClientMessage_TtyoutBuf:
		return event.TtyoutBuf.GetDelay()
	case *pb.ClientMessage_StdinBuf:
		return event.StdinBuf.GetDelay()
	case *pb.ClientMessage_StdoutBuf:
		return event.StdoutBuf.GetDelay()
	case *pb.ClientMessage_StderrBuf:
		return event.StderrBuf.GetDelay()
	case *pb.ClientMessage_WinsizeEvent:
		return event.WinsizeEvent.GetDelay()
	case *pb.ClientMessage_SuspendEvent:
		return event.SuspendEvent.GetDelay()
	default:
		return nil
	}
}

// isExitMessage reports whether msg is an ExitMessage.
func isExitMessage(msg *pb.ClientMessage) bool {
	_, ok := msg.Type.(*pb.ClientMessage_ExitMsg)
	return ok
}

// durationFromTimeSpec converts a protobuf TimeSpec into a time.Duration.
func durationFromTimeSpec(ts *pb.TimeSpec) time.Duration {
	return time.Duration(ts.GetTvSec())*time.Second + time.Duration(ts.GetTvNsec())*time.Nanosecond
}

// commitPointMsg builds a commit_point ServerMessage carrying the cumulative
// elapsed time d. Integer second/nanosecond split matches C's encoding and the
// value the client compares against its own global elapsed time.
func commitPointMsg(d time.Duration) *pb.ServerMessage {
	return &pb.ServerMessage{Type: &pb.ServerMessage_CommitPoint{
		CommitPoint: &pb.TimeSpec{
			TvSec:  int64(d / time.Second),
			TvNsec: int32(d % time.Second),
		},
	}}
}

// LogID returns the base64-encoded sudo log_id assigned when the relay session
// was created. It is stable for the lifetime of the session.
func (s *Session) LogID() string { return s.logID }

// LiveStats returns a snapshot of mutable counters for the management API.
func (s *Session) LiveStats() sessions.LiveStats {
	stats := sessions.LiveStats{
		MessagesReceived: s.msgCount.Load(),
		BytesReceived:    s.bytesReceived.Load(),
		CacheFile:        s.cacheFileName,
	}
	if t := s.lastActivity.Load(); t != nil {
		stats.LastActivity = *t
	}
	if p := s.phase.Load(); p != nil {
		stats.Phase = *p
	}
	return stats
}

func (s *Session) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	// RLock pairs with Close()'s Lock: while we hold this, Close cannot run
	// to completion. Any send that admits past the closed check is therefore
	// guaranteed to commit to the channel before close(fromClientChan) fires
	// — the writer cannot miss it.
	s.sendMu.RLock()
	defer s.sendMu.RUnlock()
	if s.closed.Load() {
		return nil, fmt.Errorf("relay session closed")
	}

	s.msgCount.Add(1)
	s.bytesReceived.Add(int64(proto.Size(msg)))
	now := time.Now()
	s.lastActivity.Store(&now)

	if _, ok := msg.Type.(*pb.ClientMessage_AcceptMsg); ok {
		if s.initialAcceptSeen.CompareAndSwap(false, true) {
			// The session's own accept, replayed here by handleAccept solely to
			// produce the log_id the client is waiting on. The write phase caches
			// it from initialAcceptMsg, so it must NOT be cached again.
			return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: s.logID}}, nil
		}
		// Every later accept is a SUB-COMMAND accept and falls through to be
		// cached and relayed like any other message. The server advertises
		// Subcommands: true, so a client using sudo's intercept/log_subcmds
		// support sends one per intercepted command; dropping them left the
		// upstream audit trail claiming a single command was run.
		//
		// It is answered with nothing, matching C: a log_id is returned only for
		// a NEW I/O session (logsrvd/logsrvd_local.c:209, gated on
		// new_session && log_io).
		//
		// Conformance: docs/logsrvd-reference/ RELAY-034.
	}

	// Use a timeout to prevent indefinite blocking. time.NewTimer+Stop
	// avoids leaking a pending timer for up to 5s on the common path where
	// the send wins immediately (time.After cannot be stopped).
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case s.fromClientChan <- msg:
	case <-timer.C:
		slog.Warn("Relay session message channel timeout", "log_id", s.logID)
		return nil, fmt.Errorf("relay session message channel timeout")
	case <-s.ctx.Done():
		return nil, fmt.Errorf("relay session cancelled")
	}

	// Generate local commit points for the downstream client so it can complete
	// its CLOSING handshake without waiting on the (asynchronously flushed)
	// upstream. The cumulative clock is advanced by EVERY delay-bearing event
	// (I/O, winsize, suspend) — one counter, mirroring C's closure->elapsed_time —
	// because the client compares the final commit_point against its own global
	// elapsed time. Lock protects cumulativeDelay and lastCommitTime which are
	// also read by the run() goroutine's context (indirectly via Close/wg.Wait).
	streamName, _ := extractIoDelay(msg)
	if delay := messageDelay(msg); delay != nil {
		s.mu.Lock()
		s.cumulativeDelay += durationFromTimeSpec(delay)
		// Throttled periodic commit on I/O events (matches C's ACK_FREQUENCY).
		// winsize/suspend advance the clock but do not themselves emit a commit.
		if streamName != "" && time.Since(s.lastCommitTime) >= commitPointInterval {
			s.lastCommitTime = time.Now()
			cp := s.cumulativeDelay
			s.mu.Unlock()
			return commitPointMsg(cp), nil
		}
		s.mu.Unlock()
	}

	// Unconditional FINAL commit on Exit (matches C handle_exit). Exit carries no
	// delay so it is handled outside the accumulation block above; without this
	// the stock client stalls in CLOSING until log_server_timeout (default 30s).
	if isExitMessage(msg) {
		s.mu.Lock()
		cp := s.cumulativeDelay
		s.mu.Unlock()
		return commitPointMsg(cp), nil
	}

	return nil, nil
}

// Close is called by the connection handler when the client disconnects. It
// signals the write-phase loop that no more messages will arrive and then
// returns immediately; durable upstream flushing continues in the background.
// Server shutdown propagates via the parent context. Safe to call multiple times.
//
// Acquiring sendMu exclusively waits for any HandleClientMessage call already
// inside its critical section to finish its channel send. After we set
// closed=true and close the channel, no new sender can pass the closed check
// and any committed buffered message will be drained by the writer's
// ok-from-receive loop. This is the synchronization Codex's adversarial
// review identified as missing.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		slog.Info("Client connection closed. Relay session writer will now complete.", "log_id", s.logID)
		s.sendMu.Lock()
		s.closed.Store(true)
		close(s.fromClientChan)
		s.sendMu.Unlock()
	})
	return nil
}

// Wait blocks until the background cache writer/flusher exits. Production
// connection cleanup deliberately does not call this; tests and coordinated
// shutdown paths can use it when they own the session lifecycle.
func (s *Session) Wait() {
	s.wg.Wait()
}

// ---- Standalone Flusher for Orphaned Files ----

// RecoverOrphans scans the relay cache directory for files left behind by prior
// sessions (crash, shutdown mid-flush, or server restart with pending flush) and
// replays them upstream. It handles two classes of files:
//
//   - *.log.flushing: renamed back to *.log so the normal recovery path picks them up
//   - *.log: flushed upstream with bounded concurrency
//
// The supplied context governs goroutine lifetime; cancelling it aborts pending
// flushes (the underlying cache file stays on disk for a future recovery pass).
// ScanOrphans takes a point-in-time snapshot of the cache files left behind by
// a previous run, restoring any mid-flush files to *.log on the way.
//
// It is deliberately separate from flushing them. The scan must happen BEFORE
// the server starts accepting connections: a session accepted while a live glob
// is running would have its own {uuid}.log picked up mid-write, renamed to
// .flushing, replayed upstream in whatever partial state it was in, and
// unlinked, truncating and duplicating a live session's audit record. Working
// from a snapshot means any file created later is, by construction, someone
// else's and is never touched.
//
// A cache directory that cannot be read is an error rather than an empty
// result: filepath.Glob reports only ErrBadPattern and returns (nil, nil) for a
// missing or unreadable directory, which would let a wrong mount or a bad chown
// silently abandon the entire backlog while the daemon looked healthy.
//
// Conformance: docs/logsrvd-reference/ ARCH-043.
func ScanOrphans(cfg *config.RelayConfig) ([]string, error) {
	slog.Info("Scanning for orphaned relay cache files", "directory", cfg.RelayCacheDirectory)

	// Probe the directory explicitly; Glob will not tell us it is unusable.
	if _, err := os.ReadDir(cfg.RelayCacheDirectory); err != nil {
		return nil, fmt.Errorf("relay cache directory %s is not readable: %w",
			cfg.RelayCacheDirectory, err)
	}

	// Restore any mid-flush files from a prior crash by renaming them back to *.log.
	flushingPattern := filepath.Join(cfg.RelayCacheDirectory, "*.log"+FlushingSuffix)
	flushingFiles, err := filepath.Glob(flushingPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to scan for in-flight relay files: %w", err)
	}
	for _, f := range flushingFiles {
		restored := f[:len(f)-len(FlushingSuffix)]
		if err := os.Rename(f, restored); err != nil {
			if os.IsNotExist(err) {
				// Another concurrent recovery (HA failover, parallel orphan
				// scan) already claimed this file. Benign.
				slog.Debug("Mid-flush cache file already claimed by another worker", "path", f)
				continue
			}
			slog.Error("Failed to recover mid-flush cache file", "path", f, "error", err)
			continue
		}
		slog.Info("Recovered mid-flush cache file for retry", "from", f, "to", restored)
	}

	pattern := filepath.Join(cfg.RelayCacheDirectory, "*.log")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to scan relay cache directory: %w", err)
	}
	return files, nil
}

// RecoverOrphans scans and then flushes in one step. Callers that must not race
// live sessions should use ScanOrphans before opening listeners and pass the
// snapshot to FlushOrphans; internal/server does exactly that.
func RecoverOrphans(ctx context.Context, cfg *config.RelayConfig) error {
	files, err := ScanOrphans(cfg)
	if err != nil {
		return err
	}
	return FlushOrphans(ctx, cfg, files)
}

// FlushOrphans replays the given cache files upstream, at most
// maxConcurrentFlushes at a time.
func FlushOrphans(ctx context.Context, cfg *config.RelayConfig, files []string) error {
	if len(files) == 0 {
		slog.Info("No orphaned relay files found")
		return nil
	}
	slog.Info("Found orphaned relay files", "count", len(files))

	// Bounded worker pool: spawn at most maxConcurrentFlushes goroutines, not
	// one per file. With a stale cache from a multi-day outage `files` can run
	// into the thousands, and the old pattern allocated a goroutine stack for
	// every entry just to block on a 5-slot semaphore.
	const maxConcurrentFlushes = 5
	workers := min(maxConcurrentFlushes, len(files))
	jobs := make(chan string, len(files))
	errChan := make(chan error, len(files))

	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for filename := range jobs {
				// Bail between jobs on cancellation. FlushOrphanedFile is
				// itself ctx-aware so a mid-flush cancel propagates through
				// errChan via the returned error.
				if err := ctx.Err(); err != nil {
					errChan <- err
					return
				}
				slog.Debug("Flushing orphaned relay file", "file", filename)
				errChan <- FlushOrphanedFile(ctx, filename, cfg)
			}
		})
	}
	wg.Wait()
	close(errChan)

	var flushErrors []error
	for err := range errChan {
		if err != nil {
			flushErrors = append(flushErrors, err)
		}
	}
	if len(flushErrors) > 0 {
		slog.Warn("Some orphaned relay files could not be flushed", "error_count", len(flushErrors))
		return errors.Join(flushErrors...)
	}
	slog.Info("Successfully flushed all orphaned relay files", "count", len(files))
	return nil
}

// FlushOrphanedFile connects to upstream and sends the content of a single file.
func FlushOrphanedFile(ctx context.Context, filePath string, cfg *config.RelayConfig) error {
	slog.Info("Found orphaned relay file, attempting to flush", "path", filePath)

	// Rename file to prevent another process from picking it up. A missing
	// file means a sibling worker already claimed it — benign skip.
	flushingFileName := filePath + FlushingSuffix
	if err := os.Rename(filePath, flushingFileName); err != nil {
		if os.IsNotExist(err) {
			slog.Debug("Orphan file already claimed by another worker", "path", filePath)
			return nil
		}
		slog.Error("Could not rename orphaned file for flushing", "path", filePath, "error", err)
		return fmt.Errorf("could not rename orphaned file %s: %w", filePath, err)
	}

	proc, err := connectToUpstream(ctx, cfg)
	if err != nil {
		slog.Error("Failed to connect to upstream for orphaned file flush", "path", flushingFileName, "error", err)
		if renameErr := os.Rename(flushingFileName, filePath); renameErr != nil {
			slog.Error("Failed to rename orphaned file back after connection failure", "path", flushingFileName, "error", renameErr)
		}
		return fmt.Errorf("failed to connect to upstream for %s: %w", filePath, err)
	}

	err = flushFile(ctx, proc, flushingFileName, cfg)
	_ = proc.Close()
	if err != nil {
		slog.Error("Failed to flush orphaned file, renaming back", "path", flushingFileName, "error", err)
		if renameErr := os.Rename(flushingFileName, filePath); renameErr != nil {
			slog.Error("Failed to rename orphaned file back after flush failure", "path", flushingFileName, "error", renameErr)
		}
		return fmt.Errorf("failed to flush orphaned file %s: %w", filePath, err)
	}
	slog.Info("Successfully flushed orphaned relay file", "path", flushingFileName)
	return nil
}

// retireCacheFile is called after flushFile finishes sending a cache file's
// contents upstream. It removes the file. If Remove fails, the file is
// renamed to DeliveredSuffix so orphan recovery cannot re-flush it on next
// startup — re-flushing already-delivered messages would duplicate audit
// records upstream, which is worse than leaking a stale on-disk file.
func retireCacheFile(filePath string) {
	err := os.Remove(filePath)
	if err == nil {
		return
	}
	delivered := filePath + DeliveredSuffix
	if renameErr := os.Rename(filePath, delivered); renameErr != nil {
		slog.Error(
			"Failed to retire flushed cache file; orphan recovery may re-flush and duplicate upstream records",
			"path", filePath,
			"remove_error", err,
			"rename_error", renameErr,
		)
		return
	}
	slog.Warn(
		"Could not remove flushed cache file; renamed to sentinel to prevent re-flush",
		"path", delivered,
		"remove_error", err,
	)
}

// flushFile replays a cache file upstream and retires it only once the upstream
// has taken responsibility for the session.
//
// The rule that matters: a successful write(2) is NOT delivery. Bytes accepted
// into the local send buffer are lost if the upstream dies before persisting
// them, and the cache file is the only other copy — so unlinking it on "we
// finished reading our own file" converts an upstream crash into silent audit
// loss. C unlinks the journal only once the closure reaches FINISHED, i.e. after
// the upstream's final commit point (logsrvd/logsrvd.c:296-305).
//
// What counts as acknowledgement depends on the session type, and the protocol
// is asymmetric here:
//
//   - I/O session (first Accept has expect_iobufs=true): the upstream returns a
//     log_id for the accept (logsrvd/logsrvd_local.c:209-223, gated on
//     new_session && log_io) and a final commit_point once the ExitMessage is
//     stored (logsrvd/logsrvd.c handle_exit → state EXITED → commit_ev). The
//     commit point is the durability signal, and we wait for it.
//   - Event-only session (expect_iobufs=false) and sub-command accepts: the
//     upstream sends NOTHING — handle_exit goes straight to FINISHED with the
//     comment "No commit point to send to client, we are finished." Waiting for
//     an acknowledgement here would fail every flush and re-deliver the accept
//     event on each retry, forever. Matching C, the write is the completion.
//
// Any error/abort ServerMessage aborts the flush with the cache file intact, so
// an upstream that rejects the session (disk full, iolog permission failure)
// causes a retry rather than a silent discard.
func flushFile(ctx context.Context, proc protocol.Processor, filePath string, cfg *config.RelayConfig) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open cache file for flushing: %w", err)
	}
	defer f.Close()

	var (
		sawAccept  bool // first AcceptMessage seen; later ones are sub-commands
		expectAck  bool // this session is an I/O session, so it will be acknowledged
		sentExit   bool // an ExitMessage was replayed, so a final commit is due
		incomplete bool // cache file was truncated; no Exit will ever be sent
	)

	for {
		msg, readErr := readProtoMessage(f)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			// Truncated tail (e.g. crash mid-write). Everything we could parse has
			// been sent; there is no Exit and therefore no commit point coming.
			// Stop here rather than looping forever on corrupt trailing bytes.
			slog.Warn("Cache file has truncated trailing record; flushing what was read",
				"path", filePath, "error", readErr)
			incomplete = true
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading message from cache during flush: %w", readErr)
		}

		if err := withOperationTimeout(ctx, cfg, func(opCtx context.Context) error {
			return proc.WriteClientMessageContext(opCtx, msg)
		}); err != nil {
			return fmt.Errorf("failed to send flushed message to upstream: %w", err)
		}

		if accept := msg.GetAcceptMsg(); accept != nil {
			if !sawAccept {
				sawAccept = true
				expectAck = accept.GetExpectIobufs()
				if expectAck {
					// Only a new I/O session gets a log_id back. Reading
					// unconditionally here is what used to hang event-only and
					// sub-command accepts.
					if err := readUpstreamAck(ctx, proc, cfg, false); err != nil {
						return fmt.Errorf("did not get log_id response from upstream: %w", err)
					}
				}
			}
			continue
		}
		if msg.GetExitMsg() != nil {
			sentExit = true
		}
	}

	if expectAck && sentExit {
		// The durability barrier. Read past any periodic commit points the
		// upstream emitted during the replay until the session is acknowledged.
		if err := readUpstreamAck(ctx, proc, cfg, true); err != nil {
			return fmt.Errorf("upstream did not acknowledge the session; keeping cache file: %w", err)
		}
	} else if incomplete {
		slog.Warn("Retiring a truncated cache file without upstream acknowledgement; "+
			"the partial session was sent but cannot be confirmed",
			"path", filePath)
	}

	retireCacheFile(filePath)
	return nil
}

// readUpstreamAck reads ServerMessages until the upstream acknowledges.
//
// When waitCommit is false it consumes exactly one message (the log_id reply to
// an accept). When true it keeps reading until a commit_point arrives, skipping
// anything else — the upstream may have emitted periodic commit points during
// the replay that are still queued ahead of the final one.
//
// An EOF reached here is a FAILURE, never an acknowledgement. It is true that C
// closes the connection once the final commit point has been written
// (logsrvd/logsrvd.c:1110-1116), but that only makes a close meaningful when a
// commit point preceded it — and this function returns as soon as one arrives,
// so any EOF observed here arrived without one. C draws the same line: a
// zero-length read while the closure is not yet FINISHED is "premature EOF from
// <relay>" and becomes an error (logsrvd/logsrvd_relay.c:869-888, and the
// SSL_ERROR_ZERO_RETURN twin at 995-1010); the journal is unlinked only at
// FINISHED (logsrvd/logsrvd.c:296-305), which for an I/O session means after the
// final commit point (logsrvd/logsrvd.c:1315-1316).
//
// Do not reinstate EOF-as-acknowledgement. An upstream killed (SIGKILL, OOM,
// restart) after draining our replay into userspace but before persisting it
// sends FIN, not RST — a clean EOF, byte-identical to a polite close. Accepting
// it retires the cache file, which is the only remaining copy, so the session
// ends up in no log server anywhere with no retry scheduled: silent audit loss.
//
// Event-only sessions are unaffected: they are never acknowledged at all, so
// flushFile does not call this function for them.
//
// An error or abort from the upstream is always a failure.
func readUpstreamAck(ctx context.Context, proc protocol.Processor, cfg *config.RelayConfig, waitCommit bool) error {
	for {
		var srvMsg *pb.ServerMessage
		err := withOperationTimeout(ctx, cfg, func(opCtx context.Context) error {
			var readErr error
			srvMsg, readErr = proc.ReadServerMessageContext(opCtx)
			return readErr
		})
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("upstream closed the connection before acknowledging the session: %w", err)
		}
		if err != nil {
			return err
		}

		switch m := srvMsg.Type.(type) {
		case *pb.ServerMessage_Error:
			return fmt.Errorf("upstream rejected the session: %s", m.Error)
		case *pb.ServerMessage_Abort:
			return fmt.Errorf("upstream aborted the session: %s", m.Abort)
		case *pb.ServerMessage_CommitPoint:
			return nil
		}
		if !waitCommit {
			return nil
		}
	}
}

func connectToUpstream(ctx context.Context, cfg *config.RelayConfig) (protocol.Processor, error) {
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout}
	var conn net.Conn
	var err error

	slog.Debug("Dialing upstream", "host", cfg.UpstreamHost, "use_tls", cfg.UseTLS, "tls_skip_verify", cfg.TLSSkipVerify)
	if cfg.UseTLS {
		minVer, verErr := config.TLSVersion(cfg.TLSMinVersion)
		if verErr != nil {
			return nil, fmt.Errorf("invalid relay tls_min_version: %w", verErr)
		}
		// InsecureSkipVerify tracks tls_skip_verify, which defaults to false —
		// so by default the upstream's chain AND hostname are verified. That is
		// deliberately stricter than C, whose relay does not verify at all
		// unless tls_checkpeer is turned on (logsrvd/tls_client.c:251-256, and
		// the default chain at logsrvd/logsrvd_conf.c:341-346,1688). See the
		// TLSSkipVerify doc comment in internal/config for the trade-off.
		// Conformance: docs/logsrvd-reference/ TLS-027.
		tlsConfig := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify, MinVersion: minVer}

		// Present a client certificate when one is configured, so an upstream
		// running with tls_checkpeer accepts us. Without this, such an upstream
		// rejects every flush at the handshake and the cache grows without bound
		// -- the failure is silent from the client's side, because relaying is
		// store-and-forward and the session was already acknowledged downstream.
		//
		// These fields are already resolved against the [server] section at config
		// load (per key, matching C's TLS_RELAY_STR), so reading them directly here
		// is correct. Conformance: docs/logsrvd-reference/ TLS-025, CONF-045.
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			cert, certErr := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if certErr != nil {
				return nil, fmt.Errorf("load relay client certificate: %w", certErr)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		// A named CA bundle replaces the platform trust store for the upstream
		// only, which is how a private-CA upstream is trusted without installing
		// its root system-wide. An unreadable or empty bundle is fatal rather than
		// a silent fall back to the system store: a typo'd path would otherwise
		// trust the public web PKI instead of the one CA that was meant.
		// Conformance: docs/logsrvd-reference/ TLS-007.
		if cfg.TLSCACertFile != "" {
			pem, readErr := os.ReadFile(cfg.TLSCACertFile)
			if readErr != nil {
				return nil, fmt.Errorf("read relay CA bundle %s: %w", cfg.TLSCACertFile, readErr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("relay CA bundle %s contains no usable PEM certificates", cfg.TLSCACertFile)
			}
			tlsConfig.RootCAs = pool
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
	slog.Debug("Starting handshake with upstream")
	helloMsg := &pb.ClientMessage{Type: &pb.ClientMessage_HelloMsg{HelloMsg: &pb.ClientHello{ClientId: "GoSudoLogSrv-Relay/1.0"}}}
	if err := withOperationTimeout(ctx, cfg, func(opCtx context.Context) error {
		return proc.WriteClientMessageContext(opCtx, helloMsg)
	}); err != nil {
		_ = proc.Close()
		return nil, fmt.Errorf("failed to send ClientHello to upstream: %w", err)
	}
	if err := withOperationTimeout(ctx, cfg, func(opCtx context.Context) error {
		_, err = proc.ReadServerMessageContext(opCtx)
		return err
	}); err != nil {
		_ = proc.Close()
		return nil, fmt.Errorf("failed to receive ServerHello from upstream: %w", err)
	}
	return proc, nil
}

// operationTimeout bounds a single message exchange with an upstream that is
// already connected. It is relay.response_timeout (C's [relay] timeout, default
// 30s, logsrvd/logsrvd_conf.c:827-841,1639), NOT relay.connect_timeout.
//
// Do not fold these two back together. connect_timeout defaults to 5s because it
// bounds a dial; using it here meant an upstream that took longer than 5s to
// fsync a session and send its final commit_point failed the flush. The cache
// file is deliberately kept on a failed flush, so the whole session was replayed
// on the next attempt and the upstream stored the same transcript twice under two
// different log IDs — duplicate audit records, growing with every retry, on
// exactly the loaded upstreams that are slowest to acknowledge.
// Conformance: docs/logsrvd-reference/ CONF-039.
func operationTimeout(cfg *config.RelayConfig) time.Duration {
	if cfg.ResponseTimeout > 0 {
		return cfg.ResponseTimeout
	}
	return 30 * time.Second
}

func withOperationTimeout(parent context.Context, cfg *config.RelayConfig, fn func(context.Context) error) error {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, operationTimeout(cfg))
	defer cancel()
	return fn(ctx)
}

// writeProtoMessage serializes and writes a single protobuf message with its length prefix.
// Length prefix and payload are combined into a single write for atomicity — a partial
// write (e.g., process crash) won't leave a length prefix without a payload.
func writeProtoMessage(w io.Writer, msg *pb.ClientMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxMessageSize {
		return fmt.Errorf("message too large: length %d exceeds limit of %d", len(data), protocol.MaxMessageSize)
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

// readProtoMessage reads a single length-prefixed protobuf message.
func readProtoMessage(r io.Reader) (*pb.ClientMessage, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	msgLen := binary.BigEndian.Uint32(lenBuf)
	if msgLen > protocol.MaxMessageSize {
		return nil, fmt.Errorf("relay cache message size %d exceeds limit of %d", msgLen, protocol.MaxMessageSize)
	}
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
