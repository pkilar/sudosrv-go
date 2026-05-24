// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/session.go
package relay

import (
	"context"
	"crypto/tls"
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
type Session struct {
	logID            string
	config           *config.RelayConfig
	initialAcceptMsg *pb.AcceptMessage
	fromClientChan   chan *pb.ClientMessage
	// sendMu serializes Close against in-flight HandleClientMessage calls.
	// HandleClientMessage holds RLock for its entire critical section
	// (closed check + channel send); Close takes the exclusive Lock so it
	// waits for every admitted send to commit to the channel before
	// flipping the closed flag and closing the channel. Without this,
	// a sender that passed the closed check could still write to a buffer
	// the writer goroutine has already abandoned, silently losing audit data.
	sendMu    sync.RWMutex
	closed    atomic.Bool // mutated under sendMu.Lock; read under sendMu.RLock
	wg        sync.WaitGroup
	closeOnce sync.Once
	cacheFileName   string
	mu              sync.Mutex               // Protects cumulativeDelay and lastCommitTime
	cumulativeDelay map[string]time.Duration // Tracks cumulative I/O delay per stream for commit points
	lastCommitTime  time.Time                // When last commit point was sent to client
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
func NewSession(ctx context.Context, sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.RelayConfig, onDone func()) (*Session, error) {
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
		cumulativeDelay:  make(map[string]time.Duration),
		ctx:              ctx,
		cancel:           cancel,
		onDone:           onDone,
	}
	s.phase.Store(&phaseWriting)

	s.wg.Add(1)
	go s.run() // Start the single, durable goroutine for this session.

	return s, nil
}

// run is the core goroutine for a session. It first writes all messages from the
// client to a local cache file. Once the session is complete (ExitMessage),
// it proceeds to persistently try to flush that file to the upstream server.
func (s *Session) run() {
	defer s.wg.Done()
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

	// Write the essential AcceptMessage first to ensure the cache file is valid for flushing.
	if err := writeProtoMessage(file, &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: s.initialAcceptMsg}}); err != nil {
		slog.Error("Failed to write initial accept message to cache", "log_id", s.logID, "error", err)
		return
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

	// Don't process the initial AcceptMsg again, it was handled in NewSession.
	if _, ok := msg.Type.(*pb.ClientMessage_AcceptMsg); ok {
		// For relay mode, we return a log ID immediately to satisfy the client
		return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: s.logID}}, nil
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

	// Generate local commit points for relay clients on I/O events,
	// throttled to commitPointInterval matching C sudo_logsrvd behavior.
	// Lock protects cumulativeDelay and lastCommitTime which are also
	// read by the run() goroutine's context (indirectly via Close/wg.Wait).
	if streamName, delay := extractIoDelay(msg); streamName != "" {
		s.mu.Lock()
		if delay != nil {
			delayDur := time.Duration(delay.TvSec)*time.Second + time.Duration(delay.TvNsec)*time.Nanosecond
			s.cumulativeDelay[streamName] += delayDur
		}
		if time.Since(s.lastCommitTime) >= commitPointInterval {
			s.lastCommitTime = time.Now()
			commitPoint := s.cumulativeDelay[streamName]
			s.mu.Unlock()
			return &pb.ServerMessage{Type: &pb.ServerMessage_CommitPoint{
				CommitPoint: &pb.TimeSpec{
					TvSec:  int64(commitPoint / time.Second),
					TvNsec: int32(commitPoint % time.Second),
				},
			}}, nil
		}
		s.mu.Unlock()
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
func RecoverOrphans(ctx context.Context, cfg *config.RelayConfig) error {
	slog.Info("Scanning for orphaned relay cache files", "directory", cfg.RelayCacheDirectory)

	// Restore any mid-flush files from a prior crash by renaming them back to *.log.
	flushingPattern := filepath.Join(cfg.RelayCacheDirectory, "*.log"+FlushingSuffix)
	flushingFiles, err := filepath.Glob(flushingPattern)
	if err != nil {
		return fmt.Errorf("failed to scan for in-flight relay files: %w", err)
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
		return fmt.Errorf("failed to scan relay cache directory: %w", err)
	}
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

func flushFile(ctx context.Context, proc protocol.Processor, filePath string, cfg *config.RelayConfig) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open cache file for flushing: %w", err)
	}
	defer f.Close()

	for {
		msg, err := readProtoMessage(f)
		if errors.Is(err, io.EOF) {
			// All messages sent successfully — retire the cache file.
			retireCacheFile(filePath)
			return nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// Truncated tail (e.g., crash mid-write). Treat as end-of-stream for
			// flush purposes so the file can be retired and recovery doesn't loop
			// forever on corrupt trailing bytes.
			slog.Warn("Cache file has truncated trailing record; flushing what was read",
				"path", filePath, "error", err)
			retireCacheFile(filePath)
			return nil
		}
		if err != nil {
			return fmt.Errorf("error reading message from cache during flush: %w", err)
		}

		if err := withOperationTimeout(ctx, cfg, func(opCtx context.Context) error {
			return proc.WriteClientMessageContext(opCtx, msg)
		}); err != nil {
			return fmt.Errorf("failed to send flushed message to upstream: %w", err)
		}

		if msg.GetAcceptMsg() != nil {
			if err := withOperationTimeout(ctx, cfg, func(opCtx context.Context) error {
				_, err := proc.ReadServerMessageContext(opCtx)
				return err
			}); err != nil {
				return fmt.Errorf("did not get log_id response from upstream: %w", err)
			}
		}
	}
}

func connectToUpstream(ctx context.Context, cfg *config.RelayConfig) (protocol.Processor, error) {
	dialer := &net.Dialer{Timeout: cfg.ConnectTimeout}
	var conn net.Conn
	var err error

	slog.Debug("Dialing upstream", "host", cfg.UpstreamHost, "use_tls", cfg.UseTLS, "tls_skip_verify", cfg.TLSSkipVerify)
	if cfg.UseTLS {
		tlsConfig := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify, MinVersion: tls.VersionTLS13}
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

func operationTimeout(cfg *config.RelayConfig) time.Duration {
	if cfg.ConnectTimeout > 0 {
		return cfg.ConnectTimeout
	}
	return 5 * time.Second
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
