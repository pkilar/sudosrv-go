// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/sink.go
package logshell

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sudosrv/internal/logsrvclient"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Sink is where a session's messages go. Two implementations exist and the
// choice between them is what makes fail-closed a narrow condition rather than a
// fleet-wide outage switch.
type Sink interface {
	// Start delivers the AcceptMessage and returns the server's log id, which is
	// empty for a sink that has not spoken to a server yet.
	Start(ctx context.Context, accept *pb.ClientMessage) (string, error)
	// Send delivers one session message.
	Send(*pb.ClientMessage) error
	// Finish is called once the ExitMessage has been sent. It blocks until the
	// session is durable, or until it is certain it cannot be made durable.
	Finish(ctx context.Context) error
	Close() error
}

// JournalPrefix and the suffixes below name logsh's spool files. They are
// deliberately distinct from internal/relay's, which has its own directory,
// its own recovery pass, and its own idea of what each suffix means -- pointing
// the two at one directory would have each retiring the other's files.
const (
	JournalPrefix      = "logsh-"
	JournalSuffix      = ".journal"
	journalFlushing    = ".flushing"
	journalUndelivered = ".undelivered"
)

// OpenSink chooses how this session will be recorded.
//
//	journal_directory usable?  -> journal, forward when the session ends
//	otherwise, server reachable? -> stream live
//	neither                     -> ErrRecordingUnavailable
//
// Journalling FIRST when a spool is configured is deliberate. It keeps the
// network out of the keystroke path entirely, so a slow or distant log server
// cannot stall the user's terminal, and it means a server outage costs nothing
// at all -- the session records normally and is delivered afterwards. Streaming
// is the path for hosts with no writable spool, typically because they sit
// beside a local sudosrv relay on loopback that owns the spool as root.
//
// Fail-closed is reached only when BOTH are impossible. That narrowness is the
// point: were it triggered by an unreachable server alone, a network blip would
// lock every recorded account out of an entire fleet at once.
func OpenSink(ctx context.Context, cfg *Config) (Sink, error) {
	var journalErr, streamErr error

	if dir := cfg.Server.JournalDirectory; dir != "" {
		s, err := newJournalSink(dir, cfg)
		if err == nil {
			return newBufferedSink(s), nil
		}
		journalErr = err
		slog.Warn("logsh journal unavailable, trying the log server directly", "dir", dir, "error", err)
	}

	proc, err := logsrvclient.Connect(ctx, cfg.ClientConfig())
	if err == nil {
		return newBufferedSink(&streamSink{proc: proc, cfg: cfg.ClientConfig()}), nil
	}
	streamErr = err

	if journalErr != nil {
		return nil, fmt.Errorf("journal unusable (%w) and log server unreachable (%w)", journalErr, streamErr)
	}
	return nil, streamErr
}

// streamSink sends messages to the log server as they are produced.
type streamSink struct {
	proc protocol.Processor
	cfg  logsrvclient.Config
	// expectAck records whether this session will be acknowledged at all. An
	// I/O session gets a log id and, at the end, a commit point. An event-only
	// session gets NEITHER: the server's EventSession returns no ServerMessage
	// for either message. Reading for a reply that is never coming would hang
	// the session forever -- for logsh that means every scp and rsync on the
	// host.
	expectAck bool
}

func (s *streamSink) Start(ctx context.Context, accept *pb.ClientMessage) (string, error) {
	s.expectAck = accept.GetAcceptMsg().GetExpectIobufs()

	if err := s.cfg.WithTimeout(ctx, func(c context.Context) error {
		return s.proc.WriteClientMessageContext(c, accept)
	}); err != nil {
		return "", fmt.Errorf("send AcceptMessage: %w", err)
	}
	if !s.expectAck {
		return "", nil
	}

	var logID string
	err := s.cfg.WithTimeout(ctx, func(c context.Context) error {
		srv, readErr := s.proc.ReadServerMessageContext(c)
		if readErr != nil {
			return readErr
		}
		switch m := srv.Type.(type) {
		case *pb.ServerMessage_LogId:
			logID = m.LogId
			return nil
		case *pb.ServerMessage_Error:
			return fmt.Errorf("%w: %s", logsrvclient.ErrUpstreamRejected, m.Error)
		case *pb.ServerMessage_Abort:
			return fmt.Errorf("%w (abort): %s", logsrvclient.ErrUpstreamRejected, m.Abort)
		default:
			return fmt.Errorf("expected a log_id, got %T", srv.Type)
		}
	})
	if err != nil {
		return "", fmt.Errorf("AcceptMessage was not acknowledged: %w", err)
	}
	return logID, nil
}

func (s *streamSink) Send(msg *pb.ClientMessage) error { return s.proc.WriteClientMessage(msg) }

// Finish waits for the server's final commit point, which is its statement that
// the transcript is durable. Returning before it would let logsh exit -- and
// sshd tear the connection down -- while the session was still only in the
// server's memory.
func (s *streamSink) Finish(ctx context.Context) error {
	if !s.expectAck {
		// Transmission IS completion for an event-only session. See expectAck.
		return nil
	}
	return logsrvclient.ReadAck(ctx, s.proc, s.cfg, true)
}

func (s *streamSink) Close() error { return s.proc.Close() }

// journalSink writes the session to a local file in wire framing and forwards it
// when the session ends.
type journalSink struct {
	path string
	file *os.File
	cfg  *Config
}

func newJournalSink(dir string, cfg *Config) (*journalSink, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create journal directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, JournalPrefix+uuid.NewString()+JournalSuffix)

	// 0600: a journal is a verbatim transcript of a privileged session, so it
	// must not be readable by other users even while it sits in a shared spool.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- path is built from a fresh UUID under a configured directory
	if err != nil {
		return nil, fmt.Errorf("create journal %s: %w", path, err)
	}
	return &journalSink{path: path, file: f, cfg: cfg}, nil
}

// Start writes the AcceptMessage as the journal's first record. No log id exists
// yet: the server assigns one when the journal is finally delivered, and nothing
// in the session needs it before then.
func (j *journalSink) Start(_ context.Context, accept *pb.ClientMessage) (string, error) {
	return "", logsrvclient.WriteMessage(j.file, accept)
}

func (j *journalSink) Send(msg *pb.ClientMessage) error {
	return logsrvclient.WriteMessage(j.file, msg)
}

// Finish flushes the completed journal to the log server.
//
// The retries are bounded and happen while the user is logging out, where a few
// seconds of delay is tolerable and an unbounded wait is not. A journal that
// still cannot be delivered is renamed rather than deleted: it is the only copy
// of that session, and losing it silently is the one outcome worse than
// delivering it late.
func (j *journalSink) Finish(ctx context.Context) error {
	if err := j.file.Sync(); err != nil {
		return fmt.Errorf("sync journal %s: %w", j.path, err)
	}
	if err := j.file.Close(); err != nil {
		return fmt.Errorf("close journal %s: %w", j.path, err)
	}
	j.file = nil

	err := flushWithBudget(ctx, j.path, j.cfg, journalRetryBudget)
	if err == nil {
		return nil
	}

	dead := j.path + journalUndelivered
	if rnErr := os.Rename(j.path, dead); rnErr != nil {
		return fmt.Errorf("journal %s could not be delivered (%w) and could not be parked (%w)", j.path, err, rnErr)
	}
	return fmt.Errorf("session recorded to %s but not delivered: %w", dead, err)
}

func (j *journalSink) Close() error {
	if j.file == nil {
		return nil
	}
	return j.file.Close()
}

// FlushJournal replays one journal file to the log server and removes it once
// the server has confirmed the session is durable.
//
// It is exported so a sweeper -- a systemd timer, or an operator by hand -- can
// drain journals left behind by a session whose flush did not succeed. logsh
// itself deliberately does NOT sweep at login: a login shell that scanned a
// spool before handing over would add the cost of every undelivered session in
// the directory to somebody's ssh latency.
func FlushJournal(ctx context.Context, path string, cfg *Config) error {
	flushing := path + journalFlushing
	if err := os.Rename(path, flushing); err != nil {
		return fmt.Errorf("claim journal %s: %w", path, err)
	}

	if err := replayJournal(ctx, flushing, cfg); err != nil {
		// Put the name back so the next attempt can find it.
		if rnErr := os.Rename(flushing, path); rnErr != nil {
			return fmt.Errorf("replay failed (%w) and the journal could not be un-claimed (%w)", err, rnErr)
		}
		return err
	}

	if err := os.Remove(flushing); err != nil {
		// Delivered but not removable. Renaming it out of the way is essential:
		// left as-is it would be replayed again on the next sweep and the server
		// would store the same session twice under two log ids.
		_ = os.Rename(flushing, path+".delivered")
	}
	return nil
}

func replayJournal(ctx context.Context, path string, cfg *Config) error {
	f, err := os.Open(path) // #nosec G304 -- caller-supplied spool path, root-configured
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	proc, err := logsrvclient.Connect(ctx, cfg.ClientConfig())
	if err != nil {
		return err
	}
	defer func() { _ = proc.Close() }()

	// A journal is self-describing on purpose: a sweeper replaying one hours
	// later has no other way to know whether the session it holds will ever be
	// acknowledged.
	expectAck, sawExit, first := false, false, true
	for {
		msg, readErr := logsrvclient.ReadMessage(f)
		if readErr != nil {
			break // EOF, or a truncated tail; either way there is no more to send
		}
		if first {
			if a, ok := msg.Type.(*pb.ClientMessage_AcceptMsg); ok {
				expectAck = a.AcceptMsg.GetExpectIobufs()
			}
			first = false
		}
		if _, ok := msg.Type.(*pb.ClientMessage_ExitMsg); ok {
			sawExit = true
		}
		if err := cfg.ClientConfig().WithTimeout(ctx, func(c context.Context) error {
			return proc.WriteClientMessageContext(c, msg)
		}); err != nil {
			return err
		}
	}

	// Only an I/O session that reached its ExitMessage is ever acknowledged.
	// Waiting for a commit point that is not coming would hang the logout.
	if !expectAck {
		return nil
	}
	if !sawExit {
		return errors.New("journal has no ExitMessage; it cannot be acknowledged")
	}
	return logsrvclient.ReadAck(ctx, proc, cfg.ClientConfig(), true)
}

// bufferedSink moves the actual delivery onto its own goroutine.
//
// Without it the relay loop performs a network write for every buffer of
// terminal output, putting a round trip between the shell producing a character
// and the user seeing it. With it the relay hands the message over and returns.
//
// A full buffer BLOCKS rather than dropping. Dropping would silently punch holes
// in an audit record, which is the failure this whole program exists to prevent;
// blocking degrades the terminal instead, visibly, and only once 1024 messages
// are already outstanding. internal/relay makes the same trade for the same
// reason.
type bufferedSink struct {
	inner Sink
	ch    chan *pb.ClientMessage
	wg    sync.WaitGroup

	mu      sync.Mutex
	sendErr error
	closed  bool
}

const sinkBufferDepth = 1024

func newBufferedSink(inner Sink) *bufferedSink {
	b := &bufferedSink{inner: inner, ch: make(chan *pb.ClientMessage, sinkBufferDepth)}
	b.wg.Add(1)
	go b.run()
	return b
}

func (b *bufferedSink) run() {
	defer b.wg.Done()
	for msg := range b.ch {
		if err := b.inner.Send(msg); err != nil {
			b.mu.Lock()
			if b.sendErr == nil {
				b.sendErr = err
			}
			b.mu.Unlock()
		}
	}
}

func (b *bufferedSink) Start(ctx context.Context, accept *pb.ClientMessage) (string, error) {
	// The accept goes synchronously: its log id is the session's identity and the
	// caller cannot proceed without knowing the server took the session.
	return b.inner.Start(ctx, accept)
}

func (b *bufferedSink) Send(msg *pb.ClientMessage) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("sink is closed")
	}
	err := b.sendErr
	b.mu.Unlock()
	if err != nil {
		return err
	}
	b.ch <- msg
	return nil
}

// Finish drains everything queued before asking the inner sink to make the
// session durable. Skipping the drain would ask the server to commit a
// transcript whose last buffers are still sitting in this channel.
func (b *bufferedSink) Finish(ctx context.Context) error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.ch)
	}
	b.mu.Unlock()
	b.wg.Wait()

	b.mu.Lock()
	sendErr := b.sendErr
	b.mu.Unlock()
	if sendErr != nil {
		return sendErr
	}
	return b.inner.Finish(ctx)
}

func (b *bufferedSink) Close() error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.ch)
	}
	b.mu.Unlock()
	b.wg.Wait()
	return b.inner.Close()
}

// journalRetryBudget bounds how long Finish spends trying to deliver a journal
// while the user waits to log out. A variable, not a constant, so tests can
// shorten it.
var journalRetryBudget = 10 * time.Second

// flushWithBudget retries a flush with backoff until the budget is spent.
//
// The budget exists because this runs during logout, with the user watching. An
// unbounded retry would hang their session on an outage; giving up too early
// would park a journal that one more second would have delivered. When it does
// give up the journal is kept, so the cost of stopping is delay, never loss.
func flushWithBudget(ctx context.Context, path string, cfg *Config, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	var err error
	for attempt := 0; ; attempt++ {
		if err = FlushJournal(ctx, path, cfg); err == nil {
			return nil
		}
		if errors.Is(err, logsrvclient.ErrUpstreamRejected) {
			// The server parsed this session and refused it. Every retry gets the
			// same answer, so spending the rest of the budget on it only delays
			// the logout. Conformance: the same reasoning as RELAY-049.
			return err
		}
		wait := logsrvclient.Backoff(attempt, time.Second)
		if time.Now().Add(wait).After(deadline) {
			return err
		}
		if sleepErr := logsrvclient.Sleep(ctx, wait); sleepErr != nil {
			return err
		}
	}
}
