// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/sink_test.go
package logshell

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/logsrvclient"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// deadAddr returns an address nothing is listening on: bind one and release it.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// acceptFor builds a plausible AcceptMessage for tests that need a journal to
// have a valid first record.
func acceptFor(t *testing.T) *pb.ClientMessage {
	t.Helper()
	meta := CollectMeta("/dev/pts/99", WinSize{Rows: 24, Cols: 80}, "/bin/sh", []string{"-sh"})
	return &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   timeSpec(time.Now()),
		InfoMsgs:     meta.InfoMessages(),
		ExpectIobufs: true,
	}}}
}

func journalFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestJournalledSessionSurvivesAServerOutage is the property the whole failure
// policy turns on.
//
// With a spool available, an unreachable log server must NOT fail the session.
// If it did, one network blip would lock every recorded account out of an entire
// fleet at the same moment -- which is exactly the outcome fail-closed is
// supposed to be narrow enough to avoid. The session records to disk, the user's
// shell runs and exits normally, and the undelivered transcript is PARKED rather
// than discarded, because it is the only copy in existence.
func TestJournalledSessionSurvivesAServerOutage(t *testing.T) {
	old := journalRetryBudget
	journalRetryBudget = 200 * time.Millisecond
	t.Cleanup(func() { journalRetryBudget = old })

	_, slave := outerTerminal(t)
	spool := t.TempDir()

	cfg := DefaultConfig()
	cfg.Server.UpstreamHost = deadAddr(t)
	cfg.Server.UseTLS = false
	cfg.Server.ConnectTimeout = 200 * time.Millisecond
	cfg.Server.JournalDirectory = spool

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", Args: []string{"-c", "printf 'WORK-GOT-DONE\\n'; exit 3"}}

	outcome, err := RunRecorded(context.Background(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil)

	// The shell must have run to completion with its real exit status.
	if outcome.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3; the outage was allowed to break the session", outcome.ExitCode)
	}
	if !strings.Contains(userSaw.String(), "WORK-GOT-DONE") {
		t.Errorf("the user's terminal missed the shell's output: %q", userSaw.String())
	}
	// The delivery failure is reported, but NOT as ErrRecordingUnavailable:
	// recording did start, so the caller must not treat this as a refusable
	// session.
	if err == nil {
		t.Error("the undelivered session was reported as a success")
	}
	if errors.Is(err, ErrRecordingUnavailable) {
		t.Error("an undeliverable journal was reported as ErrRecordingUnavailable; the caller " +
			"would apply fail-closed to a shell that has already run")
	}

	files := journalFiles(t, spool)
	if len(files) != 1 || !strings.HasSuffix(files[0], journalUndelivered) {
		t.Fatalf("spool contains %v, want exactly one %s file", files, journalUndelivered)
	}

	// The parked journal must actually contain the session, not be an empty
	// husk: it is the only remaining record of what happened.
	body, readErr := os.ReadFile(filepath.Join(spool, files[0]))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(body, []byte("WORK-GOT-DONE")) {
		t.Error("the parked journal does not contain the session transcript")
	}
}

// TestJournalledSessionIsDeliveredAndRemoved covers the normal path: spool the
// session, forward it at logout, leave nothing behind.
func TestJournalledSessionIsDeliveredAndRemoved(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)
	spool := t.TempDir()

	cfg := testConfig(srv.addr)
	cfg.Server.JournalDirectory = spool

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", Args: []string{"-c", "printf 'SPOOLED\\n'"}}
	if _, err := RunRecorded(context.Background(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	out, _, _, exit, acc := srv.snapshot()
	if !strings.Contains(out, "SPOOLED") {
		t.Errorf("the replayed transcript = %q, want the shell's output", out)
	}
	if acc == nil {
		t.Error("the AcceptMessage was not replayed; the server has no session metadata")
	}
	if exit == nil {
		t.Error("the ExitMessage was not replayed; the server never sees the session end")
	}

	// A delivered journal must be gone. Left behind, the next sweep would replay
	// it and the server would store the same session twice under two log ids.
	if files := journalFiles(t, spool); len(files) != 0 {
		t.Errorf("spool still contains %v after a successful delivery", files)
	}
}

// TestStreamingFallbackWhenSpoolIsUnusable checks the middle branch: a
// configured but unwritable spool must fall back to the server rather than
// refusing, since the server is right there.
func TestStreamingFallbackWhenSpoolIsUnusable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, which bypasses directory permissions")
	}
	srv := newMockServer(t)
	_, slave := outerTerminal(t)

	locked := filepath.Join(t.TempDir(), "nowrite")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(srv.addr)
	cfg.Server.JournalDirectory = filepath.Join(locked, "spool")

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", Args: []string{"-c", "printf 'STREAMED\\n'"}}
	if _, err := RunRecorded(context.Background(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("an unwritable spool should fall back to the server, got: %v", err)
	}

	if out, _, _, _, _ := srv.snapshot(); !strings.Contains(out, "STREAMED") {
		t.Errorf("transcript = %q, want the session streamed straight to the server", out)
	}
}

// TestFailClosedRequiresBothPathsToFail pins the narrowness of the fail-closed
// condition. Only when the spool is unusable AND the server is unreachable may a
// session be refused.
func TestFailClosedRequiresBothPathsToFail(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root, which bypasses directory permissions")
	}
	_, slave := outerTerminal(t)

	locked := filepath.Join(t.TempDir(), "nowrite")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Server.UpstreamHost = deadAddr(t)
	cfg.Server.UseTLS = false
	cfg.Server.ConnectTimeout = 200 * time.Millisecond
	cfg.Server.JournalDirectory = filepath.Join(locked, "spool")

	var userSaw bytes.Buffer
	_, err := RunRecorded(context.Background(), cfg,
		Invocation{Name: "lsh", Args: []string{"-c", "true"}}, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil)
	if err == nil {
		t.Fatal("a session with no spool and no server was recorded successfully")
	}
	if !errors.Is(err, ErrRecordingUnavailable) {
		t.Errorf("error = %v, want ErrRecordingUnavailable so fail-closed applies", err)
	}
	// Both causes must be named. An operator seeing only "connection refused"
	// would spend the outage debugging the network while the real problem was a
	// spool directory they could have fixed locally.
	if !strings.Contains(err.Error(), "journal") {
		t.Errorf("error = %q, want it to mention the journal failure too", err)
	}
}

// TestBufferedSinkDeliversEverythingBeforeFinish guards against the buffered
// writer silently truncating a transcript. Finish must drain the queue before
// handing off to the inner sink, or the last buffers of every session -- the
// part saying what the user actually did last -- go missing.
//
// It runs against a JOURNAL sink on purpose. Against a streaming sink the same
// bug merely races: Finish blocks reading the commit point, which gives the
// writer goroutine all the time it needs, so the test passes whether the drain
// is there or not. Against a journal, Finish closes the file, and every message
// still queued behind it is written to a closed descriptor and lost. Verified to
// fail when the drain is removed.
func TestBufferedSinkDeliversEverythingBeforeFinish(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)
	cfg.Server.JournalDirectory = t.TempDir()

	rec, err := StartRecorder(context.Background(), cfg,
		CollectMeta("/dev/pts/99", WinSize{Rows: 24, Cols: 80}, "/bin/sh", []string{"-sh"}))
	if err != nil {
		t.Fatalf("StartRecorder: %v", err)
	}
	defer func() { _ = rec.Close() }()

	var want bytes.Buffer
	for i := range 500 {
		chunk := []byte(strings.Repeat("x", 64) + "\n")
		if i == 499 {
			chunk = []byte("FINAL-BYTES\n")
		}
		want.Write(chunk)
		if err := rec.TTYOut(chunk); err != nil {
			t.Fatalf("TTYOut %d: %v", i, err)
		}
	}
	if err := rec.Exit(context.Background(), 0, "", false); err != nil {
		t.Fatalf("Exit: %v", err)
	}

	out, _, _, exit, _ := srv.snapshot()
	if exit == nil {
		t.Fatal("no ExitMessage reached the server")
	}
	if out != want.String() {
		t.Errorf("server received %d bytes, want %d; the buffer dropped or reordered data",
			len(out), want.Len())
	}
	if !strings.HasSuffix(out, "FINAL-BYTES\n") {
		t.Error("the last buffer written before Exit did not reach the server")
	}
}

// TestFlushJournalRefusesAJournalWithNoExit pins the one case that must never
// block: an I/O session is acknowledged only after its ExitMessage, so replaying
// a truncated journal and waiting for a commit point would hang forever.
func TestFlushJournalRefusesAJournalWithNoExit(t *testing.T) {
	srv := newMockServer(t)
	spool := t.TempDir()
	cfg := testConfig(srv.addr)

	sink, err := newJournalSink(spool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Start(context.Background(), acceptFor(t)); err != nil {
		t.Fatal(err)
	}
	path := sink.path
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- FlushJournal(context.Background(), path, cfg) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a journal with no ExitMessage was reported as delivered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FlushJournal hung waiting for a commit point that was never coming")
	}
}

// slowSink is an inner Sink that consumes deliberately slowly, so a producer
// running at full speed fills the buffered queue and has to wait.
type slowSink struct {
	mu    sync.Mutex
	count int
	delay time.Duration
}

func (s *slowSink) Start(context.Context, *pb.ClientMessage) (string, error) { return "slow", nil }
func (s *slowSink) Send(*pb.ClientMessage) error {
	time.Sleep(s.delay)
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
	return nil
}
func (s *slowSink) Finish(context.Context) error { return nil }
func (s *slowSink) Close() error                 { return nil }

func (s *slowSink) seen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// TestBufferedSinkBlocksRatherThanDropping is the backpressure test.
//
// When the queue fills, Send must WAIT. Dropping would punch silent holes in an
// audit record -- the transcript would still look complete, just missing
// whatever happened while the server was slow, which is exactly when something
// interesting is usually happening.
//
// The producer here outruns the consumer by design, so the 1024-deep queue is
// guaranteed to fill. Verified to fail when Send is changed to a non-blocking
// select with a default branch.
func TestBufferedSinkBlocksRatherThanDropping(t *testing.T) {
	inner := &slowSink{delay: 20 * time.Microsecond}
	b := newBufferedSink(inner)

	const total = sinkBufferDepth * 3
	for range total {
		if err := b.Send(&pb.ClientMessage{}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if err := b.Finish(context.Background()); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	if got := inner.seen(); got != total {
		t.Errorf("the inner sink saw %d of %d messages; %d were dropped when the queue filled",
			got, total, total-got)
	}
}

// writeJournal builds a spool file from raw frames and returns its path.
func writeJournal(t *testing.T, dir string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, JournalPrefix+"test"+JournalSuffix)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// framed renders messages in the on-disk wire framing.
func framed(t *testing.T, msgs ...*pb.ClientMessage) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, m := range msgs {
		if err := logsrvclient.WriteMessage(&buf, m); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func exitMsg() *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{}}}
}

// TestCorruptJournalIsKeptNotDeleted is the one that used to destroy evidence.
//
// Every ReadMessage error was treated as a clean end of file. A malformed FIRST
// record therefore left expectAck false, the replay reported success, and the
// caller deleted the journal -- so a corrupt spool file was reported as
// delivered and removed having sent nothing at all.
func TestCorruptJournalIsKeptNotDeleted(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)
	dir := t.TempDir()

	// A plausible length prefix followed by bytes that are not a protobuf.
	path := writeJournal(t, dir, []byte{0, 0, 0, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	err := FlushJournal(context.Background(), path, cfg)
	if err == nil {
		t.Fatal("a corrupt journal was reported as delivered")
	}
	if !errors.Is(err, ErrJournalCorrupt) {
		t.Errorf("error = %v, want ErrJournalCorrupt", err)
	}
	if _, statErr := os.Stat(path + journalCorrupt); statErr != nil {
		t.Errorf("the corrupt journal was not parked: %v; spool holds %v",
			statErr, journalFiles(t, dir))
	}
	// Nothing may have been sent: the journal is parsed before anything opens a
	// connection, so a corrupt one never half-lands on the server.
	if _, _, _, _, acc := srv.snapshot(); acc != nil {
		t.Error("a corrupt journal was partially transmitted before being rejected")
	}
}

// TestTruncatedJournalIsKeptNotDeleted covers the other corruption shape: a
// record cut in half by a crash mid-write.
func TestTruncatedJournalIsKeptNotDeleted(t *testing.T) {
	cfg := testConfig(newMockServer(t).addr)
	dir := t.TempDir()

	full := framed(t, acceptFor(t), exitMsg())
	path := writeJournal(t, dir, full[:len(full)-5]) // chop the tail

	err := FlushJournal(context.Background(), path, cfg)
	if !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("error = %v, want ErrJournalCorrupt for a truncated journal", err)
	}
	if _, statErr := os.Stat(path + journalCorrupt); statErr != nil {
		t.Errorf("the truncated journal was not kept: %v", statErr)
	}
}

// TestMetadataJournalWithoutAnAcceptIsRejected pins the first-record rule.
// Without it, a journal whose opening frame is anything else parses as
// event-only, reports success on transmission, and gets deleted.
func TestMetadataJournalWithoutAnAcceptIsRejected(t *testing.T) {
	cfg := testConfig(newMockServer(t).addr)
	dir := t.TempDir()
	path := writeJournal(t, dir, framed(t, exitMsg())) // no AcceptMessage at all

	err := FlushJournal(context.Background(), path, cfg)
	if !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("error = %v, want ErrJournalCorrupt for a journal with no AcceptMessage", err)
	}
	if _, statErr := os.Stat(path + journalCorrupt); statErr != nil {
		t.Errorf("the journal was deleted rather than kept: %v", statErr)
	}
}

// TestLostAcknowledgementDoesNotReplay is the duplicate-audit-record guard.
//
// If the server durably commits a session but its final acknowledgement is lost
// or times out, a retry would send the whole transcript again -- and the
// protocol carries no idempotency key, so the server stores it a second time
// under a different log id. The delivery is genuinely INDETERMINATE from here,
// and the only honest outcome is to park it for a human rather than guess.
func TestLostAcknowledgementDoesNotReplay(t *testing.T) {
	var accepts atomic.Int32

	// A server that takes the whole session and then goes silent, exactly as one
	// that committed and then lost its reply would look.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				proc := protocol.NewProcessorWithCloser(conn, conn, conn)
				for {
					msg, rerr := proc.ReadClientMessage()
					if rerr != nil {
						return
					}
					switch msg.Type.(type) {
					case *pb.ClientMessage_HelloMsg:
						_ = proc.WriteServerMessage(&pb.ServerMessage{
							Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{ServerId: "silent"}}})
					case *pb.ClientMessage_AcceptMsg:
						accepts.Add(1)
					case *pb.ClientMessage_ExitMsg:
						<-stop // committed, but the acknowledgement never arrives
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() { close(stop); _ = ln.Close(); wg.Wait() })

	cfg := testConfig(ln.Addr().String())
	cfg.Server.ResponseTimeout = 500 * time.Millisecond

	old := journalRetryBudget
	journalRetryBudget = 5 * time.Second // ample room for a retry, if one happened
	t.Cleanup(func() { journalRetryBudget = old })

	dir := t.TempDir()
	path := writeJournal(t, dir, framed(t, acceptFor(t), exitMsg()))

	err = flushWithBudget(context.Background(), path, cfg, journalRetryBudget)
	if err == nil {
		t.Fatal("a session that was never acknowledged was reported as delivered")
	}
	if !errors.Is(err, ErrJournalIndeterminate) {
		t.Errorf("error = %v, want ErrJournalIndeterminate", err)
	}
	if got := accepts.Load(); got != 1 {
		t.Errorf("the session was sent %d times; a lost acknowledgement must NOT be retried, "+
			"or the server stores the same transcript under two log ids", got)
	}
	if _, statErr := os.Stat(path + journalIndeterminate); statErr != nil {
		t.Errorf("the indeterminate journal was not parked for review: %v; spool holds %v",
			statErr, journalFiles(t, dir))
	}
}

// TestConnectFailureIsRetried keeps the classification honest in the other
// direction: a failure before anything is sent is safe to retry, and must not be
// parked as if it were ambiguous.
func TestConnectFailureIsRetried(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.UpstreamHost = deadAddr(t)
	cfg.Server.UseTLS = false
	cfg.Server.ConnectTimeout = 100 * time.Millisecond

	dir := t.TempDir()
	path := writeJournal(t, dir, framed(t, acceptFor(t), exitMsg()))

	err := flushWithBudget(context.Background(), path, cfg, 300*time.Millisecond)
	if err == nil {
		t.Fatal("flush succeeded with no server")
	}
	if errors.Is(err, ErrJournalIndeterminate) || errors.Is(err, ErrJournalCorrupt) {
		t.Errorf("a connect failure was classed as terminal (%v); nothing was sent, so it is "+
			"safe to try again", err)
	}
	// Still under its original name, ready for the next attempt.
	if _, statErr := os.Stat(path); statErr != nil {
		t.Errorf("the journal was not left in place for a retry: %v; spool holds %v",
			statErr, journalFiles(t, dir))
	}
}

// TestGarbageAfterAValidExitIsNotSilentlyDropped isolates the read-error
// classification.
//
// The other corruption tests are also caught by the empty-journal and
// missing-exit checks, so they would still fail if read errors were treated as a
// clean end of file. This one is not: the journal holds a complete, acknowledged
// I/O session followed by trailing garbage. Under the old behaviour the garbage
// was read as EOF, the session was delivered, and the file was DELETED -- taking
// with it whatever those bytes were, which is either a partially written record
// or evidence that something overwrote the spool.
func TestGarbageAfterAValidExitIsNotSilentlyDropped(t *testing.T) {
	cfg := testConfig(newMockServer(t).addr)
	dir := t.TempDir()

	body := framed(t, acceptFor(t), exitMsg())        // acceptFor sets expect_iobufs
	body = append(body, 0, 0, 0, 4, 0xff, 0xff, 0xff) // a length prefix and a short, invalid tail
	path := writeJournal(t, dir, body)

	err := FlushJournal(context.Background(), path, cfg)
	if err == nil {
		t.Fatal("a journal with a corrupt tail was reported as delivered and removed")
	}
	if !errors.Is(err, ErrJournalCorrupt) {
		t.Errorf("error = %v, want ErrJournalCorrupt", err)
	}
	if _, statErr := os.Stat(path + journalCorrupt); statErr != nil {
		t.Errorf("the journal was not kept: %v; spool holds %v", statErr, journalFiles(t, dir))
	}
}
