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
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
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
