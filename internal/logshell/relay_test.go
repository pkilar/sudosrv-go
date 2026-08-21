// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/relay_test.go
package logshell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"testing"
	"time"
)

// ioRecord is one session message as the server saw it: which stream it was on,
// the delay it carried, and how many payload bytes came with it.
//
// The delay is kept PER RECORD on purpose. Summing the delay column, or merely
// counting records, is invariant under sliding every delay onto its neighbour --
// which is precisely the defect worth catching, because sudoreplay sleeps a
// record's delay BEFORE writing that record's bytes, so a one-record slide
// replays every burst of output one idle gap late.
type ioRecord struct {
	kind  string // "ttyout", "ttyin", "winsize", "suspend"
	delay time.Duration
	bytes int
}

// mockServer is a minimal sudo_logsrv server: enough of the protocol to accept a
// session from logsh and record what it was told.
type mockServer struct {
	addr string
	ln   net.Listener

	mu       sync.Mutex
	accept   *pb.AcceptMessage
	ttyout   bytes.Buffer
	ttyin    bytes.Buffer
	winsizes []*pb.ChangeWindowSize
	suspend  []string
	exit     *pb.ExitMessage
	io       []ioRecord

	done chan struct{}
}

// records returns every I/O message the server received, in order.
func (s *mockServer) records() []ioRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ioRecord(nil), s.io...)
}

// ofKind filters records down to one stream.
func ofKind(recs []ioRecord, kind string) []ioRecord {
	var out []ioRecord
	for _, r := range recs {
		if r.kind == kind {
			out = append(out, r)
		}
	}
	return out
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mockServer{addr: ln.Addr().String(), ln: ln, done: make(chan struct{})}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close(); <-s.done })
	return s
}

func (s *mockServer) serve() {
	defer close(s.done)
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	proc := protocol.NewProcessorWithCloser(conn, conn, conn)
	sentInterim := false

	for {
		msg, err := proc.ReadClientMessage()
		if err != nil {
			return
		}
		switch m := msg.Type.(type) {
		case *pb.ClientMessage_HelloMsg:
			_ = proc.WriteServerMessage(&pb.ServerMessage{
				Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{ServerId: "mock"}}})
		case *pb.ClientMessage_AcceptMsg:
			s.mu.Lock()
			s.accept = m.AcceptMsg
			s.mu.Unlock()
			if m.AcceptMsg.GetExpectIobufs() {
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "mock-log-id"}})
			}
		case *pb.ClientMessage_TtyoutBuf:
			s.mu.Lock()
			s.ttyout.Write(m.TtyoutBuf.GetData())
			s.io = append(s.io, ioRecord{"ttyout", messageDelay(msg), len(m.TtyoutBuf.GetData())})
			s.mu.Unlock()
			// The real server emits a commit point on the FIRST I/O event and
			// every ACK_FREQUENCY after (internal/storage writeIoEntry), so one
			// is very likely already queued when the client sends its exit. The
			// mock reproduces that: without it, nothing here would notice a
			// client that returns on the first commit point it sees.
			if !sentInterim {
				sentInterim = true
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{}}})
			}
		case *pb.ClientMessage_TtyinBuf:
			s.mu.Lock()
			s.ttyin.Write(m.TtyinBuf.GetData())
			s.io = append(s.io, ioRecord{"ttyin", messageDelay(msg), len(m.TtyinBuf.GetData())})
			s.mu.Unlock()
		case *pb.ClientMessage_WinsizeEvent:
			s.mu.Lock()
			s.winsizes = append(s.winsizes, m.WinsizeEvent)
			s.io = append(s.io, ioRecord{"winsize", messageDelay(msg), 0})
			s.mu.Unlock()
		case *pb.ClientMessage_SuspendEvent:
			s.mu.Lock()
			s.suspend = append(s.suspend, m.SuspendEvent.GetSignal())
			s.io = append(s.io, ioRecord{"suspend", messageDelay(msg), 0})
			s.mu.Unlock()
		case *pb.ClientMessage_ExitMsg:
			s.mu.Lock()
			s.exit = m.ExitMsg
			s.mu.Unlock()
			_ = proc.WriteServerMessage(&pb.ServerMessage{
				Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{
					TvSec: 1 << 20, // comfortably past any test session's elapsed clock
				}}})
			return
		}
	}
}

func (s *mockServer) suspends() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.suspend...)
}

// waitForExit blocks until the server has read the session's ExitMessage.
//
// Needed for event-only sessions specifically. Those are never acknowledged, so
// the client returns the moment the exit has been WRITTEN and cannot know when
// the server read it -- asserting on the server's state immediately after is a
// race the client has no way to close. An I/O session does not need this: its
// Finish waits for a commit point, which the server only sends after processing
// the exit.
func waitForExit(t *testing.T, s *mockServer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, _, exit, _ := s.snapshot(); exit != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("the server never received an ExitMessage")
}

func (s *mockServer) snapshot() (out, in string, ws []*pb.ChangeWindowSize, exit *pb.ExitMessage, acc *pb.AcceptMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ttyout.String(), s.ttyin.String(), s.winsizes, s.exit, s.accept
}

// testConfig points logsh at the mock and records both directions so a single
// run can assert on each.
func testConfig(addr string) *Config {
	cfg := DefaultConfig()
	cfg.Server.UpstreamHost = addr
	cfg.Server.UseTLS = false
	cfg.LogTTYOut = true
	cfg.LogTTYIn = true
	return cfg
}

// outerTerminal builds the terminal logsh would have inherited from sshd: the
// test holds the master and drives it, logsh gets the slave.
func outerTerminal(t *testing.T) (*PTY, *os.File) {
	t.Helper()
	outer, err := OpenPTY()
	if err != nil {
		t.Fatal(err)
	}
	slave, err := outer.OpenSlave()
	if err != nil {
		t.Fatal(err)
	}
	// Give it a real size. A pty reports 0x0 until something sets one, and a
	// session recorded with no dimensions replays into a terminal sudoreplay
	// cannot size -- worth having the tests look like the sshd case.
	_ = SetWinSize(outer.Master.Fd(), WinSize{Rows: 24, Cols: 80})
	t.Cleanup(func() { _ = slave.Close(); _ = outer.Close() })
	return outer, slave
}

// TestRunRecordedCapturesOutputAndExitStatus is the core end-to-end assertion:
// a real second pty, a real child process, real bytes on the wire.
func TestRunRecordedCapturesOutputAndExitStatus(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", LoginShell: true,
		Args: []string{"-c", "printf 'HELLO-FROM-SHELL\\n'; exit 7"}}

	outcome, err := RunRecorded(t.Context(), testConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil)
	if err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	// The user's exit status must survive the recorder untouched, or `ssh host
	// false` stops meaning anything.
	if outcome.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", outcome.ExitCode)
	}

	if !strings.Contains(userSaw.String(), "HELLO-FROM-SHELL") {
		t.Errorf("the user's terminal did not receive the shell's output: %q", userSaw.String())
	}

	out, _, _, exit, acc := srv.snapshot()
	if !strings.Contains(out, "HELLO-FROM-SHELL") {
		t.Errorf("ttyout transcript = %q, want it to contain the shell's output", out)
	}
	if exit == nil {
		t.Fatal("no ExitMessage reached the server")
	}
	if exit.GetExitValue() != 7 {
		t.Errorf("ExitMessage.exit_value = %d, want 7", exit.GetExitValue())
	}
	if acc == nil || !acc.GetExpectIobufs() {
		t.Error("the AcceptMessage did not declare expect_iobufs; the server would treat " +
			"an interactive session as metadata-only")
	}
}

// TestRunRecordedCapturesInput drives the input relay: bytes the test writes to
// the outer master must reach the shell AND the ttyin transcript.
func TestRunRecordedCapturesInput(t *testing.T) {
	srv := newMockServer(t)
	outer, slave := outerTerminal(t)

	go func() {
		// The shell needs a moment to reach its read; the pty buffers regardless,
		// so this only affects ordering of the transcript, not delivery.
		time.Sleep(100 * time.Millisecond)
		_, _ = outer.Master.WriteString("SECRET-INPUT\n")
	}()

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", Args: []string{"-c", "read line; printf 'got:%s\\n' \"$line\""}}

	if _, err := RunRecorded(t.Context(), testConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	out, in, _, _, _ := srv.snapshot()
	if !strings.Contains(in, "SECRET-INPUT") {
		t.Errorf("ttyin transcript = %q, want it to contain what was typed", in)
	}
	if !strings.Contains(out, "got:SECRET-INPUT") {
		t.Errorf("the shell did not receive the typed input; ttyout = %q", out)
	}
}

// TestRunRecordedRespectsStreamToggles guards the two defaults an operator is
// most likely to rely on. log_ttyin: false must actually suppress the input
// stream -- and must NOT suppress output, which is where echo puts most
// keystrokes anyway.
func TestRunRecordedRespectsStreamToggles(t *testing.T) {
	srv := newMockServer(t)
	outer, slave := outerTerminal(t)

	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = outer.Master.WriteString("TYPED-SECRET\n")
	}()

	cfg := testConfig(srv.addr)
	cfg.LogTTYIn = false // the shipped default

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", Args: []string{"-c", "read line; printf 'ok\\n'"}}
	if _, err := RunRecorded(t.Context(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	out, in, _, _, _ := srv.snapshot()
	if in != "" {
		t.Errorf("log_ttyin was false but %q was still recorded to the ttyin stream", in)
	}
	if !strings.Contains(out, "ok") {
		t.Errorf("log_ttyin: false suppressed the OUTPUT stream too; ttyout = %q", out)
	}
}

// TestRunRecordedReportsSignalDeath checks the 128+signum convention and the
// bare signal name the log server's validation expects.
func TestRunRecordedReportsSignalDeath(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", Args: []string{"-c", "kill -TERM $$"}}

	outcome, err := RunRecorded(t.Context(), testConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil)
	if err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	if outcome.ExitCode != 128+int(15) {
		t.Errorf("ExitCode = %d, want %d for SIGTERM", outcome.ExitCode, 128+15)
	}
	// Bare name, no SIG prefix: that is what C's sig2str produces and what
	// internal/storage validates against.
	if outcome.Signal != "TERM" {
		t.Errorf("Signal = %q, want %q", outcome.Signal, "TERM")
	}
	if _, _, _, exit, _ := srv.snapshot(); exit == nil || exit.GetSignal() != "TERM" {
		t.Errorf("ExitMessage carried signal %q, want TERM", exit.GetSignal())
	}
}

// stallingServer completes the handshake and then never answers the
// AcceptMessage, so StartRecorder blocks until its response timeout.
//
// That stall is the whole point: it opens a wide, deterministic window during
// which a wrongly-ordered implementation would have its shell running. Testing
// this against a merely-unreachable server does not work, because the connect
// fails in microseconds and then RunRecorded's deferred pty.Close() SIGHUPs the
// shell before it can do anything observable -- so the test passes whether the
// ordering is right or wrong. An earlier version of this test did exactly that.
func stallingServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		proc := protocol.NewProcessorWithCloser(conn, conn, conn)
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			if _, ok := msg.Type.(*pb.ClientMessage_HelloMsg); ok {
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{ServerId: "stall"}}})
			}
			// Anything else, including the AcceptMessage, goes unanswered.
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return ln.Addr().String()
}

// TestRunRecordedFailsBeforeSpawningShell is the property the whole fail-closed
// policy rests on: when recording cannot start, no shell may have been spawned,
// and the error must say so distinguishably.
//
// If the shell ran first, fail-closed would be theatre -- the command the
// operator wanted recorded would already have executed by the time logsh
// decided to refuse the session.
func TestRunRecordedFailsBeforeSpawningShell(t *testing.T) {
	_, slave := outerTerminal(t)

	cfg := DefaultConfig()
	cfg.Server.UpstreamHost = stallingServer(t)
	cfg.Server.UseTLS = false
	// The window a wrongly-started shell would run in. Long enough that `touch`
	// cannot miss it, short enough to keep the suite quick.
	cfg.Server.ResponseTimeout = time.Second

	marker := filepath.Join(t.TempDir(), "shell-ran")
	inv := Invocation{Name: "lsh", Args: []string{"-c", "touch " + marker + "; sleep 30"}}

	var userSaw bytes.Buffer
	_, err := RunRecorded(t.Context(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil)
	if err == nil {
		t.Fatal("RunRecorded succeeded although the server never acknowledged the session")
	}
	if !errors.Is(err, ErrRecordingUnavailable) {
		t.Errorf("error = %v, want it to wrap ErrRecordingUnavailable so the caller can tell "+
			"a never-started session from one that ran unrecorded", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Error("the shell RAN despite recording being unavailable; fail-closed would be " +
			"meaningless because the command has already executed")
	}
}

// TestRecorderDelaysAreDeltas pins the timing encoding. Each IoBuffer's delay is
// the gap since the PREVIOUS event, which is what the server sums into an
// elapsed clock; sending an absolute timestamp would make every replay run at
// the wrong speed.
func TestRecorderDelaysAreDeltas(t *testing.T) {
	srv := newMockServer(t)

	cfg := testConfig(srv.addr)
	rec, err := StartRecorder(t.Context(), cfg,
		CollectMeta("/dev/pts/99", WinSize{Rows: 24, Cols: 80}, "/bin/sh", []string{"-sh"}))
	if err != nil {
		t.Fatalf("StartRecorder: %v", err)
	}
	defer func() { _ = rec.Close() }()

	if rec.LogID() != "mock-log-id" {
		t.Errorf("LogID = %q, want the id the server assigned", rec.LogID())
	}

	const gap = 60 * time.Millisecond
	time.Sleep(gap)
	if err := rec.TTYOut([]byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := rec.TTYOut([]byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := rec.Exit(t.Context(), 0, "", false); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if out, _, _, exit, _ := srv.snapshot(); exit != nil && out == "ab" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if out, _, _, _, _ := srv.snapshot(); out != "ab" {
		t.Fatalf("server received ttyout %q, want %q", out, "ab")
	}

	got := ofKind(srv.records(), "ttyout")
	if len(got) != 2 {
		t.Fatalf("server saw %d ttyout records, want 2", len(got))
	}

	// The gap PRECEDES "a", so "a" is the record that must carry it. Asserting
	// this per record is the point: the sum is 60ms either way, so a version
	// that stamped the gap on "b" instead -- replaying as a pause between the
	// two characters that never happened -- passes any total-based check.
	if got[0].delay < gap/2 {
		t.Errorf(`delay on "a" = %v, want about %v: the idle that preceded a `+
			`record belongs to THAT record, because sudoreplay sleeps a `+
			`record's delay before writing its bytes`, got[0].delay, gap)
	}
	if got[1].delay > gap/2 {
		t.Errorf(`delay on "b" = %v, want near zero: "b" followed "a" with no `+
			`pause, so the 60ms belongs to "a" and must not be repeated here `+
			`(a delay is a delta from the previous event, never an absolute `+
			`timestamp)`, got[1].delay)
	}
}

// discard keeps io.Writer in the import set for TerminalIO's Out field in tests
// that do not inspect what the user saw.
var _ io.Writer = io.Discard

// blockingSink is a Sink whose delivery takes a fixed, visible amount of time,
// standing in for a congested link or a busy daemon.
type blockingSink struct {
	block time.Duration

	mu   sync.Mutex
	seen []time.Duration
}

func (b *blockingSink) Start(context.Context, *pb.ClientMessage) (string, error) {
	return "stub-log-id", nil
}

func (b *blockingSink) Send(msg *pb.ClientMessage) error {
	time.Sleep(b.block)
	b.mu.Lock()
	b.seen = append(b.seen, messageDelay(msg))
	b.mu.Unlock()
	return nil
}

func (b *blockingSink) Finish(context.Context, time.Duration) error { return nil }
func (b *blockingSink) Close() error                                { return nil }

func (b *blockingSink) delays() []time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]time.Duration(nil), b.seen...)
}

// TestSlowDeliveryIsChargedToTheNextEventExactlyOnce pins stamping order
// against a sink that blocks.
//
// send() commits r.last = now BEFORE handing the message to the sink, so time
// spent inside delivery falls into the NEXT event's delta. That looks like a
// defect and is not: C does the same thing at plugins/sudoers/iolog.c:1076-1081,
// sampling `now`, calling io_operations.log(...), and only then storing that
// same pre-delivery timestamp into last_time. The delay a record carries is the
// gap between when two events were OFFERED to the recorder, which is what a
// viewer actually experienced -- a stalled recorder really does hold the relay
// loop, so that time really did pass.
//
// What must not happen is the timestamp moving to after delivery. Doing that --
// a tempting way to "stop charging backpressure to the next event" -- makes
// every delta measure from the end of the previous write instead of its start,
// so blocked time is silently dropped from the transcript and the replay runs
// faster than the session did. Here that would show as near-zero delays for
// events that were really a full block apart.
func TestSlowDeliveryIsChargedToTheNextEventExactlyOnce(t *testing.T) {
	const block = 150 * time.Millisecond

	sink := &blockingSink{block: block}
	now := time.Now()
	rec := &Recorder{sink: sink, cfg: testConfig("unused"), start: now, last: now}

	for range 3 {
		if err := rec.TTYOut([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(now)

	got := sink.delays()
	if len(got) != 3 {
		t.Fatalf("sink saw %d messages, want 3", len(got))
	}

	// Nothing preceded the first event, so it carries no delay -- in particular
	// it is not charged for its own delivery.
	if got[0] > block/2 {
		t.Errorf("delay on the first event = %v, want near zero; nothing "+
			"preceded it", got[0])
	}

	// Each later event was offered one blocked delivery after the one before,
	// so it carries about one block: not zero (time silently dropped) and not
	// two (the same stall counted twice).
	for i := 1; i < len(got); i++ {
		if got[i] < block/2 {
			t.Errorf("delay on event %d = %v, want about %v: %v really did pass "+
				"between the two events being offered, and a transcript that "+
				"omits it replays faster than the session ran", i, got[i], block, block)
		}
		if got[i] > 2*block {
			t.Errorf("delay on event %d = %v, want about %v: one stall is being "+
				"counted more than once", i, got[i], block)
		}
	}

	// The delays are the session's clock, so they must add up to the time that
	// actually elapsed rather than drifting from it.
	var total time.Duration
	for _, d := range got {
		total += d
	}
	if total > elapsed {
		t.Errorf("delays total %v but only %v elapsed; the recorded clock "+
			"outruns real time", total, elapsed)
	}
	if total < elapsed/2 {
		t.Errorf("delays total %v against %v elapsed; the recorded clock is "+
			"losing time the session spent", total, elapsed)
	}
}
