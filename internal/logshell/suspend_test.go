// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/suspend_test.go
package logshell

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestRecorderSuspendRejectsUnknownSignalNames guards a failure whose blast
// radius is much larger than it looks.
//
// internal/storage does not ignore a CommandSuspend it does not recognise -- it
// returns an error, which tears the session down. Sending "SIGTSTP" instead of
// "TSTP", or a name outside the allowed five, would therefore cost the entire
// transcript rather than the single event.
func TestRecorderSuspendRejectsUnknownSignalNames(t *testing.T) {
	srv := newMockServer(t)
	rec, err := StartRecorder(context.Background(), testConfig(srv.addr),
		CollectMeta("/dev/pts/99", WinSize{Rows: 24, Cols: 80}, "/bin/sh", []string{"-sh"}))
	if err != nil {
		t.Fatalf("StartRecorder: %v", err)
	}
	defer func() { _ = rec.Close() }()

	// The five the server accepts.
	for _, name := range []string{"STOP", "TSTP", "CONT", "TTIN", "TTOU"} {
		if !SuspendSignals[name] {
			t.Errorf("%q is not in SuspendSignals but internal/storage accepts it", name)
		}
	}
	// The mistakes worth guarding: the SIG-prefixed form, and a signal that is
	// real but not a suspend.
	for _, name := range []string{"SIGTSTP", "TERM", "INT", "", "sigtstp"} {
		if SuspendSignals[name] {
			t.Errorf("%q is in SuspendSignals but internal/storage would reject it and drop "+
				"the whole session", name)
		}
		if err := rec.Suspend(name); err != nil {
			t.Errorf("Suspend(%q) returned %v; it should be dropped silently", name, err)
		}
	}
}

// TestRecorderSuspendRoundTrips checks the event actually reaches the server
// with the bare name.
func TestRecorderSuspendRoundTrips(t *testing.T) {
	srv := newMockServer(t)
	rec, err := StartRecorder(context.Background(), testConfig(srv.addr),
		CollectMeta("/dev/pts/99", WinSize{Rows: 24, Cols: 80}, "/bin/sh", []string{"-sh"}))
	if err != nil {
		t.Fatalf("StartRecorder: %v", err)
	}
	defer func() { _ = rec.Close() }()

	if err := rec.Suspend("TSTP"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Suspend("CONT"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Exit(context.Background(), 0, "", false); err != nil {
		t.Fatal(err)
	}

	got := srv.suspends()
	if len(got) != 2 || got[0] != "TSTP" || got[1] != "CONT" {
		t.Errorf("server received suspend events %v, want [TSTP CONT]", got)
	}
}

// TestRecordsBinaryDataVerbatim covers terminal output that is not text: NUL
// bytes, invalid UTF-8, control characters, a lone CR.
//
// A transcript that mangles these is worse than no transcript, because it looks
// authoritative. The protobuf field is `bytes` and nothing on this path may
// treat it as a string.
func TestRecordsBinaryDataVerbatim(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)

	// Every byte 0x00-0xFF except those the tty driver itself would act on.
	// \x1a is ^Z and \x03 is ^C on the INPUT side only, so output is safe.
	var payload []byte
	for i := range 256 {
		payload = append(payload, byte(i))
	}

	// printf with octal escapes emits the bytes exactly; the pty is in raw mode
	// on our side so nothing translates them on the way out.
	var sb strings.Builder
	for _, b := range payload {
		sb.WriteString("\\")
		sb.WriteString(octal(b))
	}

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lsh", Args: []string{"-c", "printf '" + sb.String() + "'"}}
	if _, err := RunRecorded(context.Background(), testConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	out, _, _, _, _ := srv.snapshot()
	// The inner pty has OPOST on, so a bare \n becomes \r\n on the way out. That
	// is a genuine property of the terminal, not corruption, so compare on the
	// bytes that cannot be rewritten: everything except \n.
	wantNoNL := bytes.ReplaceAll(payload, []byte("\n"), nil)
	gotNoNL := bytes.ReplaceAll([]byte(out), []byte("\n"), nil)
	gotNoNL = bytes.ReplaceAll(gotNoNL, []byte("\r"), nil)
	wantNoNL = bytes.ReplaceAll(wantNoNL, []byte("\r"), nil)

	if !bytes.Contains(gotNoNL, wantNoNL) {
		t.Errorf("the recorded transcript does not contain the emitted byte range verbatim; "+
			"got %d bytes, want a superset of %d", len(gotNoNL), len(wantNoNL))
	}
	if !bytes.Contains([]byte(out), []byte{0x00}) {
		t.Error("NUL bytes did not survive into the transcript")
	}
}

func octal(b byte) string {
	const digits = "01234567"
	return string([]byte{digits[(b>>6)&7], digits[(b>>3)&7], digits[b&7]})
}

// TestRecordsHugeOutputWithoutLoss pushes 4 MiB through the real relay: a real
// pty, real 32 KiB read chunking, a real child. A recorder that lost buffers
// under volume would silently produce a transcript that ends early.
//
// It does NOT exercise the sink's backpressure path, despite the volume. The
// consumer here is a local socket that drains as fast as the producer fills, so
// the queue never approaches its depth -- verified by mutating Send to drop
// instead of block, which this test does not notice.
// TestBufferedSinkBlocksRatherThanDropping covers that.
func TestRecordsHugeOutputWithoutLoss(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)

	// 4 MiB: comfortably past relayBufSize and sinkBufferDepth, and past the
	// 2 MiB single-message protocol ceiling if anything tried to send it whole.
	const lines = 65536
	inv := Invocation{Name: "lsh", Args: []string{"-c",
		"i=0; while [ $i -lt " + itoa(lines) + " ]; do printf '0123456789abcdefghijklmnopqrstuvwxyz012345678901234567890123\\n'; i=$((i+1)); done"}}

	var userSaw bytes.Buffer
	if _, err := RunRecorded(context.Background(), testConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	out, _, _, exit, _ := srv.snapshot()
	if exit == nil {
		t.Fatal("no ExitMessage reached the server")
	}
	gotLines := strings.Count(out, "0123456789abcdefghijklmnopqrstuvwxyz")
	if gotLines != lines {
		t.Errorf("transcript holds %d of %d lines; output was lost under load", gotLines, lines)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
