// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/nonint_test.go
package logshell

import (
	"os"
	"strings"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"
	"time"
)

// pipes returns a connected pipe pair and registers cleanup.
func pipes(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

// emptyStdin returns a read end that is already at EOF.
//
// Handing a child a pipe whose write end nobody closes is a hang, not an empty
// input: anything that reads stdin -- `scp -t`, `cat`, a shell builtin `read` --
// waits forever for a writer that will never appear.
func emptyStdin(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// infoValue pulls a string-ish info value out of an AcceptMessage.
func infoValue(acc *pb.AcceptMessage, key string) string {
	for _, i := range acc.GetInfoMsgs() {
		if i.GetKey() != key {
			continue
		}
		switch v := i.Value.(type) {
		case *pb.InfoMessage_Strval:
			return v.Strval
		case *pb.InfoMessage_Strlistval:
			return strings.Join(v.Strlistval.GetStrings(), " ")
		}
	}
	return ""
}

// TestNonInteractiveDoesNotWaitForAnAcknowledgement is the one that keeps a
// fleet's file transfers working.
//
// An event-only session is never acknowledged: the server's EventSession returns
// no ServerMessage for the accept OR the exit. If logsh waited for either, every
// scp, rsync and git push on the host would hang until a timeout.
//
// The mock here deliberately answers NOTHING to an accept with
// expect_iobufs=false, exactly as the real server does. The generous timeout
// would still be blown by a single blocking read.
func TestNonInteractiveDoesNotWaitForAnAcknowledgement(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)
	// All stream toggles off: the shipped default, and the metadata-only path.
	cfg.LogStdin, cfg.LogStdout, cfg.LogStderr = false, false, false

	_, wOut := pipes(t)
	rIn := emptyStdin(t)

	inv := Invocation{Name: "lsh", Args: []string{"-c", "exit 4"}}

	done := make(chan Outcome, 1)
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		out, _ := RunNonInteractive(t.Context(), RunSpec{
			Config:     cfg,
			Invocation: inv,
			ShellPath:  "/bin/sh",
			Std:        StdIO{In: rIn, Out: wOut, Err: wOut},
		})
		done <- out
	}()
	t.Cleanup(func() { <-ran })

	select {
	case out := <-done:
		if out.ExitCode != 4 {
			t.Errorf("ExitCode = %d, want 4", out.ExitCode)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a metadata-only session blocked waiting for an acknowledgement the server " +
			"never sends; every scp on the host would hang like this")
	}

	_, _, _, _, acc := srv.snapshot()
	if acc == nil {
		t.Fatal("no AcceptMessage reached the server")
	}
	if acc.GetExpectIobufs() {
		t.Error("a metadata-only session declared expect_iobufs; the server would wait for " +
			"I/O buffers that are never sent and would answer with a log id nobody reads")
	}
}

// TestNonInteractiveRecordsTheCommandLine checks the audit value of the
// metadata-only record: it must say what was actually run, not merely that a
// shell started.
func TestNonInteractiveRecordsTheCommandLine(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)
	cfg.LogStdin, cfg.LogStdout, cfg.LogStderr = false, false, false

	_, wOut := pipes(t)
	rIn := emptyStdin(t)

	inv := Invocation{Name: "lsh", Args: []string{"-c", "scp -t /tmp/incoming"}}
	if _, err := RunNonInteractive(t.Context(), RunSpec{
		Config:     cfg,
		Invocation: inv,
		ShellPath:  "/bin/sh",
		Std:        StdIO{In: rIn, Out: wOut, Err: wOut},
	}); err != nil {
		t.Fatalf("RunNonInteractive: %v", err)
	}

	waitForExit(t, srv)

	_, _, _, _, acc := srv.snapshot()
	if acc == nil {
		t.Fatal("no AcceptMessage reached the server")
	}
	// command is the shell, matching what sudo records for `sudo sh -c '...'`;
	// the command line itself lives in runargv.
	if got := infoValue(acc, "command"); got != "/bin/sh" {
		t.Errorf("command = %q, want /bin/sh", got)
	}
	if got := infoValue(acc, "runargv"); !strings.Contains(got, "scp -t /tmp/incoming") {
		t.Errorf("runargv = %q, want it to record the command line", got)
	}
}

// TestNonInteractivePassesStreamsThroughUntouched guards the property that keeps
// scp byte-exact and fast: with no stream toggle set, nothing is copied or
// recorded, the child simply inherits the descriptors.
func TestNonInteractivePassesStreamsThroughUntouched(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)
	cfg.LogStdin, cfg.LogStdout, cfg.LogStderr = false, false, false

	rOut, wOut := pipes(t)
	rIn, wIn := pipes(t)

	payload := strings.Repeat("PAYLOAD-", 1000)
	go func() {
		_, _ = wIn.WriteString(payload)
		_ = wIn.Close()
	}()

	inv := Invocation{Name: "lsh", Args: []string{"-c", "cat"}}
	// The test must outlive this goroutine. t.Cleanup closes the pipes, and
	// returning while RunNonInteractive is still inside cmd.Start() has it
	// reading a descriptor the cleanup is concurrently closing.
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		_, _ = RunNonInteractive(t.Context(), RunSpec{
			Config:     cfg,
			Invocation: inv,
			ShellPath:  "/bin/sh",
			Std:        StdIO{In: rIn, Out: wOut, Err: wOut},
		})
		_ = wOut.Close()
	}()
	t.Cleanup(func() { <-ran })

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	for len(got) < len(payload) {
		n, err := rOut.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if string(got) != payload {
		t.Errorf("the child received/produced %d bytes, want %d; the stream was not passed "+
			"through intact", len(got), len(payload))
	}

	// And none of it may have been recorded.
	out, in, _, _, _ := srv.snapshot()
	if out != "" || in != "" {
		t.Errorf("a metadata-only session recorded stream data: out=%d bytes in=%d bytes",
			len(out), len(in))
	}
}

// TestNonInteractiveStreamTogglesPromoteToAnIOSession checks that the advertised
// log_stdout option actually captures, and flips the session to one the server
// will acknowledge.
func TestNonInteractiveStreamTogglesPromoteToAnIOSession(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)
	cfg.LogStdin, cfg.LogStderr = false, false
	cfg.LogStdout = true

	_, wOut := pipes(t)
	rIn := emptyStdin(t)

	inv := Invocation{Name: "lsh", Args: []string{"-c", "printf 'CAPTURED-STDOUT\\n'"}}
	if _, err := RunNonInteractive(t.Context(), RunSpec{
		Config:     cfg,
		Invocation: inv,
		ShellPath:  "/bin/sh",
		Std:        StdIO{In: rIn, Out: wOut, Err: wOut},
	}); err != nil {
		t.Fatalf("RunNonInteractive: %v", err)
	}

	_, _, _, exit, acc := srv.snapshot()
	if acc == nil || !acc.GetExpectIobufs() {
		t.Error("log_stdout was set but the session was still declared metadata-only, so the " +
			"captured buffers would have nowhere to go")
	}
	if exit == nil {
		t.Error("no ExitMessage reached the server")
	}
}

// TestNonInteractiveReportsExitStatus keeps `ssh host false` meaningful.
func TestNonInteractiveReportsExitStatus(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)
	cfg.LogStdin, cfg.LogStdout, cfg.LogStderr = false, false, false

	_, wOut := pipes(t)
	rIn := emptyStdin(t)

	outcome, err := RunNonInteractive(t.Context(), RunSpec{
		Config:     cfg,
		Invocation: Invocation{Name: "lsh", Args: []string{"-c", "exit 42"}},
		ShellPath:  "/bin/sh",
		Std:        StdIO{In: rIn, Out: wOut, Err: wOut},
	})
	if err != nil {
		t.Fatalf("RunNonInteractive: %v", err)
	}
	if outcome.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", outcome.ExitCode)
	}
}
