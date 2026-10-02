// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func expiryRunSpec(t *testing.T) RunSpec {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return RunSpec{Config: &Config{}, ShellPath: "/bin/bash", EnvShell: "/bin/bash",
		Std: StdIO{In: f, Out: f, Err: f}, ExpiryDeadline: time.Now().Add(400 * time.Millisecond),
		Invocation: Invocation{Args: []string{"-c", "trap '' HUP TERM; sleep 30 & wait"}}}
}

func assertExpiryOutcome(t *testing.T, out Outcome, err error, start time.Time) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if out.Signal != "KILL" || out.ExitCode != 137 {
		t.Fatalf("outcome = %+v, want KILL/137", out)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("expiry did not end session promptly")
	}
}

func TestUnrecordedExpiry(t *testing.T) {
	spec := expiryRunSpec(t)
	start := time.Now()
	out, err := RunUnrecorded(spec)
	assertExpiryOutcome(t, out, err, start)
}

func TestUnrecordedExpiryIgnoresRecordingConfiguration(t *testing.T) {
	spec := expiryRunSpec(t)
	spec.Config.CommandLog.Enabled, spec.Config.CommandLog.Required = true, true
	spec.Invocation.Args = []string{"-c", "exit 7"}
	out, err := RunUnrecorded(spec)
	if err != nil || out.ExitCode != 7 {
		t.Fatalf("outcome = %+v, error = %v", out, err)
	}
}

func TestExpiredSessionNeverStarts(t *testing.T) {
	spec := expiryRunSpec(t)
	marker := filepath.Join(t.TempDir(), "started")
	spec.Invocation.Args = []string{"-c", "touch " + marker}
	spec.ExpiryDeadline = time.Now().Add(-time.Second)
	for _, run := range []func() (Outcome, error){
		func() (Outcome, error) { return RunUnrecorded(spec) },
		func() (Outcome, error) { return RunNonInteractive(t.Context(), spec) },
		func() (Outcome, error) { return RunRecorded(t.Context(), spec, TerminalIO{}) },
	} {
		if _, err := run(); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("error = %v", err)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("child ran: %v", err)
	}
}

func TestExpiryRecheckedAfterPreparingChild(t *testing.T) {
	spec := expiryRunSpec(t)
	spec.ExpiryDeadline = time.Now().Add(20 * time.Millisecond)
	marker := filepath.Join(t.TempDir(), "started")
	build := func() *exec.Cmd {
		time.Sleep(40 * time.Millisecond)
		return exec.Command("/bin/sh", "-c", "touch "+marker)
	}
	if _, _, err := startSessionChild(build, spec, nil); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("error = %v, want expired before launch", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("child ran: %v", err)
	}
}

func TestMetadataInteractiveExpiryPreservesJobControl(t *testing.T) {
	srv := newMockServer(t)
	spec := expiryRunSpec(t)
	spec.Config = testConfig(srv.addr)
	_, slave := outerTerminal(t)
	spec.Std.In = slave
	marker := expiryJobScript(t, &spec, false)
	start := time.Now()
	out, err := RunMetadataOnly(t.Context(), spec, Nesting{Kind: NestedSudo})
	assertExpiryOutcome(t, out, err, start)
	assertExpiryJobGone(t, marker)
	waitForExit(t, srv)
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.accept.GetExpectIobufs() {
		t.Fatal("nested session requested an I/O transcript")
	}
	if srv.ttyout.Len() != 0 {
		t.Fatal("metadata session captured terminal output")
	}
}

func TestNonInteractiveExpiry(t *testing.T) {
	for _, mode := range []string{"metadata", "capture", "traced"} {
		t.Run(mode, func(t *testing.T) {
			srv := newMockServer(t)
			spec := expiryRunSpec(t)
			spec.Config = testConfig(srv.addr)
			spec.Config.LogStdin, spec.Config.LogStdout, spec.Config.LogStderr = mode == "capture", mode == "capture", mode == "capture"
			if mode == "traced" {
				spec.Config.CommandLog.Enabled, spec.Config.CommandLog.Required = true, true
				spec.CmdLog = &CommandLog{sessionID: "expiry-test", maxLen: DefaultCommandLogMaxLen, out: func(string) {}}
			}
			// The live writer supplies no bytes and remains open after expiry.
			spec.Std.In, _ = pipes(t)
			start := time.Now()
			out, err := RunNonInteractive(t.Context(), spec)
			assertExpiryOutcome(t, out, err, start)
			waitForExit(t, srv)
			srv.mu.Lock()
			defer srv.mu.Unlock()
			if srv.exit.GetSignal() != "KILL" || srv.exit.GetExitValue() != 137 {
				t.Fatalf("recorded exit = %v", srv.exit)
			}
		})
	}
}

func TestCapturedStdinDoesNotDelayNormalExit(t *testing.T) {
	srv := newMockServer(t)
	spec := expiryRunSpec(t)
	spec.Config = testConfig(srv.addr)
	spec.Config.LogStdin, spec.Config.LogStdout = true, true
	spec.ExpiryDeadline = time.Now().Add(10 * time.Second)
	spec.Std.In, _ = pipes(t)
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = output.Close() }()
	spec.Std.Out = output
	spec.Invocation.Args = []string{"-c", "printf FINISHED; exit 7"}
	start := time.Now()
	out, err := RunNonInteractive(t.Context(), spec)
	if err != nil || out.ExitCode != 7 {
		t.Fatalf("outcome = %+v, error = %v", out, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("normal exit waited for open stdin")
	}
	raw, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "FINISHED" {
		t.Fatalf("output = %q", raw)
	}
}

func TestExpiryDoesNotDiscoverAnotherSessionAfterLeaderReaped(t *testing.T) {
	rootFD := -1
	old := exec.Command("/bin/true")
	old.SysProcAttr = &syscall.SysProcAttr{PidFD: &rootFD}
	if err := old.Run(); err != nil {
		t.Fatal(err)
	}
	if rootFD < 0 {
		t.Fatal("pidfd unavailable")
	}
	defer func() { _ = syscall.Close(rootFD) }()
	marker := filepath.Join(t.TempDir(), "unrelated-job")
	other := exec.Command("/bin/bash", "-c", "sleep 30 & echo $! > "+marker+"; wait")
	other.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(-other.Process.Pid, syscall.SIGKILL); _ = other.Wait() }()
	until := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("unrelated job did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Simulate the old numeric session ID referring to another session while the
	// original leader's pinned identity has already been reaped.
	done := make(chan struct{})
	stop, _ := watchExpiry(other.Process.Pid, rootFD, time.Now().Add(20*time.Millisecond), func() { close(done) })
	defer stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expiry watcher did not fire")
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if state := procState(pid); state == "gone" || state == "Z" {
		t.Fatal("expiry killed an unrelated session's job")
	}
}

func expiryJobScript(t *testing.T, spec *RunSpec, exitLeader bool) string {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "job-pid")
	ending := "wait"
	if exitLeader {
		ending = "exit 0"
	}
	spec.Invocation.Args = []string{"-c", "set -m; trap '' HUP TERM; sleep 30 & echo $! > " + marker + "; " + ending}
	t.Cleanup(func() {
		if raw, err := os.ReadFile(marker); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && procState(pid) != "gone" && procState(pid) != "Z" {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	return marker
}

func assertExpiryJobGone(t *testing.T, marker string) {
	t.Helper()
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if state := procState(pid); state == "gone" || state == "Z" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("background job %d survived expiry", pid)
}

func TestInteractiveExpiryKillsBackgroundJobGroup(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		name := "unrecorded"
		if recorded {
			name = "recorded"
		}
		t.Run(name, func(t *testing.T) {
			spec := expiryRunSpec(t)
			_, slave := outerTerminal(t)
			spec.Std.In = slave
			marker := expiryJobScript(t, &spec, false)
			start := time.Now()
			var out Outcome
			var err error
			if recorded {
				srv := newMockServer(t)
				spec.Config = testConfig(srv.addr)
				out, err = RunRecorded(t.Context(), spec, TerminalIO{In: slave, Out: io.Discard})
			} else {
				out, err = RunUnrecorded(spec)
			}
			assertExpiryOutcome(t, out, err, start)
			assertExpiryJobGone(t, marker)
		})
	}
}

func TestExpiryKillsJobsAfterLeaderExit(t *testing.T) {
	for _, name := range []string{"capture", "interactive", "traced-capture"} {
		t.Run(name, func(t *testing.T) {
			srv := newMockServer(t)
			spec := expiryRunSpec(t)
			spec.Config = testConfig(srv.addr)
			spec.Config.LogStdout = true
			if name == "traced-capture" {
				spec.Config.CommandLog.Enabled, spec.Config.CommandLog.Required = true, true
				spec.CmdLog = &CommandLog{sessionID: "expiry-test", maxLen: DefaultCommandLogMaxLen, out: func(string) {}}
			}
			marker := expiryJobScript(t, &spec, true)
			start := time.Now()
			var err error
			if name == "interactive" {
				_, slave := outerTerminal(t)
				spec.Std.In = slave
				_, err = RunRecorded(t.Context(), spec, TerminalIO{In: slave, Out: io.Discard})
			} else {
				_, err = RunNonInteractive(t.Context(), spec)
			}
			if err != nil {
				t.Fatal(err)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("expiry hung on descendant output drain")
			}
			assertExpiryJobGone(t, marker)
		})
	}
}

func TestExpiryInterruptsStalledClientOutput(t *testing.T) {
	for _, mode := range []string{"capture", "interactive", "unrecorded"} {
		t.Run(mode, func(t *testing.T) {
			spec := expiryRunSpec(t)
			_, output := pipes(t) // Client never reads this pipe.
			spec.Std.Out, spec.Std.Err = output, output
			spec.Invocation.Args = []string{"-c", "trap '' HUP TERM; while :; do printf '%4096s' x; done"}
			start := time.Now()
			var out Outcome
			var err error
			if mode == "unrecorded" {
				out, err = RunUnrecorded(spec)
			} else {
				srv := newMockServer(t)
				spec.Config = testConfig(srv.addr)
				if mode == "interactive" {
					_, slave := outerTerminal(t)
					spec.Std.In = slave
					out, err = RunRecorded(t.Context(), spec, TerminalIO{In: slave, Out: output})
				} else {
					spec.Config.LogStdout = true
					out, err = RunNonInteractive(t.Context(), spec)
				}
			}
			assertExpiryOutcome(t, out, err, start)
		})
	}
}
