// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/cmdlog_test.go
package logshell

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// captureLog is a CommandLog that keeps its records in memory instead of
// sending them to syslog.
type captureLog struct {
	*CommandLog
	mu    sync.Mutex
	lines []string
}

func newCaptureLog(t *testing.T) *captureLog {
	t.Helper()
	cl := &captureLog{}
	inner, err := OpenCommandLog(&Config{}, "/bin/sh") // disabled: mints the UUID only
	if err != nil {
		t.Fatal(err)
	}
	inner.out = func(line string) {
		cl.mu.Lock()
		cl.lines = append(cl.lines, line)
		cl.mu.Unlock()
	}
	cl.CommandLog = inner
	return cl
}

func (c *captureLog) records() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...)
}

// commands returns the CMD= value of every exec record.
func (c *captureLog) commands() []string {
	var out []string
	for _, l := range c.records() {
		if _, cmd, ok := strings.Cut(l, "CMD="); ok {
			out = append(out, cmd)
		}
	}
	return out
}

func tracingConfig(addr string) *Config {
	cfg := testConfig(addr)
	cfg.CommandLog.Enabled = true
	cfg.CommandLog.SyslogFacility = "authpriv"
	cfg.CommandLog.SyslogPriority = "info"
	cfg.CommandLog.MaxLen = DefaultCommandLogMaxLen
	return cfg
}

// TestCommandLogRecordsEveryExec is the basic promise: one record per command,
// each carrying the session UUID.
func TestCommandLogRecordsEveryExec(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)
	cl := newCaptureLog(t)

	inv := Invocation{Name: "lsh", Args: []string{"-c", "/bin/echo ONE; /bin/echo TWO; /usr/bin/env true"}}
	if _, err := RunRecorded(context.Background(), tracingConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &bytes.Buffer{}}, cl.CommandLog); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	cmds := strings.Join(cl.commands(), "\n")
	for _, want := range []string{"/bin/echo ONE", "/bin/echo TWO", "/usr/bin/env true"} {
		if !strings.Contains(cmds, want) {
			t.Errorf("no record for %q; the command log holds:\n%s", want, cmds)
		}
	}

	// Every record must be joinable back to the session.
	id := cl.SessionID()
	if id == "" {
		t.Fatal("no session UUID was minted")
	}
	for _, l := range cl.records() {
		if !strings.Contains(l, "SESSION="+id) {
			t.Errorf("a record is missing SESSION=%s: %q", id, l)
		}
	}
}

// TestCommandLogCatchesCommandsRunFromAScript is the property that motivated
// ptrace over a shell hook.
//
// A preexec hook only ever sees what is typed at a prompt. Anything a script
// runs -- which is where an attacker would put it -- is invisible to it. Exec
// tracing sees the whole tree.
func TestCommandLogCatchesCommandsRunFromAScript(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)
	cl := newCaptureLog(t)

	dir := t.TempDir()
	script := filepath.Join(dir, "payload.sh")
	if err := os.WriteFile(script,
		[]byte("#!/bin/sh\n/bin/echo BURIED-IN-A-SCRIPT\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	inv := Invocation{Name: "lsh", Args: []string{"-c", script}}
	if _, err := RunRecorded(context.Background(), tracingConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &bytes.Buffer{}}, cl.CommandLog); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	cmds := strings.Join(cl.commands(), "\n")
	if !strings.Contains(cmds, "BURIED-IN-A-SCRIPT") {
		t.Errorf("a command run from inside a script went unlogged; a shell hook would have "+
			"missed it too, which is the whole reason for tracing. Records:\n%s", cmds)
	}
	if !strings.Contains(cmds, script) {
		t.Errorf("the script invocation itself went unlogged. Records:\n%s", cmds)
	}
}

// TestTracedSessionKeepsGroupStopWorking is the regression that would otherwise
// be found by an administrator, not by us.
//
// A traced process that enters group-stop must STAY stopped. Resuming it in the
// tracer -- the easy mistake, and what classic PTRACE_ATTACH nudges you towards
// -- silently breaks ^Z for every job inside a recorded session.
func TestTracedSessionKeepsGroupStopWorking(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)
	cl := newCaptureLog(t)

	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")

	// A child that publishes its pid, stops itself, and only prints once resumed.
	inv := Invocation{Name: "lsh", Args: []string{"-c",
		"/bin/sh -c 'echo $$ > " + pidFile + "; kill -STOP $$; /bin/echo RESUMED' & wait"}}

	done := make(chan error, 1)
	go func() {
		_, err := RunRecorded(context.Background(), tracingConfig(srv.addr), inv, "/bin/sh",
			TerminalIO{In: slave, Out: &bytes.Buffer{}}, cl.CommandLog)
		done <- err
	}()

	pid := waitForPID(t, pidFile)

	// Give the stop time to take effect, then verify the kernel still considers
	// the process stopped.
	//
	// BOTH "T" and "t" count. Since Linux 2.6.33 /proc reports group-stop as "T"
	// and ptrace-stop as "t", and a tracee held by PTRACE_LISTEN shows the
	// latter -- it is in group-stop, but ptrace is what is holding it there. The
	// property under test is simply that it did not resume: a tracer that
	// wrongly continued it would leave the process "R" or "S", and ^Z inside a
	// recorded session would not hold.
	time.Sleep(500 * time.Millisecond)
	if state := procState(pid); state != "T" && state != "t" {
		t.Errorf("a group-stopped process under tracing is in state %q, want \"T\" or \"t\"; "+
			"^Z inside a recorded session would not hold", state)
	}

	_ = syscallKill(pid, "CONT")

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunRecorded: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the traced session never finished after the stopped child was continued")
	}
}

// TestTracedSessionPassesSignalsThrough guards the other half of signal
// handling: a tracer that forgets to inject the signal it intercepted swallows
// every SIGINT and SIGTERM in the session.
func TestTracedSessionPassesSignalsThrough(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)
	cl := newCaptureLog(t)

	inv := Invocation{Name: "lsh", Args: []string{"-c", "kill -TERM $$"}}
	outcome, err := RunRecorded(context.Background(), tracingConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &bytes.Buffer{}}, cl.CommandLog)
	if err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}
	if outcome.Signal != "TERM" {
		t.Errorf("Signal = %q, want TERM; the tracer swallowed the signal instead of injecting it",
			outcome.Signal)
	}
	if outcome.ExitCode != 128+15 {
		t.Errorf("ExitCode = %d, want %d", outcome.ExitCode, 128+15)
	}
}

// TestSessionUUIDReachesTheRecordedSession is the join the whole feature exists
// for: a command record and the recorded transcript must name the same session.
func TestSessionUUIDReachesTheRecordedSession(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)
	cl := newCaptureLog(t)

	inv := Invocation{Name: "lsh", Args: []string{"-c", "/bin/echo hi"}}
	if _, err := RunRecorded(context.Background(), tracingConfig(srv.addr), inv, "/bin/sh",
		TerminalIO{In: slave, Out: &bytes.Buffer{}}, cl.CommandLog); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	_, _, _, _, acc := srv.snapshot()
	if acc == nil {
		t.Fatal("no AcceptMessage reached the server")
	}
	if got := infoValue(acc, "logsh_session"); got != cl.SessionID() {
		t.Errorf("the recorded session carries logsh_session=%q but the command log stamped %q; "+
			"the two cannot be joined", got, cl.SessionID())
	}
}

// TestCommandLogTruncationIsVisible checks that an over-long record says it was
// cut. A silently clipped audit line is one somebody later reads as the whole
// command.
func TestCommandLogTruncationIsVisible(t *testing.T) {
	cl := newCaptureLog(t)
	cl.maxLen = 120
	cl.Bind(SessionMeta{User: "root", UID: 0, TTYName: "/dev/pts/9"}, "tsid")

	cl.Exec(ExecEvent{PID: 42, Argv: []string{"/bin/echo", strings.Repeat("A", 500)}})

	last := cl.records()[len(cl.records())-1]
	if len(last) > 120 {
		t.Errorf("record is %d bytes, want <= 120", len(last))
	}
	if !strings.Contains(last, "truncated") {
		t.Errorf("an over-long record was clipped with no marker: %q", last)
	}
}

// TestCommandLogEscapesControlCharacters guards against a command forging a
// second audit record. A newline in argv must not become a line break in the
// log.
func TestCommandLogEscapesControlCharacters(t *testing.T) {
	cl := newCaptureLog(t)
	cl.Bind(SessionMeta{User: "root", UID: 0, TTYName: "/dev/pts/9"}, "tsid")

	cl.Exec(ExecEvent{PID: 42, Argv: []string{"/bin/echo", "safe\nSESSION=forged ; CMD=/bin/true"}})

	last := cl.records()[len(cl.records())-1]
	if strings.Contains(last, "\n") {
		t.Errorf("a newline survived into the record, which would read as a second forged "+
			"audit line: %q", last)
	}
	if !strings.Contains(last, "#012") {
		t.Errorf("the newline was not octal-escaped the way eventlog escapes: %q", last)
	}
}

// TestCommandLogDisabledStillMintsASessionID keeps the identifier meaningful
// when the feature is off: a session recorded today should be joinable to
// records from a host where the command log is switched on.
func TestCommandLogDisabledStillMintsASessionID(t *testing.T) {
	cl, err := OpenCommandLog(DefaultConfig(), "/bin/sh") // command_log disabled by default
	if err != nil {
		t.Fatalf("OpenCommandLog: %v", err)
	}
	if cl.SessionID() == "" {
		t.Error("no session UUID was minted with the command log disabled")
	}
	// And nothing must blow up or emit.
	cl.Bind(SessionMeta{User: "root"}, "tsid")
	cl.Exec(ExecEvent{PID: 1, Argv: []string{"/bin/true"}})
	cl.End(Outcome{})
	if err := cl.Close(); err != nil {
		t.Errorf("Close on a disabled log: %v", err)
	}
}

// waitForPID blocks until the child has published its pid.
func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path); err == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); convErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the child never published its pid to %s", path)
	return 0
}

// procState returns the single-letter process state from /proc/<pid>/stat.
//
// Parsed from the LAST ')' rather than by splitting on spaces: field 2 is the
// executable name in parentheses and may itself contain spaces and brackets.
func procState(pid int) string {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "gone"
	}
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 || i+2 >= len(raw) {
		return "unparsed"
	}
	return string(raw[i+2])
}

func syscallKill(pid int, sig string) error {
	s := syscall.SIGCONT
	if sig == "TERM" {
		s = syscall.SIGTERM
	}
	return syscall.Kill(pid, s)
}
