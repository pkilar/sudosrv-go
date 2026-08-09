// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/relay.go
package logshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

// relayBufSize is the read size for both relay directions. 32 KiB is far below
// protocol.MaxMessageSize (2 MiB) so no single buffer can ever be rejected for
// length, and large enough that a burst of output (a build log, `cat` of a big
// file) does not turn into a message per few hundred bytes.
const relayBufSize = 32 * 1024

// signalNames maps a signal to the name the log server expects: the bare name
// with no "SIG" prefix, matching C's sig2str and the validation in
// internal/storage.
var signalNames = map[syscall.Signal]string{
	syscall.SIGHUP: "HUP", syscall.SIGINT: "INT", syscall.SIGQUIT: "QUIT",
	syscall.SIGILL: "ILL", syscall.SIGTRAP: "TRAP", syscall.SIGABRT: "ABRT",
	syscall.SIGBUS: "BUS", syscall.SIGFPE: "FPE", syscall.SIGKILL: "KILL",
	syscall.SIGUSR1: "USR1", syscall.SIGSEGV: "SEGV", syscall.SIGUSR2: "USR2",
	syscall.SIGPIPE: "PIPE", syscall.SIGALRM: "ALRM", syscall.SIGTERM: "TERM",
	syscall.SIGCHLD: "CHLD", syscall.SIGCONT: "CONT", syscall.SIGSTOP: "STOP",
	syscall.SIGTSTP: "TSTP", syscall.SIGTTIN: "TTIN", syscall.SIGTTOU: "TTOU",
	syscall.SIGURG: "URG", syscall.SIGXCPU: "XCPU", syscall.SIGXFSZ: "XFSZ",
	syscall.SIGVTALRM: "VTALRM", syscall.SIGPROF: "PROF", syscall.SIGWINCH: "WINCH",
	syscall.SIGIO: "IO", syscall.SIGSYS: "SYS",
}

func signalName(s syscall.Signal) string {
	if n, ok := signalNames[s]; ok {
		return n
	}
	return ""
}

// Outcome is how a recorded session ended.
type Outcome struct {
	ExitCode   int
	Signal     string // bare name, "" if the shell exited normally
	CoreDumped bool
}

// syslogWarning is the priority for recorder problems that do not stop the
// session.
const syslogWarning = syslog.LOG_WARNING

// ErrRecordingUnavailable reports that recording could not be STARTED, and so
// that no shell was ever spawned.
//
// The distinction is the whole basis of the failure policy. Before the shell
// exists, refusing the session costs the user a login and nothing else, so
// fail-closed is a real option. Once the shell has run, its exit status is a
// fact the user is entitled to and the audit gap has already happened -- the
// only useful response then is to report loudly, not to rewrite history by
// returning a refusal code.
var ErrRecordingUnavailable = errors.New("recording could not be started")

func unavailable(err error) error { return fmt.Errorf("%w: %w", ErrRecordingUnavailable, err) }

// RunRecorded runs the shell on its own pseudo-terminal, relaying bytes between
// the user's terminal and the shell while streaming a transcript to the log
// server. It returns once the shell has exited and the server has confirmed the
// session is durable.
//
// The ordering here is deliberate and load-bearing: the recorder is started
// BEFORE the shell. If recording cannot begin, no shell has been spawned yet and
// the caller can apply its fail-closed policy on a session that never started,
// rather than having to kill a shell the user is already typing into.
// TerminalIO is the user's end of the session: the terminal logsh inherited from
// sshd. It is a parameter rather than os.Stdin/os.Stdout directly so a test can
// drive the relay through a pty pair of its own.
type TerminalIO struct {
	// In must be a real terminal descriptor: the relay reads its termios and
	// window size, so an io.Reader would not do.
	In  *os.File
	Out io.Writer
}

// StdTerminal is the production TerminalIO.
func StdTerminal() TerminalIO { return TerminalIO{In: os.Stdin, Out: os.Stdout} }

func RunRecorded(ctx context.Context, cfg *Config, inv Invocation, shellPath string, tio TerminalIO, cmdLog *CommandLog) (Outcome, error) {
	stdin := tio.In

	size, err := GetWinSize(stdin.Fd())
	if err != nil {
		// Not fatal. A terminal that will not report its size still carries a
		// session worth recording; sudoreplay simply has no dimensions to
		// restore. Guessing 80x24 would be a lie in the transcript.
		size = WinSize{}
	}

	pty, err := OpenPTY()
	if err != nil {
		return Outcome{}, unavailable(err)
	}
	defer func() { _ = pty.Close() }()

	if size.Rows != 0 || size.Cols != 0 {
		_ = SetWinSize(pty.Master.Fd(), size)
	}

	argv0 := ChildArgv0(shellPath, inv.LoginShell)
	argv := append([]string{argv0}, inv.Args...)

	meta := CollectMeta(pty.Name, size, shellPath, argv)
	meta.SessionID = cmdLog.SessionID()
	meta.ApplyNesting(DetectNesting())

	rec, err := StartRecorder(ctx, cfg, meta)
	if err != nil {
		return Outcome{}, unavailable(err)
	}
	defer func() { _ = rec.Close() }()

	// Bound only now: the tty name is part of every command record and does not
	// exist until the pty does.
	cmdLog.Bind(meta, rec.LogID())

	slave, err := pty.OpenSlave()
	if err != nil {
		return Outcome{}, unavailable(err)
	}

	build := func() *exec.Cmd {
		c := exec.Command(shellPath) // #nosec G204 -- see .golangci.yml; allowlisted by ResolveShell
		c.Args = argv
		c.Env = WithSessionEnv(PrepareEnv(os.Environ(), shellPath), cmdLog.SessionID())
		c.Stdin, c.Stdout, c.Stderr = slave, slave, slave
		// Setsid puts the shell in its own session with the INNER pty as
		// controlling terminal, which is what makes job control, ^C and ^Z work
		// inside the recorded session instead of hitting logsh. Ctty is the fd
		// number as the CHILD will see it, i.e. stdin.
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		return c
	}

	child, err := startChild(build, cfg, cmdLog)
	if err != nil {
		_ = slave.Close()
		return Outcome{}, unavailable(err)
	}

	// Drop our copy of the slave. While any descriptor for it remains open in
	// this process, reading the master never reports EOF, so the output relay
	// would block forever after the shell exits and the session would never end.
	_ = slave.Close()

	// Capture BOTH termios states: the saved one to hand back on suspend or at
	// exit, and the raw one to re-apply on resume. Re-deriving raw later would
	// mean recomputing it from whatever the terminal happened to look like at
	// that moment, which after a suspend is not the same thing.
	saved, err := MakeRaw(stdin.Fd())
	var rawState *syscall.Termios
	if err == nil {
		defer func() { _ = SetTermios(stdin.Fd(), saved) }()
		rawState, _ = GetTermios(stdin.Fd())
	}

	stopWinch := watchWindowSize(stdin, pty, rec)
	defer stopWinch()

	stopSuspend := watchSuspend(stdin.Fd(), saved, rawState, rec)
	defer stopSuspend()

	relayInput(stdin, pty.Master, rec)
	relayOutput(pty.Master, tio.Out, rec)

	outcome := child.Wait()
	cmdLog.End(outcome)

	if err := rec.Exit(ctx, outcome.ExitCode, outcome.Signal, outcome.CoreDumped); err != nil {
		// The shell has already run; its exit status is the truth and must be
		// reported. The failure to durably record it is reported separately, by
		// the caller, so an operator sees the audit gap without the user losing
		// their exit code.
		return outcome, err
	}
	return outcome, nil
}

// childProc is a started child whose exit status can be collected.
type childProc interface{ Wait() Outcome }

type plainChild struct{ cmd *exec.Cmd }

func (p plainChild) Wait() Outcome { return waitOutcome(p.cmd) }

// startChild launches the shell, under exec tracing when the command log wants
// it, and plainly otherwise.
//
// build produces a FRESH exec.Cmd each call. That is not fussiness: a failed
// trace attempt has already forked and killed a process, so its exec.Cmd is
// spent and cannot be reused for the untraced fallback.
func startChild(build func() *exec.Cmd, cfg *Config, cmdLog *CommandLog) (childProc, error) {
	if cfg.CommandLog.Enabled {
		tc, err := startTraced(build(), cmdLog.Exec)
		if err == nil {
			return tc, nil
		}
		if cfg.CommandLog.Required {
			return nil, fmt.Errorf("exec tracing is required but could not start: %w", err)
		}
		// Carry on without the command log. Refusing the login over an audit
		// add-on that a kernel setting can veto is the worse trade -- but say so
		// in both streams, because a command log that is quietly absent is
		// indistinguishable from a session that ran no commands.
		Alertf(syslogWarning, "exec tracing unavailable, continuing without a command log: %v", err)
		cmdLog.Note("exec tracing unavailable: " + err.Error())
	}

	cmd := build()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return plainChild{cmd}, nil
}

// relayInput copies the user's keystrokes to the shell.
//
// It runs on its own goroutine and is deliberately never waited for. A read on
// the user's terminal blocks until they type, so waiting for it would keep the
// session alive after the shell has already exited -- the user would have to
// press a key to get their prompt back.
func relayInput(from *os.File, to *os.File, rec *Recorder) {
	go func() {
		buf := make([]byte, relayBufSize)
		for {
			n, err := from.Read(buf)
			if n > 0 {
				// Record before forwarding: a keystroke that reaches the shell
				// but not the log is an audit gap, and the shell cannot act on
				// it any faster than we can note it.
				_ = rec.TTYIn(buf[:n])
				if _, werr := to.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

// relayOutput copies the shell's output to the user's terminal, and drives
// session termination: it returns when the master reports EOF or EIO, which is
// what the kernel gives once the shell has exited and released the slave.
//
// The user's terminal is written FIRST, then the recorder. That ordering is
// chosen for interactivity -- the recorder currently writes to the network
// synchronously, so recording first would put a round trip between the shell
// producing a character and the user seeing it. M3 moves the recorder behind a
// buffered writer, after which the ordering stops mattering.
func relayOutput(from *os.File, to io.Writer, rec *Recorder) {
	buf := make([]byte, relayBufSize)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			if _, werr := to.Write(buf[:n]); werr != nil {
				return
			}
			_ = rec.TTYOut(buf[:n])
		}
		if err != nil {
			// EIO here is normal, not an error: it is how Linux reports that the
			// last slave descriptor closed because the shell exited.
			return
		}
	}
}

// watchWindowSize propagates terminal resizes to the inner pty and records them.
// The returned function stops the watcher.
func watchWindowSize(outer *os.File, pty *PTY, rec *Recorder) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)

	var once sync.Once
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ch:
				size, err := GetWinSize(outer.Fd())
				if err != nil {
					continue
				}
				_ = SetWinSize(pty.Master.Fd(), size)
				_ = rec.WinSize(size)
			case <-done:
				return
			}
		}
	}()

	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}
}

// waitOutcome reaps the shell and translates its wait status.
//
// A shell killed by a signal reports 128+signum, which is the convention every
// other shell and every CI system already assumes. Reporting the raw signal
// number, or 0, would make `ssh host false` and a segfaulting command
// indistinguishable from success to anything reading the exit code.
func waitOutcome(cmd *exec.Cmd) Outcome {
	err := cmd.Wait()
	if err == nil {
		return Outcome{ExitCode: 0}
	}

	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return Outcome{ExitCode: 1}
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok {
		return Outcome{ExitCode: ee.ExitCode()}
	}
	if ws.Signaled() {
		sig := ws.Signal()
		return Outcome{
			ExitCode:   128 + int(sig),
			Signal:     signalName(sig),
			CoreDumped: ws.CoreDump(),
		}
	}
	return Outcome{ExitCode: ws.ExitStatus()}
}
