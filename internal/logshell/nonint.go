// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/nonint.go
package logshell

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"syscall"
	"time"
)

// StdIO is the process's three standard streams.
//
// They are *os.File rather than io.Reader/Writer for a reason that matters to
// scp: when os/exec is handed an *os.File it passes the descriptor straight to
// the child, but given any other Reader or Writer it inserts a pipe and a
// copying goroutine. On the pass-through path -- which is the whole point of
// recording non-interactive sessions as metadata only -- that copy would put a
// userspace round trip in the middle of every file transfer on the host.
type StdIO struct {
	In, Out, Err *os.File
}

// StdStreams is the production StdIO.
func StdStreams() StdIO { return StdIO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr} }

// RunSpec is one session to run: which program, how it was invoked, the streams
// to attach to it, and the command log the session is recorded against.
//
// It is shared by BOTH recorders. It began as the non-interactive path's value
// and kept that name; RunRecorded takes it too, so that the login-shell and
// forced-command entry points can hand either recorder the same thing.
//
// These fields travel together through every entry point in this package --
// the recorders differ only in the nesting and capture decisions layered on
// top -- so they are passed as one value rather than threaded individually.
//
// The zero value is not usable, and the fields do not fail alike: a missing
// Config panics on entry, while a missing Std is accepted and records the wrong
// thing. Positional arguments used to oblige the caller to name all of them; a
// struct does not, so which is which is written down per field.
type RunSpec struct {
	// ExpiryDeadline forcibly ends the supervised session at this instant.
	// Zero preserves the ordinary session lifetime.
	ExpiryDeadline time.Time

	// Config is required. RunNonInteractive dereferences it on entry, to decide
	// whether any stream is being captured.
	Config *Config

	// Invocation is argv[0] and the arguments handed through to the shell. Its
	// zero value is legitimate -- that is a shell started with no arguments.
	Invocation Invocation

	// ShellPath is required: the resolved shell to exec.
	ShellPath string

	// Std is required, and is the one field whose absence does not announce
	// itself. (*os.File).Fd reports ^uintptr(0) rather than panicking on a nil
	// file, and os/exec hands the child /dev/null for a nil stream, so a zero
	// Std yields a session recorded against the wrong terminal instead of a
	// crash.
	Std StdIO

	// CmdLog is optional. SessionID, Bind and End are each nil-safe, which is
	// what lets the tests here record a session with no command log open.
	CmdLog *CommandLog

	// Info is what sshd told us about this session: the credential that
	// authenticated it, the client's requested command, the source address. Its
	// zero value stamps nothing, which is what leaves the login-shell path
	// unchanged.
	Info SessionInfo

	// EnvShell is the value to publish as $SHELL, or "" to leave the inherited
	// value alone.
	//
	// It is NOT simply ShellPath. A forced-command route may exec something that
	// is not a shell at all -- sftp-server, rrsync -- and publishing
	// SHELL=/usr/lib/ssh/sftp-server to it would be a lie that scripts read.
	//
	// Like Std, this is a field whose absence does not announce itself: leaving
	// it empty on a shell session silently stops $SHELL being corrected, which
	// is the bug PrepareEnv exists to prevent. Set it whenever ShellPath is a
	// shell.
	EnvShell string
}

// recordsAnyStream reports whether any of the non-tty streams is being captured.
// When none is, the session is recorded as metadata only.
func (c *Config) recordsAnyStream() bool {
	return c.LogStdin || c.LogStdout || c.LogStderr
}

// RunNonInteractive runs the shell with no pseudo-terminal: `ssh host cmd`, scp,
// rsync, git-over-ssh.
//
// By default this records the session as METADATA ONLY -- who ran what, when,
// and how it exited -- and passes the three streams through untouched. A 10 GB
// transfer therefore does not produce a 10 GB transcript, and scp stays
// byte-exact and full speed.
//
// Setting any of log_stdin / log_stdout / log_stderr promotes the session to a
// full I/O recording of those streams, at the cost of that pass-through.
func RunNonInteractive(ctx context.Context, spec RunSpec) (Outcome, error) {
	return runPassthrough(ctx, spec,
		Nesting{SudoUID: -1, SudoGID: -1}, spec.Config.recordsAnyStream())
}

// RunMetadataOnly runs the shell with its streams passed straight through and
// only a metadata record kept: who, what, when, and how it exited.
//
// This is the nested case. Something above us -- sudo, or another logsh -- is
// already carrying the transcript, so allocating a second pseudo-terminal to
// capture the same bytes buys nothing and costs a layer. Passing the terminal
// through untouched also means the raw-mode keystroke-timing regression is not
// stacked a second time.
//
// It keeps a record rather than exec'ing straight through so that a nested
// session is still visible as a fact -- with both session UUIDs, so it joins to
// whatever the outer recorder stored.
// With certificate expiry enabled, interactive sessions use a private terminal
// for job control and teardown while still omitting the transcript.
func RunMetadataOnly(ctx context.Context, spec RunSpec, nesting Nesting) (Outcome, error) {
	if !spec.ExpiryDeadline.IsZero() && spec.Std.In != nil && IsTerminal(spec.Std.In.Fd()) {
		// A separate controlling terminal preserves shell job control while giving
		// the expiry supervisor a session that it can terminate independently.
		cfg := *spec.Config
		cfg.LogTTYIn, cfg.LogTTYOut = false, false
		spec.Config = &cfg
		return runRecorded(ctx, spec, TerminalIO{In: spec.Std.In, Out: spec.Std.Out}, &nesting)
	}
	return runPassthrough(ctx, spec, nesting, false)
}

func runPassthrough(ctx context.Context, spec RunSpec, nesting Nesting, captureStreams bool) (Outcome, error) {
	if err := spec.checkExpiry(); err != nil {
		return Outcome{}, err
	}
	if !spec.ExpiryDeadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.WithoutCancel(ctx), spec.ExpiryDeadline.Add(5*time.Second))
		defer cancel()
	}
	argv0 := ChildArgv0(spec.ShellPath, spec.Invocation.LoginShell)
	argv := append([]string{argv0}, spec.Invocation.Args...)

	// A nested interactive session has a real terminal even though logsh did not
	// allocate one; naming it is what lets this record be lined up against the
	// enclosing recorder's.
	meta := CollectMeta(TTYNameOf(spec.Std.In.Fd()), WinSize{}, spec.ShellPath, argv)
	meta.SessionID = spec.CmdLog.SessionID()
	meta.ApplyNesting(nesting)
	meta.ApplyAuthInfo(spec.Info, spec.Config.StripCertRealms)

	rec, err := StartEventRecorder(ctx, spec.Config, meta, captureStreams)
	if err != nil {
		return Outcome{}, unavailable(err)
	}
	defer func() { _ = rec.Close() }()

	spec.CmdLog.Bind(meta, rec.LogID())

	var wg sync.WaitGroup
	var pipes streamPipes
	var cmd *exec.Cmd
	var wireErr error

	build := func() *exec.Cmd {
		// Any previous attempt's pipes are spent along with its exec.Cmd, so the
		// streams are rewired per attempt rather than shared.
		closeAll(pipes.child)
		closeAll(pipes.drains)
		cmd = exec.Command(spec.ShellPath) // #nosec G204 -- see .golangci.yml; allowlisted by ResolveShell
		cmd.Args = argv
		cmd.Env = WithSessionEnv(PrepareEnv(os.Environ(), spec.EnvShell), spec.CmdLog.SessionID())
		pipes, wireErr = spec.wireStreams(cmd, rec, &wg, captureStreams)
		return cmd
	}

	child, stopExpiry, err := startSessionChild(build, spec, func() { closeAll(pipes.drains) }, func() error { return wireErr })
	if err != nil {
		closeAll(pipes.child)
		closeAll(pipes.drains)
		return Outcome{}, unavailable(err)
	}
	defer stopExpiry()
	defer func() { closeAll(pipes.drains) }()
	// Drop the parent's copies of the child's pipe ends, or the copying
	// goroutines never see EOF and the wait below never returns.
	closeAll(pipes.child)

	stopSignals := forwardSignals(cmd)
	defer stopSignals()

	outcome := child.Wait()
	if !spec.ExpiryDeadline.IsZero() {
		closeAll(pipes.stdin)
	}
	wg.Wait()
	stopExpiry()
	spec.CmdLog.End(outcome)

	if err := rec.Exit(ctx, outcome.ExitCode, outcome.Signal, outcome.CoreDumped); err != nil {
		return outcome, err
	}
	return outcome, nil
}

// wireStreams connects the child's three streams, teeing the ones being
// recorded. It returns the parent-side descriptors that must be closed after
// the child starts.
type streamPipes struct {
	child  []*os.File // parent's copies of child ends, closed after start
	drains []*os.File // owned relay descriptors, interrupted at expiry
	stdin  []*os.File // input relay, stopped when the child exits normally
}

func (spec RunSpec) wireStreams(cmd *exec.Cmd, rec *Recorder, wg *sync.WaitGroup, capture bool) (streamPipes, error) {
	var pipes streamPipes

	// Pass-through is the default and the fast path: handing os/exec the real
	// *os.File means the child inherits the descriptor with no copy at all.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Std.In, spec.Std.Out, spec.Std.Err

	if capture && spec.Config.LogStdin {
		pr, pw, err := os.Pipe()
		if err != nil {
			return pipes, err
		}
		pipes.child = append(pipes.child, pr)
		pipes.drains = append(pipes.drains, pw)
		pipes.stdin = append(pipes.stdin, pw)
		input := spec.Std.In
		if !spec.ExpiryDeadline.IsZero() {
			input, err = expiryFile(input, os.O_RDONLY, &pipes.drains)
			if err != nil {
				return pipes, err
			}
			if input != spec.Std.In {
				pipes.stdin = append(pipes.stdin, input)
			}
		}
		cmd.Stdin = pr
		wg.Go(func() {
			defer func() { _ = pw.Close() }()
			copyRecording(pw, input, func(b []byte) { _ = rec.Stream("stdin", b) })
		})
	}
	if capture && spec.Config.LogStdout {
		pr, pw, err := os.Pipe()
		if err != nil {
			return pipes, err
		}
		pipes.drains = append(pipes.drains, pr)
		cmd.Stdout = pw
		pipes.child = append(pipes.child, pw)
		output := spec.Std.Out
		if !spec.ExpiryDeadline.IsZero() {
			output, err = expiryFile(output, os.O_WRONLY, &pipes.drains)
			if err != nil {
				return pipes, err
			}
		}
		wg.Go(func() {
			defer func() { _ = pr.Close() }()
			copyRecording(output, pr, func(b []byte) { _ = rec.Stream("stdout", b) })
		})
	}
	if capture && spec.Config.LogStderr {
		pr, pw, err := os.Pipe()
		if err != nil {
			return pipes, err
		}
		pipes.drains = append(pipes.drains, pr)
		cmd.Stderr = pw
		pipes.child = append(pipes.child, pw)
		output := spec.Std.Err
		if !spec.ExpiryDeadline.IsZero() {
			output, err = expiryFile(output, os.O_WRONLY, &pipes.drains)
			if err != nil {
				return pipes, err
			}
		}
		wg.Go(func() {
			defer func() { _ = pr.Close() }()
			copyRecording(output, pr, func(b []byte) { _ = rec.Stream("stderr", b) })
		})
	}
	return pipes, nil
}

func closeAll(fs []*os.File) {
	for _, f := range fs {
		_ = f.Close()
	}
}

// copyRecording copies src to dst, handing each chunk to record on the way.
func copyRecording(dst io.Writer, src io.Reader, record func([]byte)) {
	buf := make([]byte, relayBufSize)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			record(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// StartEventRecorder opens a sink for a non-interactive session.
//
// expect_iobufs is set only when a stream is actually being captured. With it
// false the server stores a metadata-only record and -- crucially -- sends no
// reply at all, neither a log id nor a commit point. The sinks know not to wait;
// see streamSink.expectAck.
func StartEventRecorder(ctx context.Context, cfg *Config, meta SessionMeta, expectIobufs bool) (*Recorder, error) {
	sink, err := OpenSink(ctx, cfg)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	accept := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   timeSpec(now),
		InfoMsgs:     meta.InfoMessages(),
		ExpectIobufs: expectIobufs,
	}}}

	logID, err := sink.Start(ctx, accept)
	if err != nil {
		_ = sink.Close()
		return nil, err
	}
	return &Recorder{sink: sink, cfg: cfg, start: now, last: now, logID: logID}, nil
}

// Stream records a buffer on one of the non-tty streams.
func (r *Recorder) Stream(name string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	buf := append([]byte(nil), data...)
	return r.send(func(d *pb.TimeSpec) *pb.ClientMessage {
		io := &pb.IoBuffer{Delay: d, Data: buf}
		switch name {
		case "stdin":
			return &pb.ClientMessage{Type: &pb.ClientMessage_StdinBuf{StdinBuf: io}}
		case "stdout":
			return &pb.ClientMessage{Type: &pb.ClientMessage_StdoutBuf{StdoutBuf: io}}
		default:
			return &pb.ClientMessage{Type: &pb.ClientMessage_StderrBuf{StderrBuf: io}}
		}
	})
}

// interruptibleSignals are forwarded to a non-interactive child.
//
// There is no pty here, so there is no tty driver to turn a ^C into a signal for
// the child: logsh is simply another process in the same process group, and
// whatever kills it must be passed along by hand. Without this, `ssh host
// 'long-running'` interrupted from the client would leave the command running on
// the server after the connection dropped.
var interruptibleSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// forwardSignals relays termination signals to the child. The returned function
// stops the relay.
func forwardSignals(cmd *exec.Cmd) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, interruptibleSignals...)
	done := make(chan struct{})
	var once sync.Once

	go func() {
		for {
			select {
			case sig := <-ch:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	return func() { once.Do(func() { signal.Stop(ch); close(done) }) }
}
