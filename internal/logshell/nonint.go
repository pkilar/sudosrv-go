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
func RunNonInteractive(ctx context.Context, cfg *Config, inv Invocation, shellPath string, std StdIO) (Outcome, error) {
	argv0 := ChildArgv0(shellPath, inv.LoginShell)
	argv := append([]string{argv0}, inv.Args...)

	meta := CollectMeta("", WinSize{}, shellPath, argv)

	rec, err := StartEventRecorder(ctx, cfg, meta)
	if err != nil {
		return Outcome{}, unavailable(err)
	}
	defer func() { _ = rec.Close() }()

	cmd := exec.Command(shellPath) // #nosec G204 -- see .golangci.yml; allowlisted by ResolveShell
	cmd.Args = argv
	cmd.Env = PrepareEnv(os.Environ(), shellPath)

	var wg sync.WaitGroup
	closers, err := wireStreams(cmd, std, cfg, rec, &wg)
	if err != nil {
		return Outcome{}, unavailable(err)
	}

	if err := cmd.Start(); err != nil {
		closeAll(closers)
		return Outcome{}, unavailable(err)
	}
	// Drop the parent's copies of the child's pipe ends, or the copying
	// goroutines never see EOF and the wait below never returns.
	closeAll(closers)

	stopSignals := forwardSignals(cmd)
	defer stopSignals()

	outcome := waitOutcome(cmd)
	wg.Wait()

	if err := rec.Exit(ctx, outcome.ExitCode, outcome.Signal, outcome.CoreDumped); err != nil {
		return outcome, err
	}
	return outcome, nil
}

// wireStreams connects the child's three streams, teeing the ones being
// recorded. It returns the parent-side descriptors that must be closed after
// the child starts.
func wireStreams(cmd *exec.Cmd, std StdIO, cfg *Config, rec *Recorder, wg *sync.WaitGroup) ([]*os.File, error) {
	var closers []*os.File

	// Pass-through is the default and the fast path: handing os/exec the real
	// *os.File means the child inherits the descriptor with no copy at all.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = std.In, std.Out, std.Err

	if cfg.LogStdin {
		pr, pw, err := os.Pipe()
		if err != nil {
			return closers, err
		}
		cmd.Stdin = pr
		closers = append(closers, pr)
		wg.Go(func() {
			defer func() { _ = pw.Close() }()
			copyRecording(pw, std.In, func(b []byte) { _ = rec.Stream("stdin", b) })
		})
	}
	if cfg.LogStdout {
		pr, pw, err := os.Pipe()
		if err != nil {
			return closers, err
		}
		cmd.Stdout = pw
		closers = append(closers, pw)
		wg.Go(func() {
			defer func() { _ = pr.Close() }()
			copyRecording(std.Out, pr, func(b []byte) { _ = rec.Stream("stdout", b) })
		})
	}
	if cfg.LogStderr {
		pr, pw, err := os.Pipe()
		if err != nil {
			return closers, err
		}
		cmd.Stderr = pw
		closers = append(closers, pw)
		wg.Go(func() {
			defer func() { _ = pr.Close() }()
			copyRecording(std.Err, pr, func(b []byte) { _ = rec.Stream("stderr", b) })
		})
	}
	return closers, nil
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
func StartEventRecorder(ctx context.Context, cfg *Config, meta SessionMeta) (*Recorder, error) {
	sink, err := OpenSink(ctx, cfg)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	accept := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   timeSpec(now),
		InfoMsgs:     meta.InfoMessages(),
		ExpectIobufs: cfg.recordsAnyStream(),
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
