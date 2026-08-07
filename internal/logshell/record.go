// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/record.go
package logshell

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sudosrv/internal/logsrvclient"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"time"
)

// SessionMeta is everything the log server needs to describe a session. The
// field set is exactly the info keys internal/storage consumes, so a session
// recorded by logsh produces the same on-disk shape as one recorded by sudo and
// replays under sudoreplay unchanged.
//
// There is no privilege transition here the way there is for sudo: logsh runs as
// the logging-in user and execs their shell as the same user. The run* values
// therefore equal the submit* values. They are still sent, because the server
// and sudoreplay both expect them and an absent runuser would leave the path
// escapes and the `log` summary with empty fields.
type SessionMeta struct {
	User  string
	UID   int
	Group string
	GID   int
	Home  string
	Host  string
	Cwd   string

	// TTYName is the INNER pty, not the outer one.
	//
	// That is the terminal the shell and everything under it actually see, so it
	// is what sudo running inside this session will report as its own tty. Using
	// the outer name would make the two records impossible to correlate, which
	// is the only handle anyone has on the double-recording that happens when
	// `sudo -i` runs inside a recorded shell.
	TTYName string

	Rows, Cols uint16

	// Command is the real shell; Argv is how it was invoked, argv[0] included.
	Command string
	Argv    []string
}

// CollectMeta gathers session metadata for the current process.
//
// A failure to resolve the user's name or group is not fatal. logsh is a static
// binary, so os/user cannot consult NSS and an LDAP account resolves to nothing;
// recording a session with a numeric identity is enormously better than refusing
// to record it, and the uid is authoritative regardless.
func CollectMeta(ttyName string, size WinSize, shellPath string, argv []string) SessionMeta {
	uid, gid := os.Getuid(), os.Getgid()

	meta := SessionMeta{
		UID:     uid,
		GID:     gid,
		TTYName: ttyName,
		Rows:    size.Rows,
		Cols:    size.Cols,
		Command: shellPath,
		Argv:    argv,
	}

	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		meta.User = u.Username
		meta.Home = u.HomeDir
	}
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		meta.Group = g.Name
	}
	if h, err := os.Hostname(); err == nil {
		meta.Host = h
	}
	if cwd, err := os.Getwd(); err == nil {
		meta.Cwd = cwd
	}
	return meta
}

func strInfo(key, val string) *pb.InfoMessage {
	return &pb.InfoMessage{Key: key, Value: &pb.InfoMessage_Strval{Strval: val}}
}

func numInfo(key string, val int64) *pb.InfoMessage {
	return &pb.InfoMessage{Key: key, Value: &pb.InfoMessage_Numval{Numval: val}}
}

// InfoMessages renders the metadata in the encoding sudo itself uses: names as
// strval, ids and dimensions as numval, argv as a string list. The server
// coerces either scalar form to a string, but matching C keeps a transcript
// recorded here byte-comparable with one recorded by sudo.
func (m SessionMeta) InfoMessages() []*pb.InfoMessage {
	return []*pb.InfoMessage{
		strInfo("submituser", m.User),
		numInfo("submituid", int64(m.UID)),
		strInfo("submitgroup", m.Group),
		numInfo("submitgid", int64(m.GID)),
		strInfo("submithost", m.Host),
		strInfo("submitcwd", m.Cwd),

		strInfo("runuser", m.User),
		numInfo("runuid", int64(m.UID)),
		strInfo("rungroup", m.Group),
		numInfo("rungid", int64(m.GID)),
		strInfo("runcwd", m.Cwd),
		strInfo("runhome", m.Home),

		strInfo("ttyname", m.TTYName),
		numInfo("lines", int64(m.Rows)),
		numInfo("columns", int64(m.Cols)),

		strInfo("command", m.Command),
		{Key: "runargv", Value: &pb.InfoMessage_Strlistval{
			Strlistval: &pb.InfoMessage_StringList{Strings: m.Argv},
		}},
	}
}

// Recorder streams one session to the log server.
//
// All methods are safe for concurrent use: the ttyin and ttyout relay directions
// run on separate goroutines and both send. The mutex covers the delay
// computation as well as the write, because a delay is a delta from the previous
// event -- computing it outside the lock would let two events interleave and
// produce a transcript whose timings do not add up.
type Recorder struct {
	proc  protocol.Processor
	cfg   Config
	start time.Time

	mu   sync.Mutex
	last time.Time // when the previous event was sent
	sent bool      // an ExitMessage has been sent; further events are dropped

	logID string
}

// StartRecorder connects to the log server, sends the AcceptMessage and waits
// for the log_id that acknowledges it.
//
// Waiting is correct HERE and only here. An I/O session (expect_iobufs=true) is
// acknowledged with a log_id; an event-only one never is, and blocking for a
// reply that is not coming would hang the session forever. See ReadAck.
func StartRecorder(ctx context.Context, cfg Config, meta SessionMeta) (*Recorder, error) {
	proc, err := logsrvclient.Connect(ctx, cfg.ClientConfig())
	if err != nil {
		return nil, err
	}

	now := time.Now()
	accept := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   timeSpec(now),
		InfoMsgs:     meta.InfoMessages(),
		ExpectIobufs: true,
	}}}

	if err := cfg.ClientConfig().WithTimeout(ctx, func(opCtx context.Context) error {
		return proc.WriteClientMessageContext(opCtx, accept)
	}); err != nil {
		_ = proc.Close()
		return nil, fmt.Errorf("send AcceptMessage: %w", err)
	}

	var logID string
	if err := cfg.ClientConfig().WithTimeout(ctx, func(opCtx context.Context) error {
		srv, readErr := proc.ReadServerMessageContext(opCtx)
		if readErr != nil {
			return readErr
		}
		switch m := srv.Type.(type) {
		case *pb.ServerMessage_LogId:
			logID = m.LogId
			return nil
		case *pb.ServerMessage_Error:
			return fmt.Errorf("%w: %s", logsrvclient.ErrUpstreamRejected, m.Error)
		case *pb.ServerMessage_Abort:
			return fmt.Errorf("%w (abort): %s", logsrvclient.ErrUpstreamRejected, m.Abort)
		default:
			return fmt.Errorf("expected a log_id, got %T", srv.Type)
		}
	}); err != nil {
		_ = proc.Close()
		return nil, fmt.Errorf("AcceptMessage was not acknowledged: %w", err)
	}

	return &Recorder{proc: proc, cfg: cfg, start: now, last: now, logID: logID}, nil
}

// LogID is the server-assigned identifier for this session.
func (r *Recorder) LogID() string { return r.logID }

func timeSpec(t time.Time) *pb.TimeSpec {
	return &pb.TimeSpec{TvSec: t.Unix(), TvNsec: int32(t.Nanosecond())}
}

func durationSpec(d time.Duration) *pb.TimeSpec {
	if d < 0 {
		d = 0
	}
	return &pb.TimeSpec{TvSec: int64(d / time.Second), TvNsec: int32(d % time.Second)}
}

// send writes one message, stamping it with the delay since the previous event.
func (r *Recorder) send(build func(delay *pb.TimeSpec) *pb.ClientMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sent {
		return nil
	}
	now := time.Now()
	msg := build(durationSpec(now.Sub(r.last)))
	r.last = now
	return r.proc.WriteClientMessage(msg)
}

// TTYOut records terminal output.
func (r *Recorder) TTYOut(data []byte) error {
	if !r.cfg.LogTTYOut || len(data) == 0 {
		return nil
	}
	buf := append([]byte(nil), data...)
	return r.send(func(d *pb.TimeSpec) *pb.ClientMessage {
		return &pb.ClientMessage{Type: &pb.ClientMessage_TtyoutBuf{
			TtyoutBuf: &pb.IoBuffer{Delay: d, Data: buf},
		}}
	})
}

// TTYIn records terminal input.
//
// Off by default, and worth restating why that default means less than it looks:
// terminal echo puts nearly every keystroke into the ttyout stream anyway.
// Disabling ttyin protects only the moments echo is off, which is to say
// password prompts -- which the SERVER additionally masks on its own, by
// watching ttyout for a prompt and starring out the ttyin that follows.
func (r *Recorder) TTYIn(data []byte) error {
	if !r.cfg.LogTTYIn || len(data) == 0 {
		return nil
	}
	buf := append([]byte(nil), data...)
	return r.send(func(d *pb.TimeSpec) *pb.ClientMessage {
		return &pb.ClientMessage{Type: &pb.ClientMessage_TtyinBuf{
			TtyinBuf: &pb.IoBuffer{Delay: d, Data: buf},
		}}
	})
}

// WinSize records a terminal resize.
func (r *Recorder) WinSize(s WinSize) error {
	return r.send(func(d *pb.TimeSpec) *pb.ClientMessage {
		return &pb.ClientMessage{Type: &pb.ClientMessage_WinsizeEvent{
			WinsizeEvent: &pb.ChangeWindowSize{Delay: d, Rows: int32(s.Rows), Cols: int32(s.Cols)},
		}}
	})
}

// Exit sends the ExitMessage and waits for the server's final commit point.
//
// Waiting matters: the commit point is the server's statement that the session
// is durable. Returning before it means logsh can exit -- and sshd can tear the
// connection down -- while the transcript is still only in the server's memory.
func (r *Recorder) Exit(ctx context.Context, code int, signal string, coreDumped bool) error {
	r.mu.Lock()
	if r.sent {
		r.mu.Unlock()
		return nil
	}
	exit := &pb.ClientMessage{Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{
		RunTime:    durationSpec(time.Since(r.start)),
		ExitValue:  int32(code),
		Signal:     signal,
		DumpedCore: coreDumped,
	}}}
	r.sent = true
	r.mu.Unlock()

	if err := r.cfg.ClientConfig().WithTimeout(ctx, func(opCtx context.Context) error {
		return r.proc.WriteClientMessageContext(opCtx, exit)
	}); err != nil {
		return fmt.Errorf("send ExitMessage: %w", err)
	}
	return logsrvclient.ReadAck(ctx, r.proc, r.cfg.ClientConfig(), true)
}

// Close releases the connection. Safe to call after Exit.
func (r *Recorder) Close() error { return r.proc.Close() }
