// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/record.go
package logshell

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
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
	// User/UID/Group/GID are who the session RUNS as.
	User  string
	UID   int
	Group string
	GID   int
	Home  string
	Host  string
	Cwd   string

	// SubmitUser/UID/Group/GID are who INVOKED it, which is the same thing
	// except when sudo is in the chain.
	//
	// Keeping them apart matters for more than tidiness. Under `sudo -i` the
	// session runs as root but alice is the one at the keyboard, and a record
	// naming root in both fields cannot answer the only question anybody asks of
	// it. sudo's own logs make exactly this distinction; logsh reporting root as
	// the submitter was simply wrong.
	SubmitUser  string
	SubmitUID   int
	SubmitGroup string
	SubmitGID   int

	// Nested and ParentSession describe an enclosing recorder, if any.
	Nested        string
	ParentSession string

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

	// Source is the path to the logsh binary that recorded this session, and
	// answers "what produced this record?" A host can have sessions written by
	// sudo and by logsh in the same log store, and until now nothing in a logsh
	// record said which. It is the resolved binary, not the multi-call symlink
	// the user invoked -- the symlink name is a property of the account, while
	// this identifies the recorder.
	Source string

	// RunEnv is the environment recorded with the session, as KEY=VALUE.
	//
	// Deliberately NOT the whole environment. sudo can be configured to log it,
	// but an interactive login environment routinely carries API tokens, agent
	// sockets and proxy credentials, and this transcript is written to a log
	// store with a wider audience than the session had. What a replay actually
	// needs is TZ, without which every timestamp in the recording renders in
	// whatever timezone the person replaying it happens to be in.
	RunEnv []string

	// SessionID is logsh's own per-session UUID, minted locally rather than
	// taken from the server's log id -- that id does not exist for a journalled
	// session and does not exist at all when recording is off. It is sent as an
	// info key so a recorded session carries the same identifier the command log
	// stamps on every line, and the two can be joined.
	SessionID string
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
	// Submitter defaults to the runner; ApplyNesting corrects it under sudo.
	meta.SubmitUser, meta.SubmitUID = meta.User, uid
	meta.SubmitGroup, meta.SubmitGID = meta.Group, gid
	if h, err := os.Hostname(); err == nil {
		meta.Host = h
	}
	if cwd, err := os.Getwd(); err == nil {
		meta.Cwd = cwd
	}
	// os.Executable resolves /proc/self/exe on Linux, so an invocation through
	// the lbash symlink still reports the real binary. An error here is not
	// worth failing a login over; the key is simply omitted.
	if exe, err := os.Executable(); err == nil {
		meta.Source = exe
	}
	meta.RunEnv = []string{"TZ=" + timezoneName(localtimePath, timezoneFilePath)}
	return meta
}

// Paths consulted to resolve the system timezone when $TZ is unset. They are
// constants because nothing reassigns them: timezoneName takes the paths as
// arguments, which is what lets the tests point it at a fixture without
// mutating package state.
const (
	localtimePath    = "/etc/localtime"
	timezoneFilePath = "/etc/timezone"
)

// timezoneName reports the timezone to record with the session.
//
// $TZ wins and is passed through VERBATIM, including an empty value, which
// POSIX defines as UTC -- rewriting that would misreport the session.
//
// When $TZ is unset the value is DERIVED rather than omitted. That makes this
// entry not strictly a copy of the environment, which is the point: the session
// still ran in a definite timezone, and a transcript whose timestamps cannot be
// placed in one is materially harder to use as evidence. The derivation order
// is the one every distribution agrees on before it disagrees: the /etc/localtime
// symlink target, then Debian's /etc/timezone, then the zone abbreviation.
func timezoneName(localtime, timezoneFile string) string {
	if tz, ok := os.LookupEnv("TZ"); ok {
		return tz
	}
	if target, err := os.Readlink(localtime); err == nil {
		// .../zoneinfo/Europe/Berlin -> Europe/Berlin. The zoneinfo component is
		// what makes this a name rather than a path; without it there is nothing
		// to extract and the next source is tried.
		if _, name, found := strings.Cut(target, "zoneinfo/"); found && name != "" {
			return name
		}
	}
	if b, err := os.ReadFile(timezoneFile); err == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			return name
		}
	}
	// Last resort. An abbreviation like "CEST" is not a tzdata identifier and
	// cannot be looked up, but it is not nothing, and reaching here means the
	// host has no machine-readable answer to give.
	name, _ := time.Now().Zone()
	if name == "" {
		return "UTC"
	}
	return name
}

// ApplyNesting records an enclosing recorder and, under sudo, corrects the
// submitter to the account that escalated.
func (m *SessionMeta) ApplyNesting(n Nesting) {
	m.Nested = n.Kind.String()
	m.ParentSession = n.ParentSession

	if n.Kind != NestedSudo || n.SudoUser == "" {
		return
	}
	m.SubmitUser = n.SudoUser
	if n.SudoUID >= 0 {
		m.SubmitUID = n.SudoUID
	}
	if n.SudoGID >= 0 {
		m.SubmitGID = n.SudoGID
		if g, err := user.LookupGroupId(strconv.Itoa(n.SudoGID)); err == nil {
			m.SubmitGroup = g.Name
		} else {
			m.SubmitGroup = ""
		}
	}
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
	msgs := []*pb.InfoMessage{
		strInfo("submituser", m.SubmitUser),
		numInfo("submituid", int64(m.SubmitUID)),
		strInfo("submitgroup", m.SubmitGroup),
		numInfo("submitgid", int64(m.SubmitGID)),
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
		// internal/storage copies every info key into log.json, so this lands in
		// the recorded session's metadata without needing server-side support.
		strInfo("logsh_session", m.SessionID),
		strInfo("logsh_nested", m.Nested),
		strInfo("logsh_parent_session", m.ParentSession),
		{Key: "runargv", Value: &pb.InfoMessage_Strlistval{
			Strlistval: &pb.InfoMessage_StringList{Strings: m.Argv},
		}},
	}

	// Both are appended rather than listed above because an absent value must be
	// OMITTED, not sent empty: the server copies every key it receives straight
	// into log.json, so an empty string would write `"source": ""` and assert
	// that the recorder is unknown rather than that it was not determined. C
	// omits optional scalars whose struct member is NULL for the same reason
	// (IOLOG-023).
	if m.Source != "" {
		msgs = append(msgs, strInfo("source", m.Source))
	}
	if len(m.RunEnv) > 0 {
		msgs = append(msgs, &pb.InfoMessage{Key: "runenv", Value: &pb.InfoMessage_Strlistval{
			Strlistval: &pb.InfoMessage_StringList{Strings: m.RunEnv},
		}})
	}

	// submitenv is sent ALWAYS, and always empty. That is the opposite rule to
	// the two above, deliberately: they are omitted when unknown, whereas this
	// is a positive statement that no submit environment was recorded. C writes
	// all three arrays into log.json (IOLOG-023), so a consumer walking that
	// field set finds submitenv present and empty rather than having to guess
	// whether an absent key means "empty" or "this recorder does not send it".
	//
	// logsh has no separate submit environment to record in any case: it is the
	// login shell, so the environment it is exec'd with IS the session's. Under
	// sudo the submitter's environment belonged to a process that has already
	// been replaced, and sudo's own env_reset means what survives is not that
	// environment anyway.
	msgs = append(msgs, &pb.InfoMessage{Key: "submitenv", Value: &pb.InfoMessage_Strlistval{
		Strlistval: &pb.InfoMessage_StringList{Strings: []string{}},
	}})
	return msgs
}

// Recorder streams one session to the log server.
//
// All methods are safe for concurrent use: the ttyin and ttyout relay directions
// run on separate goroutines and both send. The mutex covers the delay
// computation as well as the write, because a delay is a delta from the previous
// event -- computing it outside the lock would let two events interleave and
// produce a transcript whose timings do not add up.
type Recorder struct {
	sink  Sink
	cfg   *Config
	start time.Time

	mu   sync.Mutex
	last time.Time // when the previous event was sent
	sent bool      // an ExitMessage has been sent; further events are dropped
	// elapsed is the running sum of the delays sent so far, which is exactly the
	// clock the server accumulates and reports back in commit points. It is what
	// tells the FINAL commit point apart from the interim ones the server emits
	// during a session -- see logsrvclient.ReadCommitAtLeast.
	elapsed time.Duration

	logID string
}

// StartRecorder opens a sink for the session and delivers its AcceptMessage.
//
// expect_iobufs is true here because this is an interactive transcript. That
// choice is what makes the log id meaningful: an I/O session is acknowledged
// with one, while an event-only session is never acknowledged at all. See
// logsrvclient.ReadAck.
func StartRecorder(ctx context.Context, cfg *Config, meta SessionMeta) (*Recorder, error) {
	sink, err := OpenSink(ctx, cfg)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	accept := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   timeSpec(now),
		InfoMsgs:     meta.InfoMessages(),
		ExpectIobufs: true,
	}}}

	logID, err := sink.Start(ctx, accept)
	if err != nil {
		_ = sink.Close()
		return nil, err
	}

	return &Recorder{sink: sink, cfg: cfg, start: now, last: now, logID: logID}, nil
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
	// Clamped: a backwards clock step would otherwise make the elapsed total
	// disagree with the server's, and the final commit point would never match.
	delta := max(now.Sub(r.last), 0)
	msg := build(durationSpec(delta))
	r.last = now
	r.elapsed += delta
	return r.sink.Send(msg)
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

// Exit sends the ExitMessage and waits for a commit point covering the whole
// session.
//
// Waiting matters: a commit point is the server's statement that everything up
// to that elapsed time is durable. Returning without one would let logsh exit,
// and sshd tear the connection down, while the transcript was still only in the
// server's memory.
//
// KNOWN RESIDUAL GAP, and it is small but real. The server emits a commit point
// on the first I/O event and every ACK_FREQUENCY after, then one more after
// processing the exit. When no time passes between the last output and the exit
// -- a shell that prints once and returns -- the interim commit point already
// covers the full elapsed clock, so it is indistinguishable from the final one
// by the only field the protocol gives us. Exit can therefore return on the
// interim one.
//
// What that costs is bounded: the TRANSCRIPT is durable either way, because the
// commit point that was accepted covers all of the I/O. Only the exit metadata
// -- exit_value, run_time, signal -- may be lost, and only if the daemon dies in
// the sub-millisecond window between the two. Closing it properly means draining
// server messages concurrently for the whole session, the way sudo's event loop
// does, which is a lot of machinery for that window in a login shell.
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

	if err := r.sink.Send(exit); err != nil {
		return fmt.Errorf("send ExitMessage: %w", err)
	}

	r.mu.Lock()
	elapsed := r.elapsed
	r.mu.Unlock()
	return r.sink.Finish(ctx, elapsed)
}

// Close releases the sink. Safe to call after Exit.
func (r *Recorder) Close() error { return r.sink.Close() }
