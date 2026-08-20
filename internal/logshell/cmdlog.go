// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/cmdlog.go
package logshell

import (
	"fmt"
	"log/syslog"
	"strconv"
	"strings"
	"sudosrv/internal/eventlog"
	"sync"

	"uuid"
)

// The command log: one syslog record per command executed in the session,
// carrying a session UUID so the records can be pieced back together.
//
// It is deliberately INDEPENDENT of session recording. It has its own toggle, it
// writes to LOCAL syslog rather than to the log server, and it works whether the
// session is being recorded, journalled, or not recorded at all. The two answer
// different questions: the transcript shows what a session looked like, this
// shows what it ran, and the second is the one a SIEM can grep.
//
// The UUID is minted here rather than taken from the server's log id. The log id
// does not exist until the server acknowledges an accept -- which never happens
// for a journalled session, and never happens at all when recording is off -- so
// depending on it would make the command log stop working in exactly the
// situations it is most wanted. logsh also sends the UUID to the server as the
// `logsh_session` info key, and internal/storage copies every info key into
// log.json, so a recorded session carries the same identifier and the two sides
// join on it.

// CommandLogSyslogTag identifies these records. Distinct from SyslogTag ("logsh",
// used for the recorder complaining about itself) so a site can route command
// records to a SIEM without also shipping recorder diagnostics.
const CommandLogSyslogTag = "logsh-cmd"

// DefaultCommandLogMaxLen matches eventlog's syslog budget.
const DefaultCommandLogMaxLen = 960

// CommandLog writes command records for one session.
//
// A nil *CommandLog is usable and does nothing, so every call site can stay free
// of enabled-checks.
type CommandLog struct {
	// out is nil when the command log is disabled. Every method then no-ops,
	// which keeps enabled-checks out of the call sites -- but the value is still
	// real, because SessionID is needed whether or not anything is being logged.
	//
	// A function rather than the *syslog.Writer directly so tests can capture
	// records without a running syslogd.
	out       func(string)
	closer    func() error
	sessionID string
	maxLen    int

	mu     sync.Mutex
	prefix string
}

// CommandLogConfig is the command_log section.
type CommandLogConfig struct {
	// Enabled turns on exec tracing. Off by default: it is implemented with
	// ptrace, which costs a stop per exec and makes strace and gdb unusable
	// inside the session, so it should be a deliberate choice.
	Enabled bool `yaml:"enabled"`

	SyslogFacility string `yaml:"syslog_facility"`
	SyslogPriority string `yaml:"syslog_priority"`

	// MaxLen bounds one record. Over-long records are truncated with a visible
	// marker rather than split: a command line is a single fact, and half of one
	// arriving as a separate syslog record reads like a different command.
	MaxLen int `yaml:"max_len"`

	// Required refuses the session when tracing cannot be started, the same way
	// fail_closed treats recording. Off by default, because ptrace can be
	// blocked by a kernel setting logsh has no way to influence, and locking
	// every account out of a host over an audit ADD-ON is a poor trade.
	Required bool `yaml:"required"`
}

// OpenCommandLog mints the session UUID and, when the command log is enabled,
// opens syslog.
//
// It ALWAYS returns a usable value, even on error and even when disabled. The
// UUID has to exist regardless: it is attached to the recorded session as an
// info key, so a session recorded with the command log switched off still
// carries the identifier that a later switched-on session would be joined by.
func OpenCommandLog(cfg *Config, shellPath string) (*CommandLog, error) {
	c := &CommandLog{sessionID: uuid.NewV4().String(), maxLen: DefaultCommandLogMaxLen}
	if !cfg.CommandLog.Enabled {
		return c, nil
	}
	w, maxLen, err := dialCommandSyslog(cfg.CommandLog)
	if err != nil {
		return c, err
	}
	c.out = func(line string) { _, _ = w.Write([]byte(line)) }
	c.closer = w.Close
	c.maxLen = maxLen
	return c, nil
}

// SessionID is the UUID stamped on every record and attached to the recorded
// session.
func (c *CommandLog) SessionID() string {
	if c == nil {
		return ""
	}
	return c.sessionID
}

// Bind supplies the session metadata, which is only known once the pty exists,
// and emits the opening record.
func (c *CommandLog) Bind(meta SessionMeta, logID string) {
	if c == nil || c.out == nil {
		return
	}
	var b strings.Builder
	// The invariant fields go on EVERY record on purpose: a query that finds one
	// interesting command should not have to join against a separate
	// session-start record to learn who ran it.
	field(&b, "SESSION", c.sessionID)
	field(&b, "USER", meta.User)
	field(&b, "UID", strconv.Itoa(meta.UID))
	field(&b, "TTY", shortTTY(meta.TTYName))

	c.mu.Lock()
	c.prefix = b.String()
	c.mu.Unlock()

	c.Start(logID, meta.Command)
}

func dialCommandSyslog(cfg CommandLogConfig) (*syslog.Writer, int, error) {
	facility, err := eventlog.ParseFacility(cfg.SyslogFacility)
	if err != nil {
		return nil, 0, fmt.Errorf("command_log.syslog_facility: %w", err)
	}
	pri, err := eventlog.ParsePriority(cfg.SyslogPriority)
	if err != nil {
		return nil, 0, fmt.Errorf("command_log.syslog_priority: %w", err)
	}
	w, err := syslog.New(facility|syslog.Priority(pri), CommandLogSyslogTag)
	if err != nil {
		return nil, 0, fmt.Errorf("connect to syslog: %w", err)
	}
	maxLen := cfg.MaxLen
	if maxLen <= 0 {
		maxLen = DefaultCommandLogMaxLen
	}
	return w, maxLen, nil
}

// field appends a " ; KEY=value" pair, escaped.
func field(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	if b.Len() > 0 {
		b.WriteString(" ; ")
	}
	b.WriteString(key)
	b.WriteString("=")
	b.WriteString(eventlog.EscapeControl(val))
}

// shortTTY trims the /dev/ prefix the way sudo's logs do.
func shortTTY(tty string) string { return strings.TrimPrefix(tty, "/dev/") }

// Exec records one executed command.
func (c *CommandLog) Exec(e ExecEvent) {
	if c == nil || c.out == nil {
		return
	}
	var b strings.Builder
	b.WriteString(c.head())
	field(&b, "PID", strconv.Itoa(e.PID))
	// EXE is the resolved binary and CMD is what argv actually said. They differ
	// whenever something is invoked through a symlink or a busybox-style
	// multi-call name -- which is precisely the case worth being able to see.
	if e.Exe != "" && (len(e.Argv) == 0 || e.Exe != e.Argv[0]) {
		field(&b, "EXE", e.Exe)
	}
	field(&b, "CMD", strings.Join(e.Argv, " "))
	c.write(b.String())
}

// Start records the beginning of a session, and ties the logsh UUID to the log
// server's own id when there is one.
func (c *CommandLog) Start(logID, command string) {
	if c == nil || c.out == nil {
		return
	}
	var b strings.Builder
	b.WriteString(c.head())
	field(&b, "EVENT", "start")
	field(&b, "TSID", logID)
	field(&b, "SHELL", command)
	c.write(b.String())
}

// End records how the session finished.
func (c *CommandLog) End(o Outcome) {
	if c == nil || c.out == nil {
		return
	}
	var b strings.Builder
	b.WriteString(c.head())
	field(&b, "EVENT", "end")
	field(&b, "EXIT", strconv.Itoa(o.ExitCode))
	field(&b, "SIGNAL", o.Signal)
	c.write(b.String())
}

// Note records something the operator needs to know about the command log
// itself, in the command-log stream so it cannot be missed by whoever is
// reading it.
func (c *CommandLog) Note(text string) {
	if c == nil || c.out == nil {
		return
	}
	var b strings.Builder
	b.WriteString(c.head())
	field(&b, "EVENT", "note")
	field(&b, "MSG", text)
	c.write(b.String())
}

// head returns the invariant prefix. Taken under the lock because Bind runs on
// the session goroutine while Exec runs on the tracer's locked thread.
func (c *CommandLog) head() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prefix
}

func (c *CommandLog) write(line string) {
	if len(line) > c.maxLen {
		// Say so in the record. A silently clipped audit line is one somebody
		// will later read as the whole command.
		marker := fmt.Sprintf("...[truncated, %d bytes]", len(line))
		keep := max(c.maxLen-len(marker), 0)
		line = line[:keep] + marker
	}
	c.out(line)
}

// Close releases the syslog connection.
func (c *CommandLog) Close() error {
	if c == nil || c.closer == nil {
		return nil
	}
	return c.closer()
}
