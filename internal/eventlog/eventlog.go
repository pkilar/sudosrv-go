// SPDX-License-Identifier: Apache-2.0
// Filename: internal/eventlog/eventlog.go

// Package eventlog emits sudo's EVENT log -- the one-line-per-command audit
// record saying who ran what, as distinct from this daemon's own operational
// log (slog) and from the I/O session transcripts under local_storage.
//
// sudo_logsrvd writes this stream by default, to syslog, at the authpriv
// facility (logsrvd/logsrvd_conf.c:919-934, 1706, 1834-1850). Sites migrating
// from it arrive with SIEM forwarders and syslog rules already written against
// that stream; without it the only central record of an accepted command is the
// on-disk session tree, which nothing is watching in real time.
//
// Conformance: docs/logsrvd-reference/ CONF-058 through CONF-064.
package eventlog

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// EventType selects the syslog priority and appears in JSON output.
type EventType string

const (
	Accept EventType = "accept"
	Reject EventType = "reject"
	Alert  EventType = "alert"
	Exit   EventType = "exit"
)

// Event is one audit record. Fields map onto C's struct eventlog; an empty
// string means "absent" and is omitted from the formatted line, matching C,
// which skips every NULL member of the record.
type Event struct {
	Type       EventType
	Time       time.Time
	SubmitUser string
	SubmitHost string
	TTYName    string
	RunChroot  string
	RunCwd     string
	RunUser    string
	RunGroup   string
	Command    string
	TSID       string // the server's log ID for the session, C's iolog_file
	Reason     string // reject/alert text
	ExitValue  string
	Signal     string
}

// FromInfoMap builds an Event from an AcceptMessage's info_msgs, which arrive
// as the flat key/value map the protocol layer produces.
func FromInfoMap(t EventType, info map[string]string) *Event {
	return &Event{
		Type:       t,
		SubmitUser: info["submituser"],
		SubmitHost: info["submithost"],
		TTYName:    info["ttyname"],
		RunChroot:  info["runchroot"],
		RunCwd:     info["runcwd"],
		RunUser:    info["runuser"],
		RunGroup:   info["rungroup"],
		Command:    info["command"],
	}
}

// shortTTY drops a leading /dev/, as C does for sudo-format lines
// (lib/eventlog/eventlog.c, "Sudo-format logs use the short form of the
// ttyname").
func shortTTY(tty string) string {
	return strings.TrimPrefix(tty, "/dev/")
}

// escapeControl renders control characters as C does, in octal #0nn form
// (LBUF_ESC_CNTRL). Without this a command name containing a newline could
// forge additional log lines, which is the whole reason C escapes here.
func escapeControl(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&b, "#%03o", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SudoLine renders the event in sudo's traditional format: the semicolon-
// separated KEY=value sequence built by new_logline (lib/eventlog/eventlog.c).
// The submituser prefix is NOT included -- both sinks add it themselves, which
// is how C splits the work between new_logline and do_syslog_sudo /
// do_logfile_sudo.
func (e *Event) SudoLine() string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+escapeControl(v))
		}
	}
	if e.Reason != "" {
		parts = append(parts, escapeControl(e.Reason))
	}
	add("HOST", e.SubmitHost)
	add("TTY", shortTTY(e.TTYName))
	add("CHROOT", e.RunChroot)
	add("PWD", e.RunCwd)
	add("USER", e.RunUser)
	add("GROUP", e.RunGroup)
	add("TSID", e.TSID)
	if e.ExitValue != "" {
		add("EXIT", e.ExitValue)
	}
	add("SIGNAL", e.Signal)
	add("COMMAND", e.Command)
	return strings.Join(parts, " ; ")
}

// JSONLine renders the event as one compact JSON object.
//
// This is a deliberate divergence from C, whose log_format: json is currently an
// alias for json_pretty and rewrites the entire file as a single JSON object on
// every event (logsrvd/logsrvd_conf.c:936-954). That shape cannot be tailed,
// cannot be appended to by two processes, and cannot be shipped line-by-line --
// all three of which are what an event stream is for. One object per line is the
// format every log shipper already understands.
// Conformance: docs/logsrvd-reference/ CONF-059.
func (e *Event) JSONLine() string {
	rec := map[string]any{
		"event":     string(e.Type),
		"timestamp": e.Time.UTC().Format(time.RFC3339Nano),
	}
	for k, v := range map[string]string{
		"submituser": e.SubmitUser,
		"submithost": e.SubmitHost,
		"ttyname":    e.TTYName,
		"runchroot":  e.RunChroot,
		"runcwd":     e.RunCwd,
		"runuser":    e.RunUser,
		"rungroup":   e.RunGroup,
		"command":    e.Command,
		"tsid":       e.TSID,
		"reason":     e.Reason,
		"exit_value": e.ExitValue,
		"signal":     e.Signal,
	} {
		if v != "" {
			rec[k] = v
		}
	}
	// Only map[string]any of strings, so marshalling cannot fail.
	b, _ := json.Marshal(rec)
	return string(b)
}

// Logger is the process-wide event log. A nil sink discards everything, which
// is what log_type: none selects and also the state before Configure runs, so
// no call site has to nil-check.
type Logger struct {
	sink atomic.Pointer[activeSink]
}

// activeSink pairs the destination with the settings that shape what reaches it.
type activeSink struct {
	sink     sink
	format   string // "sudo" or "json"
	logExit  bool
	priority map[EventType]int // -1 disables that class, matching C's "none"
}

// Global is the process-wide event logger, in the same shape as metrics.Global.
// Configure installs a sink; until it does, Log discards.
var Global = &Logger{}

// Log emits one event. It never blocks on a slow sink for long and never
// returns an error: an audit stream that fails must not take down the session
// it is describing, which is also C's posture (a failed event log write warns
// and the command still runs).
func (l *Logger) Log(e *Event) {
	active := l.sink.Load()
	if active == nil || active.sink == nil {
		return
	}
	if e.Type == Exit && !active.logExit {
		return
	}
	pri, ok := active.priority[e.Type]
	if !ok || pri < 0 {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	line := e.SudoLine()
	if active.format == "json" {
		line = e.JSONLine()
	}
	active.sink.write(pri, e.SubmitUser, line, e.Time)
}

// Close releases the current sink. Safe to call when none is installed.
func (l *Logger) Close() error {
	active := l.sink.Swap(nil)
	if active == nil || active.sink == nil {
		return nil
	}
	return active.sink.close()
}
