// SPDX-License-Identifier: Apache-2.0
// Filename: internal/eventlog/eventlog_test.go
package eventlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleEvent() *Event {
	return &Event{
		Type:       Accept,
		Time:       time.Date(2026, 8, 4, 15, 4, 5, 0, time.UTC),
		SubmitUser: "alice",
		SubmitHost: "web01",
		TTYName:    "/dev/pts/3",
		RunCwd:     "/home/alice",
		RunUser:    "root",
		RunGroup:   "wheel",
		Command:    "/bin/ls -l",
		TSID:       "0000AB",
	}
}

// TestSudoLineFormat pins the field order and separators of C's new_logline
// (lib/eventlog/eventlog.c). SIEM rules written against sudo_logsrvd parse this
// shape, so a reordering is a silently broken integration, not a cosmetic change.
func TestSudoLineFormat(t *testing.T) {
	t.Parallel()
	got := sampleEvent().SudoLine()
	want := "HOST=web01 ; TTY=pts/3 ; PWD=/home/alice ; USER=root ; GROUP=wheel ; TSID=0000AB ; COMMAND=/bin/ls -l"
	if got != want {
		t.Errorf("SudoLine()\n got: %s\nwant: %s", got, want)
	}
}

// TestSudoLineOmitsAbsentFields matches C, which skips every NULL member rather
// than emitting an empty KEY=.
func TestSudoLineOmitsAbsentFields(t *testing.T) {
	t.Parallel()
	e := &Event{Type: Accept, SubmitUser: "bob", Command: "/bin/id"}
	if got, want := e.SudoLine(), "COMMAND=/bin/id"; got != want {
		t.Errorf("SudoLine() = %q, want %q", got, want)
	}
}

// TestSudoLineEscapesControlCharacters is a log-forging guard. Without the
// octal escaping C applies (LBUF_ESC_CNTRL), a command containing a newline
// writes what looks like a second, fabricated audit record.
func TestSudoLineEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	e := &Event{Type: Accept, SubmitUser: "mallory", Command: "/bin/echo\nAug  4 12:00:00 host sudo: root : COMMAND=/bin/sh"}
	got := e.SudoLine()
	if strings.Contains(got, "\n") {
		t.Errorf("newline survived into the log line, allowing a forged record: %q", got)
	}
	if !strings.Contains(got, "#012") {
		t.Errorf("newline should be escaped as #012, got %q", got)
	}
}

// TestRejectLinePutsReasonFirst matches C, which appends args->reason ahead of
// the KEY=value sequence.
func TestRejectLinePutsReasonFirst(t *testing.T) {
	t.Parallel()
	e := &Event{Type: Reject, SubmitUser: "eve", Reason: "user NOT in sudoers", Command: "/bin/sh"}
	if got, want := e.SudoLine(), "user NOT in sudoers ; COMMAND=/bin/sh"; got != want {
		t.Errorf("SudoLine() = %q, want %q", got, want)
	}
}

func TestJSONLineIsOneCompactObject(t *testing.T) {
	t.Parallel()
	line := sampleEvent().JSONLine()
	if strings.Contains(line, "\n") {
		t.Fatal("a JSON event must be exactly one line so log shippers can read it record-by-record")
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("JSONLine is not valid JSON: %v", err)
	}
	for k, want := range map[string]string{
		"event": "accept", "submituser": "alice", "runuser": "root", "command": "/bin/ls -l",
	} {
		if rec[k] != want {
			t.Errorf("field %q = %v, want %q", k, rec[k], want)
		}
	}
	if _, present := rec["reason"]; present {
		t.Error("absent fields must be omitted, not emitted empty")
	}
}

// TestSplitSyslogLine covers do_syslog_sudo's line breaking, including the part
// that is easy to get wrong: the budget is reduced by the "%8s : " prefix and
// the user name, so the ASSEMBLED message respects maxlen rather than just its
// tail.
func TestSplitSyslogLine(t *testing.T) {
	t.Parallel()
	const maxLen = 60
	long := "COMMAND=/bin/aaaa /bin/bbbb /bin/cccc /bin/dddd /bin/eeee /bin/ffff /bin/gggg"

	parts := splitSyslogLine("alice", long, maxLen)
	if len(parts) < 2 {
		t.Fatalf("expected the line to be split, got %d part(s)", len(parts))
	}
	for i, p := range parts {
		if len(p) > maxLen {
			t.Errorf("part %d is %d bytes, over the %d limit: %q", i, len(p), maxLen, p)
		}
		if !strings.HasPrefix(p, "   alice : ") {
			t.Errorf("part %d lost the user prefix: %q", i, p)
		}
	}
	// Nothing may be dropped in the split.
	var rejoined strings.Builder
	for i, p := range parts {
		if i > 0 {
			rejoined.WriteString(" ")
		}
		rejoined.WriteString(strings.TrimPrefix(p, "   alice : "))
	}
	if rejoined.String() != long {
		t.Errorf("splitting lost or altered content:\n got: %s\nwant: %s", rejoined.String(), long)
	}
}

func TestSplitSyslogLineShortLineIsNotSplit(t *testing.T) {
	t.Parallel()
	parts := splitSyslogLine("bob", "COMMAND=/bin/id", 960)
	if len(parts) != 1 {
		t.Fatalf("short line split into %d parts", len(parts))
	}
	if want := "     bob : COMMAND=/bin/id"; parts[0] != want {
		t.Errorf("got %q, want %q", parts[0], want)
	}
}

// TestFileSinkRoundTrip exercises the logfile destination end to end.
func TestFileSinkRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sudo.log")

	l := &Logger{}
	if err := l.Configure(Settings{
		Type:     TypeLogfile,
		Format:   FormatSudo,
		FilePath: path,
		FileMode: 0600,
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	l.Log(sampleEvent())

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "alice : HOST=web01") {
		t.Errorf("event line missing the user prefix or fields: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Error("event record must be newline-terminated")
	}
	if fi, statErr := os.Stat(path); statErr == nil && fi.Mode().Perm() != 0600 {
		t.Errorf("event log created with mode %o, want 0600", fi.Mode().Perm())
	}
}

// TestLogExitGate pins CONF-060: exit records are suppressed unless log_exit is
// set, so enabling the event log does not double every session's output.
func TestLogExitGate(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		logExit bool
		want    bool
	}{
		{"suppressed by default", false, false},
		{"emitted when enabled", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "sudo.log")
			l := &Logger{}
			if err := l.Configure(Settings{
				Type: TypeLogfile, Format: FormatSudo, FilePath: path, LogExit: tt.logExit, FileMode: 0600,
			}); err != nil {
				t.Fatalf("Configure: %v", err)
			}
			t.Cleanup(func() { _ = l.Close() })

			l.Log(&Event{Type: Exit, SubmitUser: "alice", Command: "/bin/ls", ExitValue: "0"})

			data, _ := os.ReadFile(path)
			if got := len(data) > 0; got != tt.want {
				t.Errorf("exit record emitted = %v, want %v (log_exit=%v)", got, tt.want, tt.logExit)
			}
		})
	}
}

// TestPriorityNoneDisablesAClass pins C's -1 sentinel: accept_priority: "none"
// must silence accepts while leaving rejects alone.
func TestPriorityNoneDisablesAClass(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sudo.log")
	l := &Logger{}
	if err := l.Configure(Settings{
		Type: TypeLogfile, Format: FormatSudo, FilePath: path, FileMode: 0600,
		AcceptPriority: "none", RejectPriority: "alert", AlertPriority: "alert",
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	l.Log(&Event{Type: Accept, SubmitUser: "alice", Command: "/bin/ls"})
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("accept_priority: none must suppress accepts, got %q", data)
	}
	l.Log(&Event{Type: Reject, SubmitUser: "eve", Command: "/bin/sh", Reason: "not allowed"})
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "not allowed") {
		t.Errorf("rejects must still be logged, got %q", data)
	}
}

// TestUnconfiguredLoggerDiscards is what lets every call site skip a nil check.
func TestUnconfiguredLoggerDiscards(t *testing.T) {
	t.Parallel()
	l := &Logger{}
	l.Log(sampleEvent()) // must not panic
	if err := l.Close(); err != nil {
		t.Errorf("Close on an unconfigured logger: %v", err)
	}
}

// TestValidateRejectsBadValues keeps a typo from silently disabling the audit
// stream, which is what C's "unknown syslog facility" abort prevents.
func TestValidateRejectsBadValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		s       Settings
		wantErr string
	}{
		{"unset type is off, not an error", Settings{}, ""},
		{"good syslog settings", Settings{Type: TypeSyslog, Format: FormatSudo}, ""},
		{"bad type", Settings{Type: "sysog"}, "log_type"},
		{"bad format", Settings{Type: TypeNone, Format: "yaml"}, "log_format"},
		{"bad facility", Settings{Type: TypeSyslog, Facility: "authprv"}, "facility"},
		{"bad priority", Settings{Type: TypeSyslog, AcceptPriority: "notic"}, "priority"},
		{"maxlen zero normalizes", Settings{Type: TypeSyslog}, ""},
		{"logfile without a path", Settings{Type: TypeLogfile}, "logfile.path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tt.s)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && err == nil:
				t.Errorf("want error containing %q, got nil", tt.wantErr)
			case tt.wantErr != "" && err != nil && !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("want error containing %q, got %q", tt.wantErr, err)
			}
		})
	}
}

// TestConfigureReplacesPreviousSink is the reload path: the old destination must
// be released, not leaked, and events must land in the new one.
func TestConfigureReplacesPreviousSink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := filepath.Join(dir, "first.log")
	second := filepath.Join(dir, "second.log")

	l := &Logger{}
	base := Settings{Type: TypeLogfile, Format: FormatSudo, FileMode: 0600}
	base.FilePath = first
	if err := l.Configure(base); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	l.Log(&Event{Type: Accept, SubmitUser: "alice", Command: "/bin/ls"})

	base.FilePath = second
	if err := l.Configure(base); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	l.Log(&Event{Type: Accept, SubmitUser: "bob", Command: "/bin/id"})

	firstData, _ := os.ReadFile(first)
	secondData, _ := os.ReadFile(second)
	if strings.Contains(string(firstData), "bob") {
		t.Error("event went to the old destination after reconfiguration")
	}
	if !strings.Contains(string(secondData), "bob") {
		t.Errorf("event did not reach the new destination, got %q", secondData)
	}
}
