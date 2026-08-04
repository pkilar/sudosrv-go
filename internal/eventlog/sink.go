// SPDX-License-Identifier: Apache-2.0
// Filename: internal/eventlog/sink.go
package eventlog

import (
	"fmt"
	"log/slog"
	"log/syslog"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// sink is a destination for formatted event lines.
type sink interface {
	write(priority int, submitUser, line string, when time.Time)
	close() error
}

// LogTypes and formats accepted by Configure, matching C's case-sensitive
// literals (logsrvd/logsrvd_conf.c:919-934, 936-954).
const (
	TypeNone    = "none"
	TypeSyslog  = "syslog"
	TypeLogfile = "logfile"

	FormatSudo = "sudo"
	FormatJSON = "json"
)

// DefaultSyslogMaxLen is C's MAXSYSLOGLEN.
const DefaultSyslogMaxLen = 960

// defaultLogfileTimeFormat is C's default [logfile] time_format "%h %e %T",
// rendered in Go's reference layout. %e is space-padded, which "_2" gives.
const defaultLogfileTimeFormat = "Jan _2 15:04:05"

// facilities is C's table (lib/util/logfac.c:41-72), matched case-sensitively.
var facilities = map[string]syslog.Priority{
	"authpriv": syslog.LOG_AUTHPRIV,
	"auth":     syslog.LOG_AUTH,
	"daemon":   syslog.LOG_DAEMON,
	"user":     syslog.LOG_USER,
	"local0":   syslog.LOG_LOCAL0,
	"local1":   syslog.LOG_LOCAL1,
	"local2":   syslog.LOG_LOCAL2,
	"local3":   syslog.LOG_LOCAL3,
	"local4":   syslog.LOG_LOCAL4,
	"local5":   syslog.LOG_LOCAL5,
	"local6":   syslog.LOG_LOCAL6,
	"local7":   syslog.LOG_LOCAL7,
}

// priorities is C's table (lib/util/logpri.c:41-67). "none" maps to -1, the
// sentinel that disables logging for that event class.
var priorities = map[string]int{
	"alert":   int(syslog.LOG_ALERT),
	"crit":    int(syslog.LOG_CRIT),
	"debug":   int(syslog.LOG_DEBUG),
	"emerg":   int(syslog.LOG_EMERG),
	"err":     int(syslog.LOG_ERR),
	"info":    int(syslog.LOG_INFO),
	"notice":  int(syslog.LOG_NOTICE),
	"warning": int(syslog.LOG_WARNING),
	"none":    -1,
}

// ParseFacility resolves a syslog facility name.
func ParseFacility(name string) (syslog.Priority, error) {
	f, ok := facilities[name]
	if !ok {
		return 0, fmt.Errorf("unknown syslog facility %s", name)
	}
	return f, nil
}

// ParsePriority resolves a syslog priority name, or -1 for "none".
func ParsePriority(name string) (int, error) {
	p, ok := priorities[name]
	if !ok {
		return 0, fmt.Errorf("unknown syslog priority %s", name)
	}
	return p, nil
}

// syslogSink writes to the local syslog daemon.
type syslogSink struct {
	facility syslog.Priority
	maxLen   int

	mu sync.Mutex
	// writers are opened lazily per priority: log/syslog binds the priority at
	// Dial time, so one connection per priority is the only way to emit at more
	// than one. C sidesteps this by calling syslog(3) directly.
	writers map[int]*syslog.Writer
}

func newSyslogSink(facility syslog.Priority, maxLen int) *syslogSink {
	if maxLen <= 0 {
		maxLen = DefaultSyslogMaxLen
	}
	return &syslogSink{facility: facility, maxLen: maxLen, writers: map[int]*syslog.Writer{}}
}

// writerFor returns the connection for one priority, dialling on first use.
func (s *syslogSink) writerFor(pri int) (*syslog.Writer, error) {
	if w, ok := s.writers[pri]; ok {
		return w, nil
	}
	// "sudo" is the tag C uses (openlog("sudo", 0, facility)), and SIEM rules
	// written for sudo_logsrvd match on it. Do not change it to "sudosrv".
	w, err := syslog.New(s.facility|syslog.Priority(pri), "sudo")
	if err != nil {
		return nil, err
	}
	s.writers[pri] = w
	return w, nil
}

// write emits one event, splitting over-long sudo-format lines the way C does.
func (s *syslogSink) write(pri int, submitUser, line string, _ time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	w, err := s.writerFor(pri)
	if err != nil {
		// One warning per event is noisy but a silent audit hole is worse.
		slog.Warn("Event log: cannot reach syslog", "error", err)
		return
	}
	for _, part := range splitSyslogLine(submitUser, line, s.maxLen) {
		if _, err := w.Write([]byte(part)); err != nil {
			slog.Warn("Event log: syslog write failed", "error", err)
			return
		}
	}
}

func (s *syslogSink) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for pri, w := range s.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(s.writers, pri)
	}
	return firstErr
}

// splitSyslogLine reproduces do_syslog_sudo's line breaking: the record is
// emitted as "%8s : %s" of submituser and the line, and anything longer than
// maxlen is broken at the last space that fits, with the remainder emitted as
// further messages under the same prefix.
//
// C's budget subtracts the format overhead and the user name from maxlen
// (lib/eventlog/eventlog.c do_syslog_sudo), which is what keeps the ASSEMBLED
// message within the limit rather than just its tail.
func splitSyslogLine(submitUser, line string, maxLen int) []string {
	prefix := fmt.Sprintf("%8s : ", submitUser)
	budget := maxLen - len(prefix)
	if budget < 1 {
		// A pathological maxlen/user combination. Emit whole rather than loop.
		return []string{prefix + line}
	}

	var out []string
	for len(line) > 0 {
		if len(line) <= budget {
			out = append(out, prefix+line)
			break
		}
		cut := strings.LastIndex(line[:budget], " ")
		if cut <= 0 {
			cut = budget
		}
		out = append(out, prefix+line[:cut])
		line = strings.TrimLeft(line[cut:], " ")
	}
	return out
}

// fileSink appends to a plain log file.
type fileSink struct {
	path       string
	timeFormat string

	mu sync.Mutex
	f  *os.File
}

func newFileSink(path, timeFormat string, mode os.FileMode) (*fileSink, error) {
	if timeFormat == "" {
		timeFormat = defaultLogfileTimeFormat
	}
	// O_NOFOLLOW matches C (do_logfile_sudo's open flags): the event log path is
	// operator-configured and a symlink planted there would redirect audit
	// records into a file of an attacker's choosing.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	return &fileSink{path: path, timeFormat: timeFormat, f: f}, nil
}

func (s *fileSink) write(_ int, submitUser, line string, when time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := fmt.Sprintf("%s : %s : %s\n", when.Format(s.timeFormat), submitUser, line)
	// flock, as C does (sudo_lock_file in do_logfile_sudo): O_APPEND alone keeps
	// writes from interleaving only up to PIPE_BUF, and an event line with a long
	// command can exceed that.
	if err := syscall.Flock(int(s.f.Fd()), syscall.LOCK_EX); err != nil {
		slog.Warn("Event log: cannot lock event log file", "path", s.path, "error", err)
		return
	}
	defer func() { _ = syscall.Flock(int(s.f.Fd()), syscall.LOCK_UN) }()

	if _, err := s.f.WriteString(record); err != nil {
		slog.Warn("Event log: write failed", "path", s.path, "error", err)
	}
}

func (s *fileSink) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
