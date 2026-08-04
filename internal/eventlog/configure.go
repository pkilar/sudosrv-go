// SPDX-License-Identifier: Apache-2.0
// Filename: internal/eventlog/configure.go
package eventlog

import (
	"fmt"
	"log/slog"
	"os"
	"sudosrv/internal/config"
)

// Settings is the resolved event-log configuration, decoupled from the YAML
// shape so this package does not depend on the exact field names.
type Settings struct {
	Type           string
	Format         string
	LogExit        bool
	Facility       string
	AcceptPriority string
	RejectPriority string
	AlertPriority  string
	SyslogMaxLen   int
	FilePath       string
	FileTimeFormat string
	FileMode       os.FileMode
}

// SettingsFrom maps the loaded configuration onto Settings.
func SettingsFrom(cfg *config.Config) Settings {
	return Settings{
		Type:           cfg.EventLog.LogType,
		Format:         cfg.EventLog.LogFormat,
		LogExit:        cfg.EventLog.LogExit,
		Facility:       cfg.Syslog.Facility,
		AcceptPriority: cfg.Syslog.AcceptPriority,
		RejectPriority: cfg.Syslog.RejectPriority,
		AlertPriority:  cfg.Syslog.AlertPriority,
		SyslogMaxLen:   cfg.Syslog.MaxLen,
		FilePath:       cfg.LogFile.Path,
		FileTimeFormat: cfg.LogFile.TimeFormat,
		FileMode:       os.FileMode(cfg.LocalStorage.EffectiveFileMode()),
	}
}

// normalize fills blanks left by a Settings built in code rather than loaded
// from YAML.
//
// An empty Type means OFF here, not "use the default". That looks backwards
// next to config.applyZeroValueDefaults, which turns an empty log_type into
// "syslog" -- but the two never see the same value. Anything that came from a
// config file has already been through applyZeroValueDefaults, so a blank Type
// can only come from a Config assembled in code (tests, embedded use), where
// silently dialling syslog would be a side effect nobody asked for.
func (s Settings) normalize() Settings {
	if s.Type == "" {
		s.Type = TypeNone
	}
	if s.Format == "" {
		s.Format = FormatSudo
	}
	if s.Facility == "" {
		s.Facility = "authpriv"
	}
	if s.AcceptPriority == "" {
		s.AcceptPriority = "notice"
	}
	if s.RejectPriority == "" {
		s.RejectPriority = "alert"
	}
	if s.AlertPriority == "" {
		s.AlertPriority = "alert"
	}
	if s.SyslogMaxLen == 0 {
		s.SyslogMaxLen = DefaultSyslogMaxLen
	}
	if s.FileMode == 0 {
		s.FileMode = 0600
	}
	return s
}

// Validate checks the settings without opening anything, so a bad value fails
// the config load rather than the first event. C behaves the same way: an
// unknown facility or priority aborts the load
// (logsrvd/logsrvd_conf.c:986-1064).
func Validate(s Settings) error {
	s = s.normalize()
	switch s.Type {
	case TypeNone, TypeSyslog, TypeLogfile:
	default:
		return fmt.Errorf("eventlog.log_type %q is not one of none, syslog, logfile", s.Type)
	}
	switch s.Format {
	case FormatSudo, FormatJSON:
	default:
		return fmt.Errorf("eventlog.log_format %q is not one of sudo, json", s.Format)
	}
	if s.Type == TypeSyslog {
		if _, err := ParseFacility(s.Facility); err != nil {
			return fmt.Errorf("syslog.facility: %w", err)
		}
		if s.SyslogMaxLen < 1 {
			return fmt.Errorf("syslog.maxlen is %d; the minimum is 1", s.SyslogMaxLen)
		}
	}
	for name, value := range map[string]string{
		"syslog.accept_priority": s.AcceptPriority,
		"syslog.reject_priority": s.RejectPriority,
		"syslog.alert_priority":  s.AlertPriority,
	} {
		if _, err := ParsePriority(value); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if s.Type == TypeLogfile && s.FilePath == "" {
		return fmt.Errorf("eventlog.log_type is logfile but logfile.path is empty")
	}
	return nil
}

// Configure installs the sink described by s, replacing and closing any
// previous one. It is called at startup and again on SIGHUP.
//
// A failure to open the destination is returned rather than swallowed. C treats
// it the same way: "a failure to open the event log file aborts the apply"
// (logsrvd/logsrvd_conf.c:1834-1850).
func (l *Logger) Configure(s Settings) error {
	if err := Validate(s); err != nil {
		return err
	}
	s = s.normalize()

	priority := map[EventType]int{}
	for t, name := range map[EventType]string{
		Accept: s.AcceptPriority,
		Reject: s.RejectPriority,
		Alert:  s.AlertPriority,
		// C emits the exit record through the same path as accept, so it
		// inherits accept_priority rather than having a knob of its own.
		Exit: s.AcceptPriority,
	} {
		p, err := ParsePriority(name)
		if err != nil {
			return err
		}
		priority[t] = p
	}

	var newSink sink
	switch s.Type {
	case TypeNone:
		newSink = nil
	case TypeSyslog:
		facility, err := ParseFacility(s.Facility)
		if err != nil {
			return err
		}
		newSink = newSyslogSink(facility, s.SyslogMaxLen)
	case TypeLogfile:
		fs, err := newFileSink(s.FilePath, s.FileTimeFormat, s.FileMode)
		if err != nil {
			return fmt.Errorf("eventlog: cannot open %s: %w", s.FilePath, err)
		}
		newSink = fs
	}

	previous := l.sink.Swap(&activeSink{
		sink:     newSink,
		format:   s.Format,
		logExit:  s.LogExit,
		priority: priority,
	})
	if previous != nil && previous.sink != nil {
		if err := previous.sink.close(); err != nil {
			slog.Warn("Event log: closing the previous sink failed", "error", err)
		}
	}
	return nil
}
