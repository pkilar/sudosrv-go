// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/breakglass.go
package logshell

import (
	"fmt"
	"log/syslog"
	"os"
	"syscall"
)

// SyslogTag identifies logsh's own alerts. It is deliberately NOT "sudo": these
// are the recorder complaining about itself, not session audit records, and a
// site's rules for the audit stream should not have to filter them out.
const SyslogTag = "logsh"

// Alertf reports a recording failure to local syslog and to the terminal.
//
// Local syslog is the destination on purpose. Every situation this function
// exists for is one where the log server could not be reached, so routing these
// through the log server would deliver exactly nothing exactly when it matters.
//
// A failure to reach syslog is swallowed rather than escalated: this is already
// the error path, and there is nowhere left to report to. The terminal message
// still goes out.
func Alertf(p syslog.Priority, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if w, err := syslog.New(p|syslog.LOG_AUTHPRIV, SyslogTag); err == nil {
		_, _ = w.Write([]byte(msg))
		_ = w.Close()
	}
	fmt.Fprintf(os.Stderr, "logsh: %s\n", msg)
}

// BreakGlassPath returns the marker path to consult.
//
// cfg may be nil, and that is the case this function exists for. When the
// configuration itself is what failed to load, the configured marker path is
// unknown, so the compiled-in default is used instead. Without that fallback a
// syntax error in logsh.yaml would disable the very escape hatch that exists to
// recover from a syntax error in logsh.yaml.
func BreakGlassPath(cfg *Config) string {
	if cfg != nil && cfg.BreakGlassMarker != "" {
		return cfg.BreakGlassMarker
	}
	return DefaultConfig().BreakGlassMarker
}

// BreakGlassActive reports whether the marker file is present and trustworthy.
//
// The marker forces fail-open, so it is itself a way to disable recording. It is
// honoured only when root owns it and no one else can write it -- otherwise any
// user who could create the file could opt themselves out of being recorded,
// which would make the whole mechanism decorative.
//
// A marker that exists but fails those checks is reported as INACTIVE and
// alerted about loudly. Silently treating it as absent would leave an
// administrator convinced they had opened the escape hatch when they had not.
func BreakGlassActive(cfg *Config) bool {
	path := BreakGlassPath(cfg)
	if path == "" {
		return false
	}
	st, err := os.Lstat(path)
	if err != nil {
		return false // absent is the normal case, and not noteworthy
	}
	if st.Mode()&os.ModeSymlink != 0 {
		Alertf(syslog.LOG_CRIT, "break-glass marker %s is a symlink and was ignored; "+
			"replace it with a real root-owned file", path)
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if sys.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		Alertf(syslog.LOG_CRIT, "break-glass marker %s is owned by uid %d with mode %04o and was "+
			"IGNORED; it must be root-owned and not group- or world-writable, or any user could "+
			"switch off their own recording", path, sys.Uid, st.Mode().Perm())
		return false
	}
	return true
}

// BreakGlassBanner is shown on the terminal when a session proceeds unrecorded
// because the marker is in place. It is deliberately loud: an administrator who
// forgets to remove the marker has silently disabled auditing for the fleet, and
// the only thing standing between that and a quiet six-month gap is somebody
// noticing this text.
const BreakGlassBanner = `
*******************************************************************************
*  SESSION RECORDING IS DISABLED on this host (break-glass marker present).    *
*  This session is NOT being recorded. Remove the marker to restore auditing.  *
*******************************************************************************
`
