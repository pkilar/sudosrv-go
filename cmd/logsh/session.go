// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/session.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"sudosrv/internal/logshell"
)

// session is a resolved session, ready to run.
//
// It is what the two entry points produce and runSession consumes. They differ
// entirely in how they arrive at it -- runShell looks up a shell by the name it
// was invoked under, runForceCommand routes an sshd-supplied command and reads a
// certificate -- and not at all in what happens afterwards. Naming that boundary
// is what lets the shared half be written once.
type session struct {
	// Config governs recording, the command log and the failure policy.
	Config *logshell.Config

	// Target is what to exec: the program, its argv, and the value to publish
	// as $SHELL. It is also what the unrecorded and break-glass paths run, so
	// an sftp session degrading through fail-open stays an sftp session.
	Target *execTarget

	// Invocation is how the recorders build the child's argv. It is NOT
	// necessarily how logsh itself was invoked: the forced-command path
	// synthesises one from the resolved route, because argv[0] must describe
	// what is being exec'd rather than how logsh was reached.
	Invocation logshell.Invocation

	// Info is what sshd told us about the session -- the authenticating
	// credential, the client's command, the source address. Zero for a
	// login-shell session, which stamps nothing.
	Info logshell.SessionInfo

	// Nesting is whether something above us is already recording. Passed in
	// rather than detected here so the runner has no hidden dependency on
	// process ancestry and can be exercised with a chosen value.
	Nesting logshell.Nesting

	// UID and Username identify the account. Both callers have already resolved
	// these to reach their target, so they are passed rather than looked up a
	// second time. Username is "" when it could not be resolved, which
	// ShouldRecord accepts -- see its doc comment.
	UID      int
	Username string

	// Kind names this session in the "ran but was NOT durably recorded" alert,
	// which is the one message an operator reads to tell the two entry points
	// apart in a journal.
	Kind string
}

// Session kinds, used only in operator-facing alerts.
const (
	kindLoginShell   = "session"
	kindForceCommand = "forced-command session"
)

// runSession records and runs a resolved session.
//
// This is the half both entry points share, and the reason it is one function
// rather than two near-copies is that every branch in it is a POLICY decision --
// whether to record this account, what to do when the command log is
// unavailable, whether an enclosing recorder makes a second transcript
// pointless, and whether a recording failure is still refusable. Policy that is
// written twice drifts, and a drift here is either a lockout or an unrecorded
// privileged session.
//
// Every path ends in exec-a-target or refuse(). There is no path that returns
// success without running something: a forced command that exits 0 having
// exec'd nothing hands the client a session that nothing recorded.
func runSession(s session) int {
	if !s.Config.ShouldRecord(s.Username, s.UID) {
		return passthrough(s.Target)
	}

	ctx := context.Background()

	// The command log is independent of session recording in every direction:
	// its own toggle, local syslog rather than the log server, and it runs
	// whether the session is recorded, journalled, or not recorded at all.
	cmdLog, cmdLogErr := logshell.OpenCommandLog(s.Config)
	if cmdLogErr != nil {
		if s.Config.CommandLog.Required {
			return refuse(s.Config, s.Target, fmt.Sprintf("command log unavailable: %v", cmdLogErr))
		}
		logshell.Alertf(syslog.LOG_WARNING, "command log unavailable, continuing without it: %v", cmdLogErr)
	}
	defer func() { _ = cmdLog.Close() }()

	spec := logshell.RunSpec{
		Config:     s.Config,
		Invocation: s.Invocation,
		ShellPath:  s.Target.path,
		Std:        logshell.StdStreams(),
		CmdLog:     cmdLog,
		Info:       s.Info,
		EnvShell:   s.Target.envShell,
	}

	var outcome logshell.Outcome
	var err error

	switch mode := s.Config.NestedMode(s.Nesting); mode {
	case logshell.NestedModeSkip:
		logshell.Alertf(syslog.LOG_INFO,
			"session nested inside %s; not recording here (nested_sessions=%s)",
			s.Nesting.Kind, mode)
		return passthrough(s.Target)

	case logshell.NestedModeMetadata:
		// Streams pass straight through, so no second pty and no duplicate
		// transcript -- but the session still leaves a record, carrying both
		// UUIDs so it joins to whatever the outer recorder stored.
		outcome, err = logshell.RunMetadataOnly(ctx, spec, s.Nesting)

	default:
		// Interactive or not is decided by whether a terminal is attached,
		// NEVER by whether "-c" was passed or which route matched. `ssh -t host
		// /bin/bash` supplies a command AND allocates a pty; keying off either
		// would classify it as non-interactive and hand the user a fully
		// interactive, entirely unrecorded shell.
		if logshell.IsTerminal(os.Stdin.Fd()) {
			outcome, err = logshell.RunRecorded(ctx, spec, logshell.StdTerminal())
		} else {
			outcome, err = logshell.RunNonInteractive(ctx, spec)
		}
	}

	if err != nil {
		if errors.Is(err, logshell.ErrRecordingUnavailable) {
			// Nothing was ever started, so the failure policy still has a
			// meaningful choice to make.
			return refuse(s.Config, s.Target, err.Error())
		}
		// The child ran. The audit gap has already happened and cannot be undone
		// by refusing; the user's exit status is a fact they are owed. Report
		// loudly and pass it through.
		logshell.Alertf(syslog.LOG_CRIT,
			"%s for uid %d ran but was NOT durably recorded: %v", s.Kind, s.UID, err)
	}
	return outcome.ExitCode
}
