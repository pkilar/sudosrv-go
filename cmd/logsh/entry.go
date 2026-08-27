// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/entry.go
package main

import (
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/logshell"
)

// sessionInfoFromEnv gathers what sshd told us about this session.
//
// Every field is optional and no failure here is fatal. Attribution failure
// warns and proceeds: an unattributed recording is enormously better than a
// refused login, and putting a file sshd wrote on the critical path of every
// root login is exactly the fragility this design avoids elsewhere.
func sessionInfoFromEnv() logshell.SessionInfo {
	info := logshell.SessionInfo{SSHCommand: os.Getenv("SSH_ORIGINAL_COMMAND")}

	// SSH_CONNECTION is "<client ip> <client port> <server ip> <server port>".
	// Only the client half is kept: the server half is this host, which the
	// record already names. Indexing is guarded because the shape of this value
	// is sshd's promise, not ours to assume.
	if fields := strings.Fields(os.Getenv("SSH_CONNECTION")); len(fields) >= 2 {
		info.SSHClient = fields[0] + " " + fields[1]
	}

	auth, err := logshell.ReadAuthInfo(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		logshell.Alertf(syslog.LOG_CRIT,
			"no usable SSH_USER_AUTH (%v): this root session will be recorded without "+
				"certificate attribution. Is ExposeAuthInfo enabled?", err)
		return info
	}
	if auth.Method == logshell.AuthMethodKey {
		// Under the certificate design this is the break-glass account or a key
		// the fallback audit missed. Worth saying out loud, not just recording.
		logshell.Alertf(syslog.LOG_CRIT,
			"root SSH session authenticated by a plain key (%s), not a certificate: "+
				"no human is named in this session's credential", auth.KeyFingerprint)
	}
	info.Auth = auth
	return info
}

// runForceCommand is the path taken when sshd runs logsh as a forced command.
//
// REVIEW THIS AS SECURITY-RELEVANT CODE. It runs before anything else in the
// session, on a command string the client chose. A bug here is either a lockout
// or an unrecorded root session.
//
// Every path below ends in exec-a-resolved-target or refuse(). There is no
// fall-through: a forced command that returns 0 without exec'ing anything hands
// the client a session that nothing recorded.
//
// cfg is a parameter rather than a path this function loads itself: acquiring
// it -- via logshell.Load, which enforces logshell.RequiredOwnerUID -- is main's
// job, before runForceCommand is ever called. This function TRUSTS cfg without
// re-checking ownership, because main is the only production caller and main
// obtained cfg through that gate. A test may hand it a config built with
// logshell.LoadUnchecked instead, which validates content but skips the gate --
// deliberately, since exercising routing here is not exercising the
// authentication path's file-selection decision, and an unprivileged test
// process cannot manufacture a root-owned file to satisfy Load in the first
// place (chown to a uid you do not hold requires CAP_CHOWN). There is
// deliberately NO environment override anywhere in this chain: this runs with
// an environment the client influences, at the start of a root session, and the
// file main loads decides both which binary gets exec'd and whether the session
// is recorded at all.
func runForceCommand(cfg *logshell.Config) int {
	// Read the credential before anything else: sshd removes the file at session
	// end, and every later moment is another chance for it to be gone.
	info := sessionInfoFromEnv()

	target := cfg.ForceCommand.Resolve(info.SSHCommand)

	uid := os.Getuid()
	username := lookupUsername(uid)

	// The interactive and default routes run the account's own shell, which
	// routing does not resolve. An exec or command route named its own program.
	if target.NeedsShell() {
		shell, shellErr := cfg.ResolveEntryShell(logshell.PasswdPath, username, uid)
		if shellErr != nil {
			// Distinct from every other failure: there is no shell to fall back
			// to, so neither fail-open nor break-glass can rescue this. sshd
			// would equally have failed to exec this entry. Same treatment
			// runShell gives an unresolvable shell.
			logshell.Alertf(syslog.LOG_ERR, "cannot resolve a shell: %v", shellErr)
			return exitConfig
		}
		target.Path = shell
	}

	tgt := targetFromRoute(target)

	return runSession(session{
		Config: cfg,
		Target: tgt,
		// The route's argv, expressed as an Invocation so the recorders build
		// argv[0] the one way ChildArgv0 knows.
		Invocation: logshell.Invocation{
			Name:       filepath.Base(tgt.path),
			LoginShell: target.Kind == logshell.RouteInteractive,
			Args:       tgt.args,
		},
		Info: info,
		// Under sshd nothing above us is recording, so this is NestedNone and
		// NestedMode returns "record" -- the same branch this path took before
		// it shared a runner, so the refactor changes nothing here. Consulting
		// it anyway is what makes a logsh-entry that somehow ran inside another
		// logsh skip rather than capture the same bytes a second time.
		Nesting:  logshell.DetectNesting(),
		UID:      uid,
		Username: username,
		Kind:     kindForceCommand,
	})
}
