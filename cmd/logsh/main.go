// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/main.go

// Command logsh is a recording login shell.
//
// It is a multi-call binary in the busybox style: /usr/sbin/lbash and
// /usr/sbin/lzsh are symlinks to it, and the name it is invoked under selects
// the real shell to run. Set one of those symlinks as an account's shell in
// /etc/passwd and that account's sessions are recorded to a sudosrv log server,
// in the same sudoreplay-compatible format sudo produces.
//
// Invoked under its own name it runs administrative subcommands instead.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sudosrv/internal/logshell"
)

const (
	appName    = "logsh"
	appVersion = "1.0.0"
)

// Exit codes. These apply ONLY before the real shell is exec'd; once logsh
// hands off, the status the caller sees is the shell's own. That separation is
// what keeps `ssh host false` exiting 1.
const (
	exitOK      = 0
	exitGeneral = 1
	exitConfig  = 2
	exitRefused = 3 // the session could not be recorded and fail-closed applied
)

func main() {
	inv := logshell.ParseInvocation(os.Args)
	if inv.IsAdmin() {
		os.Exit(runAdmin(inv))
	}
	os.Exit(runShell(inv))
}

// runShell is the login-shell path.
//
// The configuration path is compiled in and cannot be overridden. A login shell
// is exec'd with no arguments of our choosing and with an environment the user
// controls entirely, so honouring $LOGSH_CONFIG or a relative path would let any
// recorded user point logsh at a configuration of their own and switch off their
// own recording.
func runShell(inv logshell.Invocation) int {
	cfg, err := logshell.Load(logshell.DefaultConfigPath)
	if err != nil {
		// No configuration means we cannot tell whether this user should be
		// recorded, so the safe answer is the same as "recording failed". Note
		// that BreakGlassActive(nil) still works: it falls back to the
		// compiled-in marker path precisely for this case.
		return refuse(nil, inv, "", fmt.Sprintf("configuration is unusable: %v", err))
	}

	shellPath, err := cfg.ResolveShell(inv.Name)
	if err != nil {
		// Distinct from every other failure: there is no shell to fall back to,
		// so neither fail-open nor break-glass can rescue this. Refusing is the
		// only available answer.
		logshell.Alertf(syslog.LOG_ERR, "cannot resolve a shell: %v", err)
		return exitConfig
	}

	uid := os.Getuid()
	username := lookupUsername(uid)

	if !cfg.ShouldRecord(username, uid) {
		return passthrough(inv, shellPath)
	}

	// Interactive or not is decided by whether a terminal is attached, NEVER by
	// whether "-c" was passed. `ssh -t host /bin/bash` supplies a command AND
	// allocates a pty; keying off "-c" would classify it as non-interactive and
	// hand the user a fully interactive, entirely unrecorded shell.
	ctx := context.Background()

	// The command log is independent of recording: its own toggle, local syslog
	// rather than the log server, and it runs whether the session is recorded,
	// journalled, or not recorded at all.
	cmdLog, cmdLogErr := logshell.OpenCommandLog(cfg, shellPath)
	if cmdLogErr != nil {
		if cfg.CommandLog.Required {
			return refuse(cfg, inv, shellPath, fmt.Sprintf("command log unavailable: %v", cmdLogErr))
		}
		logshell.Alertf(syslog.LOG_WARNING, "command log unavailable, continuing without it: %v", cmdLogErr)
	}
	defer func() { _ = cmdLog.Close() }()

	// Something above us may already be recording these keystrokes. `sudo -i`
	// runs the target account's passwd shell, so once logsh IS that shell the
	// session is captured twice -- three times when the invoking account also
	// uses logsh -- with a pseudo-terminal layer for each.
	nesting := logshell.DetectNesting()

	var outcome logshell.Outcome
	switch mode := cfg.NestedMode(nesting); mode {
	case logshell.NestedModeSkip:
		logshell.Alertf(syslog.LOG_INFO,
			"session nested inside %s; not recording here (nested_sessions=%s)",
			nesting.Kind, mode)
		return passthrough(inv, shellPath)

	case logshell.NestedModeMetadata:
		// Streams pass straight through, so no second pty and no duplicate
		// transcript -- but the session still leaves a record, carrying both
		// UUIDs so it joins to whatever the outer recorder stored.
		outcome, err = logshell.RunMetadataOnly(ctx, cfg, inv, shellPath,
			logshell.StdStreams(), cmdLog, nesting)

	default:
		if logshell.IsTerminal(os.Stdin.Fd()) {
			outcome, err = logshell.RunRecorded(ctx, cfg, inv, shellPath,
				logshell.StdTerminal(), cmdLog)
		} else {
			outcome, err = logshell.RunNonInteractive(ctx, cfg, inv, shellPath,
				logshell.StdStreams(), cmdLog)
		}
	}
	if err != nil {
		if errors.Is(err, logshell.ErrRecordingUnavailable) {
			// No shell was ever started, so the failure policy still has a
			// meaningful choice to make.
			return refuse(cfg, inv, shellPath, err.Error())
		}
		// The shell ran. The audit gap has already happened and cannot be
		// undone by refusing; the user's exit status is a fact they are owed.
		// Report loudly and pass it through.
		logshell.Alertf(syslog.LOG_CRIT,
			"session for uid %d ran but was NOT durably recorded: %v", uid, err)
	}
	return outcome.ExitCode
}

// lookupUsername resolves uid to a name, or "" if it cannot.
//
// Failure is not an error. logsh is built without cgo, so os/user reads
// /etc/passwd directly and cannot see NSS-provided accounts; ShouldRecord
// accepts a numeric uid for exactly that reason. See its doc comment.
func lookupUsername(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return u.Username
}

// passthrough execs the real shell with no recording. It returns only on
// failure.
func passthrough(inv logshell.Invocation, shellPath string) int {
	if err := logshell.ExecInvocation(inv, shellPath); err != nil {
		logshell.Alertf(syslog.LOG_ERR, "%v", err)
		return exitGeneral
	}
	return exitOK // unreachable: Exec replaced the process
}

// refuse applies the failure policy when a session that should be recorded
// cannot be.
//
// Order matters. An explicit fail_closed: false is the operator saying "keep
// sessions working", and is honoured without needing a marker file. The
// break-glass marker is the escape hatch for the default posture. Only when
// neither applies is the session actually refused.
func refuse(cfg *logshell.Config, inv logshell.Invocation, shellPath, reason string) int {
	canExec := shellPath != ""

	if cfg != nil && !cfg.FailClosed && canExec {
		logshell.Alertf(syslog.LOG_ERR,
			"proceeding UNRECORDED because fail_closed is disabled: %s", reason)
		return passthrough(inv, shellPath)
	}

	if logshell.BreakGlassActive(cfg) && canExec {
		logshell.Alertf(syslog.LOG_CRIT,
			"proceeding UNRECORDED via break-glass marker %s: %s",
			logshell.BreakGlassPath(cfg), reason)
		fmt.Fprint(os.Stderr, logshell.BreakGlassBanner)
		return passthrough(inv, shellPath)
	}

	logshell.Alertf(syslog.LOG_ERR, "session REFUSED for uid %d: %s", os.Getuid(), reason)
	fmt.Fprintf(os.Stderr,
		"logsh: this session cannot be recorded, and this host is configured to refuse\n"+
			"       sessions it cannot record. Contact your administrator.\n")
	return exitRefused
}

// runAdmin is the path taken when the binary is invoked under its own name.
func runAdmin(inv logshell.Invocation) int {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	configPath := fs.String("config", logshell.DefaultConfigPath, "Path to the configuration file")
	validate := fs.Bool("validate", false, "Validate the configuration and exit")
	selftest := fs.Bool("selftest", false, "Check that this host can run logsh as a login shell, and exit")
	showVersion := fs.Bool("version", false, "Show version information and exit")
	record := fs.String("record", "",
		"Record this session into DIR as a sudoreplay-compatible I/O log and contact no log server")
	shell := fs.String("shell", "",
		"Shell to run under -record (default $SHELL, then /bin/sh)")
	wire := fs.Bool("wire", false,
		"With -record, also write the raw wire-format stream as "+logshell.WireFileName)

	if err := fs.Parse(inv.Args); err != nil {
		return exitConfig
	}

	// Whether -config was given, as opposed to left at its default. Standalone
	// recording does not require a system configuration to exist -- the whole
	// point is that it runs anywhere -- so it uses built-in defaults unless the
	// user asks for a file.
	configGiven := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			configGiven = true
		}
	})

	switch {
	case *showVersion:
		fmt.Printf("%s version %s\n", appName, appVersion)
		return exitOK
	case *validate:
		return runValidate(*configPath)
	case *selftest:
		return runSelftest(*configPath)
	case *record != "":
		return runRecord(*record, *shell, *configPath, configGiven, *wire, fs.Args())
	}

	fmt.Fprintf(os.Stderr,
		"%s is a recording login shell and is not meant to be run directly.\n\n"+
			"Install it as a symlink named after the shell it should wrap (lbash for\n"+
			"/bin/bash, lzsh for /bin/zsh, ...) and set that symlink as an account's\n"+
			"shell in /etc/passwd.\n\n"+
			"To capture a session for yourself rather than for an audit trail:\n"+
			"  %s -record ./my-session          # then replay with sudoreplay\n"+
			"  %s -record ./my-session -wire    # and keep the raw wire stream too\n\n"+
			"Administrative flags:\n", appName, appName, appName)
	fs.PrintDefaults()
	return exitConfig
}

// runRecord is the standalone recorder: `logsh -record DIR`.
//
// It records THIS terminal session into DIR as the same sudoreplay-compatible
// file set the daemon writes, and contacts no log server. It exists because the
// recording machinery is useful on its own -- for capturing a session to replay,
// or to feed to something that renders one as a video -- and that use has
// nothing to do with auditing anybody.
//
// It is deliberately not the login-shell path and shares none of its policy.
// record_users does not apply, because the person running this asked for it by
// name. Nesting is not consulted, because a capture inside an already-recorded
// session is a reasonable thing to want. Neither fail-closed nor break-glass
// applies, because there is no audit obligation to fail against: if the
// directory cannot be written, the user gets an error on their terminal and no
// session starts.
func runRecord(dir, shellOverride, configPath string, configGiven, alsoWire bool, args []string) int {
	cfg, err := recordConfig(configPath, configGiven)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		return exitConfig
	}
	if !cfg.LogTTYOut {
		fmt.Fprintf(os.Stderr,
			"%s: log_ttyout is off in this configuration, so there would be nothing\n"+
				"       to record. Enable it or drop -config.\n", appName)
		return exitConfig
	}
	cfg.RecordDir = dir
	cfg.RecordWire = alsoWire

	// Quiet the storage package's own logging. It writes at INFO about opening
	// and finalising a session, which is what an operator wants in a daemon's
	// journal and is noise on the terminal of somebody recording themselves --
	// it lands on their screen the moment their shell exits. Warnings and
	// errors still come through, because those they need to see.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})))

	shellPath, err := recordShell(shellOverride)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		return exitConfig
	}

	// A recording of a session that has no terminal would hold no terminal
	// output. Saying so beats writing an empty transcript and letting the user
	// discover it when they try to replay it.
	if !logshell.IsTerminal(os.Stdin.Fd()) {
		fmt.Fprintf(os.Stderr,
			"%s: -record needs a terminal; stdin is not one.\n", appName)
		return exitConfig
	}

	// Refuse to write over an existing recording. storage opens the stream
	// files with O_TRUNC, so a second run into the same directory would
	// overwrite the first with no warning -- and a recording someone meant to
	// keep is exactly the thing not to silently destroy.
	if existing, err := os.Stat(filepath.Join(dir, "timing")); err == nil && !existing.IsDir() {
		fmt.Fprintf(os.Stderr,
			"%s: %s already holds a recording; choose another directory.\n", appName, dir)
		return exitConfig
	}

	fmt.Fprintf(os.Stderr, "%s: recording to %s\n", appName, dir)

	inv := logshell.Invocation{Name: filepath.Base(shellPath), Args: args}
	outcome, err := logshell.RunRecorded(context.Background(), cfg, inv, shellPath,
		logshell.StdTerminal(), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		if errors.Is(err, logshell.ErrRecordingUnavailable) {
			// No shell ever started, so there is no recording to point at and
			// no exit status to report.
			return exitGeneral
		}
		// The shell ran, so the files are on disk and the user is owed both the
		// exit status and the path -- a failure to write the raw copy, say,
		// leaves the I/O log perfectly usable, and saying nothing about where
		// it is would be the unhelpful half of the truth.
		reportRecording(dir, alsoWire)
		return outcome.ExitCode
	}

	reportRecording(dir, alsoWire)
	return outcome.ExitCode
}

// reportRecording tells the user where the session went and how to play it.
func reportRecording(dir string, alsoWire bool) {
	fmt.Fprintf(os.Stderr, "%s: recorded to %s\n", appName, dir)
	if alsoWire {
		fmt.Fprintf(os.Stderr, "%s: raw wire format: %s\n",
			appName, filepath.Join(dir, logshell.WireFileName))
	}
	fmt.Fprintf(os.Stderr, "%s: replay with: sudoreplay -d %s %s\n",
		appName, filepath.Dir(dir), filepath.Base(dir))
}

// recordConfig resolves the configuration a standalone recording runs under.
//
// /etc/logsh/logsh.yaml is NOT read unless -config asks for it, and its absence
// is not an error. That is the difference between a login shell and a tool: the
// login-shell path must find a configuration or it cannot tell whether the
// account should be recorded, so a missing file there is a refusal. Here the
// user has already answered that question by typing -record, and logsh is a
// single static binary -- someone who copies it onto a machine to capture a
// session should not have to install a system configuration first.
//
// Nor is the system file read opportunistically when it happens to exist. It
// describes an AUDIT deployment: it can name an upstream server, restrict
// recording to particular accounts, or switch off the very stream being
// captured. Silently inheriting that would make the same command behave
// differently from host to host, and `log_ttyout: false` in it would turn a
// capture into an empty file. Wanting those settings is what -config is for.
// A file named with -config is read with LoadUnchecked: its CONTENT is
// validated, but the root-ownership gate is not applied. That gate exists to
// stop a recorded user pointing their own login shell at a configuration they
// control, since the file decides which binary gets exec'd for their account.
// No such boundary exists here -- the caller is recording their own session as
// themselves -- and enforcing it would mean `-config ~/capture.yaml` could not
// work at all, which is not a standalone tool.
func recordConfig(configPath string, configGiven bool) (*logshell.Config, error) {
	if !configGiven {
		return logshell.DefaultConfig(), nil
	}
	return logshell.LoadUnchecked(configPath)
}

// recordShell picks the shell a standalone recording runs.
//
// $SHELL rather than the passwd entry: this records the session the user is
// actually having, and $SHELL is what their terminal gave them. It is also why
// the shells allowlist does not apply here -- that list exists to stop a stray
// symlink becoming an exec primitive for OTHER people's logins, and there is no
// privilege boundary being crossed when someone runs their own shell.
func recordShell(override string) (string, error) {
	candidate := override
	if candidate == "" {
		candidate = os.Getenv("SHELL")
	}
	if candidate == "" {
		candidate = "/bin/sh"
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", fmt.Errorf("shell %s: %w", candidate, err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("shell %s is not executable", candidate)
	}
	return candidate, nil
}

// runValidate reports content problems and permission problems independently.
//
// Reporting them separately is what lets an administrator check a draft in their
// home directory: the ownership complaint is expected there and can be read past,
// while the syntax error two lines down is the thing they actually needed to see.
// A single early return would have hidden the second behind the first.
func runValidate(path string) int {
	rc := exitOK

	cfg, err := logshell.LoadUnchecked(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		rc = exitConfig
	} else {
		fmt.Printf("ok    content: %s parses and validates\n", path)
		for _, w := range cfg.Warnings() {
			fmt.Fprintf(os.Stderr, "warn  %s\n", w)
		}
	}

	if err := logshell.CheckPerms(path, logshell.RequiredOwnerUID); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL  permissions: %v\n", err)
		rc = exitConfig
	} else {
		fmt.Printf("ok    permissions: root-owned and not group- or world-writable\n")
	}

	return rc
}

// runSelftest checks the things that would break login if they were wrong.
//
// It is what a package postinst runs BEFORE any account's shell is switched to a
// logsh symlink, so its contract is narrow and deliberate: it fails only on
// conditions that would lock a user out, and reports everything else as a
// warning. Reachability of the log server is explicitly NOT fatal -- a fresh
// install runs postinst before the daemon is up, and failing there would make
// the package uninstallable.
func runSelftest(path string) int {
	failed := false

	cfg, err := logshell.LoadUnchecked(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL  config: %v\n", err)
		return exitConfig
	}
	fmt.Printf("ok    config: %s parses and validates\n", path)

	if err := logshell.CheckPerms(path, logshell.RequiredOwnerUID); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL  permissions: %v\n", err)
		failed = true
	} else {
		fmt.Printf("ok    permissions: root-owned and not group- or world-writable\n")
	}

	for _, w := range cfg.Warnings() {
		fmt.Fprintf(os.Stderr, "warn  %s\n", w)
	}

	// A mapping that does not resolve is only FATAL when an account is actually
	// using it. Failing on any absent shell would make this unusable as a
	// package postinst check: the shipped map lists lksh and lfish among others,
	// and neither ksh nor fish is present on most hosts. An unused mapping
	// to a missing shell harms nobody -- nothing can be exec'd through it -- and
	// enable refuses it separately, before any account is switched.
	inUse, err := cfg.NamesInUse(logshell.PasswdPath)
	if err != nil {
		// Conservative: unable to tell which are in use, so treat all as in use.
		fmt.Fprintf(os.Stderr, "warn  cannot read %s (%v); treating every mapping as in use\n",
			logshell.PasswdPath, err)
		inUse = nil
	}
	for name := range cfg.Shells {
		shell, resolveErr := cfg.ResolveShell(name)
		if resolveErr == nil {
			fmt.Printf("ok    shells[%s]: %s -> %s\n", name, logshell.ChildArgv0(shell, true), shell)
			continue
		}
		if inUse == nil || inUse[name] {
			fmt.Fprintf(os.Stderr, "FAIL  shells[%s]: %v (an account is using this shell)\n",
				name, resolveErr)
			failed = true
			continue
		}
		fmt.Fprintf(os.Stderr, "warn  shells[%s]: %v (no account uses it, so not fatal)\n",
			name, resolveErr)
	}

	if len(cfg.RecordUsers) == 0 {
		fmt.Fprintf(os.Stderr, "warn  record_users is empty: no session would be recorded\n")
	}
	for _, u := range cfg.RecordUsers {
		if _, err := user.Lookup(u); err != nil {
			if _, numErr := strconv.Atoi(u); numErr != nil {
				fmt.Fprintf(os.Stderr,
					"warn  record_users[%s]: no such account on this host (list a numeric uid "+
						"if this is an NSS-provided account)\n", u)
			}
		}
	}

	if logshell.BreakGlassActive(cfg) {
		fmt.Fprintf(os.Stderr,
			"warn  break-glass marker %s is PRESENT: recording is currently disabled\n",
			logshell.BreakGlassPath(cfg))
	}

	if failed {
		return exitConfig
	}
	fmt.Printf("%s: selftest passed\n", appName)
	return exitOK
}
