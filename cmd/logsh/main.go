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
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sudosrv/internal/logshell"
)

const (
	appName = "logsh"
)

// versionUnset is what appVersion reads in a build that did not inject one.
//
// Deliberately not a number. The version used to be a hardcoded "1.0.0" while
// the VERSION file said 0.1.0, so `-version` confidently reported something no
// package had ever shipped. A word cannot be mistaken for a release, which
// makes an uninjected binary obvious instead of quietly wrong.
const versionUnset = "dev"

// appVersion is set at build time from the top-level VERSION file:
//
//	go build -ldflags "-X main.appVersion=$(cat VERSION)"
//
// The Makefile and all three packaging recipes pass it. A var, not a const,
// because -X can only write to a variable.
var appVersion = versionUnset

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
	switch {
	case inv.IsAdmin():
		os.Exit(runAdmin(inv))
	case inv.IsEntry():
		// The root-ownership gate belongs here, on the one production path, and
		// nowhere inside runForceCommand: see that function's doc comment.
		cfg, err := logshell.Load(logshell.DefaultConfigPath)
		if err != nil {
			// No configuration means we cannot tell whether this account should
			// be recorded, so the safe answer is the same as "recording failed".
			// There is nothing resolved to exec, so no target.
			os.Exit(refuse(nil, nil, fmt.Sprintf("configuration is unusable: %v", err)))
		}
		os.Exit(runForceCommand(cfg))
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
		return refuse(nil, nil, fmt.Sprintf("configuration is unusable: %v", err))
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
	return runSession(session{
		Config:     cfg,
		Target:     targetFromInvocation(inv, shellPath),
		Invocation: inv,
		// Something above us may already be recording these keystrokes. `sudo -i`
		// runs the target account's passwd shell, so once logsh IS that shell the
		// session is captured twice -- three times when the invoking account also
		// uses logsh -- with a pseudo-terminal layer for each.
		Nesting:  logshell.DetectNesting(),
		UID:      uid,
		Username: lookupUsername(uid),
		Kind:     kindLoginShell,
	})
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

// execTarget is a resolved program plus the argv and $SHELL value to run it
// with. It is what both entry points hand to passthrough and to break-glass, so
// an unrecorded session runs exactly what a recorded one would have.
type execTarget struct {
	path     string
	argv0    string
	args     []string
	envShell string // "" publishes no SHELL; see logshell.RunSpec.EnvShell
}

// targetFromInvocation builds the login-shell path's target.
func targetFromInvocation(inv logshell.Invocation, shellPath string) *execTarget {
	if shellPath == "" {
		return nil
	}
	return &execTarget{
		path:     shellPath,
		argv0:    logshell.ChildArgv0(shellPath, inv.LoginShell),
		args:     inv.Args,
		envShell: shellPath,
	}
}

// targetFromRoute builds the forced-command path's target.
//
// The interactive route is exec'd as a LOGIN shell -- argv[0] "-bash", not
// "bash". sshd marks a login shell that way and every shell decides from
// argv[0][0] alone; dropping the dash stops /etc/profile and ~/.bash_profile
// running fleet-wide, with no error anywhere, and users notice weeks later as
// "my PATH is wrong on the new boxes". Passing "-l" instead would work on bash
// and fail on shells that do not accept it.
//
// $SHELL is published only for the two routes that actually run a shell. An
// exec or command route may run sftp-server or rrsync, which are not shells.
func targetFromRoute(t logshell.Target) *execTarget {
	if t.Path == "" {
		return nil
	}
	isShell := t.Kind == logshell.RouteInteractive || t.Kind == logshell.RouteDefault
	tgt := &execTarget{
		path:  t.Path,
		argv0: logshell.ChildArgv0(t.Path, t.Kind == logshell.RouteInteractive),
		args:  t.Args,
	}
	if isShell {
		tgt.envShell = t.Path
	}
	return tgt
}

// passthrough execs the target with no recording. It returns only on failure.
func passthrough(tgt *execTarget) int {
	if tgt == nil {
		logshell.Alertf(syslog.LOG_ERR, "nothing to exec")
		return exitGeneral
	}
	if err := logshell.Exec(tgt.path, tgt.argv0, tgt.envShell, tgt.args, os.Environ()); err != nil {
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
//
// Both fallbacks exec the RESOLVED TARGET, not a shell. An sftp session that
// degraded into an interactive shell would be a broken transfer, not a graceful
// failure -- and for a forced command it would also hand the client something
// they did not ask for.
func refuse(cfg *logshell.Config, tgt *execTarget, reason string) int {
	if cfg != nil && !cfg.FailClosed && tgt != nil {
		logshell.Alertf(syslog.LOG_ERR,
			"proceeding UNRECORDED because fail_closed is disabled: %s", reason)
		return passthrough(tgt)
	}

	if logshell.BreakGlassActive(cfg) && tgt != nil {
		logshell.Alertf(syslog.LOG_CRIT,
			"proceeding UNRECORDED via break-glass marker %s: %s",
			logshell.BreakGlassPath(cfg), reason)
		fmt.Fprint(os.Stderr, logshell.BreakGlassBanner)
		return passthrough(tgt)
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
	if err := fs.Parse(inv.Args); err != nil {
		return exitConfig
	}

	switch {
	case *showVersion:
		fmt.Printf("%s version %s\n", appName, appVersion)
		return exitOK
	case *validate:
		return runValidate(*configPath)
	case *selftest:
		return runSelftest(*configPath)
	}

	fmt.Fprintf(os.Stderr,
		"%s is a recording login shell and is not meant to be run directly.\n\n"+
			"Install it as a symlink named after the shell it should wrap (lbash for\n"+
			"/bin/bash, lzsh for /bin/zsh, ...) and set that symlink as an account's\n"+
			"shell in /etc/passwd.\n\n"+
			"Administrative flags:\n", appName)
	fs.PrintDefaults()
	return exitConfig
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

	// The question an operator most needs answered before enabling a host: what
	// will a forced-command root session actually run here? The shell comes from
	// this host's passwd file, so it can differ from host to host, and printing
	// it is what makes that visible before it matters.
	if len(cfg.ForceCommand.Routes) > 0 || cfg.ForceCommand.Shell != "" {
		shell, err := cfg.ResolveEntryShell(logshell.PasswdPath, "root", 0)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "FAIL  force_command: cannot resolve root's shell: %v\n", err)
			failed = true
		case cfg.ForceCommand.Shell != "":
			fmt.Printf("ok    force_command: interactive shell for root: %s (from force_command.shell)\n", shell)
		default:
			fmt.Printf("ok    force_command: interactive shell for root: %s (from %s)\n", shell, logshell.PasswdPath)
		}

		for name, r := range cfg.ForceCommand.Routes {
			prog := r.Command
			if len(r.Exec) > 0 {
				prog = r.Exec[0]
			}
			st, statErr := os.Stat(prog)
			if statErr != nil || st.IsDir() || st.Mode()&0o111 == 0 {
				fmt.Fprintf(os.Stderr, "FAIL  force_command.routes[%s]: %s is missing or not executable\n", name, prog)
				// The sftp-server path differs by distribution, so this is
				// usually a config copied from another one. Name the path that
				// would work here.
				if name == "internal-sftp" {
					if found := logshell.FindSftpServer(); found != "" && found != prog {
						fmt.Fprintf(os.Stderr, "      On this host the sftp-server is %s\n", found)
					}
				}
				failed = true
				continue
			}
			fmt.Printf("ok    force_command.routes[%s]: %s\n", name, prog)
		}
	}

	// Reported whether or not force_command is configured: the host that most
	// needs this is the one with no route at all. What sshd does with sftp
	// decides whether a route is needed, and the sftp-server path differs by
	// distribution -- the same configuration file ships on every one, so a
	// hardcoded path is wrong on most of them. Ask the host.
	forced := len(cfg.ForceCommand.Routes) > 0 || cfg.ForceCommand.Shell != ""
	subsystem, _ := logshell.SftpSubsystem(logshell.SshdConfigPath)
	subsystemProg := ""
	if f := strings.Fields(subsystem); len(f) > 0 {
		subsystemProg = f[0]
	}
	_, hasSftpRoute := cfg.ForceCommand.Routes["internal-sftp"]

	switch {
	case subsystem == "":
		// No Subsystem line found, or the config could not be read. Nothing
		// truthful to say, so say nothing rather than guess.
	case strings.EqualFold(subsystemProg, "internal-sftp") && !hasSftpRoute:
		// A failure only for a host already committed to forced-command mode.
		// Where force_command is unconfigured this is advice about what would
		// break if it were enabled, not a defect in the present setup.
		label, out := "warn", os.Stdout
		if forced {
			label, out, failed = "FAIL", os.Stderr, true
		}
		_, _ = fmt.Fprintf(out,
			"%s  force_command.routes: %s says 'Subsystem sftp internal-sftp', which has no "+
				"binary to exec, and no internal-sftp route is configured -- sftp and modern "+
				"scp fail for forced-command sessions.\n", label, logshell.SshdConfigPath)
		if found := logshell.FindSftpServer(); found != "" {
			_, _ = fmt.Fprintf(out, "      Add to force_command.routes:\n"+
				"        internal-sftp:\n          exec: [%s, -l, INFO]\n", found)
		} else {
			_, _ = fmt.Fprintf(out, "      No sftp-server binary found in the usual locations.\n")
		}
	case !strings.EqualFold(subsystemProg, "internal-sftp") && !hasSftpRoute:
		// sshd names a real binary, so the client sends that path as its command
		// and the default route runs it. A route would be redundant.
		fmt.Printf("ok    force_command: no internal-sftp route needed (%s runs %s)\n",
			logshell.SshdConfigPath, subsystemProg)
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
