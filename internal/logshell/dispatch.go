// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/dispatch.go
package logshell

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// AdminName is the binary's own name. Invoked under it, logsh runs its
// administrative subcommands instead of acting as a shell; invoked under any
// other name it looks that name up in Config.Shells.
const AdminName = "logsh"

// EntryName is the name logsh is invoked under when sshd runs it as a forced
// command. /usr/sbin/logsh-entry is a symlink to the binary, and that path is
// what sshd_config's ForceCommand and the force-command critical option on a
// privileged certificate both name.
//
// A name rather than a flag, for two reasons. sshd invokes a forced command as
// `$SHELL -c "<command>"`, so argv[0] is the only thing logsh controls; and
// dispatching on it happens before any flag parsing, which keeps -config
// unreachable on a path that runs before any user code in a root session.
const EntryName = "logsh-entry"

// Invocation is how logsh was entered, decomposed.
type Invocation struct {
	// Name is the basename of argv[0] with any leading "-" removed: the key to
	// look up in Config.Shells.
	Name string
	// LoginShell reports that argv[0] began with "-".
	LoginShell bool
	// Args is argv[1:] verbatim. It is passed to the real shell untouched --
	// "-c", the command string, "-l", everything. logsh interprets none of it,
	// because a shell's own argument grammar is its business and second-guessing
	// it is how a wrapper breaks scp.
	Args []string
}

// ParseInvocation decomposes a process argv.
//
// The leading "-" is stripped BEFORE taking the basename, not after. sshd and
// login mark a login shell by prepending a dash to the basename they exec
// (session.c builds "-bash" from "/bin/bash"), so what arrives is "-lbash". But
// a directly-invoked logsh arrives as "/usr/sbin/lbash", and a login shell
// spelled with a path would be "-/usr/sbin/lbash". Stripping first handles all
// three; taking the basename first would leave the dash glued to the name in the
// path case and the map lookup would miss.
func ParseInvocation(argv []string) Invocation {
	inv := Invocation{Name: AdminName}
	if len(argv) > 0 {
		raw := argv[0]
		inv.LoginShell = strings.HasPrefix(raw, "-")
		raw = strings.TrimPrefix(raw, "-")
		if raw != "" {
			inv.Name = filepath.Base(raw)
		}
		inv.Args = argv[1:]
	}
	return inv
}

// IsAdmin reports whether this invocation is an administrative one rather than a
// shell one.
func (i Invocation) IsAdmin() bool { return i.Name == AdminName }

// IsEntry reports whether sshd is running logsh as a forced command, as opposed
// to as a login shell or an administrative invocation.
func (i Invocation) IsEntry() bool { return i.Name == EntryName }

// ResolveShell maps an invocation name to the real shell it stands for.
//
// Only names present in Config.Shells resolve. The map is the allowlist: logsh
// never infers a target by, say, stripping the leading "l", because that would
// make any symlink an administrator happened to create into a way to exec an
// arbitrary binary as a login shell.
//
// A resolved shell that is missing or not executable is fatal here, even though
// Warnings treats the same condition as advisory when merely surveying the map.
// The difference is that this one is about to be exec'd.
func (c *Config) ResolveShell(name string) (string, error) {
	shell, ok := c.Shells[name]
	if !ok {
		return "", fmt.Errorf("invoked as %q, which is not in the shells map", name)
	}
	st, err := os.Stat(shell)
	if err != nil {
		return "", fmt.Errorf("shell %s for %q: %w", shell, name, err)
	}
	if st.IsDir() || st.Mode()&0111 == 0 {
		return "", fmt.Errorf("shell %s for %q is not executable", shell, name)
	}
	return shell, nil
}

// ChildArgv0 builds the argv[0] to exec the real shell with.
//
// It is the shell's BASENAME, dash-prefixed when this was a login shell --
// "-bash", not "-/bin/bash" -- because that is the convention every shell reads.
// bash, zsh, ksh and dash all decide "am I a login shell?" from argv[0][0] ==
// '-' and nothing else.
//
// Getting this wrong is the single most damaging bug available in a shell
// wrapper, and it is silent: drop the dash and /etc/profile, ~/.bash_profile and
// ~/.zprofile simply stop running, fleet-wide, with no error anywhere. Users
// notice weeks later as "my PATH is wrong on the new boxes".
func ChildArgv0(shellPath string, login bool) string {
	base := filepath.Base(shellPath)
	if login {
		return "-" + base
	}
	return base
}

// PasswdPath is where login shells are read from when deciding which of the
// configured names are actually in use.
const PasswdPath = "/etc/passwd"

// NamesInUse reports which invocation names are currently some account's login
// shell, matched on the basename of the shell field.
//
// Matching on the basename rather than a full path means this does not need to
// know where the symlinks were installed, which logsh has no way to learn: the
// shells map holds names, and the passwd entry holds whatever path the operator
// pointed at.
func (c *Config) NamesInUse(passwdPath string) (map[string]bool, error) {
	raw, err := os.ReadFile(passwdPath) // #nosec G304 -- caller-supplied, root-owned system file
	if err != nil {
		return nil, err
	}
	inUse := make(map[string]bool)
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		name := strings.TrimPrefix(filepath.Base(fields[6]), "-")
		if _, ok := c.Shells[name]; ok {
			inUse[name] = true
		}
	}
	return inUse, nil
}

// ErrNoPasswdEntry reports that an account has no line in the passwd file.
var ErrNoPasswdEntry = errors.New("no passwd entry")

// PasswdShell returns an account's login shell field.
//
// os/user cannot supply this: user.User carries Uid, Gid, Username, Name and
// HomeDir, and no shell. So the file is parsed directly, which this package
// already does in NamesInUse.
//
// The account is matched by name OR by uid, the same accommodation ShouldRecord
// makes and for the same reason: logsh is built CGO_ENABLED=0, so os/user cannot
// resolve an NSS account and the caller may reach here with no name at all.
// Matching on the uid keeps the lookup working with an empty name, which is what
// stops an unresolvable name becoming a refused login.
//
// An account whose shell field is EMPTY returns "" and no error. That is a
// distinct state from an absent account, and sshd handles it specifically.
func PasswdShell(passwdPath, username string, uid int) (string, error) {
	raw, err := os.ReadFile(passwdPath) // #nosec G304 -- caller-supplied, root-owned system file
	if err != nil {
		return "", err
	}
	want := strconv.Itoa(uid)
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		if (username != "" && fields[0] == username) || fields[2] == want {
			return fields[6], nil
		}
	}
	return "", fmt.Errorf("%w for %q (uid %d) in %s", ErrNoPasswdEntry, username, uid, passwdPath)
}

// ResolveEntryShell picks the shell a forced-command session runs.
//
// ForceCommand.Shell is consulted FIRST; only when it is unset -- the normal
// case -- does the passwd entry become authoritative.
//
// With no override, this is the account's OWN shell, not a configured one.
// §4.10 of the session-logging design commits that this deployment does not
// change root's login shell -- that is its central advantage over installing
// logsh as the passwd shell. A shell named in logsh.yaml would be applied to
// every host sharing that file and would silently replace root's shell
// wherever the two disagreed, leaving a console login and an SSH login giving
// different shells for the same account. Reading the passwd entry is exactly
// what sshd would have done without ForceCommand, so enabling the recorder
// changes which shell runs on no host.
//
// The shells allowlist is deliberately NOT applied to a passwd-derived result.
// That list exists to stop a stray symlink becoming an exec primitive by
// INFERENCE; there is no inference here, the value is read from a root-owned
// field, and gating on it would refuse root's login on any host whose shell
// simply has no mapping -- a lockout for no security gain.
func (c *Config) ResolveEntryShell(passwdPath, username string, uid int) (string, error) {
	shell := c.ForceCommand.Shell
	if shell == "" {
		var err error
		shell, err = PasswdShell(passwdPath, username, uid)
		if err != nil {
			return "", err
		}
		if shell == "" {
			// sshd's own fallback: session.c substitutes _PATH_BSHELL when
			// pw_shell is empty rather than failing the session.
			shell = "/bin/sh"
		}
		// The account's shell may itself be a logsh multi-call symlink, on a
		// host that also runs the login-shell deployment. Exec'ing it would
		// start a second recorder and a second pty for one session. Resolving
		// the basename through the shells map yields the real shell, so the two
		// deployments compose instead of nesting -- and this is the same
		// basename-against-Shells test NamesInUse uses to decide the very same
		// question.
		//
		// The unwrap applies only to a passwd-derived value. An override is
		// already a real shell path, checked against the allowlist by Validate.
		shellName := strings.TrimPrefix(filepath.Base(shell), "-")
		if real, ok := c.Shells[shellName]; ok {
			shell = real
		}
	}
	if !filepath.IsAbs(shell) {
		return "", fmt.Errorf("shell %q for %q is not an absolute path", shell, username)
	}
	st, err := os.Stat(shell)
	if err != nil {
		return "", fmt.Errorf("shell %s for %q: %w", shell, username, err)
	}
	if st.IsDir() || st.Mode()&0111 == 0 {
		return "", fmt.Errorf("shell %s for %q is not executable", shell, username)
	}
	return shell, nil
}
