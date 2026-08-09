// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/dispatch.go
package logshell

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AdminName is the binary's own name. Invoked under it, logsh runs its
// administrative subcommands instead of acting as a shell; invoked under any
// other name it looks that name up in Config.Shells.
const AdminName = "logsh"

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
