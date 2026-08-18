// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/nested.go
package logshell

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Nesting detection: is something already recording these keystrokes?
//
// The case that matters is `sudo -i`. sudo runs the target account's passwd
// shell, so once logsh IS that shell the same session gets recorded twice --
// three times when the invoking account also uses logsh:
//
//	sshd pty -> logsh(alice) -> bash -> sudo -i -> logsh(root) -> bash
//	            ^^^^^^^^^^^^ transcript   ^^^^^^ transcript  ^^^^ transcript
//
// Four pseudo-terminals for one session, the same bytes stored three times, and
// the keystroke-timing regression from raw mode stacked at every layer.

// NestingKind is what, if anything, already has this session covered.
type NestingKind int

const (
	// NestedNone: logsh is the outermost recorder.
	NestedNone NestingKind = iota
	// NestedLogsh: another logsh is recording. Unambiguous -- it is certainly
	// capturing these bytes, because they pass through its pty.
	NestedLogsh
	// NestedSudo: sudo is in the chain. AMBIGUOUS: sudo records I/O only when
	// the matched sudoers rule says log_output, and nothing visible from here
	// reveals whether it did. See Config.NestedSessions.
	NestedSudo
)

func (k NestingKind) String() string {
	switch k {
	case NestedLogsh:
		return "logsh"
	case NestedSudo:
		return "sudo"
	default:
		return "none"
	}
}

// Nesting is what detection found.
type Nesting struct {
	Kind NestingKind
	// ParentSession is the enclosing logsh's UUID when there is one, so the
	// inner record can name the outer session.
	ParentSession string
	// SudoUser and friends describe who escalated. Empty / -1 when unknown.
	SudoUser string
	SudoUID  int
	SudoGID  int
}

// LogshSessionEnv carries the enclosing session's UUID to child processes.
//
// It is a fast path and a correlation aid, never the sole signal: sudo's
// env_reset strips it, so it does not survive an escalation, which is precisely
// the case worth detecting. Ancestry is what actually finds sudo.
const LogshSessionEnv = "LOGSH_SESSION"

// DetectNesting reports whether something is already recording this session.
func DetectNesting() Nesting {
	n := Nesting{SudoUID: -1, SudoGID: -1}

	// sudo sets these AFTER env_reset, so unlike most of the environment they
	// do survive an escalation. They are read for the WHO, not for the
	// detection: a user who controls their environment could set SUDO_USER by
	// hand, and the ancestry walk below is what cannot be lied to.
	n.SudoUser = os.Getenv("SUDO_USER")
	n.SudoUID = envInt("SUDO_UID")
	n.SudoGID = envInt("SUDO_GID")

	parentSession := os.Getenv(LogshSessionEnv)

	switch walkAncestry() {
	case NestedLogsh:
		n.Kind = NestedLogsh
		n.ParentSession = parentSession
	case NestedSudo:
		n.Kind = NestedSudo
	default:
		// Ancestry found nothing, but an enclosing logsh handed us its session
		// id directly. Trust it: only a logsh sets that variable, and a user
		// forging it can at most opt a session out that an outer recorder is
		// already covering.
		if parentSession != "" {
			n.Kind = NestedLogsh
			n.ParentSession = parentSession
		}
	}
	return n
}

func envInt(key string) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return -1
	}
	return v
}

// maxAncestryDepth bounds the walk. Nothing legitimate is 32 processes deep, and
// a cycle in a hand-crafted /proc must not hang a login.
const maxAncestryDepth = 32

// walkAncestry looks for sudo or another logsh among this process's ancestors.
//
// The nearer ancestor wins, which is what makes `logsh -> sudo -> logsh` report
// sudo rather than the outer logsh: sudo is the thing immediately above us, and
// it is the one whose recording decision is in question.
func walkAncestry() NestingKind {
	pid := os.Getppid()
	for range maxAncestryDepth {
		if pid <= 1 {
			return NestedNone
		}
		name, ppid, ok := procInfo(pid)
		if !ok {
			return NestedNone
		}
		switch {
		case name == "sudo":
			return NestedSudo
		case name == AdminName || isShellSymlinkName(name):
			return NestedLogsh
		}
		pid = ppid
	}
	return NestedNone
}

// isShellSymlinkName reports whether a process name looks like one of logsh's
// multi-call symlinks. The comm field is what a parent logsh shows, and it is
// the symlink name (lbash, lzsh) rather than "logsh".
//
// A login shell's comm also carries the leading dash sshd prepends.
func isShellSymlinkName(name string) bool {
	name = strings.TrimPrefix(name, "-")
	// Deliberately conservative: a fixed set rather than any "l*", which would
	// call every user's `less` a nested logsh.
	//
	// Broader than the names this build installs symlinks for, and deliberately
	// so. It covers every name the default map has ever carried, including
	// operator-configured ones (lksh, lfish) and ldash, which was dropped from
	// the defaults but may still be an account's shell on a host that upgraded.
	// Failing to recognise one of those would not be a cosmetic miss: the outer
	// logsh would go undetected and the session would be recorded twice.
	return slices.Contains([]string{"lsh", "lbash", "lzsh", "ldash", "lksh", "lfish"}, name)
}

// procInfo returns a process's comm and parent pid.
//
// comm comes from /proc/<pid>/stat rather than /proc/<pid>/exe because stat is
// world-readable while exe needs ptrace-level access to the target -- which
// fails for exactly the cross-uid cases this has to see. comm is settable by a
// process itself, so it is not a security boundary; it does not need to be,
// because the worst a forged name achieves is opting a session out of a SECOND
// recording that something else is already performing.
func procInfo(pid int) (comm string, ppid int, ok bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, false
	}
	// Field 2 is the executable name in parentheses and may itself contain
	// spaces and brackets, so it is delimited from the LAST ')' rather than by
	// splitting the line.
	open := bytes.IndexByte(raw, '(')
	close := bytes.LastIndexByte(raw, ')')
	if open < 0 || close < open {
		return "", 0, false
	}
	comm = string(raw[open+1 : close])

	rest := strings.Fields(string(raw[close+1:]))
	if len(rest) < 2 {
		return comm, 0, false
	}
	ppid, err = strconv.Atoi(rest[1]) // state, ppid
	if err != nil {
		return comm, 0, false
	}
	return comm, ppid, true
}

// Nesting mode values for Config.NestedSessions.
const (
	NestedModeRecord   = "record"
	NestedModeMetadata = "metadata"
	NestedModeSkip     = "skip"
)

// Mode returns what to do about this nesting.
//
// NestedLogsh always skips, whatever the setting says. There is no ambiguity to
// hedge against: the enclosing logsh is definitely capturing these bytes,
// because they physically pass through its pseudo-terminal on the way here.
// Recording them again buys nothing and costs another pty layer.
func (c *Config) NestedMode(n Nesting) string {
	switch n.Kind {
	case NestedNone:
		return NestedModeRecord
	case NestedLogsh:
		return NestedModeSkip
	default:
		if c.NestedSessions == "" {
			return NestedModeRecord
		}
		return c.NestedSessions
	}
}

// TTYNameOf resolves the terminal behind a descriptor, for metadata records made
// without allocating a pty of our own.
func TTYNameOf(fd uintptr) string {
	name, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10))
	if err != nil || !strings.HasPrefix(name, "/dev/") {
		return ""
	}
	return filepath.Clean(name)
}
