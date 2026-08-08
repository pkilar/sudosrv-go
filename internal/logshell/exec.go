// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/exec.go
package logshell

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// PrepareEnv returns env with SHELL pointing at the real shell rather than at
// logsh.
//
// sshd sets SHELL from the passwd entry, which for a recorded account is
// /usr/sbin/lbash. Left alone, every program that spawns "$SHELL" -- vim's :sh,
// tmux, screen, git's interactive rebase, xterm -e -- would start another logsh
// INSIDE the session logsh is already recording. That nests a second recorder
// and a second PTY per subshell, doubles every byte in the transcript, and makes
// the replay unreadable.
//
// It also matters for correctness beyond recording: scripts that test
// "$SHELL" against /etc/shells, or that parse its basename to decide which
// syntax to emit, would see a name they do not know.
//
// Nothing else in the environment is touched. logsh is not a privilege boundary
// -- it runs as the very user whose environment this is -- so sanitizing it
// would buy no security and would break legitimate setups.
func PrepareEnv(env []string, shellPath string) []string {
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "SHELL=") {
			out = append(out, "SHELL="+shellPath)
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, "SHELL="+shellPath)
	}
	return out
}

// Exec replaces the current process image with the real shell.
//
// This is execve, not fork-and-wait, for the pass-through path: the shell
// inherits our pid, our file descriptors, our controlling terminal and our
// process group, so exit status, signal delivery and job control are correct by
// construction rather than by careful proxying. A session that is not being
// recorded is then indistinguishable from one with no logsh installed at all,
// which is the property that makes it safe to set logsh as a system-wide shell
// before deciding whose sessions to record.
//
// It returns only on failure; on success the process is gone.
func Exec(shellPath, argv0 string, args, env []string) error {
	argv := make([]string, 0, len(args)+1)
	argv = append(argv, argv0)
	argv = append(argv, args...)
	if err := syscall.Exec(shellPath, argv, PrepareEnv(env, shellPath)); err != nil {
		return fmt.Errorf("exec %s: %w", shellPath, err)
	}
	return nil // unreachable
}

// WithSessionEnv adds the enclosing session's UUID to an environment, so a logsh
// started underneath this one can recognise the nesting and name its parent.
//
// It does not survive sudo's env_reset, which is why detection does not rely on
// it -- see DetectNesting.
func WithSessionEnv(env []string, sessionID string) []string {
	if sessionID == "" {
		return env
	}
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, LogshSessionEnv+"=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, LogshSessionEnv+"="+sessionID)
}

// ExecInvocation runs the resolved shell for an invocation with no recording.
// It is a free function rather than a Config method because the break-glass path
// reaches it with no usable configuration at all.
func ExecInvocation(inv Invocation, shellPath string) error {
	return Exec(shellPath, ChildArgv0(shellPath, inv.LoginShell), inv.Args, os.Environ())
}
