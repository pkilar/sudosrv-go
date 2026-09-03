// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/main_test.go
package main

import (
	"os"
	"os/exec"
	"slices"
	"sudosrv/internal/logshell"
	"testing"
)

// TestTargetFromRouteBuildsTheRightArgv.
//
// The interactive route must produce a LOGIN argv[0] -- "-bash", not "bash".
// sshd marks a login shell that way and every shell decides from argv[0][0]
// alone, so getting it wrong stops /etc/profile and ~/.bash_profile running,
// fleet-wide, with no error anywhere. This is acceptance test T-3's mechanism.
func TestTargetFromRouteBuildsTheRightArgv(t *testing.T) {
	tests := []struct {
		name      string
		target    logshell.Target
		wantArgv0 string
		wantArgs  []string
		wantEnv   string
	}{
		{
			name:      "interactive is a login shell",
			target:    logshell.Target{Kind: logshell.RouteInteractive, Path: "/bin/bash"},
			wantArgv0: "-bash",
			wantArgs:  nil,
			wantEnv:   "/bin/bash",
		},
		{
			name:      "default route runs the shell with -c",
			target:    logshell.Target{Kind: logshell.RouteDefault, Path: "/bin/bash", Args: []string{"-c", "id"}},
			wantArgv0: "bash",
			wantArgs:  []string{"-c", "id"},
			wantEnv:   "/bin/bash",
		},
		{
			// Not a shell. Publishing SHELL=/usr/lib/ssh/sftp-server would be a
			// lie, so envShell stays empty.
			name:      "exec route is not a shell",
			target:    logshell.Target{Kind: logshell.RouteExec, Path: "/usr/lib/ssh/sftp-server", Args: []string{"-l", "INFO"}},
			wantArgv0: "sftp-server",
			wantArgs:  []string{"-l", "INFO"},
			wantEnv:   "",
		},
		{
			name:      "command route is not a shell either",
			target:    logshell.Target{Kind: logshell.RouteCommand, Path: "/usr/bin/git-shell", Args: []string{"-c", "git-upload-pack x"}},
			wantArgv0: "git-shell",
			wantArgs:  []string{"-c", "git-upload-pack x"},
			wantEnv:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetFromRoute(tt.target)
			if got.path != tt.target.Path {
				t.Errorf("path = %q, want %q", got.path, tt.target.Path)
			}
			if got.argv0 != tt.wantArgv0 {
				t.Errorf("argv0 = %q, want %q", got.argv0, tt.wantArgv0)
			}
			if !slices.Equal(got.args, tt.wantArgs) {
				t.Errorf("args = %q, want %q", got.args, tt.wantArgs)
			}
			if got.envShell != tt.wantEnv {
				t.Errorf("envShell = %q, want %q", got.envShell, tt.wantEnv)
			}
		})
	}
}

// TestRefuseWithNoTargetRefuses.
//
// A nil target means there is nothing to exec, so neither fail-open nor
// break-glass can rescue the session. It must refuse rather than return success,
// because a forced command that exits 0 on an unhandled branch silently grants
// an unrecorded root session.
func TestRefuseWithNoTargetRefuses(t *testing.T) {
	cfg := logshell.DefaultConfig()
	cfg.FailClosed = false // even fail-open cannot help with nothing to run
	if got := refuse(cfg, nil, "test"); got != exitRefused {
		t.Errorf("refuse(cfg, nil) = %d, want exitRefused (%d)", got, exitRefused)
	}
}

// TestPassthroughForwardsTargetEnvShell pins the main.go half of R11:
// passthrough must forward tgt.envShell -- not tgt.path -- into
// logshell.Exec's envShell argument (main.go:240).
//
// TestTargetFromRouteBuildsTheRightArgv already covers that targetFromRoute
// COMPUTES envShell correctly. This closes the same failure shape one hop
// further down: a value computed correctly and then silently ignored at the
// call site that is supposed to forward it. exec_test.go's
// TestExecPublishesTheGivenEnvShell calls logshell.Exec directly with
// hardcoded arguments, so it cannot see a regression at main.go:240 itself --
// e.g. passing tgt.path in envShell's slot, which would still compile, since
// both are plain strings in the same argument position.
//
// passthrough ends in logshell.Exec, which calls syscall.Exec and replaces the
// calling process on success, so it cannot be invoked from this test directly
// without killing the test binary. This reuses the os.Args[0] re-exec idiom
// from exec_test.go: TestPassthroughHelperProcess is the subprocess, and
// Exec's real execve replaces IT, not this process. What comes back on its
// stdout is /bin/sh reporting the $SHELL it actually inherited.
func TestPassthroughForwardsTargetEnvShell(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestPassthroughHelperProcess$")
	cmd.Env = append(os.Environ(), "LOGSH_WANT_PASSTHROUGH_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper subprocess: %v\noutput: %s", err, out)
	}

	const want = "SHELL=/not/the/real/shell/marker"
	if got := string(out); got != want {
		t.Errorf("passthrough published %q, want %q -- tgt.envShell must reach "+
			"$SHELL, not tgt.path (/bin/sh)", got, want)
	}
}

// TestPassthroughHelperProcess is not a real test. Run under a normal `go
// test`, it checks LOGSH_WANT_PASSTHROUGH_HELPER and returns immediately, so it
// contributes nothing and shows as a trivial pass. It only does anything when
// spawned as a subprocess by TestPassthroughForwardsTargetEnvShell, which sets
// that variable -- because passthrough's execve must replace a disposable
// process, not the test binary that is running the actual assertions.
func TestPassthroughHelperProcess(t *testing.T) {
	if os.Getenv("LOGSH_WANT_PASSTHROUGH_HELPER") != "1" {
		return
	}
	tgt := &execTarget{
		path:     "/bin/sh",
		argv0:    "sh",
		args:     []string{"-c", `printf 'SHELL=%s' "$SHELL"`},
		envShell: "/not/the/real/shell/marker",
	}
	// Only returns on failure; on success Exec has already replaced this
	// process and nothing below runs.
	os.Exit(passthrough(tgt))
}
