// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/entry_test.go
package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sudosrv/internal/logshell"
	"testing"
)

// TestSessionInfoFromEnvReadsWhatSshdWrote.
//
// SSH_ORIGINAL_COMMAND and SSH_CONNECTION are set by sshd, not by the client
// directly: PermitUserEnvironment defaults to no and AcceptEnv is a narrow
// allowlist. They are still attacker-INFLUENCED -- the client chooses the
// command -- which is why the command is only ever recorded and passed as one
// -c argument, never parsed for meaning.
func TestSessionInfoFromEnvReadsWhatSshdWrote(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "internal-sftp -l INFO")
	t.Setenv("SSH_CONNECTION", "10.20.30.41 51234 10.20.30.9 22")
	t.Setenv("SSH_USER_AUTH", "")

	got := sessionInfoFromEnv()
	if got.SSHCommand != "internal-sftp -l INFO" {
		t.Errorf("SSHCommand = %q", got.SSHCommand)
	}
	// Source address and port only. The destination is this host, which the
	// record already names, and carrying it twice is noise.
	if got.SSHClient != "10.20.30.41 51234" {
		t.Errorf("SSHClient = %q, want \"10.20.30.41 51234\"", got.SSHClient)
	}
}

// TestSessionInfoFromEnvSurvivesAnEmptyEnvironment.
//
// Attribution failure warns and proceeds. Nothing here may be fatal: an
// unattributed recording beats no recording, and this code runs before anything
// else in a root session.
func TestSessionInfoFromEnvSurvivesAnEmptyEnvironment(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_USER_AUTH", "")

	got := sessionInfoFromEnv()
	if got.SSHCommand != "" || got.SSHClient != "" || got.Auth.Method != "" {
		t.Errorf("want a zero SessionInfo, got %+v", got)
	}
}

// TestSessionInfoFromEnvMalformedSshConnection guards against an index panic on
// a value that is not ours to trust the shape of.
func TestSessionInfoFromEnvMalformedSshConnection(t *testing.T) {
	t.Setenv("SSH_USER_AUTH", "")
	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	for _, v := range []string{"10.20.30.41", "", "   ", "a b c d e f g"} {
		t.Setenv("SSH_CONNECTION", v)
		_ = sessionInfoFromEnv() // must not panic
	}
}

// TestEntryNameDispatchesAwayFromAdmin.
//
// If logsh-entry ever reached the admin flag parser it would print usage and
// exit non-zero, which for a ForceCommand means root cannot log in.
func TestEntryNameDispatchesAwayFromAdmin(t *testing.T) {
	inv := logshell.ParseInvocation([]string{"/usr/sbin/logsh-entry"})
	if inv.IsAdmin() {
		t.Fatal("logsh-entry must not reach runAdmin")
	}
	if !inv.IsEntry() {
		t.Fatal("logsh-entry must be recognised as the entry point")
	}
}

// TestForcedCommandRoutesExec is acceptance tests T-1 and T-2 against
// runForceCommand: every branch execs what it should, no branch falls through
// to an unrecorded shell, and hostile input never reaches a route's argv.
//
// record_users is empty, so each session takes the unrecorded passthrough --
// which is the path that proves routing, since it execs the resolved target
// directly with nothing in between. That passthrough ends in syscall.Exec,
// which replaces the calling process on success, so each case is driven
// through the os.Args[0] re-exec idiom already established by
// TestPassthroughForwardsTargetEnvShell / TestPassthroughHelperProcess in
// main_test.go: the parent re-execs this test binary with -test.run anchored
// exactly to the helper below, and the helper loads the temp config with
// logshell.LoadUnchecked and calls runForceCommand directly with the result.
//
// This deliberately does NOT build the binary and drive it through a
// logsh-entry symlink, and deliberately does NOT go anywhere near
// logshell.Load. runForceCommand takes an already-loaded *logshell.Config
// rather than a path precisely so a test can hand it one built with
// LoadUnchecked -- content validation only, no root-ownership gate -- since an
// unprivileged test process cannot manufacture a root-owned file to satisfy
// Load in the first place (chown to a uid you do not hold requires CAP_CHOWN).
// That gate now lives in main, on the one production path, and stays real:
// internal/logshell's own TestLoadRequiresRootOwnership pins that Load actually
// enforces uid 0. Going through main's actual argv0 dispatch is covered
// separately by TestEntryNameDispatchesAwayFromAdmin, which pins that a
// logsh-entry invocation is recognised as IsEntry() and never reaches
// runAdmin; what happens once runForceCommand has a config in hand is exactly
// what this test checks, directly, with no skip and no host dependence.
func TestForcedCommandRoutesExec(t *testing.T) {
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "logsh.yaml")
	cfg := "record_users: []\n" +
		"force_command:\n" +
		"  routes:\n" +
		"    internal-sftp:\n" +
		"      exec: [/bin/echo, SFTP-ROUTE]\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		original   string
		wantOut    string
		wantAbsent string
		wantCode   int
	}{
		{
			name:     "default route runs the command through the shell",
			original: "echo hello", wantOut: "hello", wantCode: 0,
		},
		{
			// The CONFIG's argv wins; the client's arguments are discarded.
			name:     "exec route ignores the client's arguments",
			original: "internal-sftp -l DEBUG3", wantOut: "SFTP-ROUTE", wantAbsent: "DEBUG3", wantCode: 0,
		},
		{
			// The security property: field 0 is "internal-sftp;", not
			// "internal-sftp", so this must NOT match the route. It falls to the
			// default route and the shell runs the whole string -- which is what
			// a host with no ForceCommand would have done.
			name:     "a metacharacter defeats matching rather than exploiting it",
			original: "internal-sftp; echo FELL-THROUGH",
			wantOut:  "FELL-THROUGH", wantAbsent: "SFTP-ROUTE", wantCode: 0,
		},
		{
			name:     "exit status passes through",
			original: "exit 42", wantCode: 42,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestForcedCommandRoutesHelperProcess$")
			cmd.Env = append(os.Environ(),
				"LOGSH_WANT_FORCECOMMAND_HELPER=1",
				"LOGSH_FORCECOMMAND_HELPER_CONFIG="+cfgPath,
				"SSH_ORIGINAL_COMMAND="+tt.original,
				"SSH_USER_AUTH=",
			)
			out, err := cmd.CombinedOutput()

			code := 0
			if ee, ok := errors.AsType[*exec.ExitError](err); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("run: %v\n%s", err, out)
			}
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d (output: %s)", code, tt.wantCode, out)
			}
			if tt.wantOut != "" && !strings.Contains(string(out), tt.wantOut) {
				t.Errorf("output %q does not contain %q", out, tt.wantOut)
			}
			if tt.wantAbsent != "" && strings.Contains(string(out), tt.wantAbsent) {
				t.Errorf("output %q must not contain %q", out, tt.wantAbsent)
			}
		})
	}
}

// TestForcedCommandRoutesHelperProcess is not a real test. Run under a normal
// `go test`, it checks LOGSH_WANT_FORCECOMMAND_HELPER and returns immediately,
// so it contributes nothing and shows as a trivial pass. It only does anything
// when spawned as a subprocess by TestForcedCommandRoutesExec, which sets that
// variable -- because runForceCommand's unrecorded routes end in an execve that
// must replace a disposable process, not the test binary running the actual
// assertions.
func TestForcedCommandRoutesHelperProcess(t *testing.T) {
	if os.Getenv("LOGSH_WANT_FORCECOMMAND_HELPER") != "1" {
		return
	}
	// LoadUnchecked, not Load: this is a temp file the test process itself
	// wrote, so it is owned by the test's own uid, not root, and Load's
	// ownership gate would refuse it regardless of content. That gate belongs
	// on main's production path, not here -- see runForceCommand's doc comment.
	cfg, err := logshell.LoadUnchecked(os.Getenv("LOGSH_FORCECOMMAND_HELPER_CONFIG"))
	if err != nil {
		t.Fatalf("test helper: LoadUnchecked: %v", err)
	}
	inv := logshell.Invocation{Name: logshell.EntryName}
	// Only returns on failure; on success runForceCommand's own passthrough has
	// already replaced this process and nothing below runs.
	os.Exit(runForceCommand(inv, cfg))
}
