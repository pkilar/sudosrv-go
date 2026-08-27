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

// TestRunForceCommandRefusesWithoutAConfig.
//
// No configuration means logsh cannot tell whether this account should be
// recorded, so the safe answer is the same as "recording failed". It must never
// exit 0, which would silently grant an unrecorded root session.
//
// This test is safe to run anywhere precisely because an unreadable config
// reaches refuse() with no resolved target: nothing is ever exec'd, so it cannot
// replace the test process.
func TestRunForceCommandRefusesWithoutAConfig(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "id")
	t.Setenv("SSH_USER_AUTH", "")

	got := runForceCommand(logshell.Invocation{Name: logshell.EntryName},
		filepath.Join(t.TempDir(), "absent.yaml"))
	if got != exitRefused {
		t.Errorf("runForceCommand = %d, want exitRefused (%d)", got, exitRefused)
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

// buildEntry builds logsh and returns a logsh-entry symlink to it, so the
// binary dispatches through the forced-command path exactly as sshd would make
// it.
func buildEntry(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "logsh")
	build := exec.Command("go", "build", "-o", bin, "sudosrv/cmd/logsh")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	entry := filepath.Join(dir, "logsh-entry")
	if err := os.Symlink(bin, entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

// TestForcedCommandRoutesExec is acceptance tests T-1 and T-2 against the real
// binary: every branch execs what it should, no branch falls through to an
// unrecorded shell, and hostile input never reaches a route's argv.
//
// record_users is empty, so each session takes the unrecorded passthrough --
// which is the path that proves routing, since it execs the resolved target
// directly with nothing in between.
func TestForcedCommandRoutesExec(t *testing.T) {
	entry := buildEntry(t)

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
			cmd := exec.Command(entry)
			cmd.Env = append(os.Environ(),
				"SSH_ORIGINAL_COMMAND="+tt.original,
				"SSH_USER_AUTH=",
				"LOGSH_CONFIG_FOR_TEST="+cfgPath,
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
