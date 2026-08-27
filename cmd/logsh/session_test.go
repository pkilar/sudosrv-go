// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/session_test.go
package main

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"sudosrv/internal/logshell"
)

// TestRunSessionSkipsWhenNestedInsideAnotherLogsh pins the one behaviour the
// two entry points did NOT previously share.
//
// Before runSession existed, only the login-shell path consulted nested_sessions;
// the forced-command path went straight to the recorders. Under sshd that made no
// difference -- nothing is above a logsh-entry, so DetectNesting reports
// NestedNone and NestedMode returns "record" either way. It matters if a
// logsh-entry ever runs inside another logsh: without this, the same bytes are
// captured twice, through two stacked pseudo-terminals.
//
// The two cases are distinguishable without a log server, which is what makes
// this testable at all. Nested inside another logsh, the session is passed
// through and the child runs. Not nested, recording is attempted, no server is
// reachable, and fail_closed refuses the session outright.
//
// A subprocess is required because both outcomes end in execve or os.Exit.
func TestRunSessionSkipsWhenNestedInsideAnotherLogsh(t *testing.T) {
	tests := []struct {
		name     string
		nesting  string
		wantOut  string
		wantCode int
	}{
		{
			name:    "nested inside another logsh: passed through, child runs",
			nesting: "logsh", wantOut: "CHILD-RAN", wantCode: 0,
		},
		{
			// The control. Same session, same config, only the nesting differs
			// -- so a passthrough here would mean the skip branch fired for the
			// wrong reason rather than because of the nesting.
			name:    "not nested: recording is attempted and refused with no server",
			nesting: "none", wantOut: "", wantCode: exitRefused,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRunSessionNestingHelperProcess$")
			cmd.Env = append(os.Environ(),
				"LOGSH_WANT_NESTING_HELPER=1",
				"LOGSH_NESTING_KIND="+tt.nesting,
			)
			out, err := cmd.CombinedOutput()

			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("helper subprocess: %v\noutput: %s", err, out)
			}

			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d (output: %s)", code, tt.wantCode, out)
			}
			if tt.wantOut != "" && !strings.Contains(string(out), tt.wantOut) {
				t.Errorf("output %q does not contain %q", out, tt.wantOut)
			}
			if tt.wantOut == "" && strings.Contains(string(out), "CHILD-RAN") {
				t.Errorf("child ran, but this session should have been refused: %s", out)
			}
		})
	}
}

// TestRunSessionNestingHelperProcess is the subprocess half of the test above.
func TestRunSessionNestingHelperProcess(t *testing.T) {
	if os.Getenv("LOGSH_WANT_NESTING_HELPER") != "1" {
		return
	}

	cfg := logshell.DefaultConfig()
	// Record this account, so the ShouldRecord short-circuit cannot be what
	// produces a passthrough. Numeric uid because os/user cannot resolve an
	// NSS account in a CGO-free build.
	cfg.RecordUsers = []string{strconv.Itoa(os.Getuid())}
	// Unreachable on purpose: with no server and no journal, recording fails
	// and fail_closed decides. Port 0 is never listening.
	cfg.Server.UpstreamHost = "127.0.0.1:0"
	cfg.Server.JournalDirectory = ""

	nesting := logshell.Nesting{Kind: logshell.NestedNone}
	if os.Getenv("LOGSH_NESTING_KIND") == "logsh" {
		nesting = logshell.Nesting{Kind: logshell.NestedLogsh}
	}

	os.Exit(runSession(session{
		Config: cfg,
		Target: &execTarget{
			path:     "/bin/sh",
			argv0:    "sh",
			args:     []string{"-c", "printf CHILD-RAN"},
			envShell: "/bin/sh",
		},
		Invocation: logshell.Invocation{Name: "sh", Args: []string{"-c", "printf CHILD-RAN"}},
		Nesting:    nesting,
		UID:        os.Getuid(),
		Username:   "",
		Kind:       kindLoginShell,
	}))
}
