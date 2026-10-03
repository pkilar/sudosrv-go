// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/session_test.go
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sudosrv/internal/logshell"
)

func TestRunSessionCertificateExpiryPolicy(t *testing.T) {
	for _, mode := range []string{"excluded", "nested-skip", "fail-open", "expired-fail-open", "malformed-fail-open"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunSessionExpiryHelper$")
			cmd.Env = append(os.Environ(), "LOGSH_EXPIRY_HELPER="+mode)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("session did not terminate: %v, output: %s", ctx.Err(), out)
			}
			code := 0
			if ee, ok := errors.AsType[*exec.ExitError](err); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			refused := strings.HasPrefix(mode, "expired-") || strings.HasPrefix(mode, "malformed-")
			if refused {
				if code != exitRefused || strings.Contains(string(out), "CHILD-RAN") {
					t.Fatalf("invalid policy ran or was not refused: code=%d output=%s", code, out)
				}
			} else if code != 137 || !strings.Contains(string(out), "CHILD-RAN") {
				t.Fatalf("session did not run then expire: code=%d output=%s", code, out)
			}
		})
	}
}

func TestRunSessionExpiryHelper(t *testing.T) {
	mode := os.Getenv("LOGSH_EXPIRY_HELPER")
	if mode == "" {
		return
	}
	cfg := logshell.DefaultConfig()
	cfg.CommandLog.Enabled = false
	cfg.RecordUsers = []string{strconv.Itoa(os.Getuid())}
	cfg.Server.LogServers = []string{"127.0.0.1:0"}
	cfg.Server.JournalDirectory = ""
	nesting := logshell.Nesting{Kind: logshell.NestedNone}
	if mode == "excluded" {
		cfg.RecordUsers = nil
	}
	if mode == "nested-skip" {
		nesting.Kind = logshell.NestedLogsh
	}
	if strings.Contains(mode, "fail-open") {
		cfg.FailClosed = false
	}
	auth := logshell.AuthInfo{
		Method: logshell.AuthMethodCert, ValidBefore: uint64(time.Now().Unix() + 2),
		Extensions: map[string]string{logshell.TerminateOnCertExpiryExtension: ""},
	}
	if mode == "expired-fail-open" {
		auth.ValidBefore = uint64(time.Now().Unix())
	}
	if mode == "malformed-fail-open" {
		auth.Extensions[logshell.TerminateOnCertExpiryExtension] = "true"
	}
	args := []string{"-c", "printf CHILD-RAN; trap '' HUP TERM; while :; do sleep 60; done"}
	os.Exit(runSession(session{
		Config: cfg, Target: &execTarget{path: "/bin/sh", argv0: "sh", args: args, envShell: "/bin/sh"},
		Invocation: logshell.Invocation{Name: "sh", Args: args},
		Info:       logshell.SessionInfo{Auth: auth}, Nesting: nesting,
		UID: os.Getuid(), Kind: kindForceCommand,
	}))
}

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
			if ee, ok := errors.AsType[*exec.ExitError](err); ok {
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
	cfg.Server.LogServers = []string{"127.0.0.1:0"}
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

// TestRunSessionRefusesWithNoTarget pins the contract runSession's doc comment
// states: every path ends in an exec or a refusal, never a panic.
//
// Both callers resolve a target before calling, so this is unreachable today.
// It is pinned anyway because the recording path dereferences Target while
// passthrough and refuse both tolerate nil -- so the one path that would panic
// is the one a future caller is most likely to reach.
func TestRunSessionRefusesWithNoTarget(t *testing.T) {
	cfg := logshell.DefaultConfig()
	cfg.RecordUsers = []string{strconv.Itoa(os.Getuid())}

	if got := runSession(session{
		Config: cfg,
		Target: nil,
		UID:    os.Getuid(),
		Kind:   kindLoginShell,
	}); got != exitRefused {
		t.Errorf("runSession with no target = %d, want exitRefused (%d)", got, exitRefused)
	}
}

// TestRunSessionRenewedByOuterSupervisor covers a nested logsh started from a
// session whose certificate has since been renewed: the inherited certificate
// is expired, but the outer supervisor holds a newer one.
func TestRunSessionRenewedByOuterSupervisor(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewSignerFromKey(priv)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	mk := func(exp time.Time) *ssh.Certificate {
		c := &ssh.Certificate{Key: key.PublicKey(), Serial: 3, CertType: ssh.UserCert, KeyId: "person", ValidPrincipals: []string{"root"},
			ValidAfter: uint64(time.Now().Add(-2 * time.Hour).Unix()), ValidBefore: uint64(exp.Unix()),
			Extensions: map[string]string{logshell.TerminateOnCertExpiryExtension: "", logshell.PermitSessionRenewalExtension: ""}}
		if err := c.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		return c
	}
	original, renewed := mk(time.Now().Add(-time.Minute)), mk(time.Now().Add(time.Hour))
	path := filepath.Join(t.TempDir(), "outer")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var req map[string]any
				_ = json.NewDecoder(c).Decode(&req)
				_ = json.NewEncoder(c).Encode(map[string]any{"certificate": string(ssh.MarshalAuthorizedKey(renewed))})
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
			}()
		}
	}()
	for _, tc := range []struct {
		name, socket string
		wantCode     int
	}{
		{"renewed", path, 0},
		{"no supervisor", "", exitRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunSessionRenewedHelper$")
			cmd.Env = append(os.Environ(), "LOGSH_RENEWED_HELPER="+string(ssh.MarshalAuthorizedKey(original)),
				"LOGSH_RENEW_SOCKET="+tc.socket, "CERBERUS_RENEW_SOCKET=")
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := errors.AsType[*exec.ExitError](err); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tc.wantCode || (tc.wantCode == 0) != strings.Contains(string(out), "CHILD-RAN") {
				t.Fatalf("code=%d output=%s", code, out)
			}
		})
	}
}

func TestRunSessionRenewedHelper(t *testing.T) {
	text := os.Getenv("LOGSH_RENEWED_HELPER")
	if text == "" {
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed %T, want *ssh.Certificate", pub)
	}
	cfg := logshell.DefaultConfig()
	cfg.CommandLog.Enabled = false
	cfg.RecordUsers = nil // unrecorded: the supervised fallback runs the child
	args := []string{"-c", "printf CHILD-RAN"}
	os.Exit(runSession(session{
		Config: cfg, Target: &execTarget{path: "/bin/sh", argv0: "sh", args: args, envShell: "/bin/sh"},
		Invocation: logshell.Invocation{Name: "sh", Args: args},
		Info: logshell.SessionInfo{Auth: logshell.AuthInfo{
			Method: logshell.AuthMethodCert, ValidBefore: cert.ValidBefore, Extensions: cert.Extensions, Certificate: cert,
		}},
		Nesting: logshell.Nesting{Kind: logshell.NestedNone}, UID: os.Getuid(), Kind: kindForceCommand,
	}))
}
