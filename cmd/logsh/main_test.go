// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/main_test.go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecordConfigDoesNotNeedTheSystemFile is the property that makes logsh
// usable as a standalone tool: a recording must work on a machine the binary
// was merely copied onto, with no /etc/logsh/logsh.yaml and nothing installed.
//
// The path handed in here cannot be read. That is the point -- if this ever
// starts loading the file when -config was not given, this fails rather than
// the property quietly regressing into "works on the developer's machine,
// where the file happens to exist".
func TestRecordConfigDoesNotNeedTheSystemFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "definitely-not-here", "logsh.yaml")

	cfg, err := recordConfig(missing, false)
	if err != nil {
		t.Fatalf("standalone recording refused to start without a config file: %v", err)
	}
	if cfg == nil {
		t.Fatal("no configuration returned")
	}
	// It must be the built-in defaults, not an empty struct: a zero Config
	// records nothing, which would satisfy "no error" while producing an empty
	// transcript.
	if !cfg.LogTTYOut {
		t.Error("LogTTYOut is off in the default configuration; a capture would be empty")
	}
}

// TestRecordConfigIgnoresAnUnreadableSystemFile covers the other half of "does
// not need it": a file that EXISTS but cannot be parsed or read must not break
// a standalone capture either, since it is never consulted. The login-shell
// path treats that same file as a refusal, and this is the deliberate
// difference between the two.
func TestRecordConfigIgnoresAnUnreadableSystemFile(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "logsh.yaml")
	if err := os.WriteFile(broken, []byte("this: is: not: valid: yaml:\n\t- {"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := recordConfig(broken, false); err != nil {
		t.Errorf("a broken system config broke a standalone capture that never reads it: %v", err)
	}
}

// TestRecordConfigUsesTheFileWhenAsked keeps -config meaningful. Without this,
// "ignore the system file" could be implemented by ignoring every file, and
// the flag would silently do nothing.
func TestRecordConfigUsesTheFileWhenAsked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logsh.yaml")
	if err := os.WriteFile(path, []byte("log_ttyin: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := recordConfig(path, true)
	if err != nil {
		t.Fatalf("recordConfig with -config: %v", err)
	}
	if !cfg.LogTTYIn {
		t.Error("-config was given but its log_ttyin setting was not applied")
	}
}

// TestRecordConfigReportsABadFileWhenAsked: having asked for a file, the user
// gets told when it is unusable rather than silently getting defaults, which
// would record a session under settings they did not choose.
func TestRecordConfigReportsABadFileWhenAsked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logsh.yaml")
	if err := os.WriteFile(path, []byte("shells: [not, a, mapping\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := recordConfig(path, true); err == nil {
		t.Error("an unparseable -config file was accepted")
	}
}

// TestRecordConfigDoesNotRequireARootOwnedFile is why -config uses
// LoadUnchecked. The ownership gate protects the login-shell path, where the
// configuration decides which binary an account execs; applying it here would
// mean an ordinary user could not point a capture at a file in their own home
// directory, which is the only place they can put one.
//
// The temp file below is owned by whoever runs the tests, which is not root --
// exactly the case the gate rejects.
func TestRecordConfigDoesNotRequireARootOwnedFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; the ownership gate this covers would pass anyway")
	}
	path := filepath.Join(t.TempDir(), "logsh.yaml")
	if err := os.WriteFile(path, []byte("log_ttyin: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := recordConfig(path, true); err != nil {
		t.Errorf("-config refused a file the caller owns: %v", err)
	}
}

// TestRecordShellPrefersTheOverrideThenEnv pins the shell selection, including
// that an unusable one is reported before any session starts -- discovering it
// afterwards would mean a recording that captured nothing.
func TestRecordShellPrefersTheOverrideThenEnv(t *testing.T) {
	t.Setenv("SHELL", "/bin/sh")

	if got, err := recordShell("/bin/sh"); err != nil || got != "/bin/sh" {
		t.Errorf("recordShell(\"/bin/sh\") = %q, %v; want /bin/sh, nil", got, err)
	}
	if got, err := recordShell(""); err != nil || got != "/bin/sh" {
		t.Errorf("recordShell(\"\") = %q, %v; want $SHELL, nil", got, err)
	}

	dir := t.TempDir()
	notExec := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := recordShell(notExec); err == nil {
		t.Error("a non-executable shell was accepted")
	}
	if _, err := recordShell(filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing shell was accepted")
	}
	if _, err := recordShell(dir); err == nil {
		t.Error("a directory was accepted as a shell")
	}
}

// TestRecordShellFallsBackWhenEnvIsEmpty covers the machine with no $SHELL at
// all, which is normal under a service manager or a bare container.
func TestRecordShellFallsBackWhenEnvIsEmpty(t *testing.T) {
	t.Setenv("SHELL", "")

	got, err := recordShell("")
	if err != nil {
		t.Fatalf("recordShell with no $SHELL: %v", err)
	}
	if !strings.HasSuffix(got, "/sh") {
		t.Errorf("recordShell fell back to %q, want a /bin/sh-style default", got)
	}
}
