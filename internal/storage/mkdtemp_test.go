// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/mkdtemp_test.go

//go:build unix

package storage

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sudosrv/internal/config"

	"uuid"
)

// templateConfig builds a local-storage config whose iolog_file ends in the
// six-X mkdtemp template documented in sudoers(5) ("%{seq}" alternative).
func templateConfig(t *testing.T, iologFile string) (cfg *config.LocalStorageConfig, parent string) {
	t.Helper()
	tmpDir := t.TempDir()
	parent = filepath.Join(tmpDir, "sess")
	return &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		IologDir:        parent,
		IologFile:       iologFile,
		DirPermissions:  0750,
		FilePermissions: 0640,
	}, parent
}

var randomSuffixRe = regexp.MustCompile(`^[A-Za-z0-9]{6}$`)

// isExpandedSuffix reports whether s is a plausible mkdtemp expansion: six
// alphanumerics that are not still the literal template.
func isExpandedSuffix(s string) bool {
	return randomSuffixRe.MatchString(s) && s != "XXXXXX"
}

// TestSessionPathMkdtempTemplateIsUnique is the regression test for IOLOG-009.
//
// C sudo_logsrvd runs the expanded iolog path through iolog_mkpath, which calls
// mkdtemp() instead of mkdir() when the path ends in at least six X's
// (lib/iolog/iolog_mkpath.c:41-50, reached from logsrvd/iolog_writer.c:622).
// That is the uniqueness idiom sudoers(5) documents for iolog_file, and the
// only one available to an operator who does not want a shared seq file.
//
// Go created the template literally, so every session on that server landed in
// one directory named "XXXXXX" and each new session truncated the previous
// session's uuid, log, log.json, timing and I/O streams -- silent destruction of
// the audit trail the server exists to keep.
func TestSessionPathMkdtempTemplateIsUnique(t *testing.T) {
	cfg, parent := templateConfig(t, "XXXXXX")

	first, err := NewSession(uuid.NewV4(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession (first): %v", err)
	}
	defer first.Close()
	second, err := NewSession(uuid.NewV4(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession (second): %v", err)
	}
	defer second.Close()

	if first.sessionDir == second.sessionDir {
		t.Fatalf("both sessions share directory %q; the XXXXXX template was not expanded", first.sessionDir)
	}
	for _, dir := range []string{first.sessionDir, second.sessionDir} {
		if filepath.Dir(dir) != parent {
			t.Errorf("session dir %q is not under %q", dir, parent)
		}
		base := filepath.Base(dir)
		if !isExpandedSuffix(base) {
			t.Errorf("session dir base %q is not a six-character mkdtemp expansion", base)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %q: %v", dir, err)
		}
		if !info.IsDir() {
			t.Errorf("%q is not a directory", dir)
		}
	}

	// The log_id handed to the client must name the directory that was really
	// created; C sets evlog->iolog_path from the buffer mkdtemp() rewrote
	// (logsrvd/iolog_writer.c:626-630), so a restart can find the session again.
	assertLogIDMatchesDir(t, first.logID, cfg.LogDirectory, first.sessionDir)
	assertLogIDMatchesDir(t, second.logID, cfg.LogDirectory, second.sessionDir)
}

// TestEventSessionPathMkdtempTemplateIsUnique covers the event-only
// (expect_iobufs=false) constructor, which builds its path the same way.
func TestEventSessionPathMkdtempTemplateIsUnique(t *testing.T) {
	cfg, _ := templateConfig(t, "XXXXXX")
	acceptMsg := createTestAcceptMessage()
	acceptMsg.ExpectIobufs = false

	first, err := NewEventSession(uuid.NewV4(), acceptMsg, cfg)
	if err != nil {
		t.Fatalf("NewEventSession (first): %v", err)
	}
	defer first.Close()
	second, err := NewEventSession(uuid.NewV4(), acceptMsg, cfg)
	if err != nil {
		t.Fatalf("NewEventSession (second): %v", err)
	}
	defer second.Close()

	if first.sessionDir == second.sessionDir {
		t.Fatalf("both event sessions share directory %q; the XXXXXX template was not expanded", first.sessionDir)
	}
	assertLogIDMatchesDir(t, first.logID, cfg.LogDirectory, first.sessionDir)
}

// TestSessionPathMkdtempKeepsPrefixAndExtraXs pins mkdtemp(3) semantics: only
// the trailing six X's are replaced, everything before them is literal.
func TestSessionPathMkdtempKeepsPrefixAndExtraXs(t *testing.T) {
	cfg, parent := templateConfig(t, "run-XXXXXXXX")

	session, err := NewSession(uuid.NewV4(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	base := filepath.Base(session.sessionDir)
	if filepath.Dir(session.sessionDir) != parent {
		t.Errorf("session dir %q is not under %q", session.sessionDir, parent)
	}
	if len(base) != len("run-XXXXXXXX") {
		t.Errorf("session dir base %q has length %d, want %d", base, len(base), len("run-XXXXXXXX"))
	}
	if !strings.HasPrefix(base, "run-XX") {
		t.Errorf("session dir base %q lost its literal prefix; only the last six X's may be replaced", base)
	}
	if !isExpandedSuffix(base[len(base)-6:]) {
		t.Errorf("session dir base %q does not end in a six-character random suffix", base)
	}
}

// TestSessionPathWithoutTemplateIsUnchanged guards against the mkdtemp branch
// firing on ordinary paths: fewer than six trailing X's is not a template.
func TestSessionPathWithoutTemplateIsUnchanged(t *testing.T) {
	cfg, parent := templateConfig(t, "XXXXX")

	session, err := NewSession(uuid.NewV4(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	want := filepath.Join(parent, "XXXXX")
	if session.sessionDir != want {
		t.Errorf("session dir = %q, want %q (five X's is not an mkdtemp template)", session.sessionDir, want)
	}
}

// assertLogIDMatchesDir decodes the base64 log_id and checks that the path it
// carries is the session directory relative to log_directory.
func assertLogIDMatchesDir(t *testing.T, logID, logDirectory, sessionDir string) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(logID)
	if err != nil {
		t.Fatalf("decode log_id %q: %v", logID, err)
	}
	if len(raw) < 16 {
		t.Fatalf("log_id payload too short: %d bytes", len(raw))
	}
	got := string(raw[16:])
	want, err := filepath.Rel(logDirectory, sessionDir)
	if err != nil {
		t.Fatalf("relpath: %v", err)
	}
	if got != want {
		t.Errorf("log_id path = %q, want %q (log_id must name the directory actually created)", got, want)
	}
}
