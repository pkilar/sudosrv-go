// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/root_test.go

//go:build unix

package storage

import (
	"os"
	"path/filepath"
	"testing"

	"sudosrv/internal/config"
	pb "sudosrv/pkg/sudosrv_proto"

	"uuid"
)

// fixedPathConfig returns a config whose session directory is fully
// deterministic (no %{...} escapes), so a test can pre-plant files at the exact
// path a session is about to use — which is what a local attacker racing a
// predictable iolog path would do.
func fixedPathConfig(t *testing.T) (cfg *config.LocalStorageConfig, sessionDir string) {
	t.Helper()
	tmpDir := t.TempDir()
	cfg = &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		IologDir:        filepath.Join(tmpDir, "sess"),
		IologFile:       "fixed",
		DirPermissions:  0750,
		FilePermissions: 0640,
	}
	return cfg, filepath.Join(tmpDir, "sess", "fixed")
}

func acceptClientMsg() *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
}

// TestSessionRootPinsDirectoryAgainstSwap is the regression test for the
// property os.Root adds over filepath.Join + O_NOFOLLOW: resolution is pinned to
// the session directory's descriptor, not to its path string.
//
// The attack it models: a local attacker who can write in the iolog tree waits
// for a session to start, then swaps the session directory for one they control.
// With path-based resolution every subsequent open re-walks the path and lands
// in the attacker's directory. With a pinned root the writes follow the original
// directory wherever it went, and the substituted directory stays empty.
//
// The stream under test must be ttyin (or stdin): those are the only ones opened
// on demand, i.e. AFTER the swap, so they are the only ones whose resolution the
// swap can influence. stdout/stderr/ttyout are pre-created during initialize, so
// their descriptors are already bound to the original inode and the write lands
// there no matter how paths resolve — a test using one of those asserts nothing.
func TestSessionRootPinsDirectoryAgainstSwap(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)

	session, err := NewSession(uuid.NewV4(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()
	if _, err := session.HandleClientMessage(acceptClientMsg()); err != nil {
		t.Fatalf("HandleClientMessage(Accept): %v", err)
	}

	// The swap: move the real session directory aside and stand up an
	// attacker-controlled directory at the path the session was opened from.
	movedDir := sessionDir + ".moved"
	if err := os.Rename(sessionDir, movedDir); err != nil {
		t.Fatalf("rename session dir: %v", err)
	}
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatalf("recreate session dir: %v", err)
	}

	payload := []byte("post-swap keystrokes")
	ioMsg := &pb.ClientMessage{Type: &pb.ClientMessage_TtyinBuf{
		TtyinBuf: &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 1000}, Data: payload},
	}}
	if _, err := session.HandleClientMessage(ioMsg); err != nil {
		t.Fatalf("HandleClientMessage(ttyin): %v", err)
	}

	// ttyin did not exist at swap time, so this open resolved after it. The
	// file must have been created in the pinned directory, not via the path.
	got, err := os.ReadFile(filepath.Join(movedDir, "ttyin"))
	if err != nil {
		t.Fatalf("read ttyin from pinned (moved) dir: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("ttyin in pinned dir = %q, want %q", got, payload)
	}

	// Nothing may have leaked into the substituted directory.
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		t.Fatalf("read substituted dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("session wrote into the swapped-in directory: %v", names)
	}
}

// TestSessionRootRefusesSymlinkedLogJSONTmp covers log.json.tmp, which is
// deliberately clobberable (O_CREATE|O_TRUNC) so a stale tempfile from an
// interrupted write cannot wedge the session. No session file uses O_EXCL
// (IOLOG-049), so containment has to come from the root.
func TestSessionRootRefusesSymlinkedLogJSONTmp(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)

	victim := filepath.Join(t.TempDir(), "victim")
	const victimContents = "do not clobber\n"
	if err := os.WriteFile(victim, []byte(victimContents), 0600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	// Pre-plant the symlink at the exact path the session will write through.
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatalf("pre-create session dir: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(sessionDir, "log.json.tmp")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	session, err := NewSession(uuid.NewV4(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if _, err := session.HandleClientMessage(acceptClientMsg()); err == nil {
		t.Fatal("HandleClientMessage(Accept) succeeded through a symlinked log.json.tmp; want refusal")
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != victimContents {
		t.Errorf("symlink target was written through: got %q, want %q", got, victimContents)
	}
}

// TestRestartSessionRefusesSymlinkedStream checks the resume path, which opens
// pre-existing files for append and is reachable by any client holding a valid
// log_id.
func TestRestartSessionRefusesSymlinkedStream(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		DirPermissions:  0750,
		FilePermissions: 0640,
	}

	sessionUUID := uuid.NewV4()
	session, err := NewSession(sessionUUID, createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// Close is idempotent (closeOnce), so this only fires if a t.Fatalf below
	// pre-empts the explicit close; it keeps the session directory descriptor
	// from outliving a failing test.
	t.Cleanup(func() { _ = session.Close() })

	if _, err := session.HandleClientMessage(acceptClientMsg()); err != nil {
		t.Fatalf("HandleClientMessage(Accept): %v", err)
	}
	logID := session.LogID()
	sessionDir := session.sessionDir
	// Close without finalizing: finalize marks timing read-only, which is
	// exactly the state a restart is required to reject.
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	victim := filepath.Join(t.TempDir(), "victim")
	const victimContents = "do not clobber\n"
	if err := os.WriteFile(victim, []byte(victimContents), 0600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	// Swap a stream file the restart will reopen for writing.
	stdoutPath := filepath.Join(sessionDir, "stdout")
	if err := os.Remove(stdoutPath); err != nil {
		t.Fatalf("remove stdout: %v", err)
	}
	if err := os.Symlink(victim, stdoutPath); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	restarted, err := NewRestartSession(&pb.RestartMessage{
		LogId:       logID,
		ResumePoint: &pb.TimeSpec{TvSec: 0, TvNsec: 0},
	}, cfg)
	if err == nil {
		restarted.Close()
		t.Fatal("NewRestartSession succeeded through a symlinked stream file; want refusal")
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != victimContents {
		t.Errorf("symlink target was written through: got %q, want %q", got, victimContents)
	}
}
