// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/reuse_test.go

//go:build unix

package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "sudosrv/pkg/sudosrv_proto"

	"github.com/google/uuid"
)

// staleContents is long enough that a truncating open is distinguishable from a
// short overwrite: if any of it survives, the file was not truncated.
const staleContents = "STALE DATA FROM A PREVIOUS SESSION THAT MUST NOT SURVIVE\n"

// plantStaleSession creates the session directory with leftover files from an
// earlier session that never finalized -- the state IOLOG-048 says an aborted
// session leaves behind: every file present, writable, and `timing` still 0640.
func plantStaleSession(t *testing.T, sessionDir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatalf("create session dir: %v", err)
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(sessionDir, name), []byte(staleContents), 0640); err != nil {
			t.Fatalf("plant stale %s: %v", name, err)
		}
	}
}

// TestSessionReusesDirectoryByTruncating is the regression test for IOLOG-049.
//
// C sudo_logsrvd opens every session file with O_CREAT|O_TRUNC and no O_EXCL
// (lib/iolog/iolog_open.c:61 for the streams and timing, iolog_loginfo.c:106,183
// for log and log.json, logsrvd/iolog_writer.c:717 for uuid), so re-using a
// session directory truncates and overwrites. Go used O_EXCL, so the second
// session on a re-used path failed with EEXIST, the error propagated out of
// processMessage as "Internal Server Error", and the client -- whose
// ignore_iolog_errors default is false -- broke its event loop and KILLED the
// user's running privileged command. A directory is re-used whenever iolog_file
// carries no uniquifier, when the seq file is lost or restored from backup, or
// when seq wraps at maxseq.
func TestSessionReusesDirectoryByTruncating(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)
	plantStaleSession(t, sessionDir, "uuid", "log", "log.json", "timing", "stdout", "stderr", "ttyout", "ttyin")

	sessionUUID := uuid.New()
	session, err := NewSession(sessionUUID, createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession over a re-used directory: %v", err)
	}
	defer session.Close()

	if _, err := session.HandleClientMessage(acceptClientMsg()); err != nil {
		t.Fatalf("HandleClientMessage(Accept) over a re-used directory: %v", err)
	}

	// ttyin is opened on demand, so it exercises ensureStreamFile's flags.
	payload := []byte("fresh keystrokes")
	ioMsg := &pb.ClientMessage{Type: &pb.ClientMessage_TtyinBuf{
		TtyinBuf: &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 1000}, Data: payload},
	}}
	if _, err := session.HandleClientMessage(ioMsg); err != nil {
		t.Fatalf("HandleClientMessage(ttyin) over a re-used directory: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every file the new session touched must hold only the new session's data.
	for _, name := range []string{"uuid", "log", "log.json", "timing", "stdout", "stderr", "ttyout", "ttyin"} {
		got, err := os.ReadFile(filepath.Join(sessionDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(got), "STALE DATA") {
			t.Errorf("%s still contains data from the previous session: %q", name, got)
		}
	}
	got, err := os.ReadFile(filepath.Join(sessionDir, "uuid"))
	if err != nil {
		t.Fatalf("read uuid: %v", err)
	}
	if strings.TrimSpace(string(got)) != sessionUUID.String() {
		t.Errorf("uuid = %q, want %q", strings.TrimSpace(string(got)), sessionUUID)
	}
}

// TestEventSessionReusesDirectoryByTruncating covers the event-only
// (expect_iobufs=false) constructor, which writes `uuid` and `log.json` through
// the same helper. Same IOLOG-049 consequence: an EEXIST here becomes
// "Internal Server Error" and kills the client's command.
func TestEventSessionReusesDirectoryByTruncating(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)
	plantStaleSession(t, sessionDir, "uuid", "log.json")

	acceptMsg := createTestAcceptMessage()
	acceptMsg.ExpectIobufs = false

	sessionUUID := uuid.New()
	session, err := NewEventSession(sessionUUID, acceptMsg, cfg)
	if err != nil {
		t.Fatalf("NewEventSession over a re-used directory: %v", err)
	}
	defer session.Close()

	got, err := os.ReadFile(filepath.Join(sessionDir, "uuid"))
	if err != nil {
		t.Fatalf("read uuid: %v", err)
	}
	if strings.TrimSpace(string(got)) != sessionUUID.String() {
		t.Errorf("uuid = %q, want %q", strings.TrimSpace(string(got)), sessionUUID)
	}
}

// TestSessionRootRefusesSymlinkedUUID pins the containment property that must
// survive the IOLOG-049 fix: dropping O_EXCL means a pre-planted file is now
// clobbered on purpose, but a pre-planted *symlink* must still be refused. The
// refusal comes from the pinned os.Root (openSessionRoot), never from O_EXCL.
func TestSessionRootRefusesSymlinkedUUID(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)

	victim := filepath.Join(t.TempDir(), "victim")
	const victimContents = "do not clobber\n"
	if err := os.WriteFile(victim, []byte(victimContents), 0600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatalf("pre-create session dir: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(sessionDir, "uuid")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	session, err := NewSession(uuid.New(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if _, err := session.HandleClientMessage(acceptClientMsg()); err == nil {
		t.Fatal("HandleClientMessage(Accept) succeeded through a symlinked uuid; want refusal")
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != victimContents {
		t.Errorf("symlink target was written through: got %q, want %q", got, victimContents)
	}
}
