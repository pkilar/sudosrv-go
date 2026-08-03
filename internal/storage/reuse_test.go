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

// plantCompletedSession creates a session directory in the state a NORMALLY
// COMPLETED session leaves behind: every file present and `timing` chmod'ed to
// 0440 by finalize(), which is how both this server and C
// (logsrvd/logsrvd_local.c:427-431) mark a session complete.
//
// This is the common re-use case. plantStaleSession above covers the rare one --
// an aborted session, whose timing file is still writable.
func plantCompletedSession(t *testing.T, sessionDir string, names ...string) {
	t.Helper()
	plantStaleSession(t, sessionDir, names...)
	if err := os.Chmod(filepath.Join(sessionDir, "timing"), 0440); err != nil {
		t.Fatalf("mark timing complete: %v", err)
	}
}

// TestSessionReusesDirectoryAfterCompletedSession is the second half of
// IOLOG-049, and the half that dropping O_EXCL alone does not fix.
//
// finalize() clears the write bits on `timing` to mark completion, so a re-used
// directory almost always holds a READ-ONLY timing file. O_CREAT|O_TRUNC on it
// fails EACCES rather than the old EEXIST -- a different errno reaching the same
// fatal end: the accept fails, the client gets "Internal Server Error", and
// because sudoers defaults ignore_iolog_errors to false the client breaks its
// event loop and KILLS the user's running privileged command
// (plugins/sudoers/log_client.c:1650-1656).
//
// C does not fail here. Every session file it opens goes through iolog_openat,
// which on EACCES stats the file, restores the missing write bits with fchmodat
// and retries the open (lib/iolog/iolog_openat.c:58-67).
//
// Conformance: docs/logsrvd-reference/ IOLOG-049.
func TestSessionReusesDirectoryAfterCompletedSession(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)
	plantCompletedSession(t, sessionDir, "uuid", "log", "log.json", "timing", "stdout", "stderr", "ttyout", "ttyin")

	sessionUUID := uuid.New()
	session, err := NewSession(sessionUUID, createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession over a completed re-used directory: %v", err)
	}
	defer session.Close()

	if _, err := session.HandleClientMessage(acceptClientMsg()); err != nil {
		t.Fatalf("HandleClientMessage(Accept) over a completed re-used directory: %v", err)
	}
	ioMsg := &pb.ClientMessage{Type: &pb.ClientMessage_TtyinBuf{
		TtyinBuf: &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 1000}, Data: []byte("fresh keystrokes")},
	}}
	if _, err := session.HandleClientMessage(ioMsg); err != nil {
		t.Fatalf("HandleClientMessage(ttyin) over a completed re-used directory: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, name := range []string{"uuid", "log", "log.json", "timing", "stdout", "stderr", "ttyout", "ttyin"} {
		got, err := os.ReadFile(filepath.Join(sessionDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(got), "STALE DATA") {
			t.Errorf("%s still contains data from the previous session: %q", name, got)
		}
	}
}

// TestSessionReusesReadOnlyStreamFile pins the same write-bit restore on the
// stream files, which ensureStreamFile opens on demand rather than at accept.
// C applies iolog_openat uniformly (streams reach it via iolog_open,
// lib/iolog/iolog_open.c:83), so a stale read-only stream -- from a restore, a
// backup tool, or an operator -- must be made writable and truncated, not
// treated as fatal.
func TestSessionReusesReadOnlyStreamFile(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)
	plantCompletedSession(t, sessionDir, "uuid", "log", "log.json", "timing", "ttyin")
	if err := os.Chmod(filepath.Join(sessionDir, "ttyin"), 0440); err != nil {
		t.Fatalf("make ttyin read-only: %v", err)
	}

	session, err := NewSession(uuid.New(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()
	if _, err := session.HandleClientMessage(acceptClientMsg()); err != nil {
		t.Fatalf("HandleClientMessage(Accept): %v", err)
	}

	ioMsg := &pb.ClientMessage{Type: &pb.ClientMessage_TtyinBuf{
		TtyinBuf: &pb.IoBuffer{Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 1000}, Data: []byte("fresh keystrokes")},
	}}
	if _, err := session.HandleClientMessage(ioMsg); err != nil {
		t.Fatalf("HandleClientMessage(ttyin) onto a read-only stream: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(sessionDir, "ttyin"))
	if err != nil {
		t.Fatalf("read ttyin: %v", err)
	}
	if strings.Contains(string(got), "STALE DATA") {
		t.Errorf("ttyin was not truncated: %q", got)
	}
}

// TestSessionRootRefusesReadOnlySymlinkedTiming makes sure the EACCES retry did
// not open a containment hole. The retry stats and chmods the refused path, so
// if either could follow a symlink an attacker could pre-plant a read-only
// symlink to a file they do not own and have the server chmod it writable.
// os.Root refuses to traverse a symlink at any component, so the open fails with
// a symlink error rather than EACCES, the retry never runs, and the target keeps
// both its mode and its contents.
func TestSessionRootRefusesReadOnlySymlinkedTiming(t *testing.T) {
	cfg, sessionDir := fixedPathConfig(t)

	victim := filepath.Join(t.TempDir(), "victim")
	const victimContents = "do not clobber\n"
	if err := os.WriteFile(victim, []byte(victimContents), 0400); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		t.Fatalf("pre-create session dir: %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(sessionDir, "timing")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	session, err := NewSession(uuid.New(), createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()

	if _, err := session.HandleClientMessage(acceptClientMsg()); err == nil {
		t.Fatal("HandleClientMessage(Accept) succeeded through a symlinked timing; want refusal")
	}

	info, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("stat victim: %v", err)
	}
	if info.Mode().Perm() != 0400 {
		t.Errorf("symlink target was chmod'ed through the EACCES retry: mode is now %v, want 0400", info.Mode().Perm())
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != victimContents {
		t.Errorf("symlink target was written through: got %q, want %q", got, victimContents)
	}
}
