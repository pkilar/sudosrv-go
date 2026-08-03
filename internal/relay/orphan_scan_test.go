// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/orphan_scan_test.go
package relay

import (
	"os"
	"path/filepath"
	"runtime"
	"sudosrv/internal/config"
	"testing"
)

// TestScanOrphansReportsUnreadableDirectory checks that a cache directory the
// daemon cannot read is an error, not an empty result.
//
// filepath.Glob returns (nil, nil) for a missing or unreadable directory — it
// only ever reports ErrBadPattern. Recovery therefore concluded "no orphaned
// files" and the daemon came up looking healthy while every cached session on
// that volume was permanently abandoned: a wrong mount, a bad chown or a typo'd
// relay_cache_directory silently discarded the audit backlog.
//
// Conformance: docs/logsrvd-reference/ ARCH-043.
func TestScanOrphansReportsUnreadableDirectory(t *testing.T) {
	t.Run("MissingDirectory", func(t *testing.T) {
		cfg := &config.RelayConfig{
			RelayCacheDirectory: filepath.Join(t.TempDir(), "does-not-exist"),
		}
		if _, err := ScanOrphans(cfg); err == nil {
			t.Error("ScanOrphans reported success for a missing cache directory; " +
				"every cached session there would be silently abandoned")
		}
	})

	t.Run("UnreadableDirectory", func(t *testing.T) {
		if os.Geteuid() == 0 || runtime.GOOS != "linux" {
			t.Skip("requires a non-root uid on linux to make a directory unreadable")
		}
		dir := filepath.Join(t.TempDir(), "cache")
		if err := os.Mkdir(dir, 0o000); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		cfg := &config.RelayConfig{RelayCacheDirectory: dir}
		if _, err := ScanOrphans(cfg); err == nil {
			t.Error("ScanOrphans reported success for an unreadable cache directory")
		}
	})
}

// TestScanOrphansSnapshotExcludesLaterFiles checks that recovery works from a
// snapshot taken before the server starts accepting, so it cannot raid the
// cache file of a session that connects afterwards.
//
// Recovery used to glob the live cache directory from a goroutine started after
// the listeners were already serving. A session accepted in that window has its
// {uuid}.log picked up mid-write, renamed to .flushing, replayed upstream in
// whatever partial state it happened to be in, and unlinked — truncating and
// duplicating a live session's audit record while the session keeps writing to
// a now-unlinked file.
//
// Conformance: docs/logsrvd-reference/ ARCH-043.
func TestScanOrphansSnapshotExcludesLaterFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.RelayConfig{RelayCacheDirectory: dir}

	orphan := filepath.Join(dir, "11111111-1111-1111-1111-111111111111.log")
	if err := os.WriteFile(orphan, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write orphan: %v", err)
	}

	files, err := ScanOrphans(cfg)
	if err != nil {
		t.Fatalf("ScanOrphans: %v", err)
	}

	// A session accepted after the scan writes its own cache file.
	live := filepath.Join(dir, "22222222-2222-2222-2222-222222222222.log")
	if err := os.WriteFile(live, []byte("live session in progress"), 0o600); err != nil {
		t.Fatalf("write live: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("snapshot has %d files, want 1", len(files))
	}
	for _, f := range files {
		if filepath.Base(f) == filepath.Base(live) {
			t.Fatalf("snapshot included %s, a cache file created after the scan; "+
				"recovery would raid a live session", filepath.Base(live))
		}
	}
	if filepath.Base(files[0]) != filepath.Base(orphan) {
		t.Errorf("snapshot = %v, want the pre-existing orphan %s", files, filepath.Base(orphan))
	}
}
