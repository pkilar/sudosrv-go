package storage

import (
	"path/filepath"
	"testing"

	"uuid"
)

// The layout must stay byte-identical to what handler.go open-coded before, or
// reject records from an upgraded daemon stop landing beside older sessions.
func TestUUIDHierarchyPathMatchesTheFormerInlineLayout(t *testing.T) {
	u := uuid.MustParse("6bca0f12-3456-7890-abcd-ef0123456789")
	want := filepath.Join("/var/log/x", "6b", "ca", "0f")
	if got := UUIDHierarchyPath("/var/log/x", u); got != want {
		t.Errorf("UUIDHierarchyPath = %q, want %q", got, want)
	}
}

// TestUUIDHierarchySpreadsSessions is the reason session UUIDs are minted with
// NewV4 and not New.
//
// The path takes the first 24 bits of the UUID. The standard library documents
// uuid.New as "at this time" equivalent to NewV4 and reserves the right to
// change it; if it became version 7, those bits would be the top of a
// millisecond timestamp, which advances about once every 4.7 hours. Sessions
// would then pile into a single directory instead of spreading -- slowly, in
// production, and invisibly in any test that records one session.
//
// So this records many at once and insists they do not all land together.
func TestUUIDHierarchySpreadsSessions(t *testing.T) {
	const sessions = 200

	seen := map[string]bool{}
	for range sessions {
		seen[UUIDHierarchyPath("/var/log/x", uuid.NewV4())] = true
	}

	// Random 24-bit prefixes give ~200 distinct paths; a timestamp-ordered UUID
	// gives one or two. The bar is set far below the former and far above the
	// latter so it cannot flake on a coincidence.
	if len(seen) < sessions/2 {
		t.Errorf("%d sessions produced only %d distinct directories; the UUID's "+
			"leading bits are not random, so the hierarchy no longer spreads them",
			sessions, len(seen))
	}
}

// TestSessionUUIDsAreVersion4 states the same requirement directly, so a
// failure names the cause rather than the symptom.
func TestSessionUUIDsAreVersion4(t *testing.T) {
	u := uuid.NewV4()
	// RFC 9562: the version nibble is the high nibble of byte 6.
	if version := u[6] >> 4; version != 4 {
		t.Errorf("minted a version %d UUID, want 4; see UUIDHierarchyPath", version)
	}
}
