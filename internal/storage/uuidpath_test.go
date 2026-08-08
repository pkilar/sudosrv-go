package storage

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
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
