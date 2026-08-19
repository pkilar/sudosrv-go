// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/record_test.go
package logshell

import (
	"os"
	"path/filepath"
	"testing"

	pb "sudosrv/pkg/sudosrv_proto"
)

// unsetTZ removes $TZ for the duration of the test and restores whatever the
// developer's environment had. t.Setenv cannot unset, but it does register the
// restore, so setting then unsetting gets both halves.
func unsetTZ(t *testing.T) {
	t.Helper()
	t.Setenv("TZ", "placeholder")
	if err := os.Unsetenv("TZ"); err != nil {
		t.Fatal(err)
	}
}

func infoOf(msgs []*pb.InfoMessage, key string) *pb.InfoMessage {
	for _, m := range msgs {
		if m.GetKey() == key {
			return m
		}
	}
	return nil
}

// TestTimezoneNamePassesTZThroughVerbatim covers the case where the session
// really does carry a TZ. The empty value is the one worth pinning: POSIX
// defines TZ="" as UTC, so "helpfully" replacing it with the host's zone would
// record the session as having run somewhere it did not.
func TestTimezoneNamePassesTZThroughVerbatim(t *testing.T) {
	for _, tz := range []string{"Europe/Berlin", "UTC", "EST5EDT", ""} {
		t.Setenv("TZ", tz)
		if got := timezoneName("/nonexistent", "/nonexistent"); got != tz {
			t.Errorf("timezoneName() = %q, want %q passed through unchanged", got, tz)
		}
	}
}

// TestTimezoneNameDerivesFromLocaltimeSymlink is the path taken on almost every
// modern host, where $TZ is unset and /etc/localtime is a symlink into tzdata.
func TestTimezoneNameDerivesFromLocaltimeSymlink(t *testing.T) {
	unsetTZ(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "localtime")
	if err := os.Symlink("/usr/share/zoneinfo/Asia/Tokyo", link); err != nil {
		t.Fatal(err)
	}
	if got := timezoneName(link, "/nonexistent"); got != "Asia/Tokyo" {
		t.Errorf("timezoneName() = %q, want Asia/Tokyo derived from the symlink", got)
	}
}

// TestTimezoneNameIgnoresALocaltimeThatIsNotAZoneinfoPath keeps the extraction
// honest: a plain copied file, or a symlink somewhere unrelated, carries no
// name, and inventing one from the path would be worse than falling through.
func TestTimezoneNameIgnoresALocaltimeThatIsNotAZoneinfoPath(t *testing.T) {
	unsetTZ(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "localtime")
	if err := os.Symlink("/somewhere/else/tzfile", link); err != nil {
		t.Fatal(err)
	}
	tzfile := filepath.Join(dir, "timezone")
	if err := os.WriteFile(tzfile, []byte("Australia/Perth\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := timezoneName(link, tzfile); got != "Australia/Perth" {
		t.Errorf("timezoneName() = %q, want the /etc/timezone value", got)
	}
}

// TestTimezoneNameNeverReturnsEmpty matters because the value is recorded as
// "TZ=" + this. An empty result would write a bare "TZ=" into the session
// record, which reads as "the session ran in UTC" rather than "the host could
// not say".
func TestTimezoneNameNeverReturnsEmpty(t *testing.T) {
	unsetTZ(t)
	if got := timezoneName("/nonexistent", "/nonexistent"); got == "" {
		t.Error("timezoneName() = \"\" with no source available; want a fallback")
	}
}

// TestCollectMetaRecordsTheRecorderAndTimezone is the property the session
// record depends on: every session says which binary produced it and what
// timezone its timestamps are in.
func TestCollectMetaRecordsTheRecorderAndTimezone(t *testing.T) {
	t.Setenv("TZ", "Europe/Berlin")
	meta := CollectMeta("/dev/pts/3", WinSize{Rows: 24, Cols: 80}, "/bin/bash", []string{"-bash"})

	if meta.Source == "" {
		t.Error("Source is empty; the record cannot say which binary recorded it")
	}
	if len(meta.RunEnv) == 0 {
		t.Fatal("RunEnv is empty; a replay has no timezone to render timestamps in")
	}
	if meta.RunEnv[0] != "TZ=Europe/Berlin" {
		t.Errorf("RunEnv[0] = %q, want TZ=Europe/Berlin", meta.RunEnv[0])
	}
}

// TestInfoMessagesCarrySourceAndRunenv pins the wire encoding. runenv must be a
// string LIST and not a joined string: the server copies list values into
// log.json as a JSON array, which is what C produces (IOLOG-023) and what
// anything parsing the record expects.
func TestInfoMessagesCarrySourceAndRunenv(t *testing.T) {
	meta := SessionMeta{Source: "/usr/sbin/logsh", RunEnv: []string{"TZ=Asia/Tokyo"}}
	msgs := meta.InfoMessages()

	src := infoOf(msgs, "source")
	if src == nil {
		t.Fatal("no source info key; the record cannot say which binary recorded it")
	}
	if got := src.GetStrval(); got != "/usr/sbin/logsh" {
		t.Errorf("source = %q, want /usr/sbin/logsh", got)
	}

	env := infoOf(msgs, "runenv")
	if env == nil {
		t.Fatal("no runenv info key")
	}
	list := env.GetStrlistval()
	if list == nil {
		t.Fatalf("runenv is %T, want a string list so it lands in log.json as an array", env.Value)
	}
	if len(list.Strings) != 1 || list.Strings[0] != "TZ=Asia/Tokyo" {
		t.Errorf("runenv = %v, want [TZ=Asia/Tokyo]", list.Strings)
	}
}

// TestInfoMessagesAlwaysSendAnEmptySubmitenv pins the rule that is the opposite
// of the one below: source and runenv are omitted when unknown, submitenv is
// always present and always empty. It is a positive statement that no submit
// environment was recorded, so a consumer walking C's log.json field set finds
// it rather than having to guess whether an absent key means "empty" or "this
// recorder does not send it".
func TestInfoMessagesAlwaysSendAnEmptySubmitenv(t *testing.T) {
	for _, meta := range []SessionMeta{
		{},
		{Source: "/usr/sbin/logsh", RunEnv: []string{"TZ=UTC"}},
	} {
		env := infoOf(meta.InfoMessages(), "submitenv")
		if env == nil {
			t.Fatalf("no submitenv info key for %+v", meta)
		}
		list := env.GetStrlistval()
		if list == nil {
			t.Fatalf("submitenv is %T, want a string list", env.Value)
		}
		if len(list.Strings) != 0 {
			t.Errorf("submitenv = %v, want empty", list.Strings)
		}
	}
}

// TestInfoMessagesOmitAZeroTerminalSize is a bug with an invisible failure
// mode. sudoreplay refuses a session recorded as 0x0 -- it exits 1 with no
// message and replays nothing -- so a capture from a pty whose size was never
// set produced a file that looked fine and could not be played, with no clue
// why. Omitting the keys lets the server apply the 24x80 that C seeds into
// evlog before it parses info messages.
func TestInfoMessagesOmitAZeroTerminalSize(t *testing.T) {
	msgs := SessionMeta{Rows: 0, Cols: 0}.InfoMessages()
	if infoOf(msgs, "lines") != nil {
		t.Error("a zero row count was sent; sudoreplay refuses a 0x0 session")
	}
	if infoOf(msgs, "columns") != nil {
		t.Error("a zero column count was sent; sudoreplay refuses a 0x0 session")
	}
}

// TestInfoMessagesSendARealTerminalSize is the other half: a size the terminal
// did report must survive, or every recording would replay at 24x80 regardless
// of how it was actually laid out.
func TestInfoMessagesSendARealTerminalSize(t *testing.T) {
	msgs := SessionMeta{Rows: 44, Cols: 170}.InfoMessages()
	lines, cols := infoOf(msgs, "lines"), infoOf(msgs, "columns")
	if lines == nil || cols == nil {
		t.Fatalf("a reported size was dropped: lines=%v columns=%v", lines, cols)
	}
	if lines.GetNumval() != 44 || cols.GetNumval() != 170 {
		t.Errorf("size = %dx%d, want 44x170", lines.GetNumval(), cols.GetNumval())
	}
}

// TestInfoMessagesOmitAnUnknownSource covers the difference between "not
// determined" and "determined to be nothing". The server copies every key it
// receives straight into log.json, so sending an empty source would assert that
// the recorder is unknown rather than that it was never established.
func TestInfoMessagesOmitAnUnknownSource(t *testing.T) {
	msgs := SessionMeta{}.InfoMessages()
	if infoOf(msgs, "source") != nil {
		t.Error("an empty Source was still sent; it should be omitted entirely")
	}
	if infoOf(msgs, "runenv") != nil {
		t.Error("an empty RunEnv was still sent; it should be omitted entirely")
	}
}
