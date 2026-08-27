// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/record_test.go
package logshell

import (
	"os"
	"path/filepath"
	"strings"
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

// authInfoValue pulls a scalar info key out of a rendered message set.
//
// Named apart from nonint_test.go's infoValue (which reads an *AcceptMessage
// directly) because that name is already taken in this package and this helper
// takes the already-rendered []*pb.InfoMessage instead.
func authInfoValue(t *testing.T, msgs []*pb.InfoMessage, key string) (string, bool) {
	t.Helper()
	for _, m := range msgs {
		if m.Key != key {
			continue
		}
		if s, ok := m.Value.(*pb.InfoMessage_Strval); ok {
			return s.Strval, true
		}
		t.Fatalf("info key %q is not a strval", key)
	}
	return "", false
}

// TestApplyAuthInfoNamesTheHumanInSubmituser is R-2 and R-4 together.
//
// The session RUNS as root; a person authenticated it. This is the same
// correction ApplyNesting makes under `sudo -i`, where the session runs as root
// but alice is at the keyboard -- and it is why sudolens shows the human with no
// change to the frontend. A record naming root in both fields cannot answer the
// only question anybody asks of it.
func TestApplyAuthInfoNamesTheHumanInSubmituser(t *testing.T) {
	meta := SessionMeta{User: "root", UID: 0, SubmitUser: "root", SubmitUID: 0}
	meta.ApplyAuthInfo(SessionInfo{Auth: AuthInfo{
		Method:        AuthMethodCert,
		KeyID:         "jsmith@CORP.EXAMPLE.COM",
		Serial:        20260819000137,
		Principals:    []string{"root-web"},
		CAFingerprint: "SHA256:abc",
	}})

	if meta.SubmitUser != "jsmith@CORP.EXAMPLE.COM" {
		t.Errorf("SubmitUser = %q, want the certificate key ID", meta.SubmitUser)
	}
	if meta.User != "root" {
		t.Errorf("User = %q, want root: the session still RUNS as root", meta.User)
	}
	// There is no local uid for the human, so the ids keep describing the
	// process. Consumers joining on submituid must not read it as a person.
	if meta.SubmitUID != 0 {
		t.Errorf("SubmitUID = %d, want 0", meta.SubmitUID)
	}
}

// TestApplyAuthInfoPlainKeyDoesNotRewriteSubmituser.
//
// A plain key names nobody, so submituser must stay untouched -- putting a
// fingerprint there would assert an identity the credential does not carry.
// But the record must not go silent instead: logsh_auth_key is the ONLY
// identifier a plain-key session leaves behind (this is the break-glass account,
// or a key the certificate-fallback audit missed), so it must actually carry the
// fingerprint, and logsh_cert_keyid -- which would claim a key ID nobody has --
// must be absent. Asserting the pair together is what pins the exact record
// shape a plain-key session has to produce.
func TestApplyAuthInfoPlainKeyDoesNotRewriteSubmituser(t *testing.T) {
	meta := SessionMeta{User: "root", SubmitUser: "root"}
	meta.ApplyAuthInfo(SessionInfo{Auth: AuthInfo{Method: AuthMethodKey, KeyFingerprint: "SHA256:xyz"}})

	if meta.SubmitUser != "root" {
		t.Errorf("SubmitUser = %q, want root", meta.SubmitUser)
	}

	msgs := meta.InfoMessages()
	got, ok := authInfoValue(t, msgs, "logsh_auth_key")
	if !ok {
		t.Fatal("logsh_auth_key is missing; it is the only identifier this session leaves behind")
	}
	if got != "SHA256:xyz" {
		t.Errorf("logsh_auth_key = %q, want SHA256:xyz", got)
	}
	if _, ok := authInfoValue(t, msgs, "logsh_cert_keyid"); ok {
		t.Error("logsh_cert_keyid is present for a plain key, which has no key ID")
	}
}

// TestInfoMessagesCarryCertificateKeys.
func TestInfoMessagesCarryCertificateKeys(t *testing.T) {
	meta := SessionMeta{User: "root", SubmitUser: "root"}
	meta.ApplyAuthInfo(SessionInfo{
		Auth: AuthInfo{
			Method:        AuthMethodCert,
			KeyID:         "jsmith@CORP.EXAMPLE.COM",
			Serial:        20260819000137,
			Principals:    []string{"root-web", "root-everywhere"},
			CAFingerprint: "SHA256:abc",
		},
		SSHCommand: "internal-sftp -l INFO",
		SSHClient:  "10.20.30.41 51234",
	})
	msgs := meta.InfoMessages()

	for key, want := range map[string]string{
		"logsh_auth_method": AuthMethodCert,
		"logsh_cert_keyid":  "jsmith@CORP.EXAMPLE.COM",
		"logsh_cert_serial": "20260819000137",
		"logsh_cert_ca":     "SHA256:abc",
		"logsh_ssh_command": "internal-sftp -l INFO",
		"logsh_ssh_client":  "10.20.30.41 51234",
	} {
		got, ok := authInfoValue(t, msgs, key)
		if !ok {
			t.Errorf("info key %q is missing", key)
			continue
		}
		if got != want {
			t.Errorf("info key %q = %q, want %q", key, got, want)
		}
	}

	// Principals are a list, matching runargv and runenv, so log.json holds a
	// JSON array rather than a string a consumer has to re-split.
	var principals []string
	for _, m := range msgs {
		if m.Key == "logsh_cert_principals" {
			if l, ok := m.Value.(*pb.InfoMessage_Strlistval); ok {
				principals = l.Strlistval.Strings
			}
		}
	}
	if len(principals) != 2 || principals[1] != "root-everywhere" {
		t.Errorf("logsh_cert_principals = %v, want [root-web root-everywhere]", principals)
	}
}

// TestInfoMessagesOmitEmptyAuthKeys.
//
// The server copies every key it receives straight into log.json, so an empty
// string would assert "this session had no certificate key ID" rather than "this
// was not determined". The existing `source` key omits for exactly this reason.
func TestInfoMessagesOmitEmptyAuthKeys(t *testing.T) {
	msgs := SessionMeta{User: "root", SubmitUser: "root"}.InfoMessages()
	for _, key := range []string{
		"logsh_auth_method", "logsh_cert_keyid", "logsh_cert_serial",
		"logsh_cert_ca", "logsh_auth_key", "logsh_cert_principals", "logsh_ssh_command", "logsh_ssh_client",
	} {
		if _, ok := authInfoValue(t, msgs, key); ok {
			t.Errorf("info key %q must be omitted when unset", key)
		}
	}
}

// TestApplyAuthInfoTruncatesTheClientCommand.
//
// SSH_ORIGINAL_COMMAND is attacker-controlled and unbounded. An enormous value
// must not bloat every session record.
func TestApplyAuthInfoTruncatesTheClientCommand(t *testing.T) {
	meta := SessionMeta{}
	meta.ApplyAuthInfo(SessionInfo{SSHCommand: strings.Repeat("x", DefaultCommandLogMaxLen*3)})

	if len(meta.Info.SSHCommand) > DefaultCommandLogMaxLen {
		t.Errorf("SSHCommand length %d, want <= %d", len(meta.Info.SSHCommand), DefaultCommandLogMaxLen)
	}
	if !strings.HasSuffix(meta.Info.SSHCommand, "...") {
		t.Error("truncation must be visible in the value")
	}
}
