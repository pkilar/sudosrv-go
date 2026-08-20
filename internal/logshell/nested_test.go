// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/nested_test.go
package logshell

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// TestNestedModeSkipsInsideAnotherLogsh pins the one case with no judgement
// involved. An enclosing logsh is certainly recording these bytes -- they pass
// through its pseudo-terminal to reach us -- so a second recording is pure
// duplication and the setting does not get a say.
func TestNestedModeSkipsInsideAnotherLogsh(t *testing.T) {
	for _, mode := range []string{NestedModeRecord, NestedModeMetadata, NestedModeSkip, ""} {
		cfg := DefaultConfig()
		cfg.NestedSessions = mode
		got := cfg.NestedMode(Nesting{Kind: NestedLogsh})
		if got != NestedModeSkip {
			t.Errorf("nested_sessions=%q inside another logsh = %q, want %q; the outer logsh "+
				"is already capturing these bytes", mode, got, NestedModeSkip)
		}
	}
}

// TestNestedModeUnderSudoFollowsTheSetting covers the ambiguous case: sudo
// records I/O only when the matched sudoers rule says log_output, and nothing
// visible from here reveals whether it did.
func TestNestedModeUnderSudoFollowsTheSetting(t *testing.T) {
	tests := []struct{ set, want string }{
		{"", NestedModeRecord}, // the shipped default
		{NestedModeMetadata, NestedModeMetadata},
		{NestedModeSkip, NestedModeSkip},
		{NestedModeRecord, NestedModeRecord},
	}
	for _, tt := range tests {
		cfg := DefaultConfig()
		cfg.NestedSessions = tt.set
		if got := cfg.NestedMode(Nesting{Kind: NestedSudo}); got != tt.want {
			t.Errorf("nested_sessions=%q under sudo = %q, want %q", tt.set, got, tt.want)
		}
	}

	// Not nested: always a full recording, whatever the setting says.
	cfg := DefaultConfig()
	cfg.NestedSessions = NestedModeSkip
	if got := cfg.NestedMode(Nesting{Kind: NestedNone}); got != NestedModeRecord {
		t.Errorf("an un-nested session = %q, want %q; nested_sessions must not affect "+
			"ordinary logins", got, NestedModeRecord)
	}
}

// TestDefaultKeepsTheTranscriptRatherThanRiskingAGap pins the default at the
// deliberately wasteful option.
//
// Neither `metadata` nor `skip` is safe by default, and the reason is the same
// for both: on a host whose sudoers rule lacks log_output, `shell -> sudo -i ->
// root logsh` leaves the root session captured by NOTHING. A de-duplication
// feature that produces an unrecorded privileged session out of the box has made
// things worse.
//
// Duplication is recoverable -- both copies carry the same session UUID, so one
// can be dropped downstream. A transcript nobody took is gone.
func TestDefaultKeepsTheTranscriptRatherThanRiskingAGap(t *testing.T) {
	got := DefaultConfig().NestedSessions
	if got != NestedModeRecord {
		t.Errorf("the shipped nested_sessions default is %q, want %q", got, NestedModeRecord)
	}
	if got == NestedModeMetadata || got == NestedModeSkip {
		t.Error("the default leaves a session under a non-logging sudoers rule unrecorded")
	}

	// An unset value must resolve the same way, or a config that omits the key
	// gets different behaviour from one that spells out the default.
	cfg := DefaultConfig()
	cfg.NestedSessions = ""
	if m := cfg.NestedMode(Nesting{Kind: NestedSudo}); m != NestedModeRecord {
		t.Errorf("an unset nested_sessions resolves to %q, want %q", m, NestedModeRecord)
	}
}

// TestBothOptOutValuesAreWarnedAbout keeps the cost visible at deploy time.
// Each depends on a claim -- that every sudoers rule reaching a shell carries
// log_output -- that logsh has no way to verify.
func TestBothOptOutValuesAreWarnedAbout(t *testing.T) {
	for _, mode := range []string{NestedModeMetadata, NestedModeSkip} {
		cfg := DefaultConfig()
		cfg.RecordUsers = []string{"root"}
		cfg.NestedSessions = mode

		var found bool
		for _, w := range cfg.Warnings() {
			if strings.Contains(w, "nested_sessions") {
				found = true
			}
		}
		if !found {
			t.Errorf("nested_sessions=%q produced no warning, though it can leave a session "+
				"under a non-logging sudoers rule unrecorded", mode)
		}
	}
}

// TestApplyNestingRecordsWhoEscalated is the metadata fix.
//
// Under `sudo -i` the session runs as root but alice is at the keyboard. A
// record naming root in both fields cannot answer the only question anybody asks
// of it, and sudo's own logs make exactly this distinction.
func TestApplyNestingRecordsWhoEscalated(t *testing.T) {
	meta := SessionMeta{
		User: "root", UID: 0, Group: "root", GID: 0,
		SubmitUser: "root", SubmitUID: 0, SubmitGroup: "root", SubmitGID: 0,
	}
	meta.ApplyNesting(Nesting{
		Kind: NestedSudo, SudoUser: "alice", SudoUID: 1000, SudoGID: 1000,
	})

	if meta.SubmitUser != "alice" || meta.SubmitUID != 1000 {
		t.Errorf("submitter = %s/%d, want alice/1000; the record cannot say who escalated",
			meta.SubmitUser, meta.SubmitUID)
	}
	if meta.User != "root" || meta.UID != 0 {
		t.Errorf("runner = %s/%d, want root/0; the session does run as root",
			meta.User, meta.UID)
	}
	if meta.Nested != "sudo" {
		t.Errorf("Nested = %q, want \"sudo\"", meta.Nested)
	}

	// The info keys the server stores must carry the same split.
	info := map[string]string{}
	for _, i := range meta.InfoMessages() {
		if v, ok := i.Value.(interface{ String() string }); ok {
			_ = v
		}
		info[i.GetKey()] = i.GetStrval()
	}
	if info["submituser"] != "alice" {
		t.Errorf("submituser info key = %q, want alice", info["submituser"])
	}
	if info["runuser"] != "root" {
		t.Errorf("runuser info key = %q, want root", info["runuser"])
	}
}

// TestApplyNestingLeavesSubmitterAloneWithoutSudo checks the ordinary case is
// untouched.
func TestApplyNestingLeavesSubmitterAloneWithoutSudo(t *testing.T) {
	meta := SessionMeta{
		User: "alice", UID: 1000, SubmitUser: "alice", SubmitUID: 1000,
	}
	meta.ApplyNesting(Nesting{Kind: NestedNone, SudoUID: -1, SudoGID: -1})
	if meta.SubmitUser != "alice" || meta.SubmitUID != 1000 {
		t.Errorf("submitter = %s/%d, want alice/1000", meta.SubmitUser, meta.SubmitUID)
	}
}

// TestWithSessionEnvPublishesTheSessionID checks the marker a nested logsh reads,
// and that it replaces rather than appends -- two LOGSH_SESSION entries would
// leave which one wins up to the libc.
func TestWithSessionEnvPublishesTheSessionID(t *testing.T) {
	env := WithSessionEnv([]string{"PATH=/bin", LogshSessionEnv + "=stale"}, "fresh")

	var seen []string
	for _, kv := range env {
		if strings.HasPrefix(kv, LogshSessionEnv+"=") {
			seen = append(seen, kv)
		}
	}
	if len(seen) != 1 || seen[0] != LogshSessionEnv+"=fresh" {
		t.Errorf("%s entries = %v, want exactly [%s=fresh]", LogshSessionEnv, seen, LogshSessionEnv)
	}
}

// TestDetectNestingFindsTheEnclosingLogshFromEnv covers the fast path. Ancestry
// is the signal that survives sudo, but the env marker is what carries the
// parent's UUID for correlation.
func TestDetectNestingFindsTheEnclosingLogshFromEnv(t *testing.T) {
	// This covers the DEFAULT branch of DetectNesting -- the one reached only
	// when the ancestry walk finds nothing -- so it is meaningless if the test
	// runner itself has a sudo or logsh ancestor. Clearing SUDO_USER is not
	// enough: ancestry is deliberately the signal that cannot be lied to, and
	// it reports sudo whatever the environment says. Packagers hit this,
	// because makepkg's check() commonly runs under sudo and the suite then
	// failed the build.
	if walkAncestry() != NestedNone {
		t.Skip("the test runner has a sudo or logsh ancestor; the env fallback " +
			"under test applies only when ancestry finds nothing")
	}
	t.Setenv(LogshSessionEnv, "outer-uuid")
	t.Setenv("SUDO_USER", "")

	n := DetectNesting()
	if n.Kind != NestedLogsh {
		t.Errorf("Kind = %v, want %v with %s set", n.Kind, NestedLogsh, LogshSessionEnv)
	}
	if n.ParentSession != "outer-uuid" {
		t.Errorf("ParentSession = %q, want the enclosing session's id", n.ParentSession)
	}
}

// TestDetectNestingIsQuietWhenNotNested keeps an ordinary login out of the
// nested paths. `go test` itself is the parent here, which is neither sudo nor
// a logsh.
func TestDetectNestingIsQuietWhenNotNested(t *testing.T) {
	// Ancestry, not SUDO_USER: the walk is what DetectNesting actually
	// consults, and it reports a sudo ancestor even when the variable is unset.
	if walkAncestry() != NestedNone {
		t.Skip("the test runner has a sudo or logsh ancestor")
	}
	t.Setenv(LogshSessionEnv, "")

	if n := DetectNesting(); n.Kind != NestedNone {
		t.Errorf("Kind = %v, want %v for an ordinary invocation", n.Kind, NestedNone)
	}
}

// TestDetectNestingReadsTheEscalationIds pins what Nesting documents: the sudo
// ids are -1 when unknown, and "unknown" covers both an unset variable and one
// that is not a number. Nothing else asserted this -- the test above checks only
// Kind -- so seeding the fields to 0, or dropping envInt, went unnoticed.
func TestDetectNestingReadsTheEscalationIds(t *testing.T) {
	tests := []struct {
		user, uid, gid string
		wantUser       string
		wantUID        int
		wantGID        int
	}{
		{"", "", "", "", -1, -1},                       // no sudo in sight
		{"alice", "1000", "2000", "alice", 1000, 2000}, // a real escalation
		{"bob", "root", "-", "bob", -1, -1},            // set, but not numeric
	}
	for _, tt := range tests {
		t.Setenv("SUDO_USER", tt.user)
		t.Setenv("SUDO_UID", tt.uid)
		t.Setenv("SUDO_GID", tt.gid)

		n := DetectNesting()
		if n.SudoUser != tt.wantUser || n.SudoUID != tt.wantUID || n.SudoGID != tt.wantGID {
			t.Errorf("SUDO_USER=%q SUDO_UID=%q SUDO_GID=%q gave (%q, %d, %d), want (%q, %d, %d)",
				tt.user, tt.uid, tt.gid, n.SudoUser, n.SudoUID, n.SudoGID,
				tt.wantUser, tt.wantUID, tt.wantGID)
		}
	}
}

// TestProcInfoHandlesExecutableNamesWithSpaces guards the /proc/<pid>/stat parse.
// Field 2 is parenthesised and may contain spaces and brackets, so splitting the
// line on whitespace misreads both the name and the parent pid.
func TestProcInfoHandlesExecutableNamesWithSpaces(t *testing.T) {
	comm, ppid, ok := procInfo(os.Getpid())
	if !ok {
		t.Fatal("could not read this process's own /proc entry")
	}
	if comm == "" {
		t.Error("empty comm")
	}
	if ppid != os.Getppid() {
		t.Errorf("ppid = %d, want %d", ppid, os.Getppid())
	}
}

// TestIsShellSymlinkNameIsConservative keeps the ancestry check from calling
// every "l"-prefixed program a nested logsh.
func TestIsShellSymlinkNameIsConservative(t *testing.T) {
	for _, yes := range []string{"lbash", "lzsh", "lsh", "-lbash"} {
		if !isShellSymlinkName(yes) {
			t.Errorf("%q was not recognised as a logsh symlink", yes)
		}
	}
	for _, no := range []string{"less", "ls", "ln", "login", "bash", "sudo", ""} {
		if isShellSymlinkName(no) {
			t.Errorf("%q was mistaken for a logsh symlink; every session under it would "+
				"silently stop being recorded", no)
		}
	}
}

// TestMetadataOnlySessionRecordsNoTranscript is the point of the whole feature:
// a nested session must leave a record without duplicating the bytes.
func TestMetadataOnlySessionRecordsNoTranscript(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)

	_, wOut := pipes(t)
	rIn := emptyStdin(t)

	nesting := Nesting{Kind: NestedSudo, SudoUser: "alice", SudoUID: 1000, SudoGID: 1000}
	inv := Invocation{Name: "lbash", LoginShell: true,
		Args: []string{"-c", "printf 'NOT-DUPLICATED\\n'; exit 5"}}

	outcome, err := RunMetadataOnly(context.Background(), cfg, inv, "/bin/sh",
		StdIO{In: rIn, Out: wOut, Err: wOut}, nil, nesting)
	if err != nil {
		t.Fatalf("RunMetadataOnly: %v", err)
	}
	if outcome.ExitCode != 5 {
		t.Errorf("ExitCode = %d, want 5", outcome.ExitCode)
	}

	waitForExit(t, srv)

	out, in, _, exit, acc := srv.snapshot()
	if out != "" || in != "" {
		t.Errorf("a nested session produced a transcript anyway: %d out / %d in bytes",
			len(out), len(in))
	}
	if acc == nil {
		t.Fatal("no record reached the server; the nested session is invisible")
	}
	if acc.GetExpectIobufs() {
		t.Error("the nested session declared expect_iobufs; the server would wait for buffers " +
			"that never come and answer with a log id nobody reads")
	}
	if exit == nil {
		t.Error("no ExitMessage; the record cannot say how the session ended")
	}

	// The record must say who escalated and name the nesting, or it cannot be
	// lined up against the transcript sudo kept.
	if got := infoValue(acc, "submituser"); got != "alice" {
		t.Errorf("submituser = %q, want alice; the record cannot say who was at the keyboard", got)
	}
	if got := infoValue(acc, "runuser"); got == "alice" {
		t.Errorf("runuser = %q, but the session runs as the target account", got)
	}
	if got := infoValue(acc, "logsh_nested"); got != "sudo" {
		t.Errorf("logsh_nested = %q, want sudo", got)
	}
}

// TestMetadataOnlySessionPassesTheTerminalThrough checks that the child really
// does inherit the caller's streams, which is what avoids the extra pty layer
// and the second helping of the raw-mode keystroke-timing regression.
func TestMetadataOnlySessionPassesTheTerminalThrough(t *testing.T) {
	srv := newMockServer(t)
	cfg := testConfig(srv.addr)

	rOut, wOut := pipes(t)
	rIn := emptyStdin(t)

	inv := Invocation{Name: "lbash", Args: []string{"-c", "printf 'STRAIGHT-THROUGH\\n'"}}
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		_, _ = RunMetadataOnly(context.Background(), cfg, inv, "/bin/sh",
			StdIO{In: rIn, Out: wOut, Err: wOut}, nil,
			Nesting{Kind: NestedSudo, SudoUID: -1, SudoGID: -1})
		_ = wOut.Close()
	}()
	t.Cleanup(func() { <-ran })

	buf := make([]byte, 256)
	n, _ := rOut.Read(buf)
	if !bytes.Contains(buf[:n], []byte("STRAIGHT-THROUGH")) {
		t.Errorf("the caller's stream did not receive the shell's output: %q", buf[:n])
	}
}
