// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/log_summary_test.go
package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sudosrv/internal/config"
	pb "sudosrv/pkg/sudosrv_proto"

	"uuid"
)

// logSummaryLines writes a session for the given command/runargv and returns the
// three lines of its plaintext `log` file.
func logSummaryLines(t *testing.T, command string, runargv []string) []string {
	t.Helper()
	accept := createTestAcceptMessage()
	for _, m := range accept.InfoMsgs {
		if m.GetKey() == "command" {
			m.Value = &pb.InfoMessage_Strval{Strval: command}
		}
	}
	if runargv != nil {
		accept.InfoMsgs = append(accept.InfoMsgs, &pb.InfoMessage{
			Key:   "runargv",
			Value: &pb.InfoMessage_Strlistval{Strlistval: &pb.InfoMessage_StringList{Strings: runargv}},
		})
	}

	cfg := &config.LocalStorageConfig{LogDirectory: t.TempDir()}
	sess, err := NewSession(uuid.NewV4(), accept, cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	// The session files are written when the AcceptMessage is handled, not by
	// NewSession itself.
	if _, err := sess.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: accept},
	}); err != nil {
		t.Fatalf("HandleClientMessage(Accept): %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(sess.sessionDir, fileLog))
	if err != nil {
		t.Fatalf("reading log summary: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("log summary has %d lines, want 3:\n%s", len(lines), raw)
	}
	return lines
}

// TestLogSummaryIncludesCommandArguments pins the third line of the plaintext
// `log` file against C's iolog_write_info_file_legacy
// (lib/iolog/iolog_loginfo.c:128-135), which writes evlog->command followed by
// every element of runargv EXCEPT the first.
//
// This line used to carry the bare command, so a session that ran
// "/bin/sh -c ..." was recorded as "/bin/sh" -- indistinguishable from an
// interactive shell to anything reading the legacy file rather than log.json.
// Verified byte-for-byte against the real sudo_logsrvd fed the same session.
func TestLogSummaryIncludesCommandArguments(t *testing.T) {
	// runargv[0] is argv[0] -- "-sh" for a login shell -- and is deliberately
	// skipped, which is why it is deliberately DIFFERENT from the command here:
	// an implementation that joined the whole of runargv would produce
	// "/bin/sh -sh -c ..." and pass a test that used the same string for both.
	lines := logSummaryLines(t, "/bin/sh", []string{"-sh", "-c", "printf A; sleep 1"})

	const want = "/bin/sh -c printf A; sleep 1"
	if lines[2] != want {
		t.Errorf("log summary command line = %q, want %q", lines[2], want)
	}
}

// TestLogSummaryCommandWithoutArgv keeps the no-runargv case from regressing
// into a trailing space or a panic.
func TestLogSummaryCommandWithoutArgv(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"absent", nil, "/bin/ls"},
		{"empty list", []string{}, "/bin/ls"},
		{"argv0 only", []string{"ls"}, "/bin/ls"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := logSummaryLines(t, "/bin/ls", tc.argv)
			if lines[2] != tc.want {
				t.Errorf("command line = %q, want %q", lines[2], tc.want)
			}
		})
	}
}

// TestLogSummaryArgumentsAreSanitized keeps a hostile argument from forging
// extra records: the file is newline-delimited, so an embedded newline in an
// argument would otherwise append a line that reads like a separate session.
func TestLogSummaryArgumentsAreSanitized(t *testing.T) {
	lines := logSummaryLines(t, "/bin/sh", []string{"sh", "-c", "x\nforged:line"})
	if strings.Contains(lines[2], "\n") {
		t.Fatal("a newline survived into the log summary")
	}
	if !strings.Contains(lines[2], "x?forged:line") {
		t.Errorf("control character was not replaced: %q", lines[2])
	}
}

// TestLogSummaryDefaultsTerminalSize covers a tty-less client, which omits
// lines and columns. C seeds them to 24x80 before parsing info messages
// (logsrvd/iolog_writer.c:167-168); leaving them unset ends the first line in
// two empty colon-delimited fields and drops both members from log.json, which
// IOLOG-023 requires to be present always.
func TestLogSummaryDefaultsTerminalSize(t *testing.T) {
	accept := createTestAcceptMessage()
	var kept []*pb.InfoMessage
	for _, m := range accept.InfoMsgs {
		if m.GetKey() != "lines" && m.GetKey() != "columns" {
			kept = append(kept, m)
		}
	}
	accept.InfoMsgs = kept

	cfg := &config.LocalStorageConfig{LogDirectory: t.TempDir()}
	sess, err := NewSession(uuid.NewV4(), accept, cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	if _, err := sess.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: accept},
	}); err != nil {
		t.Fatalf("HandleClientMessage(Accept): %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(sess.sessionDir, fileLog))
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(raw), "\n")
	if !strings.HasSuffix(first, ":24:80") {
		t.Errorf("log summary first line = %q, want it to end in :24:80", first)
	}
}
