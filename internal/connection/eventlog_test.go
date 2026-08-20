// SPDX-License-Identifier: Apache-2.0
// Filename: internal/connection/eventlog_test.go
package connection

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	"sudosrv/internal/eventlog"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"

	"uuid"
)

// eventLogToFile points the process-wide event logger at a temp file for the
// duration of one test and returns a reader for what landed there.
func eventLogToFile(t *testing.T, logExit bool) func() string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.log")
	if err := eventlog.Global.Configure(eventlog.Settings{
		Type:     eventlog.TypeLogfile,
		Format:   eventlog.FormatSudo,
		FilePath: path,
		LogExit:  logExit,
		FileMode: 0600,
	}); err != nil {
		t.Fatalf("configure event log: %v", err)
	}
	t.Cleanup(func() { _ = eventlog.Global.Close() })
	return func() string {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

func eventTestAccept(command string) *pb.AcceptMessage {
	return &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 1},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "alice"}},
			{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "web01"}},
			{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
			{Key: "ttyname", Value: &pb.InfoMessage_Strval{Strval: "/dev/pts/3"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: command}},
		},
	}
}

// newEventTestHandler wires a handler whose sessions are mocks, so these tests
// exercise the event-log emission alone and not local storage.
func newEventTestHandler(t *testing.T) (*Handler, func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	// LogDirectory must be set even for tests that never expect to touch disk.
	// handleReject creates a UUID-hierarchy directory under it directly, and an
	// empty value makes that path relative -- so the session tree lands in the
	// package source directory instead of anywhere temporary.
	cfg := &config.Config{
		Server:       config.ServerConfig{Mode: "local", ServerID: "TestSrv"},
		LocalStorage: config.LocalStorageConfig{LogDirectory: t.TempDir()},
	}
	h := NewHandler(serverConn, cfg)
	h.sessionFactories.newLocalStorageSession = func(uuid.UUID, *pb.AcceptMessage, *config.LocalStorageConfig) (SessionHandler, error) {
		return &mockSessionHandler{
			t: t,
			HandleClientFn: func(*pb.ClientMessage) (*pb.ServerMessage, error) {
				return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: "test-id"}}, nil
			},
		}, nil
	}
	return h, func() { _ = clientConn.Close() }
}

// TestEventLogRecordsAcceptedCommand is the point of CONF-058: an accepted
// command must produce the one-line audit record sudo_logsrvd produces, because
// that stream is what a SIEM is watching. Without it the only central record is
// the on-disk session tree, which nothing reads in real time.
func TestEventLogRecordsAcceptedCommand(t *testing.T) {
	read := eventLogToFile(t, false)
	h, done := newEventTestHandler(t)
	defer done()

	if _, err := h.handleAccept(eventTestAccept("/bin/ls")); err != nil {
		t.Fatalf("handleAccept: %v", err)
	}

	got := read()
	for _, want := range []string{"alice", "HOST=web01", "TTY=pts/3", "USER=root", "COMMAND=/bin/ls"} {
		if !strings.Contains(got, want) {
			t.Errorf("event record missing %q; got %q", want, got)
		}
	}
}

// TestEventLogRecordsRejectedCommand covers the other class an audit reviewer
// cares about most: the command that was refused.
func TestEventLogRecordsRejectedCommand(t *testing.T) {
	read := eventLogToFile(t, false)
	h, done := newEventTestHandler(t)
	defer done()

	if _, err := h.handleReject(&pb.RejectMessage{
		SubmitTime: &pb.TimeSpec{TvSec: 1},
		Reason:     "user NOT in sudoers",
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "eve"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/sh"}},
		},
	}); err != nil {
		t.Fatalf("handleReject: %v", err)
	}

	got := read()
	if !strings.Contains(got, "user NOT in sudoers") || !strings.Contains(got, "COMMAND=/bin/sh") {
		t.Errorf("reject record incomplete; got %q", got)
	}
}

// TestEventLogExitRecordCarriesTheCommand pins the reason the handler retains
// acceptInfo at all: an ExitMessage names nothing, so an exit record built from
// it alone would say a command exited without saying which.
func TestEventLogExitRecordCarriesTheCommand(t *testing.T) {
	read := eventLogToFile(t, true)
	h, done := newEventTestHandler(t)
	defer done()

	if _, err := h.handleAccept(eventTestAccept("/bin/ls")); err != nil {
		t.Fatalf("handleAccept: %v", err)
	}
	if _, err := h.processMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 3}},
	}); err != nil {
		t.Fatalf("exit: %v", err)
	}

	got := read()
	if !strings.Contains(got, "EXIT=3") {
		t.Errorf("exit record missing the exit value; got %q", got)
	}
	if !strings.Contains(got, "COMMAND=/bin/ls") {
		t.Errorf("exit record does not identify the command it belongs to; got %q", got)
	}
}

// TestEventLogDisabledProducesNothing guards the default for anyone who turns
// the stream off, and the no-sink path every call site relies on.
func TestEventLogDisabledProducesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	if err := eventlog.Global.Configure(eventlog.Settings{Type: eventlog.TypeNone, FilePath: path}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	t.Cleanup(func() { _ = eventlog.Global.Close() })

	h, done := newEventTestHandler(t)
	defer done()
	if _, err := h.handleAccept(eventTestAccept("/bin/ls")); err != nil {
		t.Fatalf("handleAccept: %v", err)
	}

	if _, err := os.Stat(path); err == nil {
		t.Error("log_type: none still created an event log file")
	}
}
