// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/session_test.go
package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Helper to create a standard AcceptMessage for tests
func createTestAcceptMessage() *pb.AcceptMessage {
	return &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix(), TvNsec: 0},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"}},
			{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
			{Key: "ttyname", Value: &pb.InfoMessage_Strval{Strval: "/dev/pts/1"}},
			{Key: "lines", Value: &pb.InfoMessage_Numval{Numval: 24}},
			{Key: "columns", Value: &pb.InfoMessage_Numval{Numval: 80}},
			{Key: "cwd", Value: &pb.InfoMessage_Strval{Strval: "/home/testuser"}},
			{Key: "runcwd", Value: &pb.InfoMessage_Strval{Strval: "/home/testuser"}},
			{Key: "submituid", Value: &pb.InfoMessage_Numval{Numval: 1001}},
			{Key: "submitgid", Value: &pb.InfoMessage_Numval{Numval: 1001}},
			{Key: "submitgroup", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
			{Key: "runuid", Value: &pb.InfoMessage_Numval{Numval: 0}},
			{Key: "rungid", Value: &pb.InfoMessage_Numval{Numval: 0}},
			{Key: "rungroup", Value: &pb.InfoMessage_Strval{Strval: "root"}},
			{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "testhost"}},
		},
	}
}

func TestStorageSession(t *testing.T) {
	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")

	t.Run("SessionInitializationAndFinalizationWithIologDir", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			IologDir:        filepath.Join("%{LIVEDIR}", "%{user}"),
			IologFile:       "%{seq}",
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}

		// First message must be the AcceptMessage to initialize
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		serverResponse, err := session.HandleClientMessage(acceptClientMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
		}

		// Check for correct server response (log_id should be base64-encoded).
		// %{seq}=1 expands to the C-compatible XX/XX/XX hierarchy "00/00/01".
		expectedRelPath := "testuser/00/00/01"
		idBytes := append(sessionUUID[:], []byte(expectedRelPath)...)
		expectedLogID := base64.StdEncoding.EncodeToString(idBytes)
		if serverResponse.GetLogId() != expectedLogID {
			t.Errorf("Expected server response to be log_id '%s', got '%s'", expectedLogID, serverResponse.GetLogId())
		}

		// Send Exit message to finalize
		exitMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_ExitMsg{
				ExitMsg: &pb.ExitMessage{
					ExitValue: 0,
					RunTime:   &pb.TimeSpec{TvSec: 5, TvNsec: 123456789},
				},
			},
		}
		_, err = session.HandleClientMessage(exitMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(ExitMsg) failed: %v", err)
		}

		// Verify that directories and files were created.
		// %{seq}=1 expands to "00/00/01" (C-compatible XX/XX/XX hierarchy).
		sessDir := filepath.Join(tmpDir, "testuser", "00", "00", "01")
		if _, err := os.Stat(sessDir); os.IsNotExist(err) {
			t.Fatalf("Session directory '%s' was not created", sessDir)
		}

		// Check for log.json and its content
		logJSONPath := filepath.Join(sessDir, "log.json")
		data, err := os.ReadFile(logJSONPath)
		if err != nil {
			t.Fatalf("Failed to read log.json: %v", err)
		}
		var logMeta map[string]any
		if err := json.Unmarshal(data, &logMeta); err != nil {
			t.Fatalf("Failed to unmarshal log.json: %v", err)
		}
		if logMeta["submituser"] != "testuser" {
			t.Errorf("log.json: expected submituser 'testuser', got '%v'", logMeta["submituser"])
		}
		exitVal, ok := logMeta["exit_value"].(float64)
		if !ok {
			t.Fatalf("log.json: missing or non-float64 exit_value, got %T %v", logMeta["exit_value"], logMeta["exit_value"])
		}
		if exitVal != 0 {
			t.Errorf("log.json: expected exit_value 0, got '%v'", exitVal)
		}
		if logMeta["runcwd"] != "/home/testuser" {
			t.Errorf("log.json: expected runcwd '/home/testuser', got '%v'", logMeta["runcwd"])
		}
	})

	t.Run("IoBufferHandling", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			IologDir:        filepath.Join("%{LIVEDIR}", "%{user}"),
			IologFile:       "%{seq}",
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Send a TTY Out buffer
		ttyoutData := []byte("hello world")
		ttyoutMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_TtyoutBuf{
				TtyoutBuf: &pb.IoBuffer{
					Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 500000000}, // 1.5s
					Data:  ttyoutData,
				},
			},
		}
		_, err = session.HandleClientMessage(ttyoutMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(TtyoutBuf) failed: %v", err)
		}

		// Verify ttyout file content
		sessDir := filepath.Join(tmpDir, "testuser", "00", "00", "01") // Sequence 1 -> "00/00/01"
		ttyoutFile := filepath.Join(sessDir, "ttyout")
		content, err := os.ReadFile(ttyoutFile)
		if err != nil {
			t.Fatalf("Failed to read ttyout file: %v", err)
		}
		if string(content) != string(ttyoutData) {
			t.Errorf("ttyout content mismatch: expected '%s', got '%s'", string(ttyoutData), string(content))
		}

		// Verify timing file content uses integer format (seconds.nanoseconds)
		timingFile := filepath.Join(sessDir, "timing")
		timingContent, err := os.ReadFile(timingFile)
		if err != nil {
			t.Fatalf("Failed to read timing file: %v", err)
		}
		expectedTiming := fmt.Sprintf("%d 1.500000000 11\n", IO_EVENT_TTYOUT)
		if !strings.Contains(string(timingContent), expectedTiming) {
			t.Errorf("timing file content mismatch: expected to contain '%s', got '%s'", expectedTiming, string(timingContent))
		}

		// Verify format is integer-based (N.NNNNNNNNN), not float-based
		if strings.Contains(string(timingContent), "1.5000000") && !strings.Contains(string(timingContent), "1.500000000") {
			t.Errorf("timing file uses float format instead of integer format: %s", string(timingContent))
		}
	})

	t.Run("OldDefaultPathCreation", func(t *testing.T) {
		tmpDir := t.TempDir()
		// Test the fallback behavior when iolog_dir/file are not set
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}

		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, err = session.HandleClientMessage(acceptClientMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
		}

		// The old default path uses the first 6 chars of the log ID.
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
		if _, err := os.Stat(sessDir); os.IsNotExist(err) {
			t.Fatalf("Session directory '%s' for old default path was not created", sessDir)
		}

		logPath := filepath.Join(sessDir, "log")
		if _, err := os.Stat(logPath); os.IsNotExist(err) {
			t.Fatalf("'log' file was not created at old default path '%s'", logPath)
		}

		session.Close()
	})

	t.Run("SequenceFileHandling", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Test sequence generation
		cfg := &config.LocalStorageConfig{
			DirPermissions:  0755,
			FilePermissions: 0644,
		}
		seq1, err := getNextSeq(tmpDir, cfg)
		if err != nil {
			t.Fatalf("getNextSeq() failed: %v", err)
		}

		seq2, err := getNextSeq(tmpDir, cfg)
		if err != nil {
			t.Fatalf("getNextSeq() failed: %v", err)
		}

		// Sequences should be different and incrementing
		if seq1 == seq2 {
			t.Errorf("Expected different sequence numbers, got same: %s", seq1)
		}

		// %{seq} expands to C's XX/XX/XX hierarchy: 6 uppercase base36 chars
		// split by two slashes (length 8), so `sudoreplay <id>` resolves it.
		for _, seq := range []string{seq1, seq2} {
			if len(seq) != 8 || seq[2] != '/' || seq[5] != '/' {
				t.Errorf("expected seq in XX/XX/XX form, got %q", seq)
			}
			if strings.ToUpper(seq) != seq {
				t.Errorf("expected uppercase base36 seq (matching C), got %q", seq)
			}
		}
		// First two sequences are 1 and 2 -> "00/00/01" and "00/00/02".
		if seq1 != "00/00/01" || seq2 != "00/00/02" {
			t.Errorf("expected seq1=00/00/01 seq2=00/00/02, got %q and %q", seq1, seq2)
		}
	})

	t.Run("RandomAlphanumericString", func(t *testing.T) {
		// Test random string generation
		str1, err := randomAlphanumericString(6)
		if err != nil {
			t.Fatalf("randomAlphanumericString() failed: %v", err)
		}

		str2, err := randomAlphanumericString(6)
		if err != nil {
			t.Fatalf("randomAlphanumericString() failed: %v", err)
		}

		if len(str1) != 6 || len(str2) != 6 {
			t.Errorf("Expected length 6, got %d and %d", len(str1), len(str2))
		}

		// Should be different (very high probability)
		if str1 == str2 {
			t.Errorf("Expected different random strings, got same: %s", str1)
		}

		// Test zero length
		str3, err := randomAlphanumericString(0)
		if err != nil {
			t.Fatalf("randomAlphanumericString(0) failed: %v", err)
		}
		if len(str3) != 0 {
			t.Errorf("Expected empty string, got %s", str3)
		}
	})

	t.Run("AllIoEventTypes", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		testData := []byte("test data")
		delay := &pb.TimeSpec{TvSec: 1, TvNsec: 0}

		// Test all I/O buffer types
		testCases := []struct {
			name string
			msg  *pb.ClientMessage
		}{
			{
				name: "stdin",
				msg: &pb.ClientMessage{
					Type: &pb.ClientMessage_StdinBuf{
						StdinBuf: &pb.IoBuffer{Delay: delay, Data: testData},
					},
				},
			},
			{
				name: "stdout",
				msg: &pb.ClientMessage{
					Type: &pb.ClientMessage_StdoutBuf{
						StdoutBuf: &pb.IoBuffer{Delay: delay, Data: testData},
					},
				},
			},
			{
				name: "stderr",
				msg: &pb.ClientMessage{
					Type: &pb.ClientMessage_StderrBuf{
						StderrBuf: &pb.IoBuffer{Delay: delay, Data: testData},
					},
				},
			},
			{
				name: "ttyin",
				msg: &pb.ClientMessage{
					Type: &pb.ClientMessage_TtyinBuf{
						TtyinBuf: &pb.IoBuffer{Delay: delay, Data: testData},
					},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := session.HandleClientMessage(tc.msg)
				if err != nil {
					t.Fatalf("HandleClientMessage(%s) failed: %v", tc.name, err)
				}
			})
		}
	})

	t.Run("WinsizeAndSuspendEvents", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Test winsize event
		winsizeMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_WinsizeEvent{
				WinsizeEvent: &pb.ChangeWindowSize{
					Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
					Rows:  25,
					Cols:  80,
				},
			},
		}
		_, err = session.HandleClientMessage(winsizeMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(WinsizeEvent) failed: %v", err)
		}

		// Test suspend event
		suspendMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_SuspendEvent{
				SuspendEvent: &pb.CommandSuspend{
					Delay:  &pb.TimeSpec{TvSec: 1, TvNsec: 0},
					Signal: "STOP",
				},
			},
		}
		_, err = session.HandleClientMessage(suspendMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(SuspendEvent) failed: %v", err)
		}

		// Test resume event (CONT signal)
		resumeMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_SuspendEvent{
				SuspendEvent: &pb.CommandSuspend{
					Delay:  &pb.TimeSpec{TvSec: 1, TvNsec: 0},
					Signal: "CONT",
				},
			},
		}
		_, err = session.HandleClientMessage(resumeMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(ResumeEvent) failed: %v", err)
		}
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		// Test with invalid directory
		invalidCfg := &config.LocalStorageConfig{
			LogDirectory: "/invalid/path/that/does/not/exist",
		}

		_, err := NewSession(sessionUUID, createTestAcceptMessage(), invalidCfg)
		if err == nil {
			t.Fatal("NewSession() should have failed with invalid directory")
		}

		// Test handling message before initialization
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Try to send non-Accept message first
		ttyoutMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_TtyoutBuf{
				TtyoutBuf: &pb.IoBuffer{
					Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
					Data:  []byte("test"),
				},
			},
		}
		_, err = session.HandleClientMessage(ttyoutMsg)
		if err == nil {
			t.Fatal("HandleClientMessage() should have failed when called before initialization")
		}
	})

	t.Run("ComplexPathEscapes", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			IologDir:        "%{LIVEDIR}/%{year}/%{month}/%{day}",
			IologFile:       "%{hour}-%{minute}-%{second}-%{user}-%{command}",
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, err = session.HandleClientMessage(acceptClientMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
		}

		// Verify the complex path was created
		// Check if directory exists (allowing for timing differences)
		found := false
		entries, err := os.ReadDir(tmpDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					found = true
					break
				}
			}
		}

		if !found {
			t.Errorf("Expected date-based directory structure to be created in %s", tmpDir)
		}
	})

	t.Run("ExitMessageWithSignalAndCore", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Send Exit message with signal and core dump
		exitMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_ExitMsg{
				ExitMsg: &pb.ExitMessage{
					ExitValue:  -1,
					Signal:     "SIGKILL",
					DumpedCore: true,
					RunTime:    &pb.TimeSpec{TvSec: 10, TvNsec: 500000000},
				},
			},
		}
		_, err = session.HandleClientMessage(exitMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(ExitMsg) failed: %v", err)
		}

		// Verify log.json contains signal and core dump info
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
		logJSONPath := filepath.Join(sessDir, "log.json")
		data, err := os.ReadFile(logJSONPath)
		if err != nil {
			t.Fatalf("Failed to read log.json: %v", err)
		}

		var logMeta map[string]any
		if err := json.Unmarshal(data, &logMeta); err != nil {
			t.Fatalf("Failed to unmarshal log.json: %v", err)
		}

		if logMeta["signal"] != "SIGKILL" {
			t.Errorf("Expected signal 'SIGKILL', got '%v'", logMeta["signal"])
		}

		if logMeta["dumped_core"] != true {
			t.Errorf("Expected dumped_core true, got '%v'", logMeta["dumped_core"])
		}
	})

	t.Run("AlertMessageHandling", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Send an alert message
		alertMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_AlertMsg{
				AlertMsg: &pb.AlertMessage{
					AlertTime: &pb.TimeSpec{TvSec: 1700000000, TvNsec: 0},
					Reason:    "policy violation detected",
					InfoMsgs: []*pb.InfoMessage{
						{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/usr/bin/rm -rf /"}},
					},
				},
			},
		}
		resp, err := session.HandleClientMessage(alertMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(AlertMsg) failed: %v", err)
		}
		if resp != nil {
			t.Errorf("Expected nil response for AlertMsg, got %v", resp)
		}

		// Verify log.json contains the alert
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
		logJSONPath := filepath.Join(sessDir, "log.json")
		data, err := os.ReadFile(logJSONPath)
		if err != nil {
			t.Fatalf("Failed to read log.json: %v", err)
		}
		var logMeta map[string]any
		if err := json.Unmarshal(data, &logMeta); err != nil {
			t.Fatalf("Failed to unmarshal log.json: %v", err)
		}

		alerts, ok := logMeta["alerts"].([]any)
		if !ok || len(alerts) != 1 {
			t.Fatalf("Expected 1 alert in log.json, got %v", logMeta["alerts"])
		}
		alert := alerts[0].(map[string]any)
		if alert["reason"] != "policy violation detected" {
			t.Errorf("Expected alert reason 'policy violation detected', got '%v'", alert["reason"])
		}
	})

	t.Run("SubCommandAccept", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		initResp, _ := session.HandleClientMessage(acceptClientMsg)
		initialLogID := initResp.GetLogId()

		// Send a sub-command accept
		subCmdMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_AcceptMsg{
				AcceptMsg: &pb.AcceptMessage{
					SubmitTime: &pb.TimeSpec{TvSec: 1700000100, TvNsec: 0},
					InfoMsgs: []*pb.InfoMessage{
						{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/usr/bin/cat /etc/passwd"}},
						{Key: "event_type", Value: &pb.InfoMessage_Strval{Strval: "reject"}},
						{Key: "submit_time", Value: &pb.InfoMessage_Strval{Strval: "attacker time"}},
					},
				},
			},
		}
		resp, err := session.HandleClientMessage(subCmdMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(SubCommand AcceptMsg) failed: %v", err)
		}
		if resp == nil || resp.GetLogId() == "" {
			t.Fatal("Expected log_id response for sub-command accept")
		}
		if resp.GetLogId() != initialLogID {
			t.Errorf("Sub-command should return same log_id: expected %s, got %s", initialLogID, resp.GetLogId())
		}

		// Verify log.json
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
		data, err := os.ReadFile(filepath.Join(sessDir, "log.json"))
		if err != nil {
			t.Fatalf("Failed to read log.json: %v", err)
		}
		var logMeta map[string]any
		json.Unmarshal(data, &logMeta)

		subCmds, ok := logMeta["sub_commands"].([]any)
		if !ok || len(subCmds) != 1 {
			t.Fatalf("Expected 1 sub_command, got %v", logMeta["sub_commands"])
		}
		subCmd, ok := subCmds[0].(map[string]any)
		if !ok {
			t.Fatalf("sub_command 0: expected map[string]any, got %T", subCmds[0])
		}
		if subCmd["event_type"] != "accept" {
			t.Errorf("Expected event_type 'accept', got '%v'", subCmd["event_type"])
		}
		expectedSubmitTime := time.Unix(1700000100, 0).UTC().Format(time.RFC3339Nano)
		if subCmd["submit_time"] != expectedSubmitTime {
			t.Errorf("Expected submit_time '%s', got '%v'", expectedSubmitTime, subCmd["submit_time"])
		}
		if subCmd["command"] != "/usr/bin/cat /etc/passwd" {
			t.Errorf("Expected command '/usr/bin/cat /etc/passwd', got '%v'", subCmd["command"])
		}
	})

	t.Run("SubCommandReject", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Send a sub-command reject
		rejectMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_RejectMsg{
				RejectMsg: &pb.RejectMessage{
					SubmitTime: &pb.TimeSpec{TvSec: 1700000200, TvNsec: 0},
					Reason:     "policy denied sub-command",
					InfoMsgs: []*pb.InfoMessage{
						{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/usr/sbin/visudo"}},
						{Key: "event_type", Value: &pb.InfoMessage_Strval{Strval: "accept"}},
						{Key: "reason", Value: &pb.InfoMessage_Strval{Strval: "attacker override"}},
						{Key: "submit_time", Value: &pb.InfoMessage_Strval{Strval: "attacker time"}},
					},
				},
			},
		}
		resp, err := session.HandleClientMessage(rejectMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(SubCommand RejectMsg) failed: %v", err)
		}
		if resp != nil {
			t.Errorf("Expected nil response for sub-command reject, got %v", resp)
		}

		// Verify log.json
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
		data, err := os.ReadFile(filepath.Join(sessDir, "log.json"))
		if err != nil {
			t.Fatalf("Failed to read log.json: %v", err)
		}
		var logMeta map[string]any
		json.Unmarshal(data, &logMeta)

		subCmds, ok := logMeta["sub_commands"].([]any)
		if !ok || len(subCmds) != 1 {
			t.Fatalf("Expected 1 sub_command, got %v", logMeta["sub_commands"])
		}
		subCmd, ok := subCmds[0].(map[string]any)
		if !ok {
			t.Fatalf("sub_command 0: expected map[string]any, got %T", subCmds[0])
		}
		if subCmd["event_type"] != "reject" {
			t.Errorf("Expected event_type 'reject', got '%v'", subCmd["event_type"])
		}
		if subCmd["reason"] != "policy denied sub-command" {
			t.Errorf("Expected reason 'policy denied sub-command', got '%v'", subCmd["reason"])
		}
		expectedSubmitTime := time.Unix(1700000200, 0).UTC().Format(time.RFC3339Nano)
		if subCmd["submit_time"] != expectedSubmitTime {
			t.Errorf("Expected submit_time '%s', got '%v'", expectedSubmitTime, subCmd["submit_time"])
		}
		if subCmd["command"] != "/usr/sbin/visudo" {
			t.Errorf("Expected command '/usr/sbin/visudo', got '%v'", subCmd["command"])
		}
	})

	t.Run("MultipleSubCommands", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Send multiple sub-commands
		for i := range 3 {
			subCmdMsg := &pb.ClientMessage{
				Type: &pb.ClientMessage_AcceptMsg{
					AcceptMsg: &pb.AcceptMessage{
						SubmitTime: &pb.TimeSpec{TvSec: int64(1700000000 + i*100), TvNsec: 0},
						InfoMsgs: []*pb.InfoMessage{
							{Key: "command", Value: &pb.InfoMessage_Strval{Strval: fmt.Sprintf("/bin/cmd%d", i)}},
						},
					},
				},
			}
			_, err := session.HandleClientMessage(subCmdMsg)
			if err != nil {
				t.Fatalf("Sub-command %d failed: %v", i, err)
			}
		}

		// Verify log.json has 3 sub-commands
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
		data, err := os.ReadFile(filepath.Join(sessDir, "log.json"))
		if err != nil {
			t.Fatalf("Failed to read log.json: %v", err)
		}
		var logMeta map[string]any
		json.Unmarshal(data, &logMeta)

		subCmds, ok := logMeta["sub_commands"].([]any)
		if !ok || len(subCmds) != 3 {
			t.Fatalf("Expected 3 sub_commands, got %d", len(subCmds))
		}
	})
}

func TestCommitPointThrottling(t *testing.T) {
	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		DirPermissions:  0755,
		FilePermissions: 0644,
	}

	session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	// Initialize session
	acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
	_, _ = session.HandleClientMessage(acceptClientMsg)

	makeIoMsg := func() *pb.ClientMessage {
		return &pb.ClientMessage{
			Type: &pb.ClientMessage_TtyoutBuf{
				TtyoutBuf: &pb.IoBuffer{
					Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 100000000}, // 100ms
					Data:  []byte("x"),
				},
			},
		}
	}

	// First I/O event should always return a commit point (zero-value lastCommitTime)
	resp, err := session.HandleClientMessage(makeIoMsg())
	if err != nil {
		t.Fatalf("First I/O event failed: %v", err)
	}
	if resp == nil || resp.GetCommitPoint() == nil {
		t.Fatal("Expected commit point on first I/O event, got nil")
	}

	// Subsequent events within the 10s window should NOT return commit points
	for i := range 5 {
		resp, err := session.HandleClientMessage(makeIoMsg())
		if err != nil {
			t.Fatalf("I/O event %d failed: %v", i+2, err)
		}
		if resp != nil {
			t.Fatalf("Expected nil response for I/O event %d within throttle window, got commit point", i+2)
		}
	}

	// Simulate time passing beyond the throttle interval by backdating lastCommitTime
	session.fileMux.Lock()
	session.lastCommitTime = time.Now().Add(-commitPointInterval - time.Second)
	session.fileMux.Unlock()

	// Next event should return a commit point
	resp, err = session.HandleClientMessage(makeIoMsg())
	if err != nil {
		t.Fatalf("I/O event after interval failed: %v", err)
	}
	if resp == nil || resp.GetCommitPoint() == nil {
		t.Fatal("Expected commit point after throttle interval elapsed, got nil")
	}
}

func TestNoLogJSONRewriteOnIoEvents(t *testing.T) {
	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		DirPermissions:  0755,
		FilePermissions: 0644,
	}

	session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	// Initialize session
	acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
	_, _ = session.HandleClientMessage(acceptClientMsg)

	// Pin log.json mtime to a known past value; any subsequent write would
	// update it to "now", detectably different even at coarse FS resolution.
	sessDir := filepath.Join(tmpDir, "a1/b2/c3")
	logJSONPath := filepath.Join(sessDir, "log.json")
	pinnedTime := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(logJSONPath, pinnedTime, pinnedTime); err != nil {
		t.Fatalf("Failed to pin log.json mtime: %v", err)
	}

	// Send I/O events, winsize, and suspend — none should update log.json
	ioMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{
			TtyoutBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
				Data:  []byte("output"),
			},
		},
	}
	session.HandleClientMessage(ioMsg)

	winsizeMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_WinsizeEvent{
			WinsizeEvent: &pb.ChangeWindowSize{
				Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
				Rows:  25, Cols: 80,
			},
		},
	}
	session.HandleClientMessage(winsizeMsg)

	suspendMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_SuspendEvent{
			SuspendEvent: &pb.CommandSuspend{
				Delay:  &pb.TimeSpec{TvSec: 1, TvNsec: 0},
				Signal: "STOP",
			},
		},
	}
	session.HandleClientMessage(suspendMsg)

	// Verify log.json was NOT rewritten
	afterInfo, err := os.Stat(logJSONPath)
	if err != nil {
		t.Fatalf("Failed to stat log.json after events: %v", err)
	}
	if !afterInfo.ModTime().Equal(pinnedTime) {
		t.Errorf("log.json was rewritten during I/O hot path; mtime moved from %v to %v",
			pinnedTime, afterInfo.ModTime())
	}
}

func TestDecodeLogID(t *testing.T) {
	testUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")

	t.Run("ValidLogID", func(t *testing.T) {
		relativePath := "testuser/000001"
		logID := generateLogID(testUUID, relativePath)

		decodedUUID, decodedPath, err := DecodeLogID(logID)
		if err != nil {
			t.Fatalf("DecodeLogID() failed: %v", err)
		}
		if decodedUUID != testUUID {
			t.Errorf("UUID mismatch: expected %s, got %s", testUUID, decodedUUID)
		}
		if decodedPath != relativePath {
			t.Errorf("Path mismatch: expected %s, got %s", relativePath, decodedPath)
		}
	})

	t.Run("ValidLogIDEmptyPath", func(t *testing.T) {
		logID := base64.StdEncoding.EncodeToString(testUUID[:])

		decodedUUID, decodedPath, err := DecodeLogID(logID)
		if err != nil {
			t.Fatalf("DecodeLogID() failed: %v", err)
		}
		if decodedUUID != testUUID {
			t.Errorf("UUID mismatch: expected %s, got %s", testUUID, decodedUUID)
		}
		if decodedPath != "" {
			t.Errorf("Expected empty path, got '%s'", decodedPath)
		}
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		_, _, err := DecodeLogID("not-valid-base64!!!")
		if err == nil {
			t.Fatal("Expected error for invalid base64")
		}
	})

	t.Run("TooShort", func(t *testing.T) {
		// Only 8 bytes — need at least 16
		shortData := base64.StdEncoding.EncodeToString([]byte("tooshort"))
		_, _, err := DecodeLogID(shortData)
		if err == nil {
			t.Fatal("Expected error for too-short log_id")
		}
		if !strings.Contains(err.Error(), "too short") {
			t.Errorf("Expected 'too short' in error, got: %v", err)
		}
	})
}

func TestNewSessionLogIDSiblingPrefixPath(t *testing.T) {
	testUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	tmpDir := t.TempDir()
	logRoot := filepath.Join(tmpDir, "log-root")
	siblingPrefixDir := logRoot + "-archive"

	cfg := &config.LocalStorageConfig{
		LogDirectory:    logRoot,
		IologDir:        filepath.Join(siblingPrefixDir, "%{user}"),
		IologFile:       "%{seq}",
		DirPermissions:  0o755,
		FilePermissions: 0o644,
	}

	session, err := NewSession(testUUID, createTestAcceptMessage(), cfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	expectedPath := filepath.Join(siblingPrefixDir, "testuser", "00", "00", "01")
	if session.sessionDir != expectedPath {
		t.Fatalf("unexpected session dir: expected %q, got %q", expectedPath, session.sessionDir)
	}

	decodedUUID, decodedPath, err := DecodeLogID(session.logID)
	if err != nil {
		t.Fatalf("DecodeLogID() failed: %v", err)
	}
	if decodedUUID != testUUID {
		t.Fatalf("decoded UUID mismatch: expected %s, got %s", testUUID, decodedUUID)
	}

	// Reproduce legacy behavior to verify this test covers the historical bug:
	// raw string-prefix trimming incorrectly truncates similarly named siblings.
	legacyRelativePath := expectedPath
	if strings.HasPrefix(expectedPath, logRoot) {
		legacyRelativePath = strings.TrimPrefix(expectedPath[len(logRoot):], string(filepath.Separator))
	}
	if legacyRelativePath == expectedPath {
		t.Fatalf("test setup failed: legacy prefix logic did not alter path %q", expectedPath)
	}
	if decodedPath == legacyRelativePath {
		t.Fatalf("decoded path unexpectedly matched legacy truncated path %q", legacyRelativePath)
	}
	if decodedPath != expectedPath {
		t.Fatalf("decoded path mismatch: expected %q, got %q", expectedPath, decodedPath)
	}
}

func TestNewRestartSession(t *testing.T) {
	testUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")

	// Helper to set up a completed or active session directory
	setupSession := func(t *testing.T, finalized bool) (string, *config.LocalStorageConfig, string) {
		tmpDir := t.TempDir()
		cfg := &config.LocalStorageConfig{
			LogDirectory:    tmpDir,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		session, err := NewSession(testUUID, createTestAcceptMessage(), cfg)
		if err != nil {
			t.Fatalf("Setup NewSession() failed: %v", err)
		}

		// Initialize
		acceptMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		resp, err := session.HandleClientMessage(acceptMsg)
		if err != nil {
			t.Fatalf("Setup HandleClientMessage(Accept) failed: %v", err)
		}
		logID := resp.GetLogId()

		// Write some I/O data
		ttyoutMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_TtyoutBuf{
				TtyoutBuf: &pb.IoBuffer{
					Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
					Data:  []byte("hello"),
				},
			},
		}
		session.HandleClientMessage(ttyoutMsg)

		if finalized {
			exitMsg := &pb.ClientMessage{
				Type: &pb.ClientMessage_ExitMsg{
					ExitMsg: &pb.ExitMessage{
						ExitValue: 0,
						RunTime:   &pb.TimeSpec{TvSec: 5, TvNsec: 0},
					},
				},
			}
			session.HandleClientMessage(exitMsg)
		} else {
			session.Close()
		}

		return tmpDir, cfg, logID
	}

	t.Run("HappyPath", func(t *testing.T) {
		_, cfg, logID := setupSession(t, false)

		restartMsg := &pb.RestartMessage{
			LogId:       logID,
			ResumePoint: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
		}

		session, err := NewRestartSession(restartMsg, cfg)
		if err != nil {
			t.Fatalf("NewRestartSession() failed: %v", err)
		}
		defer session.Close()

		// Session should be already initialized — can write I/O directly
		ttyoutMsg := &pb.ClientMessage{
			Type: &pb.ClientMessage_TtyoutBuf{
				TtyoutBuf: &pb.IoBuffer{
					Delay: &pb.TimeSpec{TvSec: 2, TvNsec: 0},
					Data:  []byte(" world"),
				},
			},
		}
		resp, err := session.HandleClientMessage(ttyoutMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage after restart failed: %v", err)
		}
		if resp == nil || resp.GetCommitPoint() == nil {
			t.Fatal("Expected commit point response")
		}
	})

	t.Run("CompletedSessionFails", func(t *testing.T) {
		_, cfg, logID := setupSession(t, true)

		restartMsg := &pb.RestartMessage{
			LogId:       logID,
			ResumePoint: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
		}

		_, err := NewRestartSession(restartMsg, cfg)
		if err == nil {
			t.Fatal("Expected error when restarting completed session")
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Errorf("Expected 'read-only' in error, got: %v", err)
		}
	})

	t.Run("UUIDMismatch", func(t *testing.T) {
		_, cfg, logID := setupSession(t, false)

		// Decode the log ID, replace UUID with a different one, re-encode
		_, relativePath, _ := DecodeLogID(logID)
		wrongUUID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
		fakeLogID := generateLogID(wrongUUID, relativePath)

		restartMsg := &pb.RestartMessage{
			LogId:       fakeLogID,
			ResumePoint: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
		}

		_, err := NewRestartSession(restartMsg, cfg)
		if err == nil {
			t.Fatal("Expected error for UUID mismatch")
		}
		if !strings.Contains(err.Error(), "UUID mismatch") {
			t.Errorf("Expected 'UUID mismatch' in error, got: %v", err)
		}
	})

	t.Run("CompressedSessionFails", func(t *testing.T) {
		_, cfg, logID := setupSession(t, false)
		cfg.Compress = true

		restartMsg := &pb.RestartMessage{
			LogId:       logID,
			ResumePoint: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
		}

		_, err := NewRestartSession(restartMsg, cfg)
		if err == nil {
			t.Fatal("Expected error for compressed restart")
		}
		if !strings.Contains(err.Error(), "compressed") {
			t.Errorf("Expected 'compressed' in error, got: %v", err)
		}
	})

	t.Run("NonexistentPath", func(t *testing.T) {
		cfg := &config.LocalStorageConfig{
			LogDirectory:    "/nonexistent/path",
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		logID := generateLogID(testUUID, "some/path")
		restartMsg := &pb.RestartMessage{
			LogId:       logID,
			ResumePoint: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
		}

		_, err := NewRestartSession(restartMsg, cfg)
		if err == nil {
			t.Fatal("Expected error for nonexistent path")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("Expected 'does not exist' in error, got: %v", err)
		}
	})

	t.Run("AbsoluteLogIDPathRejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		logRoot, err := filepath.Abs(filepath.Join(tmpDir, "log-root"))
		if err != nil {
			t.Fatalf("failed to resolve absolute log root: %v", err)
		}
		cfg := &config.LocalStorageConfig{
			LogDirectory:    logRoot,
			DirPermissions:  0755,
			FilePermissions: 0644,
		}

		// Build a restartable session layout outside cfg.LogDirectory.
		outsideSessionDir, err := filepath.Abs(filepath.Join(tmpDir, "outside-session"))
		if err != nil {
			t.Fatalf("failed to resolve absolute outside session path: %v", err)
		}
		if !filepath.IsAbs(outsideSessionDir) {
			t.Fatalf("test setup failed: outside session path is not absolute: %q", outsideSessionDir)
		}
		if err := os.MkdirAll(outsideSessionDir, 0o755); err != nil {
			t.Fatalf("failed to create outside session directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outsideSessionDir, "uuid"), []byte(testUUID.String()+"\n"), 0o644); err != nil {
			t.Fatalf("failed to write uuid file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outsideSessionDir, "timing"), []byte(""), 0o644); err != nil {
			t.Fatalf("failed to write timing file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outsideSessionDir, "log.json"), []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("failed to write log.json: %v", err)
		}
		for _, streamInfo := range streamMap {
			if err := os.WriteFile(filepath.Join(outsideSessionDir, streamInfo.filename), []byte(""), 0o644); err != nil {
				t.Fatalf("failed to write stream file %s: %v", streamInfo.filename, err)
			}
		}

		absolutePathLogID := generateLogID(testUUID, outsideSessionDir)
		_, decodedPath, err := DecodeLogID(absolutePathLogID)
		if err != nil {
			t.Fatalf("failed to decode generated log_id: %v", err)
		}
		if !filepath.IsAbs(decodedPath) {
			t.Fatalf("test setup failed: decoded path is not absolute: %q", decodedPath)
		}
		restartMsg := &pb.RestartMessage{
			LogId:       absolutePathLogID,
			ResumePoint: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
		}

		session, err := NewRestartSession(restartMsg, cfg)
		if err == nil {
			session.Close()
			t.Fatal("Expected error for absolute log_id path")
		}
		if !strings.Contains(err.Error(), "absolute path") {
			t.Errorf("Expected 'absolute path' in error, got: %v", err)
		}
	})
}

func TestPathWithinBase(t *testing.T) {
	logRoot := t.TempDir()

	t.Run("PathWithinRoot", func(t *testing.T) {
		target := filepath.Join(logRoot, "aa", "bb")
		within, err := pathWithinBase(logRoot, target)
		if err != nil {
			t.Fatalf("pathWithinBase() returned unexpected error: %v", err)
		}
		if !within {
			t.Fatalf("expected %q to be within %q", target, logRoot)
		}
	})

	t.Run("AbsoluteTargetOutsideRootIsRejected", func(t *testing.T) {
		outsideRoot := t.TempDir()
		within, err := pathWithinBase(logRoot, outsideRoot)
		if err != nil {
			t.Fatalf("pathWithinBase() returned unexpected error: %v", err)
		}
		if within {
			t.Fatalf("expected %q to be rejected as outside %q", outsideRoot, logRoot)
		}
	})

	t.Run("DotDotEscapeIsRejected", func(t *testing.T) {
		target := filepath.Join(logRoot, "..", "outside")
		within, err := pathWithinBase(logRoot, target)
		if err != nil {
			t.Fatalf("pathWithinBase() returned unexpected error: %v", err)
		}
		if within {
			t.Fatalf("expected %q to be rejected as outside %q", target, logRoot)
		}
	})
}

func TestOnDemandIoFileCreation(t *testing.T) {
	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		DirPermissions:  0755,
		FilePermissions: 0644,
	}

	session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	// Initialize session
	acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
	_, err = session.HandleClientMessage(acceptClientMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
	}

	sessDir := filepath.Join(tmpDir, "a1/b2/c3")

	// stdout, stderr, ttyout should exist after initialization
	for _, name := range []string{"stdout", "stderr", "ttyout"} {
		if _, err := os.Stat(filepath.Join(sessDir, name)); os.IsNotExist(err) {
			t.Errorf("Expected pre-created stream file %s to exist", name)
		}
	}

	// stdin, ttyin should NOT exist after initialization (on-demand)
	for _, name := range []string{"stdin", "ttyin"} {
		if _, err := os.Stat(filepath.Join(sessDir, name)); !os.IsNotExist(err) {
			t.Errorf("Expected on-demand stream file %s to NOT exist after init, but it does", name)
		}
	}

	// Write to ttyin — should create the file on demand
	ttyinMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_TtyinBuf{
			TtyinBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
				Data:  []byte("input"),
			},
		},
	}
	_, err = session.HandleClientMessage(ttyinMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(TtyinBuf) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessDir, "ttyin")); os.IsNotExist(err) {
		t.Error("Expected ttyin file to be created on first write")
	}

	// Write to stdin — should create the file on demand
	stdinMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_StdinBuf{
			StdinBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 0},
				Data:  []byte("stdin input"),
			},
		},
	}
	_, err = session.HandleClientMessage(stdinMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(StdinBuf) failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessDir, "stdin")); os.IsNotExist(err) {
		t.Error("Expected stdin file to be created on first write")
	}
}

func TestDefaultValuesForAbsentFields(t *testing.T) {
	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		DirPermissions:  0755,
		FilePermissions: 0644,
	}

	// Create AcceptMessage WITHOUT submitgroup, ttyname, and submitcwd
	acceptMsg := &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: time.Now().Unix(), TvNsec: 0},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{
			{Key: "submituser", Value: &pb.InfoMessage_Strval{Strval: "testuser"}},
			{Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"}},
			{Key: "runuser", Value: &pb.InfoMessage_Strval{Strval: "root"}},
			{Key: "submithost", Value: &pb.InfoMessage_Strval{Strval: "testhost"}},
			{Key: "lines", Value: &pb.InfoMessage_Numval{Numval: 24}},
			{Key: "columns", Value: &pb.InfoMessage_Numval{Numval: 80}},
			// Intentionally omitting: submitcwd, submitgroup, ttyname
		},
	}

	session, err := NewSession(sessionUUID, acceptMsg, storageCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	// Initialize session
	acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: acceptMsg}}
	_, err = session.HandleClientMessage(acceptClientMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
	}

	// Read log.json and verify defaults
	sessDir := filepath.Join(tmpDir, "a1/b2/c3")
	logJSONPath := filepath.Join(sessDir, "log.json")
	data, err := os.ReadFile(logJSONPath)
	if err != nil {
		t.Fatalf("Failed to read log.json: %v", err)
	}
	var logMeta map[string]any
	if err := json.Unmarshal(data, &logMeta); err != nil {
		t.Fatalf("Failed to unmarshal log.json: %v", err)
	}

	for _, field := range []string{"submitcwd", "submitgroup", "ttyname"} {
		val, ok := logMeta[field]
		if !ok {
			t.Errorf("Expected default value for %s in log.json, but field is missing", field)
		} else if val != "unknown" {
			t.Errorf("Expected %s='unknown', got '%v'", field, val)
		}
	}
}

func TestTimingFileIntegerFormat(t *testing.T) {
	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		DirPermissions:  0755,
		FilePermissions: 0644,
	}

	session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
	_, _ = session.HandleClientMessage(acceptClientMsg)

	// Write I/O with specific delay values to test format
	ttyoutMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{
			TtyoutBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 3, TvNsec: 123456789},
				Data:  []byte("test"),
			},
		},
	}
	_, err = session.HandleClientMessage(ttyoutMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(TtyoutBuf) failed: %v", err)
	}

	// Write winsize event
	winsizeMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_WinsizeEvent{
			WinsizeEvent: &pb.ChangeWindowSize{
				Delay: &pb.TimeSpec{TvSec: 5, TvNsec: 7000000},
				Rows:  30,
				Cols:  120,
			},
		},
	}
	_, err = session.HandleClientMessage(winsizeMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(WinsizeEvent) failed: %v", err)
	}

	// Write suspend event
	suspendMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_SuspendEvent{
			SuspendEvent: &pb.CommandSuspend{
				Delay:  &pb.TimeSpec{TvSec: 10, TvNsec: 500000000},
				Signal: "STOP",
			},
		},
	}
	_, err = session.HandleClientMessage(suspendMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(SuspendEvent) failed: %v", err)
	}

	// Read and verify timing file
	sessDir := filepath.Join(tmpDir, "a1/b2/c3")
	timingContent, err := os.ReadFile(filepath.Join(sessDir, "timing"))
	if err != nil {
		t.Fatalf("Failed to read timing file: %v", err)
	}

	content := string(timingContent)

	// Verify I/O entry: "4 3.123456789 4\n"
	expectedIO := fmt.Sprintf("%d 3.123456789 4\n", IO_EVENT_TTYOUT)
	if !strings.Contains(content, expectedIO) {
		t.Errorf("Expected timing to contain %q, got: %s", expectedIO, content)
	}

	// Verify winsize entry: "5 5.007000000 30 120\n"
	expectedWinsize := fmt.Sprintf("%d 5.007000000 30 120\n", IO_EVENT_WINSIZE)
	if !strings.Contains(content, expectedWinsize) {
		t.Errorf("Expected timing to contain %q, got: %s", expectedWinsize, content)
	}

	// Verify suspend entry: "7 10.500000000 STOP\n"
	expectedSuspend := fmt.Sprintf("%d 10.500000000 STOP\n", IO_EVENT_SUSPEND)
	if !strings.Contains(content, expectedSuspend) {
		t.Errorf("Expected timing to contain %q, got: %s", expectedSuspend, content)
	}
}

func TestPasswordFilteringStdoutStdin(t *testing.T) {
	sessionUUID := uuid.MustParse("a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d")
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		DirPermissions:  0755,
		FilePermissions: 0644,
		PasswordFilter:  true,
	}

	session, err := NewSession(sessionUUID, createTestAcceptMessage(), storageCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
	_, _ = session.HandleClientMessage(acceptClientMsg)

	// Send password prompt via stdout (non-TTY)
	stdoutMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_StdoutBuf{
			StdoutBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 100000000},
				Data:  []byte("Password: "),
			},
		},
	}
	_, err = session.HandleClientMessage(stdoutMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(StdoutBuf) failed: %v", err)
	}

	// Send password via stdin (non-TTY) — should be masked
	stdinMsg := &pb.ClientMessage{
		Type: &pb.ClientMessage_StdinBuf{
			StdinBuf: &pb.IoBuffer{
				Delay: &pb.TimeSpec{TvSec: 0, TvNsec: 200000000},
				Data:  []byte("secret\n"),
			},
		},
	}
	_, err = session.HandleClientMessage(stdinMsg)
	if err != nil {
		t.Fatalf("HandleClientMessage(StdinBuf) failed: %v", err)
	}

	// Verify stdin file contains masked data, not "secret"
	sessDir := filepath.Join(tmpDir, "a1/b2/c3")
	stdinContent, err := os.ReadFile(filepath.Join(sessDir, "stdin"))
	if err != nil {
		t.Fatalf("Failed to read stdin file: %v", err)
	}

	if strings.Contains(string(stdinContent), "secret") {
		t.Errorf("stdin file contains unmasked password 'secret': %s", string(stdinContent))
	}
	// Should contain asterisks and the newline
	if !strings.Contains(string(stdinContent), "******") {
		t.Errorf("Expected masked content with asterisks in stdin, got: %q", string(stdinContent))
	}
}

func TestBuildSessionPathRejectsDotDotAfterExpansion(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		IologDir:        filepath.Join("%{LIVEDIR}", "%{user}"),
		IologFile:       "%{seq}",
		DirPermissions:  0o755,
		FilePermissions: 0o644,
	}

	acceptMsg := createTestAcceptMessage()
	updated := false
	for _, info := range acceptMsg.InfoMsgs {
		if info.GetKey() == "submituser" {
			info.Value = &pb.InfoMessage_Strval{Strval: ".."}
			updated = true
			break
		}
	}
	if !updated {
		t.Fatal("test setup failed: submituser info message not found")
	}

	_, err := buildSessionPath(uuid.New(), cfg, acceptMsg)
	if err == nil {
		t.Fatal("expected path traversal error for submituser='..'")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("expected path traversal error, got: %v", err)
	}
}

// TestStorageSessionCommitPoints verifies the commit_point handshake that lets a
// stock sudo client complete its CLOSING state:
//   - the cumulative clock is a single value summed across ALL streams plus
//     winsize and suspend (not per-stream), and
//   - ExitMessage returns a FINAL commit_point equal to that total.
//
// Without both, a real client stalls log_server_timeout (default 30s) at the end
// of every multi-stream I/O session and warns "lost connection to log server".
func TestStorageSessionCommitPoints(t *testing.T) {
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory:    tmpDir,
		IologDir:        filepath.Join("%{LIVEDIR}", "%{user}"),
		IologFile:       "%{seq}",
		DirPermissions:  0755,
		FilePermissions: 0644,
	}

	session, err := NewSession(uuid.New(), createTestAcceptMessage(), storageCfg)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	defer session.Close()

	if _, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()},
	}); err != nil {
		t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
	}

	// First I/O event always emits a commit point (zero-value lastCommitTime),
	// and it must carry the GLOBAL cumulative value — here just the ttyout delay.
	resp, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{
			Delay: &pb.TimeSpec{TvSec: 1, TvNsec: 100000000}, Data: []byte("out"),
		}},
	})
	if err != nil {
		t.Fatalf("HandleClientMessage(ttyout) failed: %v", err)
	}
	if cp := resp.GetCommitPoint(); cp == nil {
		t.Fatal("expected commit_point on first I/O event")
	} else if cp.TvSec != 1 || cp.TvNsec != 100000000 {
		t.Errorf("first commit_point = %d.%09d, want 1.100000000", cp.TvSec, cp.TvNsec)
	}

	// A second stream, plus winsize and suspend — all advance the SAME clock and
	// (being within the throttle interval / non-I/O) emit no commit point.
	for _, m := range []*pb.ClientMessage{
		{Type: &pb.ClientMessage_StdinBuf{StdinBuf: &pb.IoBuffer{Delay: &pb.TimeSpec{TvNsec: 200000000}, Data: []byte("in")}}},
		{Type: &pb.ClientMessage_WinsizeEvent{WinsizeEvent: &pb.ChangeWindowSize{Delay: &pb.TimeSpec{TvNsec: 300000000}, Rows: 40, Cols: 100}}},
		{Type: &pb.ClientMessage_SuspendEvent{SuspendEvent: &pb.CommandSuspend{Delay: &pb.TimeSpec{TvNsec: 400000000}, Signal: "TSTP"}}},
	} {
		if r, err := session.HandleClientMessage(m); err != nil {
			t.Fatalf("HandleClientMessage(%T) failed: %v", m.Type, err)
		} else if r != nil {
			t.Errorf("expected no commit_point for %T, got %v", m.Type, r)
		}
	}

	// Exit must return a FINAL commit_point equal to the sum of every delay:
	// 1.1 + 0.2 + 0.3 + 0.4 = 2.0s exactly.
	resp, err = session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	})
	if err != nil {
		t.Fatalf("HandleClientMessage(Exit) failed: %v", err)
	}
	cp := resp.GetCommitPoint()
	if cp == nil {
		t.Fatal("expected FINAL commit_point on Exit; without it a stock client hangs in CLOSING")
	}
	if cp.TvSec != 2 || cp.TvNsec != 0 {
		t.Errorf("final commit_point = %d.%09d, want 2.000000000 (sum of all stream/winsize/suspend delays)", cp.TvSec, cp.TvNsec)
	}
}

// TestSeqFileFormat verifies the sequence counter is stored as C sudo's ASCII
// base36 text (so a C sudo_logsrvd and this server can share an iolog tree),
// that a C-written file is read correctly, and that a legacy binary counter is
// migrated in place without resetting (which could collide session dirs).
func TestSeqFileFormat(t *testing.T) {
	cfg := &config.LocalStorageConfig{DirPermissions: 0o755, FilePermissions: 0o644}

	t.Run("WritesAsciiBase36", func(t *testing.T) {
		dir := t.TempDir()
		seq, err := getNextSeq(dir, cfg)
		if err != nil {
			t.Fatalf("getNextSeq: %v", err)
		}
		// The returned %{seq} value is the XX/XX/XX hierarchy; the on-disk
		// counter is the flat 6-char ASCII base36 form.
		if seq != "00/00/01" {
			t.Errorf("first seq = %q, want 00/00/01", seq)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "seq"))
		if err != nil {
			t.Fatalf("read seq file: %v", err)
		}
		if string(raw) != "000001\n" {
			t.Errorf("seq file = %q, want %q (ASCII base36 + newline)", raw, "000001\n")
		}
	})

	t.Run("ReadsCStyleAsciiFile", func(t *testing.T) {
		dir := t.TempDir()
		// C-style file at value 35 ("Z"); next should be 36 -> "000010".
		if err := os.WriteFile(filepath.Join(dir, "seq"), []byte("00000Z\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		seq, err := getNextSeq(dir, cfg)
		if err != nil {
			t.Fatalf("getNextSeq: %v", err)
		}
		if seq != "00/00/10" {
			t.Errorf("seq after 00000Z = %q, want 00/00/10", seq)
		}
	})

	t.Run("MigratesLegacyBinaryWithoutReset", func(t *testing.T) {
		dir := t.TempDir()
		// Legacy 4-byte big-endian counter at value 5.
		if err := os.WriteFile(filepath.Join(dir, "seq"), []byte{0, 0, 0, 5}, 0o644); err != nil {
			t.Fatal(err)
		}
		seq, err := getNextSeq(dir, cfg)
		if err != nil {
			t.Fatalf("getNextSeq: %v", err)
		}
		if seq != "00/00/06" {
			t.Errorf("seq after legacy binary 5 = %q, want 00/00/06 (counter must not reset)", seq)
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "seq"))
		if string(raw) != "000006\n" {
			t.Errorf("migrated seq file = %q, want %q (now ASCII)", raw, "000006\n")
		}
	})
}
