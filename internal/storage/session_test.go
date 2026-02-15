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

		// Check for correct server response (log_id should be base64-encoded)
		expectedRelPath := "testuser/000001"
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

		// Verify that directories and files were created
		// The sequence number will be "000001" since this test has its own tmpDir.
		sessDir := filepath.Join(tmpDir, "testuser", "000001")
		if _, err := os.Stat(sessDir); os.IsNotExist(err) {
			t.Fatalf("Session directory '%s' was not created", sessDir)
		}

		// Check for log.json and its content
		logJSONPath := filepath.Join(sessDir, "log.json")
		data, err := os.ReadFile(logJSONPath)
		if err != nil {
			t.Fatalf("Failed to read log.json: %v", err)
		}
		var logMeta map[string]interface{}
		if err := json.Unmarshal(data, &logMeta); err != nil {
			t.Fatalf("Failed to unmarshal log.json: %v", err)
		}
		if logMeta["submituser"] != "testuser" {
			t.Errorf("log.json: expected submituser 'testuser', got '%v'", logMeta["submituser"])
		}
		if logMeta["exit_value"].(float64) != 0 {
			t.Errorf("log.json: expected exit_value 0, got '%v'", logMeta["exit_value"])
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
		sessDir := filepath.Join(tmpDir, "testuser", "000001") // Sequence is 1 because of new tmpDir
		ttyoutFile := filepath.Join(sessDir, "ttyout")
		content, err := os.ReadFile(ttyoutFile)
		if err != nil {
			t.Fatalf("Failed to read ttyout file: %v", err)
		}
		if string(content) != string(ttyoutData) {
			t.Errorf("ttyout content mismatch: expected '%s', got '%s'", string(ttyoutData), string(content))
		}

		// Verify timing file content
		timingFile := filepath.Join(sessDir, "timing")
		timingContent, err := os.ReadFile(timingFile)
		if err != nil {
			t.Fatalf("Failed to read timing file: %v", err)
		}
		expectedTiming := fmt.Sprintf("%d 1.500000000 11\n", IO_EVENT_TTYOUT)
		if !strings.Contains(string(timingContent), expectedTiming) {
			t.Errorf("timing file content mismatch: expected to contain '%s', got '%s'", expectedTiming, string(timingContent))
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

		// Test sequence file format (should be 6 characters, base36)
		if len(seq1) != 6 {
			t.Errorf("Expected sequence length 6, got %d", len(seq1))
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

		var logMeta map[string]interface{}
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
		var logMeta map[string]interface{}
		if err := json.Unmarshal(data, &logMeta); err != nil {
			t.Fatalf("Failed to unmarshal log.json: %v", err)
		}

		alerts, ok := logMeta["alerts"].([]interface{})
		if !ok || len(alerts) != 1 {
			t.Fatalf("Expected 1 alert in log.json, got %v", logMeta["alerts"])
		}
		alert := alerts[0].(map[string]interface{})
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
		var logMeta map[string]interface{}
		json.Unmarshal(data, &logMeta)

		subCmds, ok := logMeta["sub_commands"].([]interface{})
		if !ok || len(subCmds) != 1 {
			t.Fatalf("Expected 1 sub_command, got %v", logMeta["sub_commands"])
		}
		subCmd := subCmds[0].(map[string]interface{})
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
		var logMeta map[string]interface{}
		json.Unmarshal(data, &logMeta)

		subCmds, ok := logMeta["sub_commands"].([]interface{})
		if !ok || len(subCmds) != 1 {
			t.Fatalf("Expected 1 sub_command, got %v", logMeta["sub_commands"])
		}
		subCmd := subCmds[0].(map[string]interface{})
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
		for i := 0; i < 3; i++ {
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
		var logMeta map[string]interface{}
		json.Unmarshal(data, &logMeta)

		subCmds, ok := logMeta["sub_commands"].([]interface{})
		if !ok || len(subCmds) != 3 {
			t.Fatalf("Expected 3 sub_commands, got %d", len(subCmds))
		}
	})
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
