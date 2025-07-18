// Filename: internal/storage/session_test.go
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"
	"time"
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
	logID := "a1b2c3d4-e5f6-4a1b-8c3d-9e8f7a6b5c4d"

	t.Run("SessionInitializationAndFinalizationWithIologDir", func(t *testing.T) {
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory: tmpDir,
			IologDir:     filepath.Join("%{LIVEDIR}", "%{user}"),
			IologFile:    "%{seq}",
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}

		// First message must be the AcceptMessage to initialize
		acceptClientMsg := &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		serverResponse, err := session.HandleClientMessage(acceptClientMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
		}

		// Check for correct server response (log_id)
		if serverResponse.GetLogId() != logID {
			t.Errorf("Expected server response to be log_id '%s', got '%s'", logID, serverResponse.GetLogId())
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
			LogDirectory: tmpDir,
			IologDir:     filepath.Join("%{LIVEDIR}", "%{user}"),
			IologFile:    "%{seq}",
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
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
			LogDirectory: tmpDir,
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
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
		seq1, err := getNextSeq(tmpDir)
		if err != nil {
			t.Fatalf("getNextSeq() failed: %v", err)
		}

		seq2, err := getNextSeq(tmpDir)
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
			LogDirectory: tmpDir,
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
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
			LogDirectory: tmpDir,
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
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

		_, err := NewSession(logID, createTestAcceptMessage(), invalidCfg)
		if err == nil {
			t.Fatal("NewSession() should have failed with invalid directory")
		}

		// Test handling message before initialization
		tmpDir := t.TempDir()
		storageCfg := &config.LocalStorageConfig{
			LogDirectory: tmpDir,
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
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
			LogDirectory: tmpDir,
			IologDir:     "%{LIVEDIR}/%{year}/%{month}/%{day}",
			IologFile:    "%{hour}-%{minute}-%{second}-%{user}-%{command}",
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
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
			LogDirectory: tmpDir,
		}

		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
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
}
