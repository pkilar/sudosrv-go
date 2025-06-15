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
}
