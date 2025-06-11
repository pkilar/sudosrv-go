// Filename: internal/storage/session_test.go
package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	pb "sudosrv/pkg/sudosrv_proto"
	"strings"
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
		},
	}
}

func TestStorageSession(t *testing.T) {
	// Setup config with a temporary directory for logs
	tmpDir := t.TempDir()
	storageCfg := &config.LocalStorageConfig{
		LogDirectory: tmpDir,
	}
	logID := "a1b2c3d4e5f6"

	t.Run("SessionInitialization", func(t *testing.T) {
		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}

		// First message must be the AcceptMessage to initialize
		acceptClientMsg := &pb.ClientMessage{Event: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		serverResponse, err := session.HandleClientMessage(acceptClientMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(Accept) failed: %v", err)
		}

		// Check for correct server response (log_id)
		if serverResponse.GetLogId() != logID {
			t.Errorf("Expected server response to be log_id '%s', got '%s'", logID, serverResponse.GetLogId())
		}

		// Verify that directories and files were created
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
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
		if logMeta["command"] != "/bin/ls" {
			t.Errorf("log.json: expected command '/bin/ls', got '%v'", logMeta["command"])
		}

		session.Close()
	})

	t.Run("IoBufferHandling", func(t *testing.T) {
		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Event: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Send a TTY Out buffer
		ttyoutData := []byte("hello world")
		ttyoutMsg := &pb.ClientMessage{
			Event: &pb.ClientMessage_TtyoutBuf{
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
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
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
		expectedTiming := "o 1.500000 11\n"
		if !strings.Contains(string(timingContent), expectedTiming) {
			t.Errorf("timing file content mismatch: expected to contain '%s', got '%s'", expectedTiming, string(timingContent))
		}
	})

	t.Run("SessionFinalization", func(t *testing.T) {
		session, err := NewSession(logID, createTestAcceptMessage(), storageCfg)
		if err != nil {
			t.Fatalf("NewSession() failed: %v", err)
		}
		defer session.Close()

		// Initialize session
		acceptClientMsg := &pb.ClientMessage{Event: &pb.ClientMessage_AcceptMsg{AcceptMsg: createTestAcceptMessage()}}
		_, _ = session.HandleClientMessage(acceptClientMsg)

		// Send Exit message
		exitMsg := &pb.ClientMessage{
			Event: &pb.ClientMessage_ExitMsg{
				ExitMsg: &pb.ExitMessage{ExitValue: 0},
			},
		}
		_, err = session.HandleClientMessage(exitMsg)
		if err != nil {
			t.Fatalf("HandleClientMessage(ExitMsg) failed: %v", err)
		}

		// Verify timing file is read-only
		sessDir := filepath.Join(tmpDir, "a1/b2/c3")
		timingFile := filepath.Join(sessDir, "timing")
		info, err := os.Stat(timingFile)
		if err != nil {
			t.Fatalf("Failed to stat timing file: %v", err)
		}
		if info.Mode().Perm() != 0440 {
			t.Errorf("Expected timing file permissions to be 0440, but got %o", info.Mode().Perm())
		}
	})
}
