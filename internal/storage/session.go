// Filename: internal/storage/session.go
package storage

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"time"
)

// Session handles saving I/O logs for one session to the local filesystem.
type Session struct {
	logID           string
	config          *config.LocalStorageConfig
	sessionDir      string
	files           map[string]*os.File
	timingFile      *os.File
	cumulativeDelay map[string]time.Duration
	fileMux         sync.Mutex
	isInitialized   bool
}

// Map stream names to filenames and timing file markers
var streamMap = map[string]struct {
	filename string
	marker   byte
}{
	"ttyin":  {filename: "ttyin", marker: 'i'},
	"ttyout": {filename: "ttyout", marker: 'o'},
	"stdin":  {filename: "stdin", marker: '0'},
	"stdout": {filename: "stdout", marker: '1'},
	"stderr": {filename: "stderr", marker: '2'},
}

// NewSession creates a new local storage session handler.
func NewSession(logID string, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (*Session, error) {
	// Create a simplified session ID for the directory name, like sudo does.
	sessID := logID[:6]
	// Construct directory path, creating subdirectories based on sessID for better organization.
	// e.g., for sessID "a1b2c3", path becomes /base/dir/a1/b2/c3
	sessionDir := filepath.Join(cfg.LogDirectory, sessID[:2], sessID[2:4], sessID[4:6])

	if err := os.MkdirAll(sessionDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create session directory %s: %w", sessionDir, err)
	}

	return &Session{
		logID:           logID,
		config:          cfg,
		sessionDir:      sessionDir,
		files:           make(map[string]*os.File),
		cumulativeDelay: make(map[string]time.Duration),
	}, nil
}

// HandleClientMessage processes a message from the client.
func (s *Session) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	s.fileMux.Lock()
	defer s.fileMux.Unlock()

	if !s.isInitialized {
		acceptMsg := msg.GetAcceptMsg()
		if acceptMsg == nil {
			return nil, fmt.Errorf("protocol error: first message to session handler was not AcceptMessage")
		}
		if err := s.initialize(acceptMsg); err != nil {
			return nil, fmt.Errorf("failed to initialize local storage session: %w", err)
		}
		s.isInitialized = true
		// Respond with the log_id
		return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: s.logID}}, nil
	}

	switch event := msg.Type.(type) {
	case *pb.ClientMessage_TtyinBuf:
		return s.writeIoEntry("ttyin", event.TtyinBuf.Delay, event.TtyinBuf.Data)
	case *pb.ClientMessage_TtyoutBuf:
		return s.writeIoEntry("ttyout", event.TtyoutBuf.Delay, event.TtyoutBuf.Data)
	case *pb.ClientMessage_StdinBuf:
		return s.writeIoEntry("stdin", event.StdinBuf.Delay, event.StdinBuf.Data)
	case *pb.ClientMessage_StdoutBuf:
		return s.writeIoEntry("stdout", event.StdoutBuf.Delay, event.StdoutBuf.Data)
	case *pb.ClientMessage_StderrBuf:
		return s.writeIoEntry("stderr", event.StderrBuf.Delay, event.StderrBuf.Data)
	case *pb.ClientMessage_WinsizeEvent:
		return s.handleWinsize(event.WinsizeEvent)
	case *pb.ClientMessage_SuspendEvent:
		return s.handleSuspend(event.SuspendEvent)
	case *pb.ClientMessage_ExitMsg:
		s.finalize(event.ExitMsg)
		return nil, nil // No response needed for Exit
	default:
		slog.Warn("Local storage session received unhandled message type", "type", fmt.Sprintf("%T", event))
		return nil, nil // Ignore unhandled
	}
}

// initialize sets up all the files for the session log.
func (s *Session) initialize(acceptMsg *pb.AcceptMessage) error {
	// Create log.json with metadata
	logMeta := make(map[string]interface{})
	for _, info := range acceptMsg.InfoMsgs {
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			logMeta[info.Key] = v.Strval
		case *pb.InfoMessage_Numval:
			logMeta[info.Key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			logMeta[info.Key] = v.Strlistval.Strings
		}
	}
	logMeta["log_id"] = s.logID
	logMeta["submit_time"] = time.Unix(acceptMsg.SubmitTime.TvSec, int64(acceptMsg.SubmitTime.TvNsec)).UTC().Format(time.RFC3339Nano)

	logFile, err := os.Create(filepath.Join(s.sessionDir, "log.json"))
	if err != nil {
		return err
	}
	defer logFile.Close()
	encoder := json.NewEncoder(logFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(logMeta); err != nil {
		return err
	}

	// Create timing file
	timingFilePath := filepath.Join(s.sessionDir, "timing")
	s.timingFile, err = os.OpenFile(timingFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}

	// Create I/O stream files
	for streamName, streamInfo := range streamMap {
		f, err := os.Create(filepath.Join(s.sessionDir, streamInfo.filename))
		if err != nil {
			return err
		}
		s.files[streamName] = f
	}
	return nil
}

// writeIoEntry writes I/O data and a corresponding timing entry.
func (s *Session) writeIoEntry(streamName string, delay *pb.TimeSpec, data []byte) (*pb.ServerMessage, error) {
	streamInfo, ok := streamMap[streamName]
	if !ok {
		return nil, fmt.Errorf("unknown stream name: %s", streamName)
	}

	ioFile := s.files[streamName]

	// Write data
	if _, err := ioFile.Write(data); err != nil {
		return nil, err
	}

	// Write timing info
	delayDur := time.Duration(delay.TvSec)*time.Second + time.Duration(delay.TvNsec)*time.Nanosecond
	s.cumulativeDelay[streamName] += delayDur

	timingRecord := fmt.Sprintf("%c %.6f %d\n",
		streamInfo.marker,
		delayDur.Seconds(),
		len(data))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	// Send commit point
	commitPoint := s.cumulativeDelay[streamName]
	return &pb.ServerMessage{Type: &pb.ServerMessage_CommitPoint{
		CommitPoint: &pb.TimeSpec{
			TvSec:  int64(commitPoint.Seconds()),
			TvNsec: int32(commitPoint.Nanoseconds() % 1e9),
		},
	}}, nil
}

func (s *Session) handleWinsize(event *pb.ChangeWindowSize) (*pb.ServerMessage, error) {
	delay := time.Duration(event.Delay.TvSec)*time.Second + time.Duration(event.Delay.TvNsec)*time.Nanosecond
	timingRecord := fmt.Sprintf("w %.6f %d %d\n", delay.Seconds(), event.Rows, event.Cols)
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}
	return nil, nil // No commit point for winsize
}

func (s *Session) handleSuspend(event *pb.CommandSuspend) (*pb.ServerMessage, error) {
	delay := time.Duration(event.Delay.TvSec)*time.Second + time.Duration(event.Delay.TvNsec)*time.Nanosecond
	timingRecord := fmt.Sprintf("s %.6f %s\n", delay.Seconds(), event.Signal)
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}
	return nil, nil // No commit point for suspend
}

// finalize cleans up and closes files, marking the log as complete.
func (s *Session) finalize(exitMsg *pb.ExitMessage) {
	slog.Info("Finalizing local storage session", "log_id", s.logID, "exit_value", exitMsg.ExitValue)
	// No lock here as it will be called from HandleClientMessage which holds the lock.
	s.Close()

	// Mark timing file as read-only to indicate completion, per sudo spec.
	timingFilePath := filepath.Join(s.sessionDir, "timing")
	if err := os.Chmod(timingFilePath, 0440); err != nil {
		slog.Error("Failed to make timing file read-only", "log_id", s.logID, "error", err)
	}
}

// Close closes all open file handles for the session.
func (s *Session) Close() error {
	for _, f := range s.files {
		f.Close()
	}
	if s.timingFile != nil {
		s.timingFile.Close()
	}
	slog.Info("Closed all log files for session", "log_id", s.logID)
	return nil
}
