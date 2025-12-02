// Filename: internal/storage/session.go
package storage

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/config"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"syscall"
	"time"
)

// Session handles saving I/O logs for one session to the local filesystem.
type Session struct {
	logID           string
	config          *config.LocalStorageConfig
	sessionDir      string
	files           map[string]*os.File
	gzipWriters     map[string]*gzip.Writer // Gzip writers for compressed streams
	timingFile      *os.File
	logJSONFile     *os.File
	cumulativeDelay map[string]time.Duration
	logMeta         map[string]interface{}
	fileMux         sync.Mutex
	isInitialized   bool
}

// IO event types for the timing file, matching native sudo implementation.
const (
	IO_EVENT_STDIN        = 0
	IO_EVENT_STDOUT       = 1
	IO_EVENT_STDERR       = 2
	IO_EVENT_TTYIN        = 3
	IO_EVENT_TTYOUT       = 4
	IO_EVENT_WINSIZE      = 5
	IO_EVENT_TTYOUT_1_8_7 = 6 // Legacy sudo 1.8.7 bug compatibility (not used)
	IO_EVENT_SUSPEND      = 7 // Used for both suspend and resume events
)

// Map stream names to filenames and timing file markers
var streamMap = map[string]struct {
	filename string
	marker   byte
}{
	"stdin":  {filename: "stdin", marker: IO_EVENT_STDIN},
	"stdout": {filename: "stdout", marker: IO_EVENT_STDOUT},
	"stderr": {filename: "stderr", marker: IO_EVENT_STDERR},
	"ttyin":  {filename: "ttyin", marker: IO_EVENT_TTYIN},
	"ttyout": {filename: "ttyout", marker: IO_EVENT_TTYOUT},
}

// Per-directory mutexes for sequence file access to reduce contention
var seqMutexMap = make(map[string]*sync.Mutex)
var seqMutexMapLock sync.RWMutex

const alphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// NewSession creates a new local storage session handler.
func NewSession(logID string, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (*Session, error) {
	sessionDir, err := buildSessionPath(logID, cfg, acceptMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to build session path: %w", err)
	}

	slog.Debug("Resolved session log path", "log_id", logID, "path", sessionDir)
	if err := os.MkdirAll(sessionDir, os.FileMode(cfg.DirPermissions)); err != nil {
		return nil, fmt.Errorf("failed to create session directory %s: %w", sessionDir, err)
	}

	return &Session{
		logID:           logID,
		config:          cfg,
		sessionDir:      sessionDir,
		files:           make(map[string]*os.File),
		gzipWriters:     make(map[string]*gzip.Writer),
		cumulativeDelay: make(map[string]time.Duration),
		logMeta:         make(map[string]any),
	}, nil
}

// randomAlphanumericString generates a cryptographically secure random alphanumeric string of length n.
func randomAlphanumericString(n int) (string, error) {
	b := make([]byte, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumericChars))))
		if err != nil {
			return "", err
		}
		b[i] = alphanumericChars[num.Int64()]
	}
	return string(b), nil
}

// buildSessionPath constructs the full path to the log directory based on config settings.
func buildSessionPath(logID string, cfg *config.LocalStorageConfig, acceptMsg *pb.AcceptMessage) (string, error) {
	// If iolog_dir is not configured, use a simple default behavior.
	if cfg.IologDir == "" || cfg.IologFile == "" {
		sessID := logID[:6] // Use the passed-in UUID for uniqueness
		return filepath.Join(cfg.LogDirectory, sessID[:2], sessID[2:4], sessID[4:6]), nil
	}

	// Create a map of info messages for easy lookup.
	infoMap := make(map[string]string)
	for _, info := range acceptMsg.InfoMsgs {
		key := info.GetKey()
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			infoMap[key] = v.Strval
		case *pb.InfoMessage_Numval:
			infoMap[key] = fmt.Sprintf("%d", v.Numval)
		}
	}

	// Get values for dynamic escapes
	seq, err := getNextSeq(cfg.LogDirectory, cfg)
	if err != nil {
		return "", err
	}
	randStr, err := randomAlphanumericString(6)
	if err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	now := time.Now()
	epochStr := fmt.Sprintf("%d", now.Unix())

	// Replacer for sudoers-style escape sequences.
	replacer := strings.NewReplacer(
		// User/Group escapes
		"%{user}", infoMap["submituser"],
		"%{uid}", infoMap["submituid"],
		"%{group}", infoMap["submitgroup"],
		"%{gid}", infoMap["submitgid"],
		"%{runuser}", infoMap["runuser"],
		"%{runuid}", infoMap["runuid"],
		"%{rungroup}", infoMap["rungroup"],
		"%{rungid}", infoMap["rungid"],
		// Host/Command escapes
		"%{hostname}", infoMap["submithost"],
		"%{command_path}", infoMap["command"],
		"%{command}", filepath.Base(infoMap["command"]),
		// Sequence and Random escapes
		"%{seq}", seq,
		"%{rand}", randStr,
		// Time/Date escapes
		"%{year}", fmt.Sprintf("%04d", now.Year()),
		"%{month}", fmt.Sprintf("%02d", now.Month()),
		"%{day}", fmt.Sprintf("%02d", now.Day()),
		"%{hour}", fmt.Sprintf("%02d", now.Hour()),
		"%{minute}", fmt.Sprintf("%02d", now.Minute()),
		"%{second}", fmt.Sprintf("%02d", now.Second()),
		"%{epoch}", epochStr,
		// Path escapes
		"%{LIVEDIR}", cfg.LogDirectory,
		// Literal percent escape
		"%%", "%",
	)

	iologDir := replacer.Replace(cfg.IologDir)
	iologFile := replacer.Replace(cfg.IologFile)

	return filepath.Join(iologDir, iologFile), nil
}

// getMutexForDir returns a mutex for the given directory, creating one if needed
func getMutexForDir(dir string) *sync.Mutex {
	seqMutexMapLock.RLock()
	if mutex, exists := seqMutexMap[dir]; exists {
		seqMutexMapLock.RUnlock()
		return mutex
	}
	seqMutexMapLock.RUnlock()

	seqMutexMapLock.Lock()
	defer seqMutexMapLock.Unlock()

	// Double-check pattern
	if mutex, exists := seqMutexMap[dir]; exists {
		return mutex
	}

	mutex := &sync.Mutex{}
	seqMutexMap[dir] = mutex
	return mutex
}

// getNextSeq generates a sudo-compatible 6-character sequence number with file locking.
func getNextSeq(baseDir string, cfg *config.LocalStorageConfig) (string, error) {
	mutex := getMutexForDir(baseDir)
	mutex.Lock()
	defer mutex.Unlock()

	// The sequence file is stored in the base log directory
	seqFile := filepath.Join(baseDir, "seq")

	// Ensure the base directory exists
	if err := os.MkdirAll(baseDir, os.FileMode(cfg.DirPermissions)); err != nil {
		return "", fmt.Errorf("could not create base directory %s: %w", baseDir, err)
	}

	f, err := os.OpenFile(seqFile, os.O_RDWR|os.O_CREATE, os.FileMode(cfg.FilePermissions))
	if err != nil {
		return "", fmt.Errorf("could not open sequence file %s: %w", seqFile, err)
	}
	defer f.Close()

	// Apply file lock for additional safety
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("could not lock sequence file: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	// Get file info to check size
	stat, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("could not stat sequence file: %w", err)
	}

	var currentSeq uint32
	if stat.Size() >= 4 {
		// Read the current sequence number
		data := make([]byte, 4)
		if _, err := f.ReadAt(data, 0); err != nil {
			return "", fmt.Errorf("could not read sequence file: %w", err)
		}
		currentSeq = binary.BigEndian.Uint32(data)
	}

	// Increment and wrap if necessary (sudo uses a base36 encoding)
	nextSeq := currentSeq + 1

	// Write the new sequence number back to the file atomically
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, nextSeq)
	if _, err := f.WriteAt(data, 0); err != nil {
		return "", fmt.Errorf("could not write to sequence file: %w", err)
	}

	// Ensure the write is flushed to disk
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("could not sync sequence file: %w", err)
	}

	// Convert the number to a 6-character, zero-padded, base36 string
	const base36 = "0123456789abcdefghijklmnopqrstuvwxyz"
	seqStr := ""
	val := nextSeq
	for i := 0; i < 6; i++ {
		seqStr = string(base36[val%36]) + seqStr
		val /= 36
	}

	return seqStr, nil
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
	// Create a map of info messages for easy lookup of string values.
	infoMap := make(map[string]string)

	slog.Debug("--- Begin AcceptMessage InfoMsgs ---")
	for _, info := range acceptMsg.InfoMsgs {
		key := info.GetKey()
		var value string
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			value = v.Strval
			s.logMeta[key] = v.Strval
		case *pb.InfoMessage_Numval:
			value = fmt.Sprintf("%d", v.Numval)
			s.logMeta[key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			value = strings.Join(v.Strlistval.Strings, " ")
			s.logMeta[key] = v.Strlistval.Strings
		}
		infoMap[key] = value
		slog.Debug("Received InfoMessage", "key", key, "value", value)
	}
	slog.Debug("--- End AcceptMessage InfoMsgs ---")

	s.logMeta["server_log_id"] = s.logID // Add our own server-side log ID for reference
	submitTime := time.Unix(acceptMsg.SubmitTime.TvSec, int64(acceptMsg.SubmitTime.TvNsec))
	s.logMeta["submit_time"] = submitTime.UTC().Format(time.RFC3339Nano)

	// --- Write the plain text `log` file ---
	logSummaryPath := filepath.Join(s.sessionDir, "log")
	summaryLine := fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s\n%s\n%s\n",
		submitTime.Unix(),
		infoMap["submituser"],
		infoMap["runuser"],
		infoMap["rungroup"],
		infoMap["ttyname"],
		infoMap["lines"],
		infoMap["columns"],
		infoMap["submitcwd"],
		infoMap["command"],
	)
	if err := os.WriteFile(logSummaryPath, []byte(summaryLine), os.FileMode(s.config.FilePermissions)); err != nil {
		return fmt.Errorf("failed to create 'log' summary file: %w", err)
	}
	slog.Debug("Created log summary file", "log_id", s.logID, "path", logSummaryPath)

	// --- Create timing and I/O stream files and initialize log.json ---
	timingFilePath := filepath.Join(s.sessionDir, "timing")
	var err error
	s.timingFile, err = os.OpenFile(timingFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.FileMode(s.config.FilePermissions))
	if err != nil {
		return err
	}
	slog.Debug("Opened timing file for session", "log_id", s.logID, "path", timingFilePath)

	// Create and initialize log.json file
	logJSONPath := filepath.Join(s.sessionDir, "log.json")
	s.logJSONFile, err = os.OpenFile(logJSONPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(s.config.FilePermissions))
	if err != nil {
		return fmt.Errorf("failed to create log.json file: %w", err)
	}
	slog.Debug("Created log.json file for session", "log_id", s.logID, "path", logJSONPath)

	// Write initial metadata to log.json
	if err := s.updateLogJSON(); err != nil {
		return fmt.Errorf("failed to write initial metadata to log.json: %w", err)
	}

	// Create I/O stream files
	for streamName, streamInfo := range streamMap {
		filePath := filepath.Join(s.sessionDir, streamInfo.filename)
		f, err := os.Create(filePath)
		if err != nil {
			return err
		}
		slog.Debug("Created IO stream file", "log_id", s.logID, "stream", streamName, "path", filePath, "compressed", s.config.Compress)
		s.files[streamName] = f

		// If compression is enabled, wrap the file with a gzip writer
		if s.config.Compress {
			gzWriter := gzip.NewWriter(f)
			s.gzipWriters[streamName] = gzWriter
		}
	}
	return nil
}

// updateLogJSON writes the current metadata to the log.json file incrementally.
func (s *Session) updateLogJSON() error {
	if s.logJSONFile == nil {
		return fmt.Errorf("log.json file not initialized")
	}

	// Seek to the beginning of the file and truncate it
	if _, err := s.logJSONFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to beginning of log.json: %w", err)
	}
	if err := s.logJSONFile.Truncate(0); err != nil {
		return fmt.Errorf("failed to truncate log.json: %w", err)
	}

	// Write the updated metadata
	encoder := json.NewEncoder(s.logJSONFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(s.logMeta); err != nil {
		return fmt.Errorf("failed to encode JSON to log.json: %w", err)
	}

	// Flush the data to disk
	if err := s.logJSONFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync log.json: %w", err)
	}

	slog.Debug("Updated log.json", "log_id", s.logID)
	return nil
}

// writeIoEntry writes I/O data and a corresponding timing entry.
func (s *Session) writeIoEntry(streamName string, delay *pb.TimeSpec, data []byte) (*pb.ServerMessage, error) {
	streamInfo, ok := streamMap[streamName]
	if !ok {
		return nil, fmt.Errorf("unknown stream name: %s", streamName)
	}

	// Write data - use gzip writer if compression is enabled, otherwise write directly
	var writer io.Writer
	if gzWriter, compressed := s.gzipWriters[streamName]; compressed {
		writer = gzWriter
	} else {
		writer = s.files[streamName]
	}

	if _, err := writer.Write(data); err != nil {
		return nil, err
	}

	// Flush gzip writer if using compression (equivalent to sudo's Z_SYNC_FLUSH)
	if gzWriter, compressed := s.gzipWriters[streamName]; compressed {
		if err := gzWriter.Flush(); err != nil {
			return nil, fmt.Errorf("failed to flush gzip writer for %s: %w", streamName, err)
		}
	}

	// Write timing info
	delayDur := time.Duration(delay.TvSec)*time.Second + time.Duration(delay.TvNsec)*time.Nanosecond
	s.cumulativeDelay[streamName] += delayDur

	timingRecord := fmt.Sprintf("%d %.9f %d\n",
		streamInfo.marker,
		delayDur.Seconds(),
		len(data))
	slog.Debug("Writing timing entry", "log_id", s.logID, "stream", streamName, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	// Update log.json with current state
	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update log.json after I/O entry", "log_id", s.logID, "error", err)
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
	timingRecord := fmt.Sprintf("%d %.9f %d %d\n", IO_EVENT_WINSIZE, delay.Seconds(), event.Rows, event.Cols)
	slog.Debug("Writing winsize entry", "log_id", s.logID, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	// Update log.json with current state
	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update log.json after winsize event", "log_id", s.logID, "error", err)
	}

	return nil, nil // No commit point for winsize
}

func (s *Session) handleSuspend(event *pb.CommandSuspend) (*pb.ServerMessage, error) {
	delay := time.Duration(event.Delay.TvSec)*time.Second + time.Duration(event.Delay.TvNsec)*time.Nanosecond

	// Sudo uses marker 7 for all suspend/resume events; signal name differentiates them
	timingRecord := fmt.Sprintf("%d %.9f %s\n", IO_EVENT_SUSPEND, delay.Seconds(), event.Signal)
	slog.Debug("Writing suspend/resume entry", "log_id", s.logID, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	// Update log.json with current state
	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update log.json after suspend/resume event", "log_id", s.logID, "error", err)
	}

	return nil, nil // No commit point for suspend
}

// finalize cleans up and closes files, marking the log as complete.
func (s *Session) finalize(exitMsg *pb.ExitMessage) {
	slog.Info("Finalizing local storage session", "log_id", s.logID, "exit_value", exitMsg.ExitValue)

	// Update metadata with exit information
	s.logMeta["exit_value"] = exitMsg.GetExitValue()
	if runTime := exitMsg.GetRunTime(); runTime != nil {
		s.logMeta["run_time"] = struct {
			Seconds     int64 `json:"seconds"`
			Nanoseconds int32 `json:"nanoseconds"`
		}{
			Seconds:     runTime.GetTvSec(),
			Nanoseconds: runTime.GetTvNsec(),
		}
	}

	now := time.Now()
	s.logMeta["timestamp"] = struct {
		Seconds     int64 `json:"seconds"`
		Nanoseconds int32 `json:"nanoseconds"`
	}{
		Seconds:     now.Unix(),
		Nanoseconds: int32(now.Nanosecond()),
	}

	if exitMsg.GetSignal() != "" {
		s.logMeta["signal"] = exitMsg.GetSignal()
	}
	if exitMsg.GetDumpedCore() {
		s.logMeta["dumped_core"] = true
	}

	// Update log.json with final exit information
	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update log.json with final exit information", "log_id", s.logID, "error", err)
	} else {
		slog.Debug("Updated log.json with final metadata", "log_id", s.logID)
	}

	// Close all file handles
	s.Close()

	// Mark timing file as read-only to indicate completion, per sudo spec.
	timingFilePath := filepath.Join(s.sessionDir, "timing")
	slog.Debug("Setting timing file to read-only", "log_id", s.logID, "path", timingFilePath)
	if err := os.Chmod(timingFilePath, 0440); err != nil {
		slog.Error("Failed to make timing file read-only", "log_id", s.logID, "error", err)
	}
}

// Close closes all open file handles for the session.
func (s *Session) Close() error {
	var lastErr error

	// First, close all gzip writers to ensure all data is flushed
	for name, gzWriter := range s.gzipWriters {
		slog.Debug("Closing gzip writer", "log_id", s.logID, "stream", name)
		if err := gzWriter.Close(); err != nil {
			slog.Error("Failed to close gzip writer", "log_id", s.logID, "stream", name, "error", err)
			lastErr = err
		}
	}

	// Then close the underlying file handles
	for name, f := range s.files {
		slog.Debug("Closing stream file", "log_id", s.logID, "stream", name)
		if err := f.Close(); err != nil {
			slog.Error("Failed to close stream file", "log_id", s.logID, "stream", name, "error", err)
			lastErr = err
		}
	}
	if s.logJSONFile != nil {
		slog.Debug("Closing log.json file", "log_id", s.logID)
		if err := s.logJSONFile.Close(); err != nil {
			slog.Error("Failed to close log.json file", "log_id", s.logID, "error", err)
			lastErr = err
		}
	}
	if s.timingFile != nil {
		slog.Debug("Closing timing file", "log_id", s.logID)
		if err := s.timingFile.Close(); err != nil {
			slog.Error("Failed to close timing file", "log_id", s.logID, "error", err)
			lastErr = err
		}
	}
	slog.Info("Closed all log files for session", "log_id", s.logID)
	return lastErr
}
