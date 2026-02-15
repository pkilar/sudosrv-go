// Filename: internal/storage/session.go
package storage

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
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

	"github.com/google/uuid"
)

// commitPointInterval matches C sudo_logsrvd's ACK_FREQUENCY (10 seconds).
// Commit points are only sent when this interval has elapsed since the last one.
const commitPointInterval = 10 * time.Second

// Session handles saving I/O logs for one session to the local filesystem.
type Session struct {
	logID           string
	sessionUUID     uuid.UUID
	config          *config.LocalStorageConfig
	sessionDir      string
	files           map[string]*os.File
	gzipWriters     map[string]*gzip.Writer // Gzip writers for compressed streams
	timingFile      *os.File
	logJSONFile     *os.File
	cumulativeDelay map[string]time.Duration
	logMeta         map[string]interface{}
	passwordFilter  *PasswordFilter // Password filtering for security
	lastCommitTime  time.Time       // Tracks when last commit point was sent
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

// validSuspendSignals is the set of signal names allowed in CommandSuspend messages,
// matching the C sudo_logsrvd validation (signals sent without "SIG" prefix).
var validSuspendSignals = map[string]bool{
	"STOP": true,
	"TSTP": true,
	"CONT": true,
	"TTIN": true,
	"TTOU": true,
}

// Per-directory mutexes for sequence file access to reduce contention
var seqMutexMap = make(map[string]*sync.Mutex)
var seqMutexMapLock sync.RWMutex

const alphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// sanitizePathComponent removes forward slashes from user-controlled path values
// to prevent path traversal attacks via escape sequence expansion.
// Matches the behavior of strlcpy_no_slash() in C sudo_logsrvd.
func sanitizePathComponent(s string) string {
	return strings.ReplaceAll(s, "/", "")
}

// containsDotDot checks whether a path contains a ".." component,
// matching C sudo_logsrvd's contains_dot_dot() check.
func containsDotDot(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// pathWithinBase returns true when target stays lexically within base.
// Both values are cleaned before checking.
func pathWithinBase(base, target string) (bool, error) {
	relPath, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
	if err != nil {
		return false, err
	}

	return relPath != ".." && !strings.HasPrefix(relPath, ".."+string(filepath.Separator)), nil
}

// deriveLogIDRelativePath returns the path component that should be embedded in
// log_id. It only strips logDirectory when sessionDir is a true descendant.
func deriveLogIDRelativePath(logDirectory, sessionDir string) string {
	cleanLogDirectory := filepath.Clean(logDirectory)
	cleanSessionDir := filepath.Clean(sessionDir)

	relPath, err := filepath.Rel(cleanLogDirectory, cleanSessionDir)
	if err != nil {
		return cleanSessionDir
	}
	if relPath == "." {
		return ""
	}
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return cleanSessionDir
	}

	return relPath
}

// generateLogID creates a log ID matching the C sudo_logsrvd format:
// base64(16-byte UUID + relative_path).
func generateLogID(sessionUUID uuid.UUID, relativePath string) string {
	idBytes := make([]byte, 0, 16+len(relativePath))
	idBytes = append(idBytes, sessionUUID[:]...)
	idBytes = append(idBytes, []byte(relativePath)...)
	return base64.StdEncoding.EncodeToString(idBytes)
}

// NewSession creates a new local storage session handler.
func NewSession(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (*Session, error) {
	sessionDir, err := buildSessionPath(sessionUUID, cfg, acceptMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to build session path: %w", err)
	}

	// Compute relative path for log_id generation (matches C sudo_logsrvd behavior).
	relativePath := deriveLogIDRelativePath(cfg.LogDirectory, sessionDir)
	logID := generateLogID(sessionUUID, relativePath)

	slog.Debug("Resolved session log path", "log_id", logID, "path", sessionDir)
	if err := os.MkdirAll(sessionDir, os.FileMode(cfg.DirPermissions)); err != nil {
		return nil, fmt.Errorf("failed to create session directory %s: %w", sessionDir, err)
	}

	session := &Session{
		logID:           logID,
		sessionUUID:     sessionUUID,
		config:          cfg,
		sessionDir:      sessionDir,
		files:           make(map[string]*os.File),
		gzipWriters:     make(map[string]*gzip.Writer),
		cumulativeDelay: make(map[string]time.Duration),
		logMeta:         make(map[string]any),
	}

	// Initialize password filter if enabled
	if cfg.PasswordFilter {
		session.passwordFilter = NewPasswordFilter()
		slog.Debug("Password filtering enabled for session", "log_id", logID)
	}

	return session, nil
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
func buildSessionPath(sessionUUID uuid.UUID, cfg *config.LocalStorageConfig, acceptMsg *pb.AcceptMessage) (string, error) {
	// If iolog_dir is not configured, use a simple default behavior.
	if cfg.IologDir == "" || cfg.IologFile == "" {
		uuidStr := sessionUUID.String()
		sessID := uuidStr[:6] // Use the UUID string for uniqueness
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
	// User-controlled values are sanitized to strip "/" characters,
	// matching C sudo_logsrvd's strlcpy_no_slash() behavior.
	replacer := strings.NewReplacer(
		// User/Group escapes (sanitized — user-controlled)
		"%{user}", sanitizePathComponent(infoMap["submituser"]),
		"%{uid}", sanitizePathComponent(infoMap["submituid"]),
		"%{group}", sanitizePathComponent(infoMap["submitgroup"]),
		"%{gid}", sanitizePathComponent(infoMap["submitgid"]),
		"%{runuser}", sanitizePathComponent(infoMap["runuser"]),
		"%{runuid}", sanitizePathComponent(infoMap["runuid"]),
		"%{rungroup}", sanitizePathComponent(infoMap["rungroup"]),
		"%{rungid}", sanitizePathComponent(infoMap["rungid"]),
		// Host/Command escapes (sanitized — user-controlled)
		"%{hostname}", sanitizePathComponent(infoMap["submithost"]),
		"%{command_path}", sanitizePathComponent(infoMap["command"]),
		"%{command}", sanitizePathComponent(filepath.Base(infoMap["command"])),
		// Sequence and Random escapes (server-generated, safe)
		"%{seq}", seq,
		"%{rand}", randStr,
		// Time/Date escapes (server-generated, safe)
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

	// Reject paths containing ".." to prevent directory traversal.
	// This check must run before filepath.Join, which cleans the path and
	// could otherwise hide the original ".." components.
	// Matches C sudo_logsrvd's contains_dot_dot() behavior on expanded values.
	if containsDotDot(iologDir) || containsDotDot(iologFile) {
		return "", fmt.Errorf("path traversal detected in constructed path components: dir=%q file=%q", iologDir, iologFile)
	}

	fullPath := filepath.Join(iologDir, iologFile)

	return fullPath, nil
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
	case *pb.ClientMessage_AlertMsg:
		return s.handleAlert(event.AlertMsg)
	case *pb.ClientMessage_AcceptMsg:
		return s.handleSubCommandAccept(event.AcceptMsg)
	case *pb.ClientMessage_RejectMsg:
		return s.handleSubCommandReject(event.RejectMsg)
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

	// --- Write the UUID file (matches C sudo_logsrvd's iolog_store_uuid) ---
	uuidPath := filepath.Join(s.sessionDir, "uuid")
	if err := os.WriteFile(uuidPath, []byte(s.sessionUUID.String()+"\n"), os.FileMode(s.config.FilePermissions)); err != nil {
		return fmt.Errorf("failed to write uuid file: %w", err)
	}
	slog.Debug("Created UUID file", "log_id", s.logID, "path", uuidPath)

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

	// Apply password filtering if enabled
	dataToWrite := data
	if s.passwordFilter != nil {
		if streamName == "ttyout" {
			// Check output for password prompts
			s.passwordFilter.CheckOutput(data)
		} else if streamName == "ttyin" {
			// Filter input if password prompt was detected
			dataToWrite = s.passwordFilter.FilterInput(data)
			if len(dataToWrite) != len(data) || string(dataToWrite) != string(data) {
				slog.Debug("Password input masked", "log_id", s.logID, "original_len", len(data), "masked_len", len(dataToWrite))
			}
		}
	}

	// Write data - use gzip writer if compression is enabled, otherwise write directly
	var writer io.Writer
	if gzWriter, compressed := s.gzipWriters[streamName]; compressed {
		writer = gzWriter
	} else {
		writer = s.files[streamName]
	}

	if _, err := writer.Write(dataToWrite); err != nil {
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

	// Only send commit points at commitPointInterval, matching C sudo_logsrvd's ACK_FREQUENCY.
	// The first I/O event always sends one (zero-value lastCommitTime guarantees this).
	if time.Since(s.lastCommitTime) >= commitPointInterval {
		s.lastCommitTime = time.Now()
		commitPoint := s.cumulativeDelay[streamName]
		return &pb.ServerMessage{Type: &pb.ServerMessage_CommitPoint{
			CommitPoint: &pb.TimeSpec{
				TvSec:  int64(commitPoint.Seconds()),
				TvNsec: int32(commitPoint.Nanoseconds() % 1e9),
			},
		}}, nil
	}

	return nil, nil
}

func (s *Session) handleWinsize(event *pb.ChangeWindowSize) (*pb.ServerMessage, error) {
	delay := time.Duration(event.Delay.TvSec)*time.Second + time.Duration(event.Delay.TvNsec)*time.Nanosecond
	timingRecord := fmt.Sprintf("%d %.9f %d %d\n", IO_EVENT_WINSIZE, delay.Seconds(), event.Rows, event.Cols)
	slog.Debug("Writing winsize entry", "log_id", s.logID, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	return nil, nil // No commit point for winsize
}

func (s *Session) handleSuspend(event *pb.CommandSuspend) (*pb.ServerMessage, error) {
	// Validate signal against allowed set, matching C sudo_logsrvd behavior.
	if !validSuspendSignals[event.Signal] {
		return nil, fmt.Errorf("invalid CommandSuspend signal: %q", event.Signal)
	}

	delay := time.Duration(event.Delay.TvSec)*time.Second + time.Duration(event.Delay.TvNsec)*time.Nanosecond

	// Sudo uses marker 7 for all suspend/resume events; signal name differentiates them
	timingRecord := fmt.Sprintf("%d %.9f %s\n", IO_EVENT_SUSPEND, delay.Seconds(), event.Signal)
	slog.Debug("Writing suspend/resume entry", "log_id", s.logID, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	return nil, nil // No commit point for suspend
}

// handleAlert records a security alert in the session's log.json metadata.
func (s *Session) handleAlert(alertMsg *pb.AlertMessage) (*pb.ServerMessage, error) {
	alert := map[string]interface{}{
		"reason": alertMsg.GetReason(),
	}
	if alertTime := alertMsg.GetAlertTime(); alertTime != nil {
		alert["alert_time"] = time.Unix(alertTime.TvSec, int64(alertTime.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	// Extract info messages
	infoMap := make(map[string]interface{})
	for _, info := range alertMsg.GetInfoMsgs() {
		key := info.GetKey()
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			infoMap[key] = v.Strval
		case *pb.InfoMessage_Numval:
			infoMap[key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			infoMap[key] = v.Strlistval.GetStrings()
		}
	}
	if len(infoMap) > 0 {
		alert["info"] = infoMap
	}

	// Append to alerts array in metadata
	alerts, _ := s.logMeta["alerts"].([]interface{})
	alerts = append(alerts, alert)
	s.logMeta["alerts"] = alerts

	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update log.json after alert", "log_id", s.logID, "error", err)
	}

	slog.Info("Recorded alert in session", "log_id", s.logID, "reason", alertMsg.GetReason())
	return nil, nil // No commit point for alerts
}

// handleSubCommandAccept records a sub-command accept event in the session metadata.
// Sub-commands share the parent session's iolog_path, matching C sudo_logsrvd behavior.
func (s *Session) handleSubCommandAccept(acceptMsg *pb.AcceptMessage) (*pb.ServerMessage, error) {
	entry := map[string]interface{}{
		"event_type": "accept",
	}
	if st := acceptMsg.GetSubmitTime(); st != nil {
		entry["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	// Extract info messages
	infoMap := make(map[string]interface{})
	for _, info := range acceptMsg.GetInfoMsgs() {
		key := info.GetKey()
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			infoMap[key] = v.Strval
		case *pb.InfoMessage_Numval:
			infoMap[key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			infoMap[key] = v.Strlistval.GetStrings()
		}
	}
	if len(infoMap) > 0 {
		for k, v := range infoMap {
			// Preserve authoritative fields already set by the server.
			if _, exists := entry[k]; exists {
				continue
			}
			entry[k] = v
		}
	}

	subCmds, _ := s.logMeta["sub_commands"].([]interface{})
	subCmds = append(subCmds, entry)
	s.logMeta["sub_commands"] = subCmds

	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update log.json after sub-command accept", "log_id", s.logID, "error", err)
	}

	slog.Info("Recorded sub-command accept", "log_id", s.logID)
	// Return the same log_id — sub-commands share iolog_path
	return &pb.ServerMessage{Type: &pb.ServerMessage_LogId{LogId: s.logID}}, nil
}

// handleSubCommandReject records a sub-command reject event in the session metadata.
func (s *Session) handleSubCommandReject(rejectMsg *pb.RejectMessage) (*pb.ServerMessage, error) {
	entry := map[string]interface{}{
		"event_type": "reject",
		"reason":     rejectMsg.GetReason(),
	}
	if st := rejectMsg.GetSubmitTime(); st != nil {
		entry["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	// Extract info messages
	infoMap := make(map[string]interface{})
	for _, info := range rejectMsg.GetInfoMsgs() {
		key := info.GetKey()
		switch v := info.Value.(type) {
		case *pb.InfoMessage_Strval:
			infoMap[key] = v.Strval
		case *pb.InfoMessage_Numval:
			infoMap[key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			infoMap[key] = v.Strlistval.GetStrings()
		}
	}
	if len(infoMap) > 0 {
		for k, v := range infoMap {
			// Preserve authoritative fields already set by the server.
			if _, exists := entry[k]; exists {
				continue
			}
			entry[k] = v
		}
	}

	subCmds, _ := s.logMeta["sub_commands"].([]interface{})
	subCmds = append(subCmds, entry)
	s.logMeta["sub_commands"] = subCmds

	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update log.json after sub-command reject", "log_id", s.logID, "error", err)
	}

	slog.Info("Recorded sub-command reject", "log_id", s.logID, "reason", rejectMsg.GetReason())
	return nil, nil // No response for sub-command rejects
}

// DecodeLogID decodes a log ID back into the UUID and relative path components.
// The log ID format is: base64(16-byte UUID + relative_path).
func DecodeLogID(logID string) (uuid.UUID, string, error) {
	decoded, err := base64.StdEncoding.DecodeString(logID)
	if err != nil {
		return uuid.UUID{}, "", fmt.Errorf("failed to base64 decode log_id: %w", err)
	}
	if len(decoded) < 16 {
		return uuid.UUID{}, "", fmt.Errorf("decoded log_id too short: %d bytes (need at least 16)", len(decoded))
	}

	var sessionUUID uuid.UUID
	copy(sessionUUID[:], decoded[:16])
	relativePath := string(decoded[16:])

	return sessionUUID, relativePath, nil
}

// NewRestartSession creates a session that resumes an existing log from a RestartMessage.
func NewRestartSession(restartMsg *pb.RestartMessage, cfg *config.LocalStorageConfig) (*Session, error) {
	sessionUUID, relativePath, err := DecodeLogID(restartMsg.GetLogId())
	if err != nil {
		return nil, fmt.Errorf("invalid log_id in RestartMessage: %w", err)
	}

	// Path safety check
	if filepath.IsAbs(relativePath) || strings.HasPrefix(filepath.ToSlash(relativePath), "/") || filepath.VolumeName(relativePath) != "" {
		return nil, fmt.Errorf("absolute path detected in log_id path: %s", relativePath)
	}
	if containsDotDot(relativePath) {
		return nil, fmt.Errorf("path traversal detected in log_id path: %s", relativePath)
	}

	sessionDir := filepath.Join(cfg.LogDirectory, relativePath)
	withinLogRoot, err := pathWithinBase(cfg.LogDirectory, sessionDir)
	if err != nil {
		return nil, fmt.Errorf("failed to validate session path: %w", err)
	}
	if !withinLogRoot {
		return nil, fmt.Errorf("log_id path escapes log root: %s", relativePath)
	}

	// Verify session directory exists
	if _, err := os.Stat(sessionDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("session directory does not exist: %s", sessionDir)
	}

	// Read and verify UUID file
	uuidPath := filepath.Join(sessionDir, "uuid")
	uuidData, err := os.ReadFile(uuidPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read uuid file: %w", err)
	}
	storedUUID := strings.TrimSpace(string(uuidData))
	if storedUUID != sessionUUID.String() {
		return nil, fmt.Errorf("UUID mismatch: log_id contains %s but session has %s", sessionUUID.String(), storedUUID)
	}

	// Check timing file is writable (not completed — finalize() sets 0440)
	timingPath := filepath.Join(sessionDir, "timing")
	timingInfo, err := os.Stat(timingPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat timing file: %w", err)
	}
	if timingInfo.Mode().Perm()&0200 == 0 {
		return nil, fmt.Errorf("session already completed (timing file is read-only)")
	}

	// Reject compressed restarts — complexity of resuming mid-gzip-stream not worth it
	if cfg.Compress {
		return nil, fmt.Errorf("restart not supported for compressed sessions")
	}

	// Open timing file in append mode
	timingFile, err := os.OpenFile(timingPath, os.O_APPEND|os.O_WRONLY, os.FileMode(cfg.FilePermissions))
	if err != nil {
		return nil, fmt.Errorf("failed to open timing file for restart: %w", err)
	}

	// Open log.json for reading existing metadata and subsequent updates
	logJSONPath := filepath.Join(sessionDir, "log.json")
	logJSONFile, err := os.OpenFile(logJSONPath, os.O_RDWR, os.FileMode(cfg.FilePermissions))
	if err != nil {
		timingFile.Close()
		return nil, fmt.Errorf("failed to open log.json for restart: %w", err)
	}

	// Read existing metadata
	logMeta := make(map[string]interface{})
	decoder := json.NewDecoder(logJSONFile)
	if err := decoder.Decode(&logMeta); err != nil {
		timingFile.Close()
		logJSONFile.Close()
		return nil, fmt.Errorf("failed to read existing log.json: %w", err)
	}

	// Open I/O stream files in append mode
	files := make(map[string]*os.File)
	for streamName, streamInfo := range streamMap {
		filePath := filepath.Join(sessionDir, streamInfo.filename)
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, os.FileMode(cfg.FilePermissions))
		if err != nil {
			// Clean up already opened files
			for _, openFile := range files {
				openFile.Close()
			}
			timingFile.Close()
			logJSONFile.Close()
			return nil, fmt.Errorf("failed to open stream file %s for restart: %w", streamName, err)
		}
		files[streamName] = f
	}

	// Restore cumulative delay from resume_point
	cumulativeDelay := make(map[string]time.Duration)
	if resumePoint := restartMsg.GetResumePoint(); resumePoint != nil {
		dur := time.Duration(resumePoint.TvSec)*time.Second + time.Duration(resumePoint.TvNsec)*time.Nanosecond
		// Apply to all streams as a starting point
		for streamName := range streamMap {
			cumulativeDelay[streamName] = dur
		}
	}

	session := &Session{
		logID:           restartMsg.GetLogId(),
		sessionUUID:     sessionUUID,
		config:          cfg,
		sessionDir:      sessionDir,
		files:           files,
		gzipWriters:     make(map[string]*gzip.Writer), // empty — no compression for restart
		cumulativeDelay: cumulativeDelay,
		logMeta:         logMeta,
		timingFile:      timingFile,
		logJSONFile:     logJSONFile,
		isInitialized:   true, // Already initialized from existing session
	}

	// Initialize password filter if enabled
	if cfg.PasswordFilter {
		session.passwordFilter = NewPasswordFilter()
	}

	// Record restart event in log.json
	restarts, _ := logMeta["restarts"].([]interface{})
	restartEntry := map[string]interface{}{
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	}
	if resumePoint := restartMsg.GetResumePoint(); resumePoint != nil {
		restartEntry["resume_point_sec"] = resumePoint.TvSec
		restartEntry["resume_point_nsec"] = resumePoint.TvNsec
	}
	restarts = append(restarts, restartEntry)
	session.logMeta["restarts"] = restarts

	if err := session.updateLogJSON(); err != nil {
		slog.Error("Failed to record restart event in log.json", "log_id", session.logID, "error", err)
	}

	slog.Info("Resumed session via RestartMessage", "log_id", session.logID, "session_dir", sessionDir)
	return session, nil
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
