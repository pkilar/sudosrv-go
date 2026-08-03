// SPDX-License-Identifier: Apache-2.0
// Filename: internal/storage/session.go

//go:build unix

package storage

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	"sudosrv/internal/sessions"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// commitPointInterval matches C sudo_logsrvd's ACK_FREQUENCY (10 seconds).
// Commit points are only sent when this interval has elapsed since the last one.
const commitPointInterval = 10 * time.Second

// Session handles saving I/O logs for one session to the local filesystem.
//
// Lock ordering (must be observed by any code added later):
//
//	fileMux  → passwordFilter.mu
//
// HandleClientMessage acquires fileMux and may then call into passwordFilter
// methods (CheckOutput/FilterInput) which take passwordFilter.mu internally.
// Acquiring locks in the reverse order will deadlock.
type Session struct {
	logID       string
	sessionUUID uuid.UUID
	config      *config.LocalStorageConfig
	sessionDir  string
	// root pins sessionDir; all session file I/O is resolved relative to it.
	// Closed by Close() after every file handle inside it. See openSessionRoot.
	root        *os.Root
	files       map[string]*os.File
	gzipWriters map[string]*gzip.Writer // Gzip writers for compressed streams
	timingFile  *os.File
	// cumulativeDelay is a SINGLE counter summed across every I/O, winsize, and
	// suspend delay — mirroring C sudo_logsrvd's one closure->elapsed_time. Every
	// commit_point (periodic and the final one on Exit) reports this value, which
	// is exactly what the client compares against its own global elapsed time
	// before leaving the CLOSING state. A per-stream value would never satisfy
	// the client's committed==elapsed equality for multi-stream sessions.
	cumulativeDelay time.Duration
	logMeta         map[string]any
	passwordFilter  *PasswordFilter // Password filtering for security
	lastCommitTime  time.Time       // Tracks when last commit point was sent
	fileMux         sync.Mutex
	closeOnce       sync.Once
	isInitialized   bool
	// Live stats exposed to the management API. Each counter is an independent
	// atomic, so a reader may observe an incoherent triple (e.g. msgCount
	// incremented but bytesReceived not yet, or lastActivity stale by one
	// message). Eventual consistency is acceptable for an admin UI; do not
	// rely on these for correctness checks.
	msgCount      atomic.Int64
	bytesReceived atomic.Int64
	lastActivity  atomic.Pointer[time.Time]
}

// Compile-time check that Session satisfies the sessions.MetadataProvider
// contract consumed by the management API.
var _ sessions.MetadataProvider = (*Session)(nil)

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

// preCreateStreams lists I/O streams that are created at session initialization.
// stdin and ttyin are created on-demand when data arrives, matching C sudo_logsrvd behavior.
var preCreateStreams = map[string]bool{
	"stdout": true, "stderr": true, "ttyout": true,
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

// seqMutexMap holds per-directory mutexes for sequence file access to reduce
// contention. Entries are never removed because the set of distinct log
// directories is expected to be small and stable (typically one per
// iolog_dir template). If the deployment creates directories dynamically
// at a high rate, this map will grow unboundedly; in that scenario consider
// adding an eviction policy.
var seqMutexMap = make(map[string]*sync.Mutex)
var seqMutexMapLock sync.RWMutex

const alphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Fixed file names inside a session directory. Every session file operation
// goes through Session.root / EventSession.root, so these are single-component
// names resolved relative to that root — never joined into a full path.
const (
	fileUUID    = "uuid"
	fileLog     = "log"
	fileLogJSON = "log.json"
	fileTiming  = "timing"
	// tmp sibling used for the atomic log.json replace.
	fileLogJSONTmp = fileLogJSON + ".tmp"
)

// openSessionRoot pins dir as an os.Root. Every file operation in the session
// resolves relative to the returned directory descriptor, which supplies two
// guarantees the session's on-disk integrity depends on:
//
//   - Symlinks are refused at every path component, so a symlink pre-planted
//     inside a predictable session directory cannot redirect a write.
//   - Resolution is bound to the descriptor, not to the path string. Renaming or
//     swapping any component of dir after the root is open cannot redirect a
//     later write, closing the TOCTOU window between creating the session
//     directory and opening the files inside it.
//
// A symlinked directory ABOVE dir is not covered: os.OpenRoot resolves the root
// path itself, and the os.MkdirAll that creates dir is a plain path-based call.
//
// On Linux the kernel enforces this via openat2(RESOLVE_BENEATH).
func openSessionRoot(dir string) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to pin session directory %s: %w", dir, err)
	}
	return root, nil
}

// sanitizePathComponent replaces forward slashes in user-controlled path values
// with underscores, preventing path traversal via escape-sequence expansion
// while matching C sudo_logsrvd's strlcpy_no_slash() (lib/iolog/iolog_path.c),
// which maps '/' to '_'. This both blocks traversal and produces the same
// on-disk component a C server would (e.g. a submituser "a/b" -> "a_b").
func sanitizePathComponent(s string) string {
	return strings.ReplaceAll(s, "/", "_")
}

// sanitizeLogSummaryField makes a client-supplied value safe for the plaintext
// `log` summary file, whose first line is colon-delimited and whose records are
// newline-delimited. Control characters (including CR/LF) are replaced with '?'
// so a hostile client cannot split a record or forge additional ones, and ':'
// is replaced with '_' in colon-delimited fields so field boundaries cannot be
// shifted. log.json is unaffected — JSON encoding already escapes these.
func sanitizeLogSummaryField(s string, colonDelimited bool) string {
	return strings.Map(func(r rune) rune {
		switch {
		case colonDelimited && r == ':':
			return '_'
		case r < 0x20 || r == 0x7f:
			return '?'
		default:
			return r
		}
	}, s)
}

// strftimeExpand expands C strftime-style "%X" date/time escapes against t,
// matching the strftime pass C sudo applies to an iolog path after %{...}
// expansion (lib/iolog/iolog_path.c). "%%" collapses to a literal "%". Only the
// common atomic codes are supported; codes that would introduce a path
// separator or control character (e.g. %D, %F, %T, %n, %t) and any unrecognized
// code are copied through verbatim, so an unknown escape can never inject a "/"
// into a path component.
func strftimeExpand(s string, t time.Time) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch c := s[i]; c {
		case '%':
			b.WriteByte('%')
		case 'Y':
			b.WriteString(t.Format("2006"))
		case 'y':
			b.WriteString(t.Format("06"))
		case 'C':
			fmt.Fprintf(&b, "%02d", t.Year()/100)
		case 'm':
			b.WriteString(t.Format("01"))
		case 'd':
			b.WriteString(t.Format("02"))
		case 'e':
			fmt.Fprintf(&b, "%2d", t.Day())
		case 'H':
			b.WriteString(t.Format("15"))
		case 'I':
			b.WriteString(t.Format("03"))
		case 'M':
			b.WriteString(t.Format("04"))
		case 'S':
			b.WriteString(t.Format("05"))
		case 'p':
			b.WriteString(t.Format("PM"))
		case 'A':
			b.WriteString(t.Format("Monday"))
		case 'a':
			b.WriteString(t.Format("Mon"))
		case 'B':
			b.WriteString(t.Format("January"))
		case 'b', 'h':
			b.WriteString(t.Format("Jan"))
		case 'j':
			fmt.Fprintf(&b, "%03d", t.YearDay())
		case 'u': // ISO weekday, 1=Mon .. 7=Sun
			if wd := int(t.Weekday()); wd == 0 {
				b.WriteByte('7')
			} else {
				b.WriteString(strconv.Itoa(wd))
			}
		case 'w': // weekday, 0=Sun .. 6=Sat
			b.WriteString(strconv.Itoa(int(t.Weekday())))
		default:
			// Unknown / unsupported code: copy verbatim (never expands to a
			// path separator), matching glibc's pass-through for unknown codes.
			b.WriteByte('%')
			b.WriteByte(c)
		}
	}
	return b.String()
}

// writeSessionFileAt is a replacement for os.WriteFile used for files that a
// session creates at startup. It truncates a pre-existing file rather than
// refusing it, matching C sudo_logsrvd, which opens `uuid` with
// O_CREAT|O_TRUNC|O_WRONLY (logsrvd/iolog_writer.c:717) and `log`/`log.json`
// the same way (lib/iolog/iolog_loginfo.c:106,183). Do NOT reintroduce O_EXCL:
// a re-used session directory (iolog_file without a uniquifier, a lost or
// restored seq file, or seq wrapping at maxseq) would then fail with EEXIST,
// which reaches the client as "Internal Server Error" and — because sudoers
// defaults ignore_iolog_errors to false — makes sudo kill the user's running
// privileged command. Conformance: docs/logsrvd-reference/ IOLOG-049.
//
// Symlink safety does not depend on O_EXCL: it comes from root, which refuses
// to traverse a symlink at any component (see openSessionRoot).
func writeSessionFileAt(root *os.Root, name string, data []byte, perm os.FileMode) (err error) {
	f, err := openSessionFileAt(root, name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	_, err = f.Write(data)
	return err
}

// openSessionFileAt opens a session file through root, restoring the owner
// write bit and retrying once if the open is refused with EACCES.
//
// This is the Go equivalent of C's iolog_openat (lib/iolog/iolog_openat.c:58-67),
// through which sudo_logsrvd routes every session file — uuid
// (logsrvd/iolog_writer.c:717), log and log.json (lib/iolog/iolog_loginfo.c:
// 106,183), and timing plus every stream via iolog_open
// (lib/iolog/iolog_open.c:83). On EACCES it stats the file and, if the write
// bits implied by iolog_filemode are missing, fchmodat()s them back and repeats
// the open.
//
// Without this, dropping O_EXCL (IOLOG-049) only half-fixes directory re-use.
// finalize() chmods `timing` to 0440 to mark the session complete, exactly as C
// does (logsrvd/logsrvd_local.c:427-431), so every NORMALLY COMPLETED session
// leaves a read-only timing file behind. A later session landing on that
// directory then gets EACCES from the O_TRUNC open instead of the old EEXIST —
// the same fatal accept, the same "Internal Server Error" to the client, and
// (ignore_iolog_errors defaulting to false) the same SIGKILL of the user's
// already-running privileged command. Re-use after a *completed* session is the
// common case; the aborted-session case that leaves timing writable is the rare
// one.
//
// Only the owner write bit is restored, and only on a file that already exists
// inside the pinned root. Symlink containment is unaffected: root refuses to
// traverse a symlink at any component, so both the Stat and the Chmod resolve to
// the same contained regular file the open just refused. C's second fallback —
// retrying as iolog_uid/iolog_gid for NFS — has no analogue here and is
// deliberately not emulated.
func openSessionFileAt(root *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := root.OpenFile(name, flag, perm)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return f, err
	}

	info, statErr := root.Stat(name)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0200 != 0 {
		// Not the missing-write-bit case: report the original open error.
		return nil, err
	}
	if chmodErr := root.Chmod(name, info.Mode().Perm()|0200); chmodErr != nil {
		return nil, err
	}
	slog.Debug("Restored write bit on a read-only session file from a previous session",
		"file", name, "previous_mode", info.Mode().Perm())

	f, retryErr := root.OpenFile(name, flag, perm)
	if retryErr != nil {
		return nil, retryErr
	}
	// Put the intended mode back; the restore above was only to get the fd.
	if chmodErr := root.Chmod(name, perm); chmodErr != nil {
		slog.Warn("Failed to reset mode on a re-used session file", "file", name, "error", chmodErr)
	}
	return f, nil
}

// containsDotDot checks whether a path contains a ".." component,
// matching C sudo_logsrvd's contains_dot_dot() check.
func containsDotDot(path string) bool {
	for seg := range strings.SplitSeq(filepath.ToSlash(path), "/") {
		if seg == ".." {
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

	// The directory is created before log_id is derived: an mkdtemp template
	// makes createSessionDir return a different path than buildSessionPath
	// produced, and log_id must name the directory that really exists. C does
	// the same, setting evlog->iolog_path from the buffer iolog_mkpath rewrote
	// (logsrvd/iolog_writer.c:622-630).
	sessionDir, err = createSessionDir(sessionDir, os.FileMode(cfg.DirPermissions))
	if err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	// Compute relative path for log_id generation (matches C sudo_logsrvd behavior).
	relativePath := deriveLogIDRelativePath(cfg.LogDirectory, sessionDir)
	logID := generateLogID(sessionUUID, relativePath)

	slog.Debug("Resolved session log path", "log_id", logID, "path", sessionDir)
	root, err := openSessionRoot(sessionDir)
	if err != nil {
		return nil, err
	}

	session := &Session{
		logID:       logID,
		sessionUUID: sessionUUID,
		config:      cfg,
		sessionDir:  sessionDir,
		root:        root,
		files:       make(map[string]*os.File),
		gzipWriters: make(map[string]*gzip.Writer),
		logMeta:     make(map[string]any),
	}

	// Initialize password filter if enabled
	if cfg.PasswordFilter {
		session.passwordFilter = NewPasswordFilter()
		slog.Debug("Password filtering enabled for session", "log_id", logID)
	}

	return session, nil
}

// EventSession persists accepted commands that do not have I/O buffers. These
// commands still need an audit record and final exit status, but they should not
// create sudoreplay stream/timing files.
type EventSession struct {
	logID      string
	config     *config.LocalStorageConfig
	sessionDir string
	// root pins sessionDir; see Session.root and openSessionRoot.
	root      *os.Root
	logMeta   map[string]any
	closeOnce sync.Once
	// Live stats exposed to the management API. Same eventual-consistency
	// contract as Session: each counter is an independent atomic and an API
	// reader may observe an incoherent triple. Do not use for correctness.
	msgCount      atomic.Int64
	bytesReceived atomic.Int64
	lastActivity  atomic.Pointer[time.Time]
}

// Compile-time check that EventSession satisfies sessions.MetadataProvider.
var _ sessions.MetadataProvider = (*EventSession)(nil)

// NewEventSession creates a local metadata-only session for an accepted command
// where ExpectIobufs is false.
func NewEventSession(sessionUUID uuid.UUID, acceptMsg *pb.AcceptMessage, cfg *config.LocalStorageConfig) (_ *EventSession, retErr error) {
	sessionDir, err := buildSessionPath(sessionUUID, cfg, acceptMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to build event session path: %w", err)
	}
	// Create the directory before deriving log_id; see NewSession for why the
	// order matters when iolog_file is an mkdtemp template.
	sessionDir, err = createSessionDir(sessionDir, os.FileMode(cfg.DirPermissions))
	if err != nil {
		return nil, fmt.Errorf("failed to create event session directory: %w", err)
	}
	relativePath := deriveLogIDRelativePath(cfg.LogDirectory, sessionDir)
	logID := generateLogID(sessionUUID, relativePath)

	root, err := openSessionRoot(sessionDir)
	if err != nil {
		return nil, err
	}
	// The caller only gets a session it can Close() on the success path, so any
	// failure below has to release the root descriptor here.
	defer func() {
		if retErr != nil {
			_ = root.Close() // constructor failed; retErr is what the caller needs
		}
	}()

	event := &EventSession{
		logID:      logID,
		config:     cfg,
		sessionDir: sessionDir,
		root:       root,
		logMeta:    make(map[string]any),
	}
	maps.Copy(event.logMeta, protocol.InfoMsgsToMap(acceptMsg.GetInfoMsgs()))
	event.logMeta["event_type"] = "accept"
	event.logMeta["server_log_id"] = logID
	event.logMeta["expect_iobufs"] = false
	if acceptMsg.SubmitTime == nil {
		return nil, fmt.Errorf("AcceptMessage missing required submit_time")
	}
	submitTime := time.Unix(acceptMsg.SubmitTime.TvSec, int64(acceptMsg.SubmitTime.TvNsec))
	event.logMeta["submit_time"] = submitTime.UTC().Format(time.RFC3339Nano)

	if err := writeSessionFileAt(root, fileUUID, []byte(sessionUUID.String()+"\n"), os.FileMode(cfg.FilePermissions)); err != nil {
		return nil, fmt.Errorf("failed to write event uuid file: %w", err)
	}
	if err := event.updateLogJSON(); err != nil {
		return nil, fmt.Errorf("failed to write event log.json: %w", err)
	}

	slog.Info("Started local event-only session", "log_id", logID, "path", sessionDir)
	return event, nil
}

// LogID returns the base64-encoded sudo log_id assigned when the event session
// was created. It is stable for the lifetime of the session.
func (s *EventSession) LogID() string { return s.logID }

// LiveStats returns a snapshot of mutable counters for the management API.
func (s *EventSession) LiveStats() sessions.LiveStats {
	stats := sessions.LiveStats{
		MessagesReceived: s.msgCount.Load(),
		BytesReceived:    s.bytesReceived.Load(),
		SessionDir:       s.sessionDir,
	}
	if t := s.lastActivity.Load(); t != nil {
		stats.LastActivity = *t
	}
	return stats
}

func (s *EventSession) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	s.msgCount.Add(1)
	s.bytesReceived.Add(int64(proto.Size(msg)))
	now := time.Now()
	s.lastActivity.Store(&now)
	switch event := msg.Type.(type) {
	case *pb.ClientMessage_ExitMsg:
		s.finalize(event.ExitMsg)
		return nil, nil
	case *pb.ClientMessage_AlertMsg:
		alert := map[string]any{"reason": event.AlertMsg.GetReason()}
		if alertTime := event.AlertMsg.GetAlertTime(); alertTime != nil {
			alert["alert_time"] = time.Unix(alertTime.TvSec, int64(alertTime.TvNsec)).UTC().Format(time.RFC3339Nano)
		}
		if info := protocol.InfoMsgsToMap(event.AlertMsg.GetInfoMsgs()); len(info) > 0 {
			alert["info"] = info
		}
		alerts, _ := s.logMeta["alerts"].([]any)
		alerts = append(alerts, alert)
		s.logMeta["alerts"] = alerts
		return nil, s.updateLogJSON()
	case *pb.ClientMessage_AcceptMsg:
		entry := map[string]any{"event_type": "accept"}
		if st := event.AcceptMsg.GetSubmitTime(); st != nil {
			entry["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
		}
		mergePreservingExisting(entry, protocol.InfoMsgsToMap(event.AcceptMsg.GetInfoMsgs()))
		subCmds, _ := s.logMeta["sub_commands"].([]any)
		subCmds = append(subCmds, entry)
		s.logMeta["sub_commands"] = subCmds
		return nil, s.updateLogJSON()
	case *pb.ClientMessage_RejectMsg:
		entry := map[string]any{
			"event_type": "reject",
			"reason":     event.RejectMsg.GetReason(),
		}
		if st := event.RejectMsg.GetSubmitTime(); st != nil {
			entry["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
		}
		mergePreservingExisting(entry, protocol.InfoMsgsToMap(event.RejectMsg.GetInfoMsgs()))
		subCmds, _ := s.logMeta["sub_commands"].([]any)
		subCmds = append(subCmds, entry)
		s.logMeta["sub_commands"] = subCmds
		return nil, s.updateLogJSON()
	default:
		return nil, fmt.Errorf("event-only session received unexpected message type %T", event)
	}
}

func (s *EventSession) Close() error {
	s.closeOnce.Do(func() {
		if err := s.root.Close(); err != nil {
			slog.Error("Failed to close event session directory handle", "log_id", s.logID, "error", err)
		}
		slog.Info("Closed local event-only session", "log_id", s.logID)
	})
	return nil
}

func (s *EventSession) finalize(exitMsg *pb.ExitMessage) {
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
	if exitMsg.GetSignal() != "" {
		s.logMeta["signal"] = exitMsg.GetSignal()
	}
	if exitMsg.GetDumpedCore() {
		s.logMeta["dumped_core"] = true
	}
	if err := s.updateLogJSON(); err != nil {
		slog.Error("Failed to update event-only log.json with final exit information", "log_id", s.logID, "error", err)
	}
}

func (s *EventSession) updateLogJSON() (err error) {
	data, err := json.MarshalIndent(s.logMeta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode JSON for event log.json: %w", err)
	}
	data = append(data, '\n')

	f, err := s.root.OpenFile(fileLogJSONTmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(s.config.FilePermissions))
	if err != nil {
		return fmt.Errorf("failed to open event log.json tempfile: %w", err)
	}
	defer func() {
		if err != nil {
			_ = s.root.Remove(fileLogJSONTmp) // best-effort cleanup on failure
		}
	}()

	if _, err = f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("failed to write event log.json tempfile: %w", err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to fsync event log.json tempfile: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("failed to close event log.json tempfile: %w", err)
	}
	if err = s.root.Rename(fileLogJSONTmp, fileLogJSON); err != nil {
		return fmt.Errorf("failed to rename event log.json tempfile into place: %w", err)
	}
	return nil
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

// mkdtempSuffixLen is the number of trailing 'X' characters that mark an
// expanded iolog path as an mkdtemp(3) template rather than a literal name.
const mkdtempSuffixLen = 6

// mkdtempAttempts bounds the retries on a name collision, standing in for the
// TMP_MAX loop inside libc's mkdtemp().
const mkdtempAttempts = 64

// createSessionDir creates the session directory and returns the path actually
// created, which is not necessarily the path passed in.
//
// If the last path component ends in six 'X' characters it is an mkdtemp(3)
// template, and the X's are replaced with random characters to make the
// directory unique. C sudo_logsrvd applies exactly this rule: every expanded
// iolog path goes through iolog_mkpath (logsrvd/iolog_writer.c:622), which
// dispatches to iolog_mkdtemp() instead of iolog_mkdirs() when the path ends in
// at least six X's (lib/iolog/iolog_mkpath.c:41-50). sudoers(5) documents the
// template as the way to make iolog_file unique without a shared seq file, so
// operators do configure it.
//
// Without this, the template is taken literally: every session on the server
// shares one directory named "XXXXXX" and each new session truncates the
// previous session's uuid, log, log.json, timing and I/O streams — silent loss
// of the audit trail. Do not replace this with a bare os.MkdirAll.
//
// Only the trailing six X's are substituted, matching mkdtemp(3): a template of
// "run-XXXXXXXX" keeps "run-XX" literally and randomizes the last six.
func createSessionDir(path string, perm os.FileMode) (string, error) {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, strings.Repeat("X", mkdtempSuffixLen)) {
		if err := os.MkdirAll(path, perm); err != nil {
			return "", err
		}
		return path, nil
	}

	// Intermediate directories are created first, as C's iolog_mkdtemp does via
	// sudo_open_parent_dir (lib/iolog/iolog_mkdtemp.c).
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, perm); err != nil {
		return "", err
	}
	prefix := base[:len(base)-mkdtempSuffixLen]
	for range mkdtempAttempts {
		suffix, err := randomAlphanumericString(mkdtempSuffixLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate unique directory suffix: %w", err)
		}
		candidate := filepath.Join(parent, prefix+suffix)
		// Mkdir is exclusive, so a losing racer simply retries with a new name.
		err = os.Mkdir(candidate, perm)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("failed to create unique directory for template %s after %d attempts", path, mkdtempAttempts)
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
			infoMap[key] = strconv.FormatInt(v.Numval, 10)
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
	epochStr := strconv.FormatInt(now.Unix(), 10)

	// Replacer for sudoers-style escape sequences.
	// User-controlled values are sanitized ("/" -> "_") to prevent traversal,
	// matching C sudo_logsrvd's strlcpy_no_slash() behavior.
	runuser := sanitizePathComponent(infoMap["runuser"])
	rungroup := sanitizePathComponent(infoMap["rungroup"])
	replacer := strings.NewReplacer(
		// User/Group escapes (sanitized — user-controlled)
		"%{user}", sanitizePathComponent(infoMap["submituser"]),
		"%{uid}", sanitizePathComponent(infoMap["submituid"]),
		"%{group}", sanitizePathComponent(infoMap["submitgroup"]),
		"%{gid}", sanitizePathComponent(infoMap["submitgid"]),
		"%{runuser}", runuser,
		"%{runuid}", sanitizePathComponent(infoMap["runuid"]),
		"%{rungroup}", rungroup,
		"%{rungid}", sanitizePathComponent(infoMap["rungid"]),
		// Canonical sudo names for the run-as identity (lib/iolog/iolog_path.c:
		// fill_runas_user / fill_runas_group). Aliased to the same values so a
		// template copied from a C sudoers config expands identically.
		"%{runas_user}", runuser,
		"%{runas_group}", rungroup,
		// Host/Command escapes (sanitized — user-controlled)
		"%{hostname}", sanitizePathComponent(infoMap["submithost"]),
		"%{command_path}", sanitizePathComponent(infoMap["command"]),
		"%{command}", sanitizePathComponent(filepath.Base(infoMap["command"])),
		// Sequence and Random escapes (server-generated, safe)
		"%{seq}", seq,
		"%{rand}", randStr,
		// Time/Date escapes (server-generated, safe) — Go brace-style extensions
		"%{year}", fmt.Sprintf("%04d", now.Year()),
		"%{month}", fmt.Sprintf("%02d", now.Month()),
		"%{day}", fmt.Sprintf("%02d", now.Day()),
		"%{hour}", fmt.Sprintf("%02d", now.Hour()),
		"%{minute}", fmt.Sprintf("%02d", now.Minute()),
		"%{second}", fmt.Sprintf("%02d", now.Second()),
		"%{epoch}", epochStr,
		// Path escapes
		"%{LIVEDIR}", cfg.LogDirectory,
		// NOTE: literal "%%" and bare strftime "%X" codes are handled by
		// strftimeExpand below (after brace expansion), matching C's model.
	)

	iologDir := replacer.Replace(cfg.IologDir)
	iologFile := replacer.Replace(cfg.IologFile)

	// After %{...} expansion, apply C-style strftime over the path for bare
	// "%X" date/time codes and to collapse "%%" -> "%". C sudo runs strftime on
	// the whole iolog path (lib/iolog/iolog_path.c), so a template using the
	// standard sudo date escapes (e.g. "%Y-%m-%d") expands the same way here.
	iologDir = strftimeExpand(iologDir, now)
	iologFile = strftimeExpand(iologFile, now)

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

// mergePreservingExisting copies keys from src into dst that are not already
// present in dst. Used wherever client-supplied InfoMsgs are merged into a
// sub-command event entry — the authoritative fields (event_type, reason,
// submit_time) must never be clobbered by a client-controlled key collision.
func mergePreservingExisting(dst, src map[string]any) {
	for k, v := range src {
		if _, exists := dst[k]; exists {
			continue
		}
		dst[k] = v
	}
}

// readLogJSON opens, decodes, and closes a log.json file. Keeping the file
// handle scoped to this helper prevents the double-close hazard that arose
// when the decode-then-close sequence was inlined into a restart path with
// multiple downstream error returns.
func readLogJSONAt(root *os.Root, name string) (map[string]any, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open log.json for restart: %w", err)
	}
	defer f.Close()

	logMeta := make(map[string]any)
	if err := json.NewDecoder(f).Decode(&logMeta); err != nil {
		return nil, fmt.Errorf("failed to read existing log.json: %w", err)
	}
	return logMeta, nil
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
	// f.Close releases the flock implicitly on Linux/BSD — no explicit
	// LOCK_UN defer needed. (Pairing one with the file-Close defer would
	// run LOCK_UN first under LIFO ordering, which is harmless today but a
	// footgun if the close path is ever wrapped or replaced.)
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("could not lock sequence file: %w", err)
	}

	// Get file info to check size
	stat, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("could not stat sequence file: %w", err)
	}

	var currentSeq uint32
	if size := stat.Size(); size > 0 {
		raw := make([]byte, size)
		if _, err := f.ReadAt(raw, 0); err != nil && err != io.EOF {
			return "", fmt.Errorf("could not read sequence file: %w", err)
		}
		currentSeq, err = parseSeqFile(raw)
		if err != nil {
			return "", fmt.Errorf("could not parse sequence file %s: %w", seqFile, err)
		}
	}

	// Sequence numbers are encoded as 6-char base36 strings; 36^6 = 2,176,782,336
	// is the maximum representable. Beyond that we'd silently truncate via the
	// modulo loop and collide with earlier sequences, corrupting session
	// uniqueness. Fail loudly instead.
	const maxSeq uint32 = 36 * 36 * 36 * 36 * 36 * 36
	if currentSeq >= maxSeq-1 {
		return "", fmt.Errorf("sequence space exhausted at %d (max %d); rotate %s to recover",
			currentSeq, maxSeq-1, seqFile)
	}
	nextSeq := currentSeq + 1

	// Write the new sequence back as ASCII base36 text (6 chars + newline),
	// matching C sudo's on-disk seq format (lib/iolog/iolog_nextid.c) so a C
	// sudo_logsrvd and this server can interoperate on a shared iolog tree.
	data := formatSeqFile(nextSeq)
	if _, err := f.WriteAt(data, 0); err != nil {
		return "", fmt.Errorf("could not write to sequence file: %w", err)
	}
	// Truncate to the exact ASCII length so migrating from the shorter legacy
	// binary format leaves no stale trailing bytes.
	if err := f.Truncate(int64(len(data))); err != nil {
		return "", fmt.Errorf("could not truncate sequence file: %w", err)
	}

	// Ensure the write is flushed to disk
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("could not sync sequence file: %w", err)
	}

	// Convert the number to a 6-character, zero-padded base36 string using the
	// UPPERCASE alphabet C sudo uses (lib/iolog/iolog_nextid.c:57), then split it
	// into the XX/XX/XX directory hierarchy C's fill_seq emits
	// (logsrvd/iolog_writer.c:469). sudoreplay resolves a session by building
	// session_dir/%.2s/%.2s/%.2s from the 6-char id (sudoreplay.c:327), so the
	// on-disk layout must use this split form, not a flat 6-char directory.
	const base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var raw [6]byte
	val := nextSeq
	for i := 5; i >= 0; i-- {
		raw[i] = base36[val%36]
		val /= 36
	}

	return fmt.Sprintf("%c%c/%c%c/%c%c", raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]), nil
}

// parseSeqFile decodes the on-disk sequence counter. The canonical format
// (matching C sudo's iolog_nextid) is ASCII base36 text, optionally followed by
// a newline/NUL. Older Go servers wrote a 4-byte big-endian uint32, so we fall
// back to that when the bytes are not valid base36 text — this migrates the
// counter in place on the next write instead of resetting it (a reset could
// collide new sessions with existing on-disk session directories).
func parseSeqFile(raw []byte) (uint32, error) {
	if s := strings.Trim(string(raw), "\x00\n\r \t"); s != "" {
		if v, err := strconv.ParseUint(s, 36, 32); err == nil {
			return uint32(v), nil
		}
	}
	if len(raw) >= 4 {
		return binary.BigEndian.Uint32(raw[:4]), nil
	}
	return 0, fmt.Errorf("unrecognized sequence file content (%d bytes)", len(raw))
}

// formatSeqFile renders the sequence counter in C sudo's on-disk format: six
// uppercase base36 digits followed by a newline (7 bytes total).
func formatSeqFile(seq uint32) []byte {
	const base36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	buf := make([]byte, 7)
	v := seq
	for i := 5; i >= 0; i-- {
		buf[i] = base36[v%36]
		v /= 36
	}
	buf[6] = '\n'
	return buf
}

// LogID returns the base64-encoded sudo log_id assigned when the session was
// created. It is stable for the lifetime of the session.
func (s *Session) LogID() string { return s.logID }

// LiveStats returns a snapshot of mutable counters for the management API.
// Counters are read with atomic loads; this method does not contend with the
// file-write fileMux.
func (s *Session) LiveStats() sessions.LiveStats {
	stats := sessions.LiveStats{
		MessagesReceived: s.msgCount.Load(),
		BytesReceived:    s.bytesReceived.Load(),
		SessionDir:       s.sessionDir,
	}
	if t := s.lastActivity.Load(); t != nil {
		stats.LastActivity = *t
	}
	return stats
}

// recordActivity updates the live counters used by the management API. Called
// from HandleClientMessage on every message.
func (s *Session) recordActivity(msg *pb.ClientMessage) {
	s.msgCount.Add(1)
	s.bytesReceived.Add(int64(proto.Size(msg)))
	now := time.Now()
	s.lastActivity.Store(&now)
}

// HandleClientMessage processes a message from the client.
func (s *Session) HandleClientMessage(msg *pb.ClientMessage) (*pb.ServerMessage, error) {
	s.recordActivity(msg)
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
		// Send a FINAL commit_point carrying the full cumulative elapsed time,
		// matching C sudo_logsrvd's handle_exit (it schedules an immediate commit
		// event before closing). The stock client enters CLOSING after Exit and
		// blocks until it receives a commit_point where committed==elapsed; without
		// this the client stalls log_server_timeout (default 30s) and warns.
		final := s.commitPointMsg()
		s.finalize(event.ExitMsg)
		return final, nil
	default:
		slog.Warn("Local storage session received unhandled message type", "type", fmt.Sprintf("%T", event))
		return nil, nil // Ignore unhandled
	}
}

// initialize sets up all the files for the session log.
func (s *Session) initialize(acceptMsg *pb.AcceptMessage) (retErr error) {
	// Clean up partially-opened files if initialization fails
	defer func() {
		if retErr != nil {
			for _, gzWriter := range s.gzipWriters {
				_ = gzWriter.Close()
			}
			for _, f := range s.files {
				f.Close()
			}
			if s.timingFile != nil {
				s.timingFile.Close()
				s.timingFile = nil
			}
			s.files = make(map[string]*os.File)
			s.gzipWriters = make(map[string]*gzip.Writer)
		}
	}()

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
			value = strconv.FormatInt(v.Numval, 10)
			s.logMeta[key] = v.Numval
		case *pb.InfoMessage_Strlistval:
			value = strings.Join(v.Strlistval.Strings, " ")
			s.logMeta[key] = v.Strlistval.Strings
		}
		infoMap[key] = value
		slog.Debug("Received InfoMessage", "key", key, "value", value)
	}
	slog.Debug("--- End AcceptMessage InfoMsgs ---")

	// Apply defaults for absent optional fields, matching C sudo_logsrvd behavior.
	for _, field := range []string{"submitcwd", "submitgroup", "ttyname"} {
		if infoMap[field] == "" {
			infoMap[field] = "unknown"
			s.logMeta[field] = "unknown"
		}
	}

	s.logMeta["server_log_id"] = s.logID // Add our own server-side log ID for reference
	if acceptMsg.SubmitTime == nil {
		return fmt.Errorf("AcceptMessage missing required submit_time")
	}
	submitTime := time.Unix(acceptMsg.SubmitTime.TvSec, int64(acceptMsg.SubmitTime.TvNsec))
	s.logMeta["submit_time"] = submitTime.UTC().Format(time.RFC3339Nano)
	// `timestamp` is the session's START time and must be recorded HERE, at
	// accept, from the client's submit_time -- not stamped at exit. sudoreplay -l
	// displays it as the session start and filters fromdate/todate on it, so a
	// value taken at exit reports every session as starting when it ended, and a
	// session that never exits gets none at all and lists as "Dec 31 1969".
	// C takes it from the client's event_time (lib/eventlog/eventlog.c:943).
	// Conformance: docs/logsrvd-reference/ IOLOG-024.
	s.logMeta["timestamp"] = struct {
		Seconds     int64 `json:"seconds"`
		Nanoseconds int32 `json:"nanoseconds"`
	}{
		Seconds:     acceptMsg.SubmitTime.TvSec,
		Nanoseconds: acceptMsg.SubmitTime.TvNsec,
	}

	// --- Write the UUID file (matches C sudo_logsrvd's iolog_store_uuid) ---
	// A pre-existing file is truncated, not refused (see writeSessionFileAt).
	// s.root refuses to traverse a symlink at any component, which is what
	// defends against a local attacker pre-planting a symlink inside a
	// predictable sessionDir.
	if err := writeSessionFileAt(s.root, fileUUID, []byte(s.sessionUUID.String()+"\n"), os.FileMode(s.config.FilePermissions)); err != nil {
		return fmt.Errorf("failed to write uuid file: %w", err)
	}
	slog.Debug("Created UUID file", "log_id", s.logID, "path", filepath.Join(s.sessionDir, fileUUID))

	// --- Write the plain text `log` file ---
	summaryLine := fmt.Sprintf("%d:%s:%s:%s:%s:%s:%s\n%s\n%s\n",
		submitTime.Unix(),
		sanitizeLogSummaryField(infoMap["submituser"], true),
		sanitizeLogSummaryField(infoMap["runuser"], true),
		sanitizeLogSummaryField(infoMap["rungroup"], true),
		sanitizeLogSummaryField(infoMap["ttyname"], true),
		sanitizeLogSummaryField(infoMap["lines"], true),
		sanitizeLogSummaryField(infoMap["columns"], true),
		sanitizeLogSummaryField(infoMap["submitcwd"], false),
		sanitizeLogSummaryField(infoMap["command"], false),
	)
	if err := writeSessionFileAt(s.root, fileLog, []byte(summaryLine), os.FileMode(s.config.FilePermissions)); err != nil {
		return fmt.Errorf("failed to create 'log' summary file: %w", err)
	}
	slog.Debug("Created log summary file", "log_id", s.logID, "path", filepath.Join(s.sessionDir, fileLog))

	// --- Create timing and I/O stream files and initialize log.json ---
	var err error
	// O_TRUNC, not O_EXCL: C opens timing in mode "w", i.e. O_CREAT|O_TRUNC
	// (lib/iolog/iolog_open.c:61 via iolog_create, logsrvd/iolog_writer.c:658),
	// so a re-used session directory is overwritten rather than rejected. With
	// O_EXCL the second session on a re-used path failed, the client saw
	// "Internal Server Error" and killed the user's privileged command.
	//
	// And openSessionFileAt rather than root.OpenFile, because O_TRUNC alone is
	// not enough here: finalize() leaves this file 0440 on every completed
	// session, so the O_TRUNC open of a re-used directory fails EACCES instead.
	// C restores the write bit and retries (lib/iolog/iolog_openat.c:58-67).
	// Conformance: docs/logsrvd-reference/ IOLOG-049.
	s.timingFile, err = openSessionFileAt(s.root, fileTiming, os.O_APPEND|os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(s.config.FilePermissions))
	if err != nil {
		return err
	}
	slog.Debug("Opened timing file for session", "log_id", s.logID, "path", filepath.Join(s.sessionDir, fileTiming))

	// Write initial metadata to log.json
	if err := s.updateLogJSON(); err != nil {
		return fmt.Errorf("failed to write initial metadata to log.json: %w", err)
	}

	// Create pre-initialized I/O stream files (stdout, stderr, ttyout).
	// stdin and ttyin are created on-demand when data arrives, matching C sudo_logsrvd.
	for streamName := range preCreateStreams {
		if err := s.ensureStreamFile(streamName); err != nil {
			return err
		}
	}
	return nil
}

// ensureStreamFile creates the I/O stream file if it doesn't already exist.
// This supports on-demand creation for stdin/ttyin, matching C sudo_logsrvd behavior.
func (s *Session) ensureStreamFile(streamName string) error {
	if _, exists := s.files[streamName]; exists {
		return nil
	}
	streamInfo, ok := streamMap[streamName]
	if !ok {
		return fmt.Errorf("unknown stream name: %s", streamName)
	}
	// O_TRUNC, not O_EXCL — same reason as the timing file above: C's iolog_open
	// mode "w" is O_CREAT|O_TRUNC (lib/iolog/iolog_open.c:61), so a stale stream
	// left behind in a re-used directory is truncated, not treated as a fatal
	// error. openSessionFileAt for the same reason as timing: C routes the
	// streams through iolog_openat too (iolog_open.c:83), so a stale read-only
	// stream is made writable and truncated, not treated as fatal.
	// Conformance: docs/logsrvd-reference/ IOLOG-049.
	f, err := openSessionFileAt(s.root, streamInfo.filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(s.config.FilePermissions))
	if err != nil {
		return err
	}
	slog.Debug("Created IO stream file", "log_id", s.logID, "stream", streamName,
		"path", filepath.Join(s.sessionDir, streamInfo.filename), "compressed", s.config.Compress)
	s.files[streamName] = f

	if s.config.Compress {
		s.gzipWriters[streamName] = gzip.NewWriter(f)
	}
	return nil
}

// updateLogJSON writes the current metadata to log.json atomically.
// A crash mid-write can only leave either the old or new complete file on
// disk — never an empty or partial one. Implementation: marshal → write to
// sibling ".tmp" → fsync → rename. The rename is atomic on POSIX when source
// and destination are on the same filesystem.
//
// timingFile doubles as the "session files are open" sentinel: it is non-nil
// from the moment initialize opens it (and from construction for a restart)
// until Close nils it, which is exactly the window in which s.root is usable.
func (s *Session) updateLogJSON() (err error) {
	if s.timingFile == nil {
		return fmt.Errorf("session files are not open")
	}

	data, err := json.MarshalIndent(s.logMeta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode JSON for log.json: %w", err)
	}
	data = append(data, '\n')

	// Clobber any stale tempfile from a prior interrupted write.
	f, err := s.root.OpenFile(fileLogJSONTmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(s.config.FilePermissions))
	if err != nil {
		return fmt.Errorf("failed to open log.json tempfile: %w", err)
	}
	defer func() {
		if err != nil {
			_ = s.root.Remove(fileLogJSONTmp) // best-effort cleanup on failure
		}
	}()

	if _, err = f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("failed to write log.json tempfile: %w", err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to fsync log.json tempfile: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("failed to close log.json tempfile: %w", err)
	}
	if err = s.root.Rename(fileLogJSONTmp, fileLogJSON); err != nil {
		return fmt.Errorf("failed to rename log.json tempfile into place: %w", err)
	}

	slog.Debug("Updated log.json", "log_id", s.logID)
	return nil
}

// writeIoEntry writes I/O data and a corresponding timing entry.
func (s *Session) writeIoEntry(streamName string, delay *pb.TimeSpec, data []byte) (*pb.ServerMessage, error) {
	if delay == nil {
		return nil, fmt.Errorf("missing delay in %s I/O buffer", streamName)
	}

	streamInfo, ok := streamMap[streamName]
	if !ok {
		return nil, fmt.Errorf("unknown stream name: %s", streamName)
	}

	// Ensure the stream file exists (on-demand creation for stdin/ttyin)
	if err := s.ensureStreamFile(streamName); err != nil {
		return nil, fmt.Errorf("failed to create stream file %s: %w", streamName, err)
	}

	// Apply password filtering if enabled.
	// C sudo_logsrvd runs filtering on both TTY and non-TTY streams:
	// prompt detection on ttyout/stdout, input masking on ttyin/stdin.
	dataToWrite := data
	if s.passwordFilter != nil {
		if streamName == "ttyout" || streamName == "stdout" {
			// Check output for password prompts
			s.passwordFilter.CheckOutput(data)
		} else if streamName == "ttyin" || streamName == "stdin" {
			// Filter input if password prompt was detected
			dataToWrite = s.passwordFilter.FilterInput(data)
			if len(dataToWrite) != len(data) || string(dataToWrite) != string(data) {
				slog.Debug("Password input masked", "log_id", s.logID, "original_len", len(data), "masked_len", len(dataToWrite))
			}
		}
	}

	// Write data - use gzip writer if compression is enabled, otherwise write directly.
	// One map lookup serves both the choice of writer and the post-write Flush call.
	gzWriter, compressed := s.gzipWriters[streamName]
	var writer io.Writer = s.files[streamName]
	if compressed {
		writer = gzWriter
	}

	if _, err := writer.Write(dataToWrite); err != nil {
		return nil, err
	}

	// Flush gzip writer if using compression (equivalent to sudo's Z_SYNC_FLUSH)
	if compressed {
		if err := gzWriter.Flush(); err != nil {
			return nil, fmt.Errorf("failed to flush gzip writer for %s: %w", streamName, err)
		}
	}

	// Write timing info using integer format matching C sudo_logsrvd: "%d %lld.%09d %zu\n"
	s.cumulativeDelay += durationFromTimeSpec(delay)

	timingRecord := fmt.Sprintf("%d %d.%09d %d\n",
		streamInfo.marker,
		delay.TvSec,
		delay.TvNsec,
		len(dataToWrite))
	slog.Debug("Writing timing entry", "log_id", s.logID, "stream", streamName, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	// Only send commit points at commitPointInterval, matching C sudo_logsrvd's ACK_FREQUENCY.
	// The first I/O event always sends one (zero-value lastCommitTime guarantees this).
	if time.Since(s.lastCommitTime) >= commitPointInterval {
		s.lastCommitTime = time.Now()
		return s.commitPointMsg(), nil
	}

	return nil, nil
}

// durationFromTimeSpec converts a protobuf TimeSpec delay into a time.Duration.
func durationFromTimeSpec(ts *pb.TimeSpec) time.Duration {
	return time.Duration(ts.GetTvSec())*time.Second + time.Duration(ts.GetTvNsec())*time.Nanosecond
}

// commitPointMsg builds a ServerMessage carrying the session's cumulative
// elapsed time. The client compares this value against its own global elapsed
// time; integer second/nanosecond split matches C's commit_point encoding.
// Callers must hold fileMux (cumulativeDelay is mutated under it).
func (s *Session) commitPointMsg() *pb.ServerMessage {
	d := s.cumulativeDelay
	return &pb.ServerMessage{Type: &pb.ServerMessage_CommitPoint{
		CommitPoint: &pb.TimeSpec{
			TvSec:  int64(d / time.Second),
			TvNsec: int32(d % time.Second),
		},
	}}
}

func (s *Session) handleWinsize(event *pb.ChangeWindowSize) (*pb.ServerMessage, error) {
	if event.Delay == nil {
		return nil, fmt.Errorf("missing delay in ChangeWindowSize event")
	}
	// Advance the cumulative elapsed clock, matching C's update_elapsed_time on
	// winsize events. The value is reported by the next periodic commit and by
	// the final commit on Exit; winsize itself emits no commit point.
	s.cumulativeDelay += durationFromTimeSpec(event.Delay)

	timingRecord := fmt.Sprintf("%d %d.%09d %d %d\n", IO_EVENT_WINSIZE, event.Delay.TvSec, event.Delay.TvNsec, event.Rows, event.Cols)
	slog.Debug("Writing winsize entry", "log_id", s.logID, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	return nil, nil // No commit point for winsize
}

func (s *Session) handleSuspend(event *pb.CommandSuspend) (*pb.ServerMessage, error) {
	if event.Delay == nil {
		return nil, fmt.Errorf("missing delay in CommandSuspend event")
	}
	// Validate signal against allowed set, matching C sudo_logsrvd behavior.
	if !validSuspendSignals[event.Signal] {
		return nil, fmt.Errorf("invalid CommandSuspend signal: %q", event.Signal)
	}

	// Advance the cumulative elapsed clock, matching C's update_elapsed_time on
	// suspend events, so the final commit on Exit includes suspend/resume gaps.
	s.cumulativeDelay += durationFromTimeSpec(event.Delay)

	// Sudo uses marker 7 for all suspend/resume events; signal name differentiates them
	timingRecord := fmt.Sprintf("%d %d.%09d %s\n", IO_EVENT_SUSPEND, event.Delay.TvSec, event.Delay.TvNsec, event.Signal)
	slog.Debug("Writing suspend/resume entry", "log_id", s.logID, "record", strings.TrimSpace(timingRecord))
	if _, err := s.timingFile.WriteString(timingRecord); err != nil {
		return nil, err
	}

	return nil, nil // No commit point for suspend
}

// handleAlert records a security alert in the session's log.json metadata.
func (s *Session) handleAlert(alertMsg *pb.AlertMessage) (*pb.ServerMessage, error) {
	alert := map[string]any{
		"reason": alertMsg.GetReason(),
	}
	if alertTime := alertMsg.GetAlertTime(); alertTime != nil {
		alert["alert_time"] = time.Unix(alertTime.TvSec, int64(alertTime.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	if info := protocol.InfoMsgsToMap(alertMsg.GetInfoMsgs()); len(info) > 0 {
		alert["info"] = info
	}

	// Append to alerts array in metadata
	alerts, _ := s.logMeta["alerts"].([]any)
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
	entry := map[string]any{
		"event_type": "accept",
	}
	if st := acceptMsg.GetSubmitTime(); st != nil {
		entry["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	mergePreservingExisting(entry, protocol.InfoMsgsToMap(acceptMsg.GetInfoMsgs()))

	subCmds, _ := s.logMeta["sub_commands"].([]any)
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
	entry := map[string]any{
		"event_type": "reject",
		"reason":     rejectMsg.GetReason(),
	}
	if st := rejectMsg.GetSubmitTime(); st != nil {
		entry["submit_time"] = time.Unix(st.TvSec, int64(st.TvNsec)).UTC().Format(time.RFC3339Nano)
	}

	mergePreservingExisting(entry, protocol.InfoMsgsToMap(rejectMsg.GetInfoMsgs()))

	subCmds, _ := s.logMeta["sub_commands"].([]any)
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

// parseTimingDelay parses a "sec.nsec" timing delay field into a Duration.
func parseTimingDelay(s string) (time.Duration, error) {
	secStr, nsecStr, ok := strings.Cut(s, ".")
	if !ok {
		return 0, fmt.Errorf("missing decimal in delay %q", s)
	}
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad seconds in delay %q: %w", s, err)
	}
	// Written as %09d; pad short fields and use the first 9 digits defensively.
	for len(nsecStr) < 9 {
		nsecStr += "0"
	}
	nsec, err := strconv.ParseInt(nsecStr[:9], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("bad nanoseconds in delay %q: %w", s, err)
	}
	return time.Duration(sec)*time.Second + time.Duration(nsec)*time.Nanosecond, nil
}

// computeResumeOffsets replays the timing file to find the byte offset at which a
// restart should resume so resent I/O OVERWRITES (not duplicates) everything
// recorded after target. It mirrors C sudo's iolog_seekto: each record's delay
// is accumulated and each stream's offset advanced by the record's byte count
// until the cumulative elapsed time equals target. An exact match is required —
// an overshoot or hitting EOF first means resume_point does not align with the
// stored log (same condition C treats as an error), reported via the error so
// the caller can fall back to append mode. A zero target resumes at the start.
func computeResumeOffsetsAt(root *os.Root, name string, target time.Duration) (int64, map[string]int64, error) {
	streamOffsets := make(map[string]int64)
	if target <= 0 {
		return 0, streamOffsets, nil
	}
	data, err := root.ReadFile(name)
	if err != nil {
		return 0, nil, fmt.Errorf("read timing file: %w", err)
	}
	markerToStream := map[int]string{
		IO_EVENT_STDIN: "stdin", IO_EVENT_STDOUT: "stdout", IO_EVENT_STDERR: "stderr",
		IO_EVENT_TTYIN: "ttyin", IO_EVENT_TTYOUT: "ttyout",
	}

	var elapsed time.Duration
	var timingOffset int64
	content := string(data)
	for len(content) > 0 {
		var line string
		if nl := strings.IndexByte(content, '\n'); nl >= 0 {
			line = content[:nl]
			timingOffset += int64(nl + 1)
			content = content[nl+1:]
		} else {
			line = content
			timingOffset += int64(len(content))
			content = ""
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, nil, fmt.Errorf("malformed timing record %q", line)
		}
		marker, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0, nil, fmt.Errorf("bad timing marker %q: %w", fields[0], err)
		}
		delay, err := parseTimingDelay(fields[1])
		if err != nil {
			return 0, nil, err
		}
		elapsed += delay
		if stream, isIO := markerToStream[marker]; isIO {
			if len(fields) < 3 {
				return 0, nil, fmt.Errorf("I/O timing record missing byte count: %q", line)
			}
			nbytes, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("bad timing byte count %q: %w", fields[2], err)
			}
			streamOffsets[stream] += nbytes
		}

		if elapsed >= target {
			if elapsed == target {
				return timingOffset, streamOffsets, nil
			}
			return 0, nil, fmt.Errorf("resume_point %v overshoots stored timing (nearest boundary %v)", target, elapsed)
		}
	}
	return 0, nil, fmt.Errorf("resume_point %v is beyond the end of the stored timing", target)
}

// openForRestartAt opens an existing session file for a restart. When seek is
// true it truncates to off and positions the file there, so resumed I/O
// overwrites the post-resume_point region (matching C's iolog_seekto read->write
// switch); otherwise it opens in append mode. Resolution through root guards
// against a symlink swap between finalize and restart.
func openForRestartAt(root *os.Root, name string, cfg *config.LocalStorageConfig, seek bool, off int64) (*os.File, error) {
	if !seek {
		return root.OpenFile(name, os.O_APPEND|os.O_WRONLY, os.FileMode(cfg.FilePermissions))
	}
	f, err := root.OpenFile(name, os.O_WRONLY, os.FileMode(cfg.FilePermissions))
	if err != nil {
		return nil, err
	}
	// Seek WITHOUT truncating. Resumed I/O overwrites from the resume point
	// forward, which is what prevents duplication; truncating here would instead
	// let a RestartMessage{resume_point: 0} erase a session's whole transcript
	// before the client sends a byte, and anyone holding the log_id of an
	// unfinalized session can send that. C never truncates — there is no
	// ftruncate in lib/iolog or logsrvd, only iolog_seekto
	// (logsrvd/logsrvd_local.c:584).
	//
	// Any bytes left beyond the resumed data are inert: sudoreplay is driven by
	// the timing file, which is rewritten from the resume point on, so it never
	// reads past what the timing records describe.
	//
	// Conformance: docs/logsrvd-reference/ IOLOG-045.
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		f.Close()
		return nil, fmt.Errorf("seek to resume offset %d: %w", off, err)
	}
	return f, nil
}

// NewRestartSession creates a session that resumes an existing log from a RestartMessage.
func NewRestartSession(restartMsg *pb.RestartMessage, cfg *config.LocalStorageConfig) (_ *Session, retErr error) {
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

	// Verify session directory exists, then pin it. Every check and open below
	// resolves against this descriptor, so the directory the UUID is verified in
	// is provably the same one the resumed writes land in: a path-string swap
	// between the checks and the opens cannot redirect them.
	if _, err := os.Stat(sessionDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("session directory does not exist: %s", sessionDir)
	}
	root, err := openSessionRoot(sessionDir)
	if err != nil {
		return nil, err
	}
	// Released on every failure below; on success it transfers to the Session,
	// whose Close() owns it.
	defer func() {
		if retErr != nil {
			_ = root.Close() // constructor failed; retErr is what the caller needs
		}
	}()

	// Read and verify UUID file
	uuidData, err := root.ReadFile(fileUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to read uuid file: %w", err)
	}
	storedUUID := strings.TrimSpace(string(uuidData))
	if storedUUID != sessionUUID.String() {
		return nil, fmt.Errorf("UUID mismatch: log_id contains %s but session has %s", sessionUUID.String(), storedUUID)
	}

	// Check timing file is writable (not completed — finalize() sets 0440)
	timingInfo, err := root.Stat(fileTiming)
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

	// Determine where to resume. C sudo's iolog_seekto (logsrvd/logsrv_util.c)
	// replays the timing file to find the byte offset of resume_point in each
	// stream, then OVERWRITES everything after it so resent I/O is not
	// duplicated. We do the same: compute the offsets, then truncate+seek each
	// file to its resume position. If resume_point does not align with the
	// stored timing (overshoot or past EOF — e.g. an older client that sent
	// per-stream commit points), fall back to append mode rather than failing
	// the restart, logging a warning so the divergence is visible.
	rp := restartMsg.GetResumePoint()
	resumeDur := time.Duration(rp.GetTvSec())*time.Second + time.Duration(rp.GetTvNsec())*time.Nanosecond
	timingOffset, streamOffsets, seekErr := computeResumeOffsetsAt(root, fileTiming, resumeDur)
	useSeek := seekErr == nil
	if seekErr != nil && resumeDur > 0 {
		slog.Warn("Restart resume_point does not align with stored timing; appending instead of seeking (overlap region may be duplicated)",
			"log_id", restartMsg.GetLogId(), "resume_point", resumeDur, "error", seekErr)
	}

	// Open the timing file positioned at the resume point (or append on fallback).
	timingFile, err := openForRestartAt(root, fileTiming, cfg, useSeek, timingOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to open timing file for restart: %w", err)
	}

	// Read existing log.json; the subsequent atomic rewrite goes through root.
	// Decoded in a helper so the file handle is scoped strictly to the decode
	// and cannot leak into later error paths.
	logMeta, err := readLogJSONAt(root, fileLogJSON)
	if err != nil {
		timingFile.Close()
		return nil, err
	}

	// Open existing I/O stream files at their resume offset (or append on
	// fallback). stdin/ttyin may not exist (on-demand creation), so only open
	// files that are present; absent streams had no pre-resume data (offset 0).
	files := make(map[string]*os.File)
	for streamName, streamInfo := range streamMap {
		if _, statErr := root.Stat(streamInfo.filename); os.IsNotExist(statErr) {
			continue // On-demand file not yet created, will be created on first write
		}
		f, err := openForRestartAt(root, streamInfo.filename, cfg, useSeek, streamOffsets[streamName])
		if err != nil {
			// Clean up already opened files
			for _, openFile := range files {
				openFile.Close()
			}
			timingFile.Close()
			return nil, fmt.Errorf("failed to open stream file %s for restart: %w", streamName, err)
		}
		files[streamName] = f
	}

	// Restore the cumulative elapsed clock from resume_point so commit points
	// after the restart continue from where the prior session left off.
	var cumulativeDelay time.Duration
	if resumeDur > 0 {
		cumulativeDelay = resumeDur
	}

	session := &Session{
		logID:           restartMsg.GetLogId(),
		sessionUUID:     sessionUUID,
		config:          cfg,
		sessionDir:      sessionDir,
		root:            root,
		files:           files,
		gzipWriters:     make(map[string]*gzip.Writer), // empty — no compression for restart
		cumulativeDelay: cumulativeDelay,
		logMeta:         logMeta,
		timingFile:      timingFile,
		isInitialized:   true, // Already initialized from existing session
	}

	// Initialize password filter if enabled
	if cfg.PasswordFilter {
		session.passwordFilter = NewPasswordFilter()
	}

	// Record restart event in log.json
	restarts, _ := logMeta["restarts"].([]any)
	restartEntry := map[string]any{
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

	// Mark the timing file read-only to indicate completion, per sudo spec.
	//
	// This must precede Close(), which releases the s.root the chmod resolves
	// through. Ordering against the close is otherwise immaterial: the timing
	// handle is already open (POSIX checks permissions at open time, not per
	// write) and finalize issues no further writes. A restart arriving between
	// the chmod and the close is correctly rejected as already completed.
	slog.Debug("Setting timing file to read-only", "log_id", s.logID, "path", filepath.Join(s.sessionDir, fileTiming))
	if err := s.root.Chmod(fileTiming, 0440); err != nil {
		slog.Error("Failed to make timing file read-only", "log_id", s.logID, "error", err)
	}

	// Close all file handles, then the session directory descriptor.
	_ = s.Close()
}

// Close closes all open file handles for the session.
// Safe to call multiple times; only the first call performs cleanup.
func (s *Session) Close() error {
	var lastErr error
	s.closeOnce.Do(func() {
		// First, close all gzip writers to ensure all data is flushed
		for name, gzWriter := range s.gzipWriters {
			slog.Debug("Closing gzip writer", "log_id", s.logID, "stream", name)
			if err := gzWriter.Close(); err != nil {
				slog.Error("Failed to close gzip writer", "log_id", s.logID, "stream", name, "error", err)
				lastErr = err
			}
		}

		// Then close the underlying file handles. log.json has no persistent
		// fd — updateLogJSON writes it atomically by tempfile + rename.
		for name, f := range s.files {
			slog.Debug("Closing stream file", "log_id", s.logID, "stream", name)
			if err := f.Close(); err != nil {
				slog.Error("Failed to close stream file", "log_id", s.logID, "stream", name, "error", err)
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

		// Nil out to prevent use-after-close
		s.files = nil
		s.gzipWriters = nil
		s.timingFile = nil

		// Release the session directory descriptor last — every file opened
		// through it is closed by this point. The field is deliberately left
		// non-nil: a stray call after Close then fails with os.ErrClosed
		// instead of panicking on a nil dereference.
		if err := s.root.Close(); err != nil {
			slog.Error("Failed to close session directory handle", "log_id", s.logID, "error", err)
			lastErr = err
		}
		slog.Info("Closed all log files for session", "log_id", s.logID)
	})
	return lastErr
}
