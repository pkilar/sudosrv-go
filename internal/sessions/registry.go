// SPDX-License-Identifier: Apache-2.0

// Package sessions provides an in-memory registry of currently active sudo
// sessions for the management API. The registry is keyed by the server-side
// session UUID (matching the value already emitted as log_id in slog) and is
// populated by the connection handler when an AcceptMessage or RestartMessage
// initializes a session, then drained when the connection terminates.
package sessions

import (
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionInfo is the registry record for one active session. Static fields are
// populated at registration time; live fields are obtained via Provider on
// demand so the API never returns stale counters.
type SessionInfo struct {
	SessionID    string           // sessionUUID.String(); registry key
	ServerLogID  string           // base64-encoded sudo log_id; populated after session init
	SessionUUID  uuid.UUID        // raw UUID
	Mode         string           // "local" or "relay"
	RemoteAddr   string           // client connection's remote address
	StartedAt    time.Time        // server-side connection start
	SubmitTime   time.Time        // AcceptMessage.submit_time
	ExpectIobufs bool             // whether I/O buffers are expected for this session
	Info         map[string]any   // flattened AcceptMessage.InfoMsgs
	Provider     MetadataProvider // optional accessor for live counters
}

// MetadataProvider is implemented by session types that can expose live
// counters to the management API. Sessions that do not implement it appear in
// the registry with zero-valued LiveStats.
type MetadataProvider interface {
	LiveStats() LiveStats
}

// LiveStats is a snapshot of mutable per-session state. Mode-specific fields
// (SessionDir, CacheFile, Phase) are populated only when relevant.
type LiveStats struct {
	MessagesReceived int64
	BytesReceived    int64
	LastActivity     time.Time
	SessionDir       string // local mode: on-disk session directory
	CacheFile        string // relay mode: cache file path
	Phase            string // relay mode: "writing" or "flushing"
}

// Registry holds the active session set. The zero value is not usable; call
// NewRegistry. It is safe for concurrent use.
//
// Records are stored by value and returned by value, so callers reading from
// the API path never observe in-flight mutations from a registering goroutine.
// The static fields of SessionInfo are set once at Register time; live
// counters are read through the MetadataProvider hook, which uses its own
// synchronization (typically sync/atomic) on the underlying session.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]SessionInfo
}

// NewRegistry returns an empty registry ready for use.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]SessionInfo)}
}

// Register adds a session to the registry, replacing any existing entry with
// the same SessionID. A nil receiver is a no-op so callers that may not have a
// registry (e.g., unit tests) can call this unconditionally.
func (r *Registry) Register(info SessionInfo) {
	if r == nil || info.SessionID == "" {
		return
	}
	r.mu.Lock()
	r.sessions[info.SessionID] = info
	r.mu.Unlock()
}

// Deregister removes the session with the given ID. Missing IDs are silently
// ignored. A nil receiver is a no-op.
func (r *Registry) Deregister(sessionID string) {
	if r == nil || sessionID == "" {
		return
	}
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
}

// Get returns a copy of the registered session matching id. The lookup tries
// the SessionID (UUID form) first, then falls back to a linear scan for a
// matching ServerLogID so callers can paste either form.
func (r *Registry) Get(id string) (SessionInfo, bool) {
	if r == nil || id == "" {
		return SessionInfo{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.sessions[id]; ok {
		return s, true
	}
	for _, s := range r.sessions {
		if s.ServerLogID != "" && s.ServerLogID == id {
			return s, true
		}
	}
	return SessionInfo{}, false
}

// Snapshot returns copies of the active sessions, sorted by StartedAt
// descending (newest first). The returned slice is decoupled from the
// underlying map; callers may iterate without holding the registry lock.
func (r *Registry) Snapshot() []SessionInfo {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]SessionInfo, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	r.mu.RUnlock()
	// Newest-first by StartedAt; Compare(b, a) so larger (newer) sorts first.
	slices.SortFunc(out, func(a, b SessionInfo) int { return b.StartedAt.Compare(a.StartedAt) })
	return out
}

// Len returns the current number of registered sessions.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}
