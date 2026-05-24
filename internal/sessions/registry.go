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
//
// Info is a reference type (map). The registry treats it as read-only after
// Register; callers MUST NOT mutate the map returned from Get/Snapshot.
// API handlers that need to expose Info externally should defensive-copy via
// maps.Clone — see internal/api/server.go:detail.
type SessionInfo struct {
	SessionID    string           // sessionUUID.String(); registry key
	ServerLogID  string           // base64-encoded sudo log_id; populated after session init
	SessionUUID  uuid.UUID        // raw UUID
	Mode         string           // "local" or "relay"
	RemoteAddr   string           // client connection's remote address
	StartedAt    time.Time        // server-side connection start
	SubmitTime   time.Time        // AcceptMessage.submit_time
	ExpectIobufs bool             // whether I/O buffers are expected for this session
	Info         map[string]any   // flattened AcceptMessage.InfoMsgs; treat as read-only post-Register
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
//
// byLogID is a secondary index mapping ServerLogID → SessionID so Get() can
// answer either-form lookups in O(1) instead of a linear scan that an
// authenticated client could trivially weaponize by polling random IDs.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]SessionInfo
	byLogID  map[string]string
}

// NewRegistry returns an empty registry ready for use.
func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[string]SessionInfo),
		byLogID:  make(map[string]string),
	}
}

// Register adds a session to the registry, replacing any existing entry with
// the same SessionID. A nil receiver is a no-op so callers that may not have a
// registry (e.g., unit tests) can call this unconditionally.
//
// Two cases need careful index hygiene:
//
//  1. Re-register under the same SessionID with a different ServerLogID:
//     drop the old logID → SessionID mapping so it can't outlive its owner.
//  2. Register under a NEW SessionID with the same ServerLogID as an existing
//     entry (e.g., a restart/reconnect overlap where the old connection is
//     still finishing teardown): the newer entry takes ownership of the
//     logID index. The older SessionID is still reachable via its primary
//     key, but Get(logID) returns the newer record. This matches operator
//     intent — when two sessions share a log_id during an overlap, the
//     active recovery is the one worth surfacing.
func (r *Registry) Register(info SessionInfo) {
	if r == nil || info.SessionID == "" {
		return
	}
	r.mu.Lock()
	if prev, ok := r.sessions[info.SessionID]; ok && prev.ServerLogID != "" && prev.ServerLogID != info.ServerLogID {
		delete(r.byLogID, prev.ServerLogID)
	}
	r.sessions[info.SessionID] = info
	if info.ServerLogID != "" {
		r.byLogID[info.ServerLogID] = info.SessionID
	}
	r.mu.Unlock()
}

// Deregister removes the session with the given ID. Missing IDs are silently
// ignored. A nil receiver is a no-op.
//
// The secondary-index delete is OWNERSHIP-AWARE: we only drop
// byLogID[prev.ServerLogID] when it still points at the SessionID being
// removed. If a newer session has since claimed the same ServerLogID
// (restart/reconnect overlap), removing the old session must not clobber
// the newer one's lookup — that would 404 a recovery session that an
// operator is actively trying to inspect.
func (r *Registry) Deregister(sessionID string) {
	if r == nil || sessionID == "" {
		return
	}
	r.mu.Lock()
	if prev, ok := r.sessions[sessionID]; ok && prev.ServerLogID != "" {
		if owner, ok := r.byLogID[prev.ServerLogID]; ok && owner == sessionID {
			delete(r.byLogID, prev.ServerLogID)
		}
	}
	delete(r.sessions, sessionID)
	r.mu.Unlock()
}

// Get returns a copy of the registered session matching id. The lookup tries
// the SessionID (UUID form) first, then the ServerLogID secondary index, so
// callers can paste either form and pay only O(1) work.
func (r *Registry) Get(id string) (SessionInfo, bool) {
	if r == nil || id == "" {
		return SessionInfo{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.sessions[id]; ok {
		return s, true
	}
	if sid, ok := r.byLogID[id]; ok {
		if s, ok := r.sessions[sid]; ok {
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
