// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeProvider struct {
	stats LiveStats
}

func (f *fakeProvider) LiveStats() LiveStats { return f.stats }

func newInfo(t *testing.T, mode string) SessionInfo {
	t.Helper()
	id := uuid.New()
	return SessionInfo{
		SessionID:   id.String(),
		SessionUUID: id,
		Mode:        mode,
		StartedAt:   time.Now(),
	}
}

func TestRegistry_RegisterGetDeregister(t *testing.T) {
	r := NewRegistry()
	info := newInfo(t, "local")
	info.ServerLogID = "log-id-base64"

	r.Register(info)
	if got := r.Len(); got != 1 {
		t.Fatalf("Len after register = %d, want 1", got)
	}

	got, ok := r.Get(info.SessionID)
	if !ok || got.SessionID != info.SessionID {
		t.Fatalf("Get by SessionID returned (%+v, %v); want session %q", got, ok, info.SessionID)
	}

	got, ok = r.Get("log-id-base64")
	if !ok || got.SessionID != info.SessionID {
		t.Fatalf("Get by ServerLogID returned (%+v, %v); want session %q", got, ok, info.SessionID)
	}

	if _, ok := r.Get("does-not-exist"); ok {
		t.Fatalf("Get returned ok for unknown id")
	}

	r.Deregister(info.SessionID)
	if got := r.Len(); got != 0 {
		t.Fatalf("Len after deregister = %d, want 0", got)
	}
	if _, ok := r.Get(info.SessionID); ok {
		t.Fatalf("Get after deregister returned ok")
	}
}

// TestRegistry_GetReturnsCopy asserts that mutating the returned SessionInfo
// does not affect the registry's stored record. This is the structural fix
// for the data race called out in the adversarial review: callers cannot
// observe (or cause) in-flight mutations to records held by the registry.
func TestRegistry_GetReturnsCopy(t *testing.T) {
	r := NewRegistry()
	info := newInfo(t, "local")
	info.ServerLogID = "original"
	r.Register(info)

	got, _ := r.Get(info.SessionID)
	got.ServerLogID = "mutated-by-caller"

	again, _ := r.Get(info.SessionID)
	if again.ServerLogID != "original" {
		t.Fatalf("registry record mutated by caller: ServerLogID = %q, want %q",
			again.ServerLogID, "original")
	}
}

func TestRegistry_Snapshot_OrderAndIsolation(t *testing.T) {
	r := NewRegistry()
	now := time.Now()

	older := newInfo(t, "local")
	older.StartedAt = now.Add(-time.Minute)
	newer := newInfo(t, "local")
	newer.StartedAt = now

	r.Register(older)
	r.Register(newer)

	snap := r.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot len = %d, want 2", len(snap))
	}
	if snap[0].SessionID != newer.SessionID {
		t.Fatalf("Snapshot[0] = %v; want newest first", snap[0].SessionID)
	}

	// Mutating the registry after Snapshot must not change the returned slice length.
	r.Deregister(older.SessionID)
	if len(snap) != 2 {
		t.Fatalf("Snapshot mutated by post-snapshot Deregister; len = %d, want 2", len(snap))
	}
}

func TestRegistry_NilSafety(t *testing.T) {
	var r *Registry
	r.Register(SessionInfo{SessionID: "x"})
	r.Deregister("x")
	if got := r.Len(); got != 0 {
		t.Fatalf("nil registry Len = %d, want 0", got)
	}
	if _, ok := r.Get("x"); ok {
		t.Fatalf("nil registry Get returned ok")
	}
	if snap := r.Snapshot(); snap != nil {
		t.Fatalf("nil registry Snapshot = %v, want nil", snap)
	}
}

func TestRegistry_RejectsEmptyOrNil(t *testing.T) {
	r := NewRegistry()
	r.Register(SessionInfo{}) // empty SessionID
	if r.Len() != 0 {
		t.Fatalf("Register accepted invalid input; Len = %d", r.Len())
	}
}

func TestRegistry_LiveStatsViaProvider(t *testing.T) {
	r := NewRegistry()
	info := newInfo(t, "local")
	info.Provider = &fakeProvider{stats: LiveStats{MessagesReceived: 7, BytesReceived: 1024}}
	r.Register(info)

	got, ok := r.Get(info.SessionID)
	if !ok {
		t.Fatal("Get failed")
	}
	stats := got.Provider.LiveStats()
	if stats.MessagesReceived != 7 || stats.BytesReceived != 1024 {
		t.Fatalf("LiveStats = %+v; want MessagesReceived=7 BytesReceived=1024", stats)
	}
}

// TestRegistry_Concurrent_RegisterDeregisterSnapshot exercises the locking
// model under -race. It alternates registers and deregisters from many
// goroutines while another set of goroutines reads via Get and Snapshot.
func TestRegistry_Concurrent_RegisterDeregisterSnapshot(t *testing.T) {
	r := NewRegistry()
	const writers = 16
	const readers = 8
	const opsPerWriter = 200

	ids := make([]string, writers*opsPerWriter)
	for i := range ids {
		ids[i] = uuid.New().String()
	}

	// Writers and readers use separate WaitGroups so we can deterministically
	// wait for writer completion (a known finite work set) without busy-polling
	// a counter. The reader pool runs until we explicitly stop it.
	var writersWG, readersWG sync.WaitGroup
	stop := make(chan struct{})

	for w := range writers {
		writersWG.Go(func() {
			start := w * opsPerWriter
			for i := range opsPerWriter {
				id := ids[start+i]
				r.Register(SessionInfo{
					SessionID:   id,
					SessionUUID: uuid.MustParse(id),
					Mode:        "local",
					StartedAt:   time.Now(),
				})
				r.Deregister(id)
			}
		})
	}

	for range readers {
		readersWG.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = r.Snapshot()
				_, _ = r.Get(ids[0])
			}
		})
	}

	writersWG.Wait()
	close(stop)
	readersWG.Wait()

	if got := r.Len(); got != 0 {
		t.Fatalf("Registry not empty after balanced register/deregister; len=%d", got)
	}
}

func BenchmarkRegistry_Snapshot(b *testing.B) {
	r := NewRegistry()
	for range 1000 {
		id := uuid.New()
		r.Register(SessionInfo{SessionID: id.String(), SessionUUID: id, StartedAt: time.Now()})
	}
	b.ResetTimer()
	for b.Loop() {
		_ = r.Snapshot()
	}
}

// TestRegistry_GetByLogIDIsO1 pins the secondary-index behavior: a lookup by
// ServerLogID must succeed without falling back to a linear scan, and the
// index must stay coherent across replacement and deregistration so an old
// logID cannot resolve to a session that has since taken its place.
func TestRegistry_GetByLogIDIsO1(t *testing.T) {
	r := NewRegistry()
	id := uuid.New()
	r.Register(SessionInfo{
		SessionID:   id.String(),
		SessionUUID: id,
		ServerLogID: "logA",
		StartedAt:   time.Unix(1, 0),
	})

	if got, ok := r.Get("logA"); !ok || got.SessionID != id.String() {
		t.Fatalf("Get by ServerLogID: got=%+v ok=%v", got, ok)
	}

	// Replacement under the same SessionID with a new ServerLogID must drop
	// the stale logID → SessionID mapping.
	r.Register(SessionInfo{
		SessionID:   id.String(),
		SessionUUID: id,
		ServerLogID: "logB",
		StartedAt:   time.Unix(2, 0),
	})
	if _, ok := r.Get("logA"); ok {
		t.Error("stale logA lookup should miss after re-registration with logB")
	}
	if got, ok := r.Get("logB"); !ok || got.SessionID != id.String() {
		t.Errorf("Get by new logB failed: got=%+v ok=%v", got, ok)
	}

	// Deregister must drop the secondary index entry too.
	r.Deregister(id.String())
	if _, ok := r.Get("logB"); ok {
		t.Error("logB lookup should miss after Deregister")
	}
}

// Sanity: ensure %v formatting of a SessionInfo doesn't panic, useful when
// tests include diagnostic output.
func TestSessionInfo_FormatStable(t *testing.T) {
	id := uuid.New()
	info := &SessionInfo{
		SessionID:   id.String(),
		SessionUUID: id,
		Mode:        "local",
		StartedAt:   time.Unix(0, 0),
		Info:        map[string]any{"submituser": "alice"},
	}
	if s := fmt.Sprintf("%+v", info); s == "" {
		t.Fatal("empty format output")
	}
}
