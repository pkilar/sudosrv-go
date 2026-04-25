// Filename: internal/metrics/metrics_test.go
package metrics

import (
	"sync"
	"testing"
	"time"
)

func TestNewMetricsInitialState(t *testing.T) {
	t.Parallel()
	m := newMetrics()

	got := map[string]int64{
		"TotalConnections":  m.GetTotalConnections(),
		"ActiveConnections": m.GetActiveConnections(),
		"FailedConnections": m.GetFailedConnections(),
		"TotalSessions":     m.GetTotalSessions(),
		"ActiveSessions":    m.GetActiveSessions(),
		"LocalSessions":     m.GetLocalSessions(),
		"RelaySessions":     m.GetRelaySessions(),
		"MessagesProcessed": m.GetMessagesProcessed(),
		"MessageErrors":     m.GetMessageErrors(),
	}
	for name, v := range got {
		if v != 0 {
			t.Errorf("%s = %d, want 0", name, v)
		}
	}
	if m.GetUptime() < 0 {
		t.Errorf("GetUptime() = %v, want >= 0", m.GetUptime())
	}
}

func TestConnectionCounters(t *testing.T) {
	t.Parallel()
	m := newMetrics()

	m.IncrementConnections()
	m.IncrementConnections()
	m.IncrementConnections()
	if got, want := m.GetTotalConnections(), int64(3); got != want {
		t.Errorf("TotalConnections after 3x Inc: got %d, want %d", got, want)
	}
	if got, want := m.GetActiveConnections(), int64(3); got != want {
		t.Errorf("ActiveConnections after 3x Inc: got %d, want %d", got, want)
	}

	m.DecrementActiveConnections()
	if got, want := m.GetActiveConnections(), int64(2); got != want {
		t.Errorf("ActiveConnections after Dec: got %d, want %d", got, want)
	}
	if got, want := m.GetTotalConnections(), int64(3); got != want {
		t.Errorf("TotalConnections must not change on Dec: got %d, want %d", got, want)
	}

	m.IncrementFailedConnections()
	m.IncrementFailedConnections()
	if got, want := m.GetFailedConnections(), int64(2); got != want {
		t.Errorf("FailedConnections: got %d, want %d", got, want)
	}
	if m.GetTotalConnections() != 3 || m.GetActiveConnections() != 2 {
		t.Errorf("FailedConnections inc must not affect total/active")
	}
}

func TestSessionCounters(t *testing.T) {
	t.Parallel()
	m := newMetrics()

	m.IncrementSessions()
	m.IncrementSessions()
	if got, want := m.GetTotalSessions(), int64(2); got != want {
		t.Errorf("TotalSessions: got %d, want %d", got, want)
	}
	if got, want := m.GetActiveSessions(), int64(2); got != want {
		t.Errorf("ActiveSessions: got %d, want %d", got, want)
	}

	m.DecrementActiveSessions()
	if got, want := m.GetActiveSessions(), int64(1); got != want {
		t.Errorf("ActiveSessions after Dec: got %d, want %d", got, want)
	}
	if got, want := m.GetTotalSessions(), int64(2); got != want {
		t.Errorf("TotalSessions must not change on Dec: got %d, want %d", got, want)
	}

	m.IncrementLocalSessions()
	m.IncrementLocalSessions()
	m.IncrementRelaySessions()
	if got, want := m.GetLocalSessions(), int64(2); got != want {
		t.Errorf("LocalSessions: got %d, want %d", got, want)
	}
	if got, want := m.GetRelaySessions(), int64(1); got != want {
		t.Errorf("RelaySessions: got %d, want %d", got, want)
	}
	if m.GetTotalSessions() != 2 || m.GetActiveSessions() != 1 {
		t.Errorf("Local/Relay session inc must not affect total/active")
	}
}

func TestMessageCounters(t *testing.T) {
	t.Parallel()
	m := newMetrics()

	m.IncrementMessagesProcessed()
	m.IncrementMessagesProcessed()
	m.IncrementMessagesProcessed()
	m.IncrementMessageErrors()
	if got, want := m.GetMessagesProcessed(), int64(3); got != want {
		t.Errorf("MessagesProcessed: got %d, want %d", got, want)
	}
	if got, want := m.GetMessageErrors(), int64(1); got != want {
		t.Errorf("MessageErrors: got %d, want %d", got, want)
	}
}

func TestReset(t *testing.T) {
	t.Parallel()
	m := newMetrics()

	m.IncrementConnections()
	m.IncrementSessions()
	m.IncrementLocalSessions()
	m.IncrementRelaySessions()
	m.IncrementMessagesProcessed()
	m.IncrementMessageErrors()
	m.IncrementFailedConnections()

	m.Reset()

	got := map[string]int64{
		"TotalConnections":  m.GetTotalConnections(),
		"ActiveConnections": m.GetActiveConnections(),
		"FailedConnections": m.GetFailedConnections(),
		"TotalSessions":     m.GetTotalSessions(),
		"ActiveSessions":    m.GetActiveSessions(),
		"LocalSessions":     m.GetLocalSessions(),
		"RelaySessions":     m.GetRelaySessions(),
		"MessagesProcessed": m.GetMessagesProcessed(),
		"MessageErrors":     m.GetMessageErrors(),
	}
	for name, v := range got {
		if v != 0 {
			t.Errorf("%s after Reset = %d, want 0", name, v)
		}
	}
	// Reset moves serverStartTime to "now"; uptime should be near zero.
	if uptime := m.GetUptime(); uptime > time.Second {
		t.Errorf("GetUptime() after Reset = %v, want < 1s", uptime)
	}
}

func TestConcurrentIncrements(t *testing.T) {
	t.Parallel()
	m := newMetrics()

	const goroutines = 50
	const perGoroutine = 1000

	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range perGoroutine {
				m.IncrementConnections()
				m.IncrementSessions()
				m.IncrementLocalSessions()
				m.IncrementRelaySessions()
				m.IncrementMessagesProcessed()
				m.IncrementMessageErrors()
				m.IncrementFailedConnections()
			}
		})
	}
	wg.Wait()

	want := int64(goroutines * perGoroutine)
	checks := map[string]int64{
		"TotalConnections":  m.GetTotalConnections(),
		"ActiveConnections": m.GetActiveConnections(),
		"FailedConnections": m.GetFailedConnections(),
		"TotalSessions":     m.GetTotalSessions(),
		"ActiveSessions":    m.GetActiveSessions(),
		"LocalSessions":     m.GetLocalSessions(),
		"RelaySessions":     m.GetRelaySessions(),
		"MessagesProcessed": m.GetMessagesProcessed(),
		"MessageErrors":     m.GetMessageErrors(),
	}
	for name, got := range checks {
		if got != want {
			t.Errorf("%s after concurrent inc: got %d, want %d", name, got, want)
		}
	}
}

func TestConcurrentIncrementDecrement(t *testing.T) {
	t.Parallel()
	m := newMetrics()

	const goroutines = 50
	const perGoroutine = 1000

	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range perGoroutine {
				m.IncrementConnections()
				m.DecrementActiveConnections()
				m.IncrementSessions()
				m.DecrementActiveSessions()
			}
		})
	}
	wg.Wait()

	if got := m.GetActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections after balanced inc/dec: got %d, want 0", got)
	}
	if got := m.GetActiveSessions(); got != 0 {
		t.Errorf("ActiveSessions after balanced inc/dec: got %d, want 0", got)
	}
	if got, want := m.GetTotalConnections(), int64(goroutines*perGoroutine); got != want {
		t.Errorf("TotalConnections: got %d, want %d", got, want)
	}
	if got, want := m.GetTotalSessions(), int64(goroutines*perGoroutine); got != want {
		t.Errorf("TotalSessions: got %d, want %d", got, want)
	}
}

func TestGlobalIsInitialized(t *testing.T) {
	t.Parallel()
	if Global == nil {
		t.Fatal("Global is nil")
	}
	// All getters must return non-negative values without panicking.
	_ = Global.GetTotalConnections()
	_ = Global.GetActiveConnections()
	_ = Global.GetFailedConnections()
	_ = Global.GetTotalSessions()
	_ = Global.GetActiveSessions()
	_ = Global.GetLocalSessions()
	_ = Global.GetRelaySessions()
	_ = Global.GetMessagesProcessed()
	_ = Global.GetMessageErrors()
	if Global.GetUptime() < 0 {
		t.Errorf("Global.GetUptime() = %v, want >= 0", Global.GetUptime())
	}
}
