// Filename: internal/metrics/metrics.go
package metrics

import (
	"sync/atomic"
	"time"
)

// Metrics holds basic operational metrics for the server.
// All counter fields use atomic.Int64 to enforce atomic access at the type level,
// preventing accidental non-atomic reads or writes.
type Metrics struct {
	totalConnections  atomic.Int64
	activeConnections atomic.Int64
	failedConnections atomic.Int64

	totalSessions  atomic.Int64
	activeSessions atomic.Int64
	localSessions  atomic.Int64
	relaySessions  atomic.Int64

	messagesProcessed atomic.Int64
	messageErrors     atomic.Int64

	serverStartTime time.Time
}

// Global metrics instance
var Global = newMetrics()

func newMetrics() *Metrics {
	return &Metrics{
		serverStartTime: time.Now(),
	}
}

// Connection tracking
func (m *Metrics) IncrementConnections() {
	m.totalConnections.Add(1)
	m.activeConnections.Add(1)
}

func (m *Metrics) DecrementActiveConnections() {
	m.activeConnections.Add(-1)
}

func (m *Metrics) IncrementFailedConnections() {
	m.failedConnections.Add(1)
}

// Session tracking
func (m *Metrics) IncrementSessions() {
	m.totalSessions.Add(1)
	m.activeSessions.Add(1)
}

func (m *Metrics) DecrementActiveSessions() {
	m.activeSessions.Add(-1)
}

func (m *Metrics) IncrementLocalSessions() {
	m.localSessions.Add(1)
}

func (m *Metrics) IncrementRelaySessions() {
	m.relaySessions.Add(1)
}

// Message tracking
func (m *Metrics) IncrementMessagesProcessed() {
	m.messagesProcessed.Add(1)
}

func (m *Metrics) IncrementMessageErrors() {
	m.messageErrors.Add(1)
}

// Getters for safe reading
func (m *Metrics) GetTotalConnections() int64 {
	return m.totalConnections.Load()
}

func (m *Metrics) GetActiveConnections() int64 {
	return m.activeConnections.Load()
}

func (m *Metrics) GetFailedConnections() int64 {
	return m.failedConnections.Load()
}

func (m *Metrics) GetTotalSessions() int64 {
	return m.totalSessions.Load()
}

func (m *Metrics) GetActiveSessions() int64 {
	return m.activeSessions.Load()
}

func (m *Metrics) GetLocalSessions() int64 {
	return m.localSessions.Load()
}

func (m *Metrics) GetRelaySessions() int64 {
	return m.relaySessions.Load()
}

func (m *Metrics) GetMessagesProcessed() int64 {
	return m.messagesProcessed.Load()
}

func (m *Metrics) GetMessageErrors() int64 {
	return m.messageErrors.Load()
}

func (m *Metrics) GetUptime() time.Duration {
	return time.Since(m.serverStartTime)
}

// Reset resets all counters to zero. Intended for use in tests.
func (m *Metrics) Reset() {
	m.totalConnections.Store(0)
	m.activeConnections.Store(0)
	m.failedConnections.Store(0)
	m.totalSessions.Store(0)
	m.activeSessions.Store(0)
	m.localSessions.Store(0)
	m.relaySessions.Store(0)
	m.messagesProcessed.Store(0)
	m.messageErrors.Store(0)
	m.serverStartTime = time.Now()
}
