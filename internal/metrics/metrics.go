// Filename: internal/metrics/metrics.go
package metrics

import (
	"sync/atomic"
	"time"
)

// Metrics holds basic operational metrics for the server.
type Metrics struct {
	// Connection metrics
	TotalConnections  int64
	ActiveConnections int64
	FailedConnections int64

	// Session metrics
	TotalSessions  int64
	ActiveSessions int64
	LocalSessions  int64
	RelaySessions  int64

	// Message metrics
	MessagesProcessed int64
	MessageErrors     int64

	// Timing metrics
	ServerStartTime time.Time
}

// Global metrics instance
var Global = &Metrics{
	ServerStartTime: time.Now(),
}

// Connection tracking
func (m *Metrics) IncrementConnections() {
	atomic.AddInt64(&m.TotalConnections, 1)
	atomic.AddInt64(&m.ActiveConnections, 1)
}

func (m *Metrics) DecrementActiveConnections() {
	atomic.AddInt64(&m.ActiveConnections, -1)
}

func (m *Metrics) IncrementFailedConnections() {
	atomic.AddInt64(&m.FailedConnections, 1)
}

// Session tracking
func (m *Metrics) IncrementSessions() {
	atomic.AddInt64(&m.TotalSessions, 1)
	atomic.AddInt64(&m.ActiveSessions, 1)
}

func (m *Metrics) DecrementActiveSessions() {
	atomic.AddInt64(&m.ActiveSessions, -1)
}

func (m *Metrics) IncrementLocalSessions() {
	atomic.AddInt64(&m.LocalSessions, 1)
}

func (m *Metrics) IncrementRelaySessions() {
	atomic.AddInt64(&m.RelaySessions, 1)
}

// Message tracking
func (m *Metrics) IncrementMessagesProcessed() {
	atomic.AddInt64(&m.MessagesProcessed, 1)
}

func (m *Metrics) IncrementMessageErrors() {
	atomic.AddInt64(&m.MessageErrors, 1)
}

// Getters for safe reading
func (m *Metrics) GetTotalConnections() int64 {
	return atomic.LoadInt64(&m.TotalConnections)
}

func (m *Metrics) GetActiveConnections() int64 {
	return atomic.LoadInt64(&m.ActiveConnections)
}

func (m *Metrics) GetFailedConnections() int64 {
	return atomic.LoadInt64(&m.FailedConnections)
}

func (m *Metrics) GetTotalSessions() int64 {
	return atomic.LoadInt64(&m.TotalSessions)
}

func (m *Metrics) GetActiveSessions() int64 {
	return atomic.LoadInt64(&m.ActiveSessions)
}

func (m *Metrics) GetLocalSessions() int64 {
	return atomic.LoadInt64(&m.LocalSessions)
}

func (m *Metrics) GetRelaySessions() int64 {
	return atomic.LoadInt64(&m.RelaySessions)
}

func (m *Metrics) GetMessagesProcessed() int64 {
	return atomic.LoadInt64(&m.MessagesProcessed)
}

func (m *Metrics) GetMessageErrors() int64 {
	return atomic.LoadInt64(&m.MessageErrors)
}

func (m *Metrics) GetUptime() time.Duration {
	return time.Since(m.ServerStartTime)
}
