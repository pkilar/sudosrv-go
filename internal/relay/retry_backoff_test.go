// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/retry_backoff_test.go
package relay

import (
	"net"
	"sync"
	"testing"
	"time"

	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"

	"uuid"
)

// failAfterConnectServer accepts connections, completes the ServerHello
// handshake, then hangs up without acknowledging the replayed AcceptMessage.
// That is a flush that fails *after* a successful connect — the case
// RELAY-044 says must be throttled just like a failed connect.
type failAfterConnectServer struct {
	listener net.Listener
	wg       sync.WaitGroup

	mu      sync.Mutex
	connect []time.Time
}

func newFailAfterConnectServer(t *testing.T) *failAfterConnectServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &failAfterConnectServer{listener: l}
	s.wg.Go(func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return // listener closed
			}
			s.mu.Lock()
			s.connect = append(s.connect, time.Now())
			s.mu.Unlock()
			s.wg.Go(func() {
				defer conn.Close()
				proc := protocol.NewProcessor(conn, conn)
				if _, err := proc.ReadClientMessage(); err != nil { // ClientHello
					return
				}
				if err := proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{}},
				}); err != nil {
					return
				}
				// Read the replayed AcceptMessage and then drop the connection
				// without the log_id reply, so flushFile fails immediately.
				_, _ = proc.ReadClientMessage()
			})
		}
	})
	return s
}

func (s *failAfterConnectServer) Close() {
	s.listener.Close()
	s.wg.Wait()
}

func (s *failAfterConnectServer) Addr() string { return s.listener.Addr().String() }

func (s *failAfterConnectServer) connectTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.connect...)
}

// TestRelayFlushFailureIsThrottled pins RELAY-044: a flush that fails after the
// upstream connection succeeded must back off before the next attempt, exactly
// as a failed connect does. Without it the session goroutine re-connects and
// re-sends the whole cached session as fast as the round trip allows, forever
// under the default reconnect_attempts of -1.
func TestRelayFlushFailureIsThrottled(t *testing.T) {
	upstream := newFailAfterConnectServer(t)
	defer upstream.Close()

	const attempts = 3
	// MaxReconnectInterval caps calculateBackoff, so every wait here is
	// 50ms + jitter(0-50ms) rather than the 1s-and-doubling production curve.
	const maxInterval = 100 * time.Millisecond

	cfg := &config.RelayConfig{
		RelayCacheDirectory:  t.TempDir(),
		ReconnectAttempts:    attempts,
		MaxReconnectInterval: maxInterval,
		ConnectTimeout:       2 * time.Second,
		UpstreamHost:         upstream.Addr(),
	}

	session, err := NewSession(t.Context(), uuid.NewV4(), createTestAcceptMessage(), cfg, nil)
	if err != nil {
		t.Fatalf("NewSession() failed: %v", err)
	}
	if _, err := session.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{ExitValue: 0}},
	}); err != nil {
		t.Fatalf("HandleClientMessage(exit): %v", err)
	}
	session.Close()
	waitRelaySession(t, session, 30*time.Second)

	times := upstream.connectTimes()
	if len(times) != attempts {
		t.Fatalf("got %d upstream connections, want %d (attempt accounting)", len(times), attempts)
	}

	// calculateBackoff never returns less than maxInterval/2, and the connect
	// timestamps only add handshake time on top, so every gap must clear it.
	const minGap = maxInterval / 2
	for i := 1; i < len(times); i++ {
		if gap := times[i].Sub(times[i-1]); gap < minGap {
			t.Errorf("retry %d followed retry %d after %s; want at least %s of backoff",
				i, i-1, gap, minGap)
		}
	}
}
