// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/response_timeout_test.go
package relay

import (
	"os"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"
	"time"
)

// slowAckUpstream answers the accept with a log_id and the exit with a final
// commit_point, delaying each reply by ackDelay.
func slowAckUpstream(t *testing.T, ackDelay time.Duration) string {
	t.Helper()
	return startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			switch {
			case msg.GetAcceptMsg() != nil:
				time.Sleep(ackDelay)
				if err := proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "slow-id"},
				}); err != nil {
					return
				}
			case msg.GetExitMsg() != nil:
				time.Sleep(ackDelay)
				if err := proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{
						CommitPoint: &pb.TimeSpec{TvSec: 1},
					},
				}); err != nil {
					return
				}
			}
		}
	})
}

// TestUpstreamResponseTimeoutIsIndependentOfConnectTimeout pins the two relay
// timeouts apart. connect_timeout bounds the dial; how long we wait for an
// already-connected upstream to answer is a separate, much more generous budget
// (C's [relay] timeout, default 30s).
//
// When the response wait was connect_timeout, an upstream that acknowledged a
// session in more than 5s failed the flush; the cache file is kept on failure,
// so the whole session was replayed and stored upstream a second time under a
// new log ID. Conformance: docs/logsrvd-reference/ CONF-039.
func TestUpstreamResponseTimeoutIsIndependentOfConnectTimeout(t *testing.T) {
	addr := slowAckUpstream(t, 600*time.Millisecond)

	cfg := &config.RelayConfig{
		UpstreamHost:    addr,
		ConnectTimeout:  200 * time.Millisecond,
		ResponseTimeout: 5 * time.Second,
	}

	path := writeCacheFile(t, ioAccept(), exitMsg())
	if err := flushCache(t, path, cfg); err != nil {
		t.Fatalf("flush failed against an upstream that acknowledged in 600ms with "+
			"connect_timeout=200ms: %v; a slow-but-healthy upstream must not fail the "+
			"flush, or the whole session is replayed and stored twice", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cache file still present after a successful flush: %v", err)
	}
}

// TestUpstreamResponseTimeoutStillBoundsTheWait is the other half: the flush must
// not block forever on an upstream that accepts bytes and never answers.
func TestUpstreamResponseTimeoutStillBoundsTheWait(t *testing.T) {
	addr := startAckServer(t, drain) // reads everything, answers nothing

	cfg := &config.RelayConfig{
		UpstreamHost:    addr,
		ConnectTimeout:  2 * time.Second,
		ResponseTimeout: 300 * time.Millisecond,
	}

	path := writeCacheFile(t, ioAccept(), exitMsg())
	start := time.Now()
	if err := flushCache(t, path, cfg); err == nil {
		t.Fatal("flush succeeded against an upstream that never acknowledged the session")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("flush took %v against a silent upstream; response_timeout=300ms must bound it", elapsed)
	}
	requireExists(t, path, "the upstream never acknowledged the session")
}

// TestResponseTimeoutFallback pins the in-package fallback at C's 30s rather
// than the 5s connect budget, for configs built without going through
// config.LoadConfig.
func TestResponseTimeoutFallback(t *testing.T) {
	if got := operationTimeout(&config.RelayConfig{ConnectTimeout: 5 * time.Second}); got != 30*time.Second {
		t.Errorf("operationTimeout with an unset response_timeout: got %v, want 30s "+
			"(C's [relay] timeout); it must not fall back to connect_timeout", got)
	}
}
