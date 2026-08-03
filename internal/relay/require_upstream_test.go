// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/require_upstream_test.go
package relay

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	"testing"

	"github.com/google/uuid"
)

// freeAddrNoListener returns an address with nothing listening on it: bind an
// ephemeral port, note it, then release it.
func freeAddrNoListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return addr
}

// TestRequireUpstreamRejectsWhenUnreachable covers the fail-closed policy.
//
// By default this relay is store-and-forward: an unreachable upstream is not an
// error, the session spools to disk and is delivered later. That is the right
// default — it keeps privileged work running through an upstream outage — but it
// is fail-OPEN with respect to auditing, and it differs from C's default relay,
// which streams to the upstream and makes sudo refuse the command when the relay
// list is exhausted. Sites that require an auditable path before privileged
// execution need the other behavior.
//
// Conformance: docs/logsrvd-reference/ RELAY-010.
func TestRequireUpstreamRejectsWhenUnreachable(t *testing.T) {
	acceptMsg := ioAccept().GetAcceptMsg()

	t.Run("DefaultSpoolsWhenUnreachable", func(t *testing.T) {
		cfg := &config.RelayConfig{
			UpstreamHost:        freeAddrNoListener(t),
			RelayCacheDirectory: t.TempDir(),
			ConnectTimeout:      durabilityConfig("x").ConnectTimeout,
			// RequireUpstream defaults to false.
		}
		s, err := NewSession(context.Background(), uuid.New(), acceptMsg, cfg, func() {})
		if err != nil {
			t.Fatalf("default relay must accept the session and spool it, got: %v", err)
		}
		// Close only signals the writer; the background goroutine is still
		// creating and writing {uuid}.log. Wait for it, or t.TempDir cleanup
		// races the write and fails with "directory not empty".
		_ = s.Close()
		s.Wait()
	})

	t.Run("RequireUpstreamRejects", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &config.RelayConfig{
			UpstreamHost:        freeAddrNoListener(t),
			RelayCacheDirectory: dir,
			ConnectTimeout:      durabilityConfig("x").ConnectTimeout,
			RequireUpstream:     true,
		}
		_, err := NewSession(context.Background(), uuid.New(), acceptMsg, cfg, func() {})
		if err == nil {
			t.Fatal("require_upstream is set but an unreachable upstream still accepted the session; " +
				"the command would run with no auditable path to the log server")
		}
		if !errors.Is(err, ErrUpstreamUnreachable) {
			t.Errorf("error %v does not wrap ErrUpstreamUnreachable, so the handler cannot "+
				"tell the client specifically why the command was refused", err)
		}
		// A refused session must not leave a cache file behind: nothing was accepted.
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatalf("read cache dir: %v", readErr)
		}
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".log" {
				t.Errorf("refused session left cache file %s", e.Name())
			}
		}
	})

	t.Run("RequireUpstreamAcceptsWhenReachable", func(t *testing.T) {
		addr := startAckServer(t, func(proc protocol.Processor) {
			for {
				if _, err := proc.ReadClientMessage(); err != nil {
					return
				}
			}
		})
		cfg := durabilityConfig(addr)
		cfg.RelayCacheDirectory = t.TempDir()
		cfg.RequireUpstream = true

		s, err := NewSession(context.Background(), uuid.New(), acceptMsg, cfg, func() {})
		if err != nil {
			t.Fatalf("reachable upstream must be accepted: %v", err)
		}
		// See DefaultSpoolsWhenUnreachable: Wait before t.TempDir cleanup.
		_ = s.Close()
		s.Wait()
	})
}
