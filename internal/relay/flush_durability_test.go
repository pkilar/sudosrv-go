// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/flush_durability_test.go
package relay

import (
	"net"
	"os"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"testing"
	"time"
)

// startAckServer runs a fake upstream that completes the ClientHello handshake
// and then hands the connection to handle. handle must return when the peer
// disconnects, so the listener can be torn down.
func startAckServer(t *testing.T, handle func(proc protocol.Processor)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
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
				handle(proc)
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return ln.Addr().String()
}

// drain reads client messages until the peer goes away.
func drain(proc protocol.Processor) {
	for {
		if _, err := proc.ReadClientMessage(); err != nil {
			return
		}
	}
}

func durabilityConfig(addr string) *config.RelayConfig {
	return &config.RelayConfig{
		UpstreamHost:   addr,
		ConnectTimeout: 2 * time.Second,
		// Without this the flush falls back to operationTimeout's 30s, and
		// TestFlushRequiresUpstreamCommitBeforeRetiringCache waits it out in
		// full -- 30s of this package's runtime spent on a value that test
		// never asserts. The 30s default stays pinned by
		// TestResponseTimeoutFallback, which checks it directly.
		ResponseTimeout: 2 * time.Second,
	}
}

// writeCacheFile builds a relay cache file in the same length-prefixed format
// the write phase produces.
func writeCacheFile(t *testing.T, msgs ...*pb.ClientMessage) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create cache file: %v", err)
	}
	for _, m := range msgs {
		if err := writeProtoMessage(f, m); err != nil {
			t.Fatalf("write cache message: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close cache file: %v", err)
	}
	return path
}

func ioAccept() *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 1},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{{
			Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"},
		}},
	}}}
}

func eventOnlyAccept() *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 1},
		ExpectIobufs: false,
		InfoMsgs: []*pb.InfoMessage{{
			Key: "command", Value: &pb.InfoMessage_Strval{Strval: "/bin/ls"},
		}},
	}}}
}

func exitMsg() *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{
		RunTime: &pb.TimeSpec{TvSec: 1},
	}}}
}

func flushCache(t *testing.T, path string, cfg *config.RelayConfig) error {
	t.Helper()
	ctx := t.Context()
	proc, err := connectToUpstream(ctx, cfg)
	if err != nil {
		t.Fatalf("connectToUpstream: %v", err)
	}
	defer func() { _ = proc.Close() }()
	return flushFile(ctx, proc, path, cfg)
}

func requireExists(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("cache file was retired but %s; the only copy of this session is now gone: %v", why, err)
	}
}

// TestFlushRequiresUpstreamCommitBeforeRetiringCache is the core durability
// guarantee: for an I/O session the cache file must survive until the upstream
// acknowledges the session with its final commit_point.
//
// Writing bytes into a TCP socket is not delivery. If the upstream dies before
// it persists them, whatever sat in the send buffer is gone — and if the cache
// file has already been unlinked, that session exists nowhere. C unlinks the
// journal only once the closure reaches FINISHED, i.e. after the upstream's
// final commit point (logsrvd/logsrvd.c:296-305).
//
// Conformance: docs/logsrvd-reference/ RELAY-042, RELAY-054.
func TestFlushRequiresUpstreamCommitBeforeRetiringCache(t *testing.T) {
	// This upstream answers the Accept with a log_id, so the replay runs to
	// completion, but never sends the final commit_point — the case where the
	// upstream took the bytes and then failed to persist them. Answering the
	// Accept matters: without it the flush stalls earlier and the retire
	// decision this test exists to check is never reached.
	addr := startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			if msg.GetAcceptMsg() != nil {
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "upstream-log-id"},
				})
			}
			// ExitMessage is deliberately left unacknowledged.
		}
	})
	path := writeCacheFile(t, ioAccept(), exitMsg())

	err := flushCache(t, path, durabilityConfig(addr))

	if err == nil {
		t.Error("flushFile reported success without any upstream acknowledgement")
	}
	requireExists(t, path, "the upstream never sent a commit_point")
}

// TestFlushRetiresCacheAfterUpstreamCommit is the other half: once the upstream
// does acknowledge, the cache file must be retired, or every session would be
// replayed forever and duplicated upstream.
func TestFlushRetiresCacheAfterUpstreamCommit(t *testing.T) {
	addr := startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			switch msg.Type.(type) {
			case *pb.ClientMessage_AcceptMsg:
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "upstream-log-id"},
				})
			case *pb.ClientMessage_ExitMsg:
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{TvSec: 1}},
				})
			}
		}
	})
	path := writeCacheFile(t, ioAccept(), exitMsg())

	if err := flushCache(t, path, durabilityConfig(addr)); err != nil {
		t.Fatalf("flushFile failed against an acknowledging upstream: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("cache file survived a fully acknowledged flush; it would be replayed and duplicated upstream")
	}
}

// TestFlushTreatsUpstreamErrorAsFailure covers the upstream rejecting the
// session outright — disk full, iolog permission failure, quota. That reply
// must not be mistaken for an acknowledgement.
//
// Conformance: docs/logsrvd-reference/ RELAY-020.
func TestFlushTreatsUpstreamErrorAsFailure(t *testing.T) {
	addr := startAckServer(t, func(proc protocol.Processor) {
		if _, err := proc.ReadClientMessage(); err != nil { // AcceptMessage
			return
		}
		_ = proc.WriteServerMessage(&pb.ServerMessage{
			Type: &pb.ServerMessage_Error{Error: "unable to create I/O log"},
		})
		drain(proc)
	})
	path := writeCacheFile(t, ioAccept(), exitMsg())

	err := flushCache(t, path, durabilityConfig(addr))

	if err == nil {
		t.Error("an upstream error reply was treated as a successful flush")
	}
	requireExists(t, path, "the upstream rejected the session")
}

// TestFlushKeepsCacheWhenUpstreamClosesWithoutCommit covers the upstream dying
// mid-flush: it read our replay into userspace, answered the Accept, and then
// went away — SIGKILL, OOM, a restart, or a TCP proxy dropping the backend —
// without ever persisting the session. A process death sends FIN, not RST, so
// what we see is a clean EOF, indistinguishable at the socket layer from a
// polite close.
//
// C treats exactly this as "premature EOF from <relay>" and errors out
// (logsrvd/logsrvd_relay.c:869-888), because it unlinks the journal only at
// FINISHED (logsrvd/logsrvd.c:296-305) and an I/O session reaches FINISHED only
// when the upstream's final commit_point arrives (logsrvd/logsrvd.c:1315-1316).
//
// Conformance: docs/logsrvd-reference/ RELAY-022.
func TestFlushKeepsCacheWhenUpstreamClosesWithoutCommit(t *testing.T) {
	addr := startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			if msg.GetAcceptMsg() != nil {
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "upstream-log-id"},
				})
			}
			if msg.GetExitMsg() != nil {
				// Died here: bytes consumed, nothing committed, socket closed.
				return
			}
		}
	})
	path := writeCacheFile(t, ioAccept(), exitMsg())

	err := flushCache(t, path, durabilityConfig(addr))

	if err == nil {
		t.Error("a clean upstream EOF with no commit_point was treated as acknowledgement")
	}
	requireExists(t, path, "the upstream closed before sending a commit_point")
}

// TestFlushEventOnlySessionNeedsNoAcknowledgement guards the opposite failure.
//
// The protocol defines no acknowledgement for a session with
// expect_iobufs=false: the server sends a log_id only for a new I/O session
// (logsrvd/logsrvd_local.c:209) and, on exit without log_io, goes straight to
// FINISHED without a commit point (logsrvd/logsrvd.c). Blocking for an
// acknowledgement that is never coming would fail the flush and re-deliver the
// accept event upstream on every retry, forever.
//
// Conformance: docs/logsrvd-reference/ RELAY-019.
func TestFlushEventOnlySessionNeedsNoAcknowledgement(t *testing.T) {
	// Event-only upstream: reads, never replies — exactly like the C server.
	addr := startAckServer(t, drain)
	path := writeCacheFile(t, eventOnlyAccept(), exitMsg())

	done := make(chan error, 1)
	go func() { done <- flushCache(t, path, durabilityConfig(addr)) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("event-only flush failed waiting for an acknowledgement the protocol never sends: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("event-only flush blocked waiting for a log_id/commit_point that never arrives")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("event-only cache file was not retired; it would be re-delivered upstream on every retry")
	}
}

// TestInterimCommitPointDoesNotRetireTheCache is the gap the durability barrier
// had, despite its own comment claiming otherwise.
//
// flushFile said it would "read past any periodic commit points the upstream
// emitted during the replay until the session is acknowledged", but
// readUpstreamAck returned on the FIRST commit point it saw. An upstream emits
// one on the first I/O event of a session and every ACK_FREQUENCY thereafter
// (internal/storage writeIoEntry), so by the end of a replay one is very likely
// already queued -- and accepting it meant treating a fraction of a session as
// acknowledged and then unlinking the only copy of the rest.
//
// The upstream here sends an interim commit point covering nothing, then goes
// quiet. The cache file must survive.
func TestInterimCommitPointDoesNotRetireTheCache(t *testing.T) {
	addr := startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			switch msg.Type.(type) {
			case *pb.ClientMessage_AcceptMsg:
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "id"}})
			case *pb.ClientMessage_TtyoutBuf:
				// Covers nothing: the elapsed clock so far is zero.
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{}}})
			}
			// The final commit point never comes.
		}
	})

	cfg := durabilityConfig(addr)
	cfg.ResponseTimeout = 700 * time.Millisecond

	path := writeCacheFile(t,
		ioAccept(),
		&pb.ClientMessage{Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{
			Delay: &pb.TimeSpec{TvSec: 2}, Data: []byte("output\n"),
		}}},
		exitMsg(),
	)

	if err := flushCache(t, path, cfg); err == nil {
		t.Error("flush reported success on an interim commit point that covered none of the " +
			"session; the cache file would be unlinked with the session possibly unstored")
	}
	requireExists(t, path, "the upstream never sent a commit point covering the session")
}

// TestFinalCommitPointRetiresTheCache is the other half: a commit point that
// DOES cover the replayed session must be accepted, or every flush would fail
// and no journal would ever be retired.
func TestFinalCommitPointRetiresTheCache(t *testing.T) {
	addr := startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			switch msg.Type.(type) {
			case *pb.ClientMessage_AcceptMsg:
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "id"}})
			case *pb.ClientMessage_TtyoutBuf:
				// An interim one first, exactly as a real upstream sends.
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{}}})
			case *pb.ClientMessage_ExitMsg:
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{TvSec: 2}}})
			}
		}
	})

	cfg := durabilityConfig(addr)
	cfg.ResponseTimeout = 5 * time.Second

	path := writeCacheFile(t,
		ioAccept(),
		&pb.ClientMessage{Type: &pb.ClientMessage_TtyoutBuf{TtyoutBuf: &pb.IoBuffer{
			Delay: &pb.TimeSpec{TvSec: 2}, Data: []byte("output\n"),
		}}},
		exitMsg(),
	)

	if err := flushCache(t, path, cfg); err != nil {
		t.Fatalf("flush failed against an upstream that did acknowledge the session: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a fully acknowledged session left its cache file behind; the next sweep would "+
			"replay it and the upstream would store it twice (stat err: %v)", err)
	}
}
