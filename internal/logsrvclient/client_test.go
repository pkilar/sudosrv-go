// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logsrvclient/client_test.go
package logsrvclient

import (
	"errors"
	"io"
	"net"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// This package was extracted from internal/relay, whose suite exercises most of
// it transitively. These cover the two things that suite cannot: behaviour the
// relay never asks for, because the relay is only ever one particular caller.

// serveOnce runs handler against a single accepted connection.
//
// The handler is given a stop channel to park on rather than blocking outright.
// A handler that parks forever would keep this goroutine alive past the test,
// and the cleanup below waits for it -- an unresponsive server fixture would
// deadlock the suite instead of failing it.
func serveOnce(t *testing.T, handler func(proc protocol.Processor, stop <-chan struct{})) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		handler(protocol.NewProcessorWithCloser(conn, conn, conn), stop)
	}()
	t.Cleanup(func() { close(stop); _ = ln.Close(); <-done })
	return ln.Addr().String()
}

// hello completes the handshake from the server side.
func hello(proc protocol.Processor) {
	_, _ = proc.ReadClientMessage()
	_ = proc.WriteServerMessage(&pb.ServerMessage{
		Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{ServerId: "test"}}})
}

// TestConnectAnnouncesTheConfiguredClientID is the reason ClientID became a
// field rather than staying the hardcoded relay string.
//
// A log server's records have to distinguish a relayed session from one
// originated by sudo or by the recording login shell. With the id hardcoded,
// every logsh session on the fleet would have arrived claiming to be a relay.
func TestConnectAnnouncesTheConfiguredClientID(t *testing.T) {
	got := make(chan string, 1)
	addr := serveOnce(t, func(proc protocol.Processor, stop <-chan struct{}) {
		msg, err := proc.ReadClientMessage()
		if err != nil {
			got <- "<read failed>"
			return
		}
		got <- msg.GetHelloMsg().GetClientId()
		_ = proc.WriteServerMessage(&pb.ServerMessage{
			Type: &pb.ServerMessage_Hello{Hello: &pb.ServerHello{ServerId: "test"}}})
		<-stop
	})

	proc, err := Connect(t.Context(), Config{
		ClientID:       "TestClient/9.9",
		UpstreamHost:   addr,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = proc.Close() }()

	select {
	case id := <-got:
		if id != "TestClient/9.9" {
			t.Errorf("the server saw client_id %q, want %q", id, "TestClient/9.9")
		}
		if id == "GoSudoLogSrv-Relay/1.0" {
			t.Error("the client id is still hardcoded to the relay's")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never received a ClientHello")
	}
}

// TestReadAckWithoutWaitCommitReturnsOnTheFirstMessage covers the path the relay
// takes only for a sub-command accept, and which logsh depends on for its own
// accept handling.
//
// waitCommit=false must consume exactly one message and return. Reading further
// would block on a reply the server has no reason to send.
func TestReadAckWithoutWaitCommitReturnsOnTheFirstMessage(t *testing.T) {
	addr := serveOnce(t, func(proc protocol.Processor, stop <-chan struct{}) {
		hello(proc)
		// One log id, and then deliberate silence.
		_ = proc.WriteServerMessage(&pb.ServerMessage{
			Type: &pb.ServerMessage_LogId{LogId: "abc"}})
		<-stop
	})

	cfg := Config{ClientID: "t", UpstreamHost: addr, ConnectTimeout: 5 * time.Second,
		ResponseTimeout: 2 * time.Second}
	proc, err := Connect(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = proc.Close() }()

	done := make(chan error, 1)
	go func() { done <- ReadAck(t.Context(), proc, cfg, false) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ReadAck(waitCommit=false) = %v, want nil after one message", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadAck(waitCommit=false) kept reading past the first message")
	}
}

// TestReadAckTreatsAnErrorReplyAsDefinitive pins the sentinel that separates
// "could not be reached" from "was refused". Only the first is worth retrying;
// treating a refusal as retryable spins forever on a journal the server has
// already said no to.
func TestReadAckTreatsAnErrorReplyAsDefinitive(t *testing.T) {
	addr := serveOnce(t, func(proc protocol.Processor, stop <-chan struct{}) {
		hello(proc)
		_ = proc.WriteServerMessage(&pb.ServerMessage{
			Type: &pb.ServerMessage_Error{Error: "policy says no"}})
		<-stop
	})

	cfg := Config{ClientID: "t", UpstreamHost: addr, ConnectTimeout: 5 * time.Second,
		ResponseTimeout: 2 * time.Second}
	proc, err := Connect(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = proc.Close() }()

	err = ReadAck(t.Context(), proc, cfg, true)
	if !errors.Is(err, ErrUpstreamRejected) {
		t.Errorf("ReadAck on an error reply = %v, want it to wrap ErrUpstreamRejected", err)
	}
}

// TestReadAckTreatsEOFAsFailure guards against the most expensive possible
// misreading of the protocol.
//
// A server killed after draining a replay but before persisting it sends FIN,
// which is byte-identical to a polite close. Accepting that as an
// acknowledgement lets a caller retire the journal -- often the only copy -- so
// the session ends up in no log server anywhere, with no retry scheduled.
func TestReadAckTreatsEOFAsFailure(t *testing.T) {
	addr := serveOnce(t, func(proc protocol.Processor, _ <-chan struct{}) {
		hello(proc)
		_ = proc.Close() // clean close, no commit point
	})

	cfg := Config{ClientID: "t", UpstreamHost: addr, ConnectTimeout: 5 * time.Second,
		ResponseTimeout: 2 * time.Second}
	proc, err := Connect(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = proc.Close() }()

	err = ReadAck(t.Context(), proc, cfg, true)
	if err == nil {
		t.Fatal("a clean EOF was accepted as an acknowledgement; the caller would retire a " +
			"journal the server never persisted")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Logf("EOF surfaced as %v, which is acceptable so long as it is an error", err)
	}
}

// TestOperationTimeoutFallsBackToTheProtocolDefault keeps the two timeouts
// distinct. Reusing a 5s connect budget here once made a server that took longer
// than 5s to fsync a session fail the flush, so the whole session was replayed
// and stored twice under two log ids.
func TestOperationTimeoutFallsBackToTheProtocolDefault(t *testing.T) {
	if got := (Config{ConnectTimeout: 5 * time.Second}).OperationTimeout(); got != DefaultResponseTimeout {
		t.Errorf("OperationTimeout with no response_timeout = %v, want %v (it must NOT borrow "+
			"connect_timeout)", got, DefaultResponseTimeout)
	}
	if got := (Config{ResponseTimeout: 90 * time.Second}).OperationTimeout(); got != 90*time.Second {
		t.Errorf("OperationTimeout = %v, want the configured 90s", got)
	}
}
