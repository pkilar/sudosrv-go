// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/subcommand_test.go
package relay

import (
	"context"
	"path/filepath"
	"sudosrv/internal/config"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func subCommandAccept(cmd string) *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 2},
		ExpectIobufs: false, // sub-commands reuse the session's I/O log
		InfoMsgs: []*pb.InfoMessage{{
			Key: "command", Value: &pb.InfoMessage_Strval{Strval: cmd},
		}},
	}}}
}

// TestRelayForwardsSubCommandAccepts checks that an AcceptMessage arriving
// mid-session is relayed upstream rather than silently dropped.
//
// The server advertises Subcommands: true in its ServerHello
// (internal/connection/handler.go), so a client running with sudo's intercept /
// log_subcmds support will send an AcceptMessage per intercepted sub-command.
// The C server journals each one (logsrvd/logsrvd_journal.c journal_accept) and
// answers none of them with a log_id — only a NEW I/O session gets that
// (logsrvd/logsrvd_local.c:209, gated on new_session && log_io).
//
// Dropping them means the relayed audit trail claims the user ran one command
// when they ran ten, which is a silent hole in the record the whole daemon
// exists to keep.
//
// Conformance: docs/logsrvd-reference/ RELAY-034.
func TestRelayForwardsSubCommandAccepts(t *testing.T) {
	var (
		mu       sync.Mutex
		accepts  []string
		gotExit  = make(chan struct{})
		exitOnce sync.Once
	)

	addr := startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			switch {
			case msg.GetAcceptMsg() != nil:
				cmd := ""
				for _, i := range msg.GetAcceptMsg().GetInfoMsgs() {
					if i.GetKey() == "command" {
						cmd = i.GetStrval()
					}
				}
				mu.Lock()
				accepts = append(accepts, cmd)
				mu.Unlock()
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_LogId{LogId: "upstream-log-id"},
				})
			case msg.GetExitMsg() != nil:
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{TvSec: 1}},
				})
				exitOnce.Do(func() { close(gotExit) })
			}
		}
	})

	cfg := durabilityConfig(addr)
	cfg.RelayCacheDirectory = t.TempDir()
	// This test drives the full session (write phase + background flush), so the
	// reconnect loop in run() needs a budget; the direct flushFile tests bypass it.
	cfg.ReconnectAttempts = 3
	cfg.MaxReconnectInterval = 50 * time.Millisecond

	session, err := NewSession(context.Background(), uuid.New(),
		ioAccept().GetAcceptMsg(), cfg, func() {})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Mirror the connection handler: handleAccept replays the session's own
	// AcceptMessage through HandleClientMessage to obtain the log_id. That one
	// must be answered and NOT re-cached; only what follows is a sub-command.
	resp, err := session.HandleClientMessage(ioAccept())
	if err != nil {
		t.Fatalf("initial accept: %v", err)
	}
	if resp.GetLogId() == "" {
		t.Fatal("the session's own accept must still be answered with a log_id")
	}

	if _, err := session.HandleClientMessage(subCommandAccept("/usr/bin/id")); err != nil {
		t.Fatalf("sub-command accept rejected: %v", err)
	}
	if _, err := session.HandleClientMessage(exitMsg()); err != nil {
		t.Fatalf("exit rejected: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	session.Wait()

	select {
	case <-gotExit:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never received the ExitMessage")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(accepts) != 2 {
		t.Fatalf("upstream received %d AcceptMessage(s) %v, want 2 (the session accept "+
			"and the /usr/bin/id sub-command); a dropped sub-command accept is a silent "+
			"hole in the relayed audit trail", len(accepts), accepts)
	}
	if accepts[1] != "/usr/bin/id" {
		t.Errorf("second accept was %q, want /usr/bin/id", accepts[1])
	}
}

// TestRelayEventOnlyAcceptCachesSubCommandAccepts covers the sub-command accept
// that follows an EVENT-ONLY accept (expect_iobufs=false).
//
// The connection handler splits the two accept flavours: handleAccept replays
// the session's own AcceptMessage through HandleClientMessage to obtain the
// log_id, while handleEventOnlyAccept does not — sudo does not expect a log_id
// when I/O logging is off (C: logsrvd/logsrvd_journal.c:571 only calls
// fmt_log_id_message when msg->expect_iobufs). This test drives the session the
// way handleEventOnlyAccept does, i.e. without that replay.
//
// C journals every accept unconditionally (journal_accept), so the upstream
// must see both the session accept and the intercepted sub-command accept.
//
// Conformance: docs/logsrvd-reference/ PROTO-015.
func TestRelayEventOnlyAcceptCachesSubCommandAccepts(t *testing.T) {
	var (
		mu       sync.Mutex
		accepts  []string
		gotExit  = make(chan struct{})
		exitOnce sync.Once
	)

	addr := startAckServer(t, func(proc protocol.Processor) {
		for {
			msg, err := proc.ReadClientMessage()
			if err != nil {
				return
			}
			switch {
			case msg.GetAcceptMsg() != nil:
				cmd := ""
				for _, i := range msg.GetAcceptMsg().GetInfoMsgs() {
					if i.GetKey() == "command" {
						cmd = i.GetStrval()
					}
				}
				mu.Lock()
				accepts = append(accepts, cmd)
				mu.Unlock()
			case msg.GetExitMsg() != nil:
				_ = proc.WriteServerMessage(&pb.ServerMessage{
					Type: &pb.ServerMessage_CommitPoint{CommitPoint: &pb.TimeSpec{TvSec: 1}},
				})
				exitOnce.Do(func() { close(gotExit) })
			}
		}
	})

	cfg := durabilityConfig(addr)
	cfg.RelayCacheDirectory = t.TempDir()
	cfg.ReconnectAttempts = 3
	cfg.MaxReconnectInterval = 50 * time.Millisecond

	session, err := NewSession(context.Background(), uuid.New(),
		eventOnlyAccept().GetAcceptMsg(), cfg, func() {})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// No replay of the session's own accept: handleEventOnlyAccept returns
	// (nil, nil) instead of routing it through HandleClientMessage.
	resp, err := session.HandleClientMessage(subCommandAccept("/usr/bin/id"))
	if err != nil {
		t.Fatalf("sub-command accept rejected: %v", err)
	}
	if resp.GetLogId() != "" {
		t.Errorf("sub-command accept answered with log_id %q; sudo is not waiting for one "+
			"on an event-only session and the unsolicited reply desynchronises the stream",
			resp.GetLogId())
	}
	if _, err := session.HandleClientMessage(exitMsg()); err != nil {
		t.Fatalf("exit rejected: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	session.Wait()

	select {
	case <-gotExit:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never received the ExitMessage")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(accepts) != 2 {
		t.Fatalf("upstream received %d AcceptMessage(s) %v, want 2 (the event-only session "+
			"accept and the /usr/bin/id sub-command); the first sub-command of an event-only "+
			"session is swallowed, so the relayed audit trail loses a command that ran",
			len(accepts), accepts)
	}
	if accepts[1] != "/usr/bin/id" {
		t.Errorf("second accept was %q, want /usr/bin/id", accepts[1])
	}
}

// TestSubCommandAcceptReusesOneJournalAndOneLogID asserts RELAY-034 in the
// terms the requirement is written in, rather than only in terms of what the
// upstream receives: an Accept arriving while a journal already exists must
// append to it, and must create neither a second journal file nor a second
// log_id (logsrvd/logsrvd_journal.c:560-563).
//
// The second half is what the connection layer guarantees -- processMessage
// routes any message to the already-active session instead of calling
// handleAccept again, which would mint a fresh UUID and a fresh cache file.
// This test covers the session's own half of the contract.
func TestSubCommandAcceptReusesOneJournalAndOneLogID(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.RelayConfig{
		UpstreamHost:        "127.0.0.1:1", // never dialled; the write phase is what we inspect
		ConnectTimeout:      50 * time.Millisecond,
		RelayCacheDirectory: dir,
		ReconnectAttempts:   1,
	}

	sessionUUID := uuid.New()
	s, err := NewSession(context.Background(), sessionUUID, ioAcceptMsg("/bin/ls"), cfg, nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// The session's own accept, replayed by handleAccept for the log_id.
	first, err := s.HandleClientMessage(&pb.ClientMessage{
		Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: ioAcceptMsg("/bin/ls")},
	})
	if err != nil {
		t.Fatalf("initial accept: %v", err)
	}
	firstLogID := first.GetLogId()
	if firstLogID == "" {
		t.Fatal("the session's own accept must be answered with a log_id")
	}

	// Two intercepted sub-commands.
	for _, cmd := range []string{"/usr/bin/id", "/bin/cat"} {
		resp, subErr := s.HandleClientMessage(&pb.ClientMessage{
			Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: ioAcceptMsg(cmd)},
		})
		if subErr != nil {
			t.Fatalf("sub-command accept %s: %v", cmd, subErr)
		}
		if got := resp.GetLogId(); got != "" {
			t.Errorf("sub-command accept for %s was answered with log_id %q; only a NEW I/O session gets one", cmd, got)
		}
	}
	if s.LogID() != firstLogID {
		t.Errorf("session log_id changed from %q to %q across sub-command accepts", firstLogID, s.LogID())
	}
	_ = s.Close()

	// Exactly one journal file for the whole session.
	journals, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(journals) != 1 {
		t.Fatalf("found %d journal files %v, want exactly 1: a sub-command accept must reuse the session's journal", len(journals), journals)
	}
}

// ioAcceptMsg builds an I/O-logging AcceptMessage for the named command.
func ioAcceptMsg(command string) *pb.AcceptMessage {
	return &pb.AcceptMessage{
		SubmitTime:   &pb.TimeSpec{TvSec: 1},
		ExpectIobufs: true,
		InfoMsgs: []*pb.InfoMessage{{
			Key: "command", Value: &pb.InfoMessage_Strval{Strval: command},
		}},
	}
}
