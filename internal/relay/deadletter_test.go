// SPDX-License-Identifier: Apache-2.0
// Filename: internal/relay/deadletter_test.go
package relay

import (
	"errors"
	"os"
	"sudosrv/internal/protocol"
	pb "sudosrv/pkg/sudosrv_proto"
	"testing"
)

// rejectingUpstream answers the Accept with a log_id so the replay runs to
// completion, then refuses the session outright with an error ServerMessage --
// the "disk full", "iolog permission denied", "malformed session" class of
// answer that no amount of retrying will change.
func rejectingUpstream(t *testing.T) string {
	t.Helper()
	return startAckServer(t, func(proc protocol.Processor) {
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
					Type: &pb.ServerMessage_Error{Error: "unable to create iolog dir: Permission denied"},
				})
			}
		}
	})
}

// TestUpstreamErrorIsDistinguishableFromTransientFailure pins the sentinel that
// the whole poison-message path hangs off. Without it every failure looks alike
// and the retry loop cannot tell "come back later" from "never".
// Conformance: docs/logsrvd-reference/ RELAY-049.
func TestUpstreamErrorIsDistinguishableFromTransientFailure(t *testing.T) {
	path := writeCacheFile(t, ioAccept(), exitMsg())

	err := flushCache(t, path, durabilityConfig(rejectingUpstream(t)))

	if err == nil {
		t.Fatal("flushFile reported success although the upstream refused the session")
	}
	if !errors.Is(err, ErrUpstreamRejected) {
		t.Errorf("flushFile error = %v, want one matching ErrUpstreamRejected", err)
	}
	requireExists(t, path, "flushFile must leave the retire/park decision to its caller")
}

// TestRejectedOrphanIsParkedNotRetried is the behavior that requirement asks
// for: an orphan the upstream refuses must leave the retry rotation. Renaming
// it back to *.log hands it straight to the next startup's sweep, which gets
// the same refusal -- C's forever loop (logsrvd/logsrvd_relay.c:638-661).
// Conformance: docs/logsrvd-reference/ RELAY-049.
func TestRejectedOrphanIsParkedNotRetried(t *testing.T) {
	path := writeCacheFile(t, ioAccept(), exitMsg())
	cfg := durabilityConfig(rejectingUpstream(t))

	err := FlushOrphanedFile(t.Context(), path, cfg)
	if err == nil {
		t.Fatal("FlushOrphanedFile reported success although the upstream refused the session")
	}

	// Not left where orphan recovery would find it again...
	for _, retryable := range []string{path, path + FlushingSuffix} {
		if _, statErr := os.Stat(retryable); statErr == nil {
			t.Errorf("%s still exists; the next orphan sweep will replay a session the upstream already refused", retryable)
		}
	}
	// ...but not discarded either.
	parked := path + RejectedSuffix
	if _, statErr := os.Stat(parked); statErr != nil {
		t.Fatalf("expected the refused journal to be parked at %s: %v", parked, statErr)
	}
	if data, readErr := os.ReadFile(parked); readErr != nil || len(data) == 0 {
		t.Errorf("parked journal at %s must retain the session bytes (err=%v, len=%d)", parked, readErr, len(data))
	}
}

// TestIOSessionWithoutExitIsParkedNotRemoved covers the most reachable half of
// RELAY-042: any session whose client dies without sending an ExitMessage. No
// commit point can ever arrive for it, so unlinking discards the only copy of a
// session the upstream may not have persisted, and retrying replays it on every
// restart forever. It must be parked instead.
// Conformance: docs/logsrvd-reference/ RELAY-042.
func TestIOSessionWithoutExitIsParkedNotRemoved(t *testing.T) {
	// No ExitMessage in the journal at all.
	path := writeCacheFile(t, ioAccept())
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
		}
	})

	if err := flushCache(t, path, durabilityConfig(addr)); err != nil {
		t.Fatalf("flushFile should transmit and park, not fail: %v", err)
	}

	if _, err := os.Stat(path); err == nil {
		t.Error("journal left in place; an unfinishable session would be replayed on every restart")
	}
	parked := path + IncompleteSuffix
	data, err := os.ReadFile(parked)
	if err != nil {
		t.Fatalf("expected the unacknowledgeable journal to be parked at %s: %v", parked, err)
	}
	if len(data) == 0 {
		t.Errorf("parked journal at %s is empty; the session bytes must survive", parked)
	}
}

// TestEventOnlySessionStillRetires guards the boundary of the change above.
// C sends no acknowledgement for an event-only session at all -- handle_exit
// goes straight to FINISHED, "No commit point to send to client" -- so for
// these the write IS the completion and the journal must still be removed.
// Parking them would leave a file per event-only session on disk forever.
func TestEventOnlySessionStillRetires(t *testing.T) {
	path := writeCacheFile(t, eventOnlyAccept(), exitMsg())
	addr := startAckServer(t, func(proc protocol.Processor) { drain(proc) })

	if err := flushCache(t, path, durabilityConfig(addr)); err != nil {
		t.Fatalf("flushFile: %v", err)
	}

	for _, leftover := range []string{path, path + IncompleteSuffix, path + RejectedSuffix} {
		if _, err := os.Stat(leftover); err == nil {
			t.Errorf("%s exists; an acknowledged event-only session must be retired, not kept", leftover)
		}
	}
}

// TestDeadLetterStripsFlushingSuffix keeps parked files out of both orphan
// recovery globs (*.log and *.log.flushing). A parked file that still ended in
// .flushing would be restored to *.log by ScanOrphans and retried after all.
func TestDeadLetterStripsFlushingSuffix(t *testing.T) {
	path := writeCacheFile(t, ioAccept())
	flushing := path + FlushingSuffix
	if err := os.Rename(path, flushing); err != nil {
		t.Fatalf("rename: %v", err)
	}

	deadLetter(flushing, RejectedSuffix, "test")

	if _, err := os.Stat(path + RejectedSuffix); err != nil {
		t.Errorf("expected %s: %v", path+RejectedSuffix, err)
	}
	if _, err := os.Stat(flushing + RejectedSuffix); err == nil {
		t.Error("parked file kept its .flushing suffix; ScanOrphans would restore and retry it")
	}
}
