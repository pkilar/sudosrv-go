// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/burst_e2e_test.go
package logshell

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minBurstMsgsPerSec is the throughput a legitimate terminal burst must be
// delivered at. It is deliberately far below what the server allows and far
// above what it used to: the per-connection limit was 100 messages/sec, which
// is under what an ordinary session produces, because a pty hands over output
// in small reads. This floor fails at the old limit by more than an order of
// magnitude while leaving a slow CI machine plenty of room.
const minBurstMsgsPerSec = 1000.0

// minBurstMessages is the point below which the throughput figure stops meaning
// anything, because a session that short is dominated by connect and handshake
// rather than by delivery.
//
// How many messages a given volume of output turns into is NOT a property of
// this code: it depends on how the kernel coalesces the shell's writes before
// our read drains them, which varies with machine speed and load. The same
// command measured 3426 messages on a developer laptop and 418 on a CI runner,
// an eight-fold spread. That is why the burst below is sized so that even
// heavy coalescing clears this bar by an order of magnitude, rather than the
// bar being tuned to whatever one machine happened to produce.
const minBurstMessages = 300

// TestBurstOfOutputIsNotThrottled guards the defect that made recordings lie.
//
// `seq 1 200000` is ~1.3MB and is over in about a second, but it reaches the
// server as thousands of separate ttyout buffers. Throttled to 100/sec that
// took minutes, and the cost was not merely slowness:
//
//   - logsh writes the user's terminal BEFORE recording, so the session still
//     looked instant to the person being recorded while delivery fell behind.
//     The backlog was then charged to whatever event came next and written into
//     the timing file as elapsed time, so a replay showed multi-second pauses
//     between a keystroke and its output that never happened. A transcript that
//     misstates when things happened is worse than one that arrives late.
//   - Logout blocked until the backlog drained, because the exit waits for the
//     server to commit the session.
//
// The assertion is throughput rather than wall clock so it does not become a
// timing-sensitive flake on a loaded machine.
func TestBurstOfOutputIsNotThrottled(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the daemon")
	}
	addr, logDir := startSudosrv(t)
	_, slave := outerTerminal(t)

	cfg := DefaultConfig()
	cfg.Server.UpstreamHost = addr
	cfg.Server.UseTLS = false
	cfg.LogTTYOut = true

	var userSaw bytes.Buffer
	inv := Invocation{Name: "lbash", LoginShell: true,
		Args: []string{"-c", "seq 1 200000"}}

	started := time.Now()
	if _, err := RunRecorded(t.Context(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}
	elapsed := time.Since(started)

	session := findSessionDir(t, logDir)
	timing, err := os.ReadFile(filepath.Join(session, "timing"))
	if err != nil {
		t.Fatal(err)
	}

	var messages int
	for line := range strings.SplitSeq(strings.TrimSpace(string(timing)), "\n") {
		var marker, size int
		var delay float64
		if _, err := fmt.Sscanf(line, "%d %f %d", &marker, &delay, &size); err == nil {
			messages++
		}
	}
	// If the burst ever stops arriving as many small buffers this test still
	// passes, but it would no longer be testing throttling -- so say so rather
	// than reporting a silent success.
	if messages < minBurstMessages {
		t.Fatalf("the burst produced only %d messages, below the %d needed for the "+
			"throughput figure to mean anything; this no longer exercises per-message "+
			"throttling and the floor below would prove nothing", messages, minBurstMessages)
	}

	rate := float64(messages) / elapsed.Seconds()
	t.Logf("%d messages in %v (%.0f msg/sec)", messages, elapsed.Round(time.Millisecond), rate)
	if rate < minBurstMsgsPerSec {
		t.Errorf("delivered %.0f msg/sec, want at least %.0f: a legitimate terminal "+
			"burst is being throttled, which distorts the recorded timing and "+
			"delays logout", rate, minBurstMsgsPerSec)
	}
}
