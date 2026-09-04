// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/timing_e2e_test.go
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

// timingRecord is one line of a sudoreplay timing file paired with the stream
// bytes it accounts for.
type timingRecord struct {
	marker int
	delay  float64
	data   []byte
}

// readTiming parses a recording's timing file and walks the ttyout stream
// alongside it, so a test can ask which bytes a given delay precedes.
//
// That pairing is the whole point. The timing file's delay column is only
// meaningful against the payload it is attached to: sudoreplay sleeps a
// record's delay and THEN writes that record's bytes
// (sudo lib/iolog/iolog_timing.c: "sleep_time is the number of seconds to sleep
// before writing the data"). Checks that reduce the column to a sum or a count
// cannot tell a correct recording from one with every delay slid onto its
// neighbour.
func readTiming(t *testing.T, dir string) []timingRecord {
	t.Helper()

	timing, err := os.ReadFile(filepath.Join(dir, "timing"))
	if err != nil {
		t.Fatal(err)
	}
	stream, err := os.ReadFile(filepath.Join(dir, "ttyout"))
	if err != nil {
		t.Fatal(err)
	}

	var recs []timingRecord
	off := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(timing)), "\n") {
		var marker, size int
		var delay float64
		if _, err := fmt.Sscanf(line, "%d %f %d", &marker, &delay, &size); err != nil {
			continue
		}
		rec := timingRecord{marker: marker, delay: delay}
		// Marker 4 is IO_EVENT_TTYOUT; only those consume the ttyout stream.
		if marker == 4 {
			end := min(off+size, len(stream))
			rec.data = stream[off:end]
			off = end
		}
		recs = append(recs, rec)
	}
	return recs
}

// findRecord returns the record whose bytes contain needle.
func findRecord(t *testing.T, recs []timingRecord, needle string) timingRecord {
	t.Helper()
	for _, r := range recs {
		if bytes.Contains(r.data, []byte(needle)) {
			return r
		}
	}
	var have []string
	for _, r := range recs {
		have = append(have, fmt.Sprintf("%d %.6f %q", r.marker, r.delay, r.data))
	}
	t.Fatalf("no timing record carries %q; the recording holds:\n  %s",
		needle, strings.Join(have, "\n  "))
	return timingRecord{}
}

// TestIdleLandsOnTheRecordThatFollowsIt pins delay-to-payload alignment in the
// file that sudoreplay actually reads.
//
// The session prints BEFORE, idles a second, then prints AFTER. The second
// belongs to AFTER, because a delay is the pause preceding its own bytes. An
// implementation that stamped it on BEFORE instead would replay the pause a
// record early -- output appearing one idle gap late for the rest of the
// session -- while still summing to the same one second.
//
// It runs against the real daemon rather than a stub because the property spans
// both halves: logsh stamps the delay on the IoBuffer, and internal/storage
// transcribes it into the timing file. A test of either half alone would pass
// while the pair disagreed.
func TestIdleLandsOnTheRecordThatFollowsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the daemon")
	}
	addr, logDir := startSudosrv(t)
	_, slave := outerTerminal(t)

	cfg := DefaultConfig()
	cfg.Server.LogServers = []string{addr}
	cfg.LogTTYOut = true

	var userSaw bytes.Buffer
	inv := Invocation{Name: "sh", Args: []string{"-c", "printf BEFORE; sleep 1; printf AFTER"}}
	if _, err := RunRecorded(t.Context(), RunSpec{
		Config:     cfg,
		Invocation: inv,
		ShellPath:  "/bin/sh",
		EnvShell:   "/bin/sh",
	}, TerminalIO{In: slave, Out: &userSaw}); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	recs := readTiming(t, findSessionDir(t, logDir))
	before := findRecord(t, recs, "BEFORE")
	after := findRecord(t, recs, "AFTER")

	if before.delay > 0.5 {
		t.Errorf("delay on the BEFORE record = %.3fs, want near zero: nothing "+
			"preceded it, so the idle that comes AFTER it must not be charged here",
			before.delay)
	}
	if after.delay < 0.9 || after.delay > 3.0 {
		t.Errorf("delay on the AFTER record = %.3fs, want about 1s: the sleep "+
			"preceded these bytes, so sudoreplay must pause here before writing them",
			after.delay)
	}
}

// TestTrailingIdleIsNotRecorded pins the asymmetry that distinguishes
// sleep-then-write from write-then-sleep, using only the total.
//
// The session prints once and then sleeps with no further output. Because a
// delay is only ever written as part of the record that FOLLOWS it, and no
// record follows, the trailing second must not appear in the timing file at
// all: the total stays near zero even though the session ran for a second.
//
// The complement is TestIdleLandsOnTheRecordThatFollowsIt above, which sleeps
// for the same second with output on the far side and finds it charged to that
// output. The PAIR is the discriminator -- identical sleeps, totals that differ
// only by whether an event followed. An implementation that recorded the pause
// following each output instead would have to flush a trailing record here and
// would total about a second in both.
//
// It does NOT catch a delay slid one record forward; nothing follows the single
// output for a gap to slide onto. TestIdleLandsOnTheRecordThatFollowsIt covers
// that case, and does so per record.
func TestTrailingIdleIsNotRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the daemon")
	}
	addr, logDir := startSudosrv(t)
	_, slave := outerTerminal(t)

	cfg := DefaultConfig()
	cfg.Server.LogServers = []string{addr}
	cfg.LogTTYOut = true

	var userSaw bytes.Buffer
	inv := Invocation{Name: "sh", Args: []string{"-c", "printf ONLY; sleep 1"}}
	started := time.Now()
	if _, err := RunRecorded(t.Context(), RunSpec{
		Config:     cfg,
		Invocation: inv,
		ShellPath:  "/bin/sh",
		EnvShell:   "/bin/sh",
	}, TerminalIO{In: slave, Out: &userSaw}); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}
	realTime := time.Since(started)

	if realTime < time.Second {
		t.Fatalf("the session only ran %v; it was supposed to sleep a second, "+
			"so this proves nothing", realTime)
	}

	recs := readTiming(t, findSessionDir(t, logDir))
	findRecord(t, recs, "ONLY") // the output itself must be there

	var total float64
	for _, r := range recs {
		total += r.delay
	}
	if total > 0.5 {
		t.Errorf("timing file totals %.3fs for a session whose only pause came "+
			"AFTER its last output; want near zero. A trailing idle has no "+
			"following record to attach to, so recording it means delays are "+
			"being stamped on the wrong side of their bytes", total)
	}
}
