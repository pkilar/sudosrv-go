// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/localsink_test.go
package logshell

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLocalRecordingIsAReplayableSession is the feature in one test: with
// RecordDir set, a session lands on disk as the same file set the daemon
// writes, and no server is involved -- the config below names no upstream at
// all, so anything that reached for one would fail rather than quietly succeed.
func TestLocalRecordingIsAReplayableSession(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a shell")
	}
	dir := filepath.Join(t.TempDir(), "capture")
	_, slave := outerTerminal(t)

	cfg := DefaultConfig()
	cfg.RecordDir = dir
	cfg.LogTTYOut = true

	var userSaw bytes.Buffer
	// Output AFTER the pause, deliberately. A delay is recorded on the event
	// that follows it, so a session that sleeps and then prints nothing leaves
	// the sleep out of the timing file entirely -- correctly, since there is no
	// event to attach it to.
	inv := Invocation{Name: "sh", Args: []string{"-c", "printf LOCAL-MARKER; sleep 1; printf DONE"}}

	started := time.Now()
	outcome, err := RunRecorded(context.Background(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil)
	if err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}
	realTime := time.Since(started)
	if outcome.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", outcome.ExitCode)
	}

	// The sudoreplay-compatible set. A missing member means the transcript
	// exists but nothing can play it back.
	for _, name := range []string{"log", "log.json", "timing", "ttyout"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			entries, _ := os.ReadDir(dir)
			var have []string
			for _, e := range entries {
				have = append(have, e.Name())
			}
			t.Errorf("recording is missing %s; it holds %v", name, have)
		}
	}

	ttyout, err := os.ReadFile(filepath.Join(dir, "ttyout"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(ttyout, []byte("LOCAL-MARKER")) {
		t.Errorf("ttyout does not hold the session output: %q", ttyout)
	}

	// Timing must reflect the session, or a replay runs at the wrong speed --
	// which for the converter use case is the whole product.
	timing, err := os.ReadFile(filepath.Join(dir, "timing"))
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	var events int
	for line := range strings.SplitSeq(strings.TrimSpace(string(timing)), "\n") {
		var marker, size int
		var delay float64
		if _, err := fmt.Sscanf(line, "%d %f %d", &marker, &delay, &size); err == nil {
			events++
			total += delay
		}
	}
	if events == 0 {
		t.Fatal("the timing file has no events; sudoreplay would have no pacing")
	}
	// The shell sleeps 1s, so a recording that collapsed the timeline or
	// invented one shows up here.
	if total < 0.9 || total > realTime.Seconds()+0.5 {
		t.Errorf("recorded time %.3fs is not the session's %.3fs", total, realTime.Seconds())
	}

	var meta map[string]any
	raw, err := os.ReadFile(filepath.Join(dir, "log.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("log.json is not valid JSON: %v\n%s", err, raw)
	}
	if meta["command"] != "/bin/sh" {
		t.Errorf("log.json command = %v, want /bin/sh", meta["command"])
	}
}

// TestLocalRecordingNeedsNoServer states the property that makes this usable
// away from any infrastructure: OpenSink must not dial when RecordDir is set.
// The upstream below is a port nothing listens on, so a sink that tried to
// connect would fail and this would not return one.
func TestLocalRecordingNeedsNoServer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RecordDir = filepath.Join(t.TempDir(), "capture")
	cfg.Server.UpstreamHost = "127.0.0.1:1"

	sink, err := OpenSink(context.Background(), cfg)
	if err != nil {
		t.Fatalf("OpenSink with RecordDir set: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
}

// TestSplitSessionDirRejectsPercent guards the reason the path is taken
// literally. storage expands %{...} and then strftime over the I/O log path, so
// a directory named for a percentage would be rewritten into something else --
// silently, and into a location the user never asked for.
func TestSplitSessionDirRejectsPercent(t *testing.T) {
	for _, dir := range []string{"/tmp/100%", "/tmp/run%{user}", "/tmp/%Y"} {
		if _, _, err := splitSessionDir(dir); err == nil {
			t.Errorf("splitSessionDir(%q) was accepted; the path expansion would rewrite it", dir)
		}
	}
}

// TestSplitSessionDirRejectsARootWithNoName covers the degenerate inputs: there
// has to be a directory to write into.
func TestSplitSessionDirRejectsARootWithNoName(t *testing.T) {
	for _, dir := range []string{"/", "//"} {
		if _, _, err := splitSessionDir(dir); err == nil {
			t.Errorf("splitSessionDir(%q) was accepted", dir)
		}
	}
}

// TestSplitSessionDirIsAbsoluteAndSplit pins what storage is handed: a relative
// path has to become absolute, or the recording lands wherever the process
// happens to be and the path reported to the user is meaningless.
func TestSplitSessionDirIsAbsoluteAndSplit(t *testing.T) {
	parent, name, err := splitSessionDir("relative/capture")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(parent) {
		t.Errorf("parent %q is not absolute", parent)
	}
	if name != "capture" {
		t.Errorf("name = %q, want capture", name)
	}
}
