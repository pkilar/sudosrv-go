// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/localsink_test.go
package logshell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sudosrv/internal/logsrvclient"
	pb "sudosrv/pkg/sudosrv_proto"
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
	outcome, err := RunRecorded(t.Context(), cfg, inv, "/bin/sh",
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

	sink, err := OpenSink(t.Context(), cfg)
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

// readWire decodes a raw copy with the same reader the flush path and
// cmd/wiredump use, so a file these tests call intact is one the real code can
// read.
func readWire(t *testing.T, path string) []*pb.ClientMessage {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening the wire copy: %v", err)
	}
	defer f.Close()

	var msgs []*pb.ClientMessage
	for {
		msg, err := logsrvclient.ReadMessage(f)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return msgs
			}
			t.Fatalf("the wire copy does not decode after %d messages: %v", len(msgs), err)
		}
		msgs = append(msgs, msg)
	}
}

// TestLocalRecordingAlsoWritesTheWireCopy is the feature: the same session,
// additionally kept as the raw stream the client produced. It must be the WHOLE
// stream -- a copy missing the accept has no metadata and one missing the exit
// cannot say how the session ended, and either would decode without complaint.
func TestLocalRecordingAlsoWritesTheWireCopy(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a shell")
	}
	dir := filepath.Join(t.TempDir(), "capture")
	_, slave := outerTerminal(t)

	cfg := DefaultConfig()
	cfg.RecordDir = dir
	cfg.RecordWire = true
	cfg.LogTTYOut = true

	var userSaw bytes.Buffer
	inv := Invocation{Name: "sh", Args: []string{"-c", "printf WIRE-MARKER; sleep 1; printf DONE"}}
	if _, err := RunRecorded(t.Context(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw}, nil); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}

	// Both forms, side by side. The I/O log is asserted elsewhere; here it only
	// has to still be there, because the raw copy must be an ADDITION.
	if _, err := os.Stat(filepath.Join(dir, "timing")); err != nil {
		t.Errorf("the I/O log is missing alongside the wire copy: %v", err)
	}

	msgs := readWire(t, filepath.Join(dir, WireFileName))
	if len(msgs) < 3 {
		t.Fatalf("the wire copy holds %d messages, too few to be a session", len(msgs))
	}
	if msgs[0].GetAcceptMsg() == nil {
		t.Errorf("the wire copy does not open with an AcceptMessage; %T", msgs[0].Type)
	}
	if msgs[len(msgs)-1].GetExitMsg() == nil {
		t.Errorf("the wire copy does not end with an ExitMessage; %T", msgs[len(msgs)-1].Type)
	}

	var sawMarker bool
	var total time.Duration
	for _, m := range msgs {
		if b := m.GetTtyoutBuf(); b != nil {
			total += time.Duration(b.GetDelay().GetTvSec())*time.Second +
				time.Duration(b.GetDelay().GetTvNsec())
			if bytes.Contains(b.GetData(), []byte("WIRE-MARKER")) {
				sawMarker = true
			}
		}
	}
	if !sawMarker {
		t.Error("the wire copy does not carry the session output")
	}
	// The delays must be the real ones, not zeroes: this file exists to be the
	// record of what the client produced, timings included.
	if total < 900*time.Millisecond {
		t.Errorf("wire delays total %v, want about the 1s the shell slept", total)
	}
}

// TestLocalRecordingOmitsTheWireCopyByDefault keeps the raw stream opt-in. It
// is a second copy of the session, unfiltered and in a format nothing but this
// project reads, so it should appear only when asked for.
func TestLocalRecordingOmitsTheWireCopyByDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	sink, err := newLocalSink(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if _, err := os.Stat(filepath.Join(dir, WireFileName)); !os.IsNotExist(err) {
		t.Errorf("a wire copy was created without being asked for: %v", err)
	}
}

// TestLocalSinkRefusesToAppendToAWireFile: appending would splice two sessions
// into one stream that decodes cleanly and describes neither, which is worse
// than either failing or overwriting because nothing downstream can detect it.
func TestLocalSinkRefusesToAppendToAWireFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	first, err := newLocalSink(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := newLocalSink(dir, true); err == nil {
		t.Error("a second recording opened the existing wire file instead of refusing")
	}
}

// TestLocalSinkReportsAFailedWireWrite covers the half of this that is easy to
// get wrong: the I/O log is written by separate code and stays intact, so a
// broken raw copy has no visible symptom unless it is reported. Finish is where
// the caller looks.
func TestLocalSinkReportsAFailedWireWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "capture")
	sink, err := newLocalSink(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Close the descriptor underneath the tap, which is the shape of any write
	// failure: the next write fails and every one after it is pointless.
	if err := sink.wire.Close(); err != nil {
		t.Fatal(err)
	}
	sink.tap(&pb.ClientMessage{Type: &pb.ClientMessage_TtyoutBuf{
		TtyoutBuf: &pb.IoBuffer{Delay: spec(0), Data: []byte("x")},
	}})

	if sink.wireErr == nil {
		t.Fatal("a failed wire write was not recorded")
	}
	if err := sink.Finish(t.Context(), 0); err == nil {
		t.Error("Finish reported success with an incomplete wire copy")
	}
}

func spec(d time.Duration) *pb.TimeSpec {
	return &pb.TimeSpec{TvSec: int64(d / time.Second), TvNsec: int32(d % time.Second)}
}
