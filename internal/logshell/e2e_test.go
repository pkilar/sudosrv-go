// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/e2e_test.go
package logshell

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// End-to-end against the real daemon.
//
// Every other test in this package talks to a mock server, which proves logsh
// sends what it intends to send. This one proves the other half: that what it
// sends is what sudosrv expects, and that the result on disk is a session tree
// sudoreplay can read. A protocol misunderstanding -- a missing info key, the
// wrong expect_iobufs, an unacknowledged accept -- shows up only here.
//
// It builds and runs the actual binary rather than importing internal/server,
// partly because the server's shutdown handles are unexported, and partly
// because this is then exercising what an operator actually deploys.

func buildSudosrv(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "sudosrv")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/sudosrv")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building sudosrv: %v\n%s", err, out)
	}
	return bin
}

// freePort reserves a port and releases it. The window between release and the
// daemon binding is a race in principle; in a test on loopback it is not one in
// practice, and the alternative is parsing the daemon's log for its address.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// startSudosrv runs the daemon in local mode against a scratch log directory and
// returns its address and that directory.
func startSudosrv(t *testing.T) (addr, logDir string) {
	t.Helper()
	bin := buildSudosrv(t)
	dir := t.TempDir()
	logDir = filepath.Join(dir, "iolog")
	addr = freePort(t)

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := "" +
		"server:\n" +
		"  mode: local\n" +
		"  listen_address: \"" + addr + "\"\n" +
		"  server_operational_log_level: debug\n" +
		"local_storage:\n" +
		"  log_directory: \"" + logDir + "\"\n" +
		"  iolog_dir: \"%{LIVEDIR}/%{user}\"\n" +
		"  iolog_file: \"%{seq}\"\n" +
		"eventlog:\n" +
		"  log_type: none\n" +
		"api:\n" +
		"  listen_address: \"\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-config", cfgPath)
	var daemonLog bytes.Buffer
	cmd.Stdout, cmd.Stderr = &daemonLog, &daemonLog
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting sudosrv: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("sudosrv output:\n%s", daemonLog.String())
		}
	})

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return addr, logDir
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sudosrv did not start listening on %s\n%s", addr, daemonLog.String())
	return "", ""
}

// findSessionDir returns the one session directory beneath root.
func findSessionDir(t *testing.T, root string) string {
	t.Helper()
	var found []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && info.Name() == "log.json" {
			found = append(found, filepath.Dir(p))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		var all []string
		_ = filepath.Walk(filepath.Dir(root), func(p string, i os.FileInfo, e error) error {
			if e == nil {
				all = append(all, p)
			}
			return nil
		})
		t.Fatalf("expected exactly one session under %s, found %v\nfull tree:\n%s",
			root, found, strings.Join(all, "\n"))
	}
	return found[0]
}

// TestEndToEndInteractiveSessionLandsOnDisk is the whole feature, once.
func TestEndToEndInteractiveSessionLandsOnDisk(t *testing.T) {
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
		Args: []string{"-c", "printf 'END-TO-END-MARKER\\n'; exit 9"}}

	outcome, err := RunRecorded(context.Background(), cfg, inv, "/bin/sh",
		TerminalIO{In: slave, Out: &userSaw})
	if err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}
	if outcome.ExitCode != 9 {
		t.Errorf("ExitCode = %d, want 9", outcome.ExitCode)
	}

	session := findSessionDir(t, logDir)

	// The sudoreplay-compatible file set. A missing member here means the
	// transcript exists but nothing can play it back.
	for _, name := range []string{"log", "log.json", "timing", "ttyout"} {
		if _, statErr := os.Stat(filepath.Join(session, name)); statErr != nil {
			entries, _ := os.ReadDir(session)
			var have []string
			for _, e := range entries {
				have = append(have, e.Name())
			}
			t.Errorf("session is missing %s; it holds %v", name, have)
		}
	}

	ttyout, err := os.ReadFile(filepath.Join(session, "ttyout"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(ttyout, []byte("END-TO-END-MARKER")) {
		t.Errorf("the stored ttyout stream does not contain the session output: %q", ttyout)
	}

	// timing is what sudoreplay uses to pace playback. An empty one replays the
	// whole session instantaneously, which is indistinguishable from a broken
	// recording to anyone reviewing it.
	timing, err := os.ReadFile(filepath.Join(session, "timing"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(timing)) == 0 {
		t.Error("the timing file is empty; sudoreplay would have no pacing information")
	}

	// The metadata the server derived from logsh's info keys. If logsh sent a
	// key the server did not expect, or omitted one it needs, it shows up here.
	raw, err := os.ReadFile(filepath.Join(session, "log.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("log.json is not valid JSON: %v\n%s", err, raw)
	}
	for _, key := range []string{"submituser", "runuser", "command", "ttyname"} {
		if v, ok := meta[key]; !ok || v == "" {
			t.Errorf("log.json is missing %s; the audit record cannot say who ran what", key)
		}
	}
	if got, _ := meta["exit_value"].(float64); int(got) != 9 {
		t.Errorf("log.json exit_value = %v, want 9", meta["exit_value"])
	}
}

// TestEndToEndNonInteractiveSessionIsMetadataOnly proves the scp path against
// the real daemon: a record with the command and no I/O streams, and no hang.
func TestEndToEndNonInteractiveSessionIsMetadataOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the daemon")
	}
	addr, logDir := startSudosrv(t)

	cfg := DefaultConfig()
	cfg.Server.UpstreamHost = addr
	cfg.Server.UseTLS = false

	_, wOut := pipes(t)
	rIn := emptyStdin(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RunNonInteractive(context.Background(), cfg,
			Invocation{Name: "lsh", Args: []string{"-c", "true"}}, "/bin/sh",
			StdIO{In: rIn, Out: wOut, Err: wOut})
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("a metadata-only session hung against the real daemon")
	}

	session := findSessionDir(t, logDir)
	entries, err := os.ReadDir(session)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// The point of the metadata-only path: no transcript streams at all.
	for _, stream := range []string{"ttyin", "ttyout", "stdout", "stderr"} {
		if slicesContains(names, stream) {
			t.Errorf("a metadata-only session wrote a %s stream; it holds %v", stream, names)
		}
	}
	if !slicesContains(names, "log.json") {
		t.Errorf("no log.json was written; the command went unrecorded. Directory holds %v", names)
	}
}

func slicesContains(hay []string, needle string) bool {
	return slices.Contains(hay, needle)
}
