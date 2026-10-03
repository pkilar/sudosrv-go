// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// readPIDFile waits for a marker file holding a PID and returns it.
func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil {
				return pid
			}
		}
		if time.Now().After(until) {
			t.Fatalf("marker %s never written", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func alive(pid int) bool {
	s := procState(pid)
	return s != "gone" && s != "Z"
}

// killOnCleanup SIGKILLs the PID in marker (if any) when the test ends.
func killOnCleanup(t *testing.T, marker string) {
	t.Helper()
	t.Cleanup(func() {
		if raw, err := os.ReadFile(marker); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && alive(pid) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
}

func waitGone(t *testing.T, pid int, within time.Duration, what string) {
	t.Helper()
	until := time.Now().Add(within)
	for time.Now().Before(until) {
		if !alive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s (pid %d) still alive after %s", what, pid, within)
}

// sessionMembers lists the live (non-zombie) processes in session sid.
func sessionMembers(sid int) []int {
	entries, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if state, s := processStat(pid); s == sid && state != 'Z' {
			out = append(out, pid)
		}
	}
	return out
}

// killSessionOnCleanup reaps stragglers of the session led by the PID in marker.
func killSessionOnCleanup(t *testing.T, marker string) {
	t.Helper()
	t.Cleanup(func() {
		raw, err := os.ReadFile(marker)
		if err != nil {
			return
		}
		sid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || sid <= 1 {
			return
		}
		for _, pid := range sessionMembers(sid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
}

// supervisorFor reports whether a detached supervisor for sid is running.
func supervisorFor(sid int) bool {
	entries, _ := os.ReadDir("/proc")
	want := ExpirySupervisorArg + "\x00" + strconv.Itoa(sid) + "\x00"
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err == nil && strings.Contains(string(raw), want) {
			return true
		}
	}
	return false
}

// TestExpiryHandoffAfterShellExit proves a job that outlives its shell is killed
// at the certificate deadline by the detached supervisor, while the session
// itself returns at once and a job that left the session is left alone.
func TestExpiryHandoffAfterShellExit(t *testing.T) {
	for _, mode := range []string{"unrecorded", "noninteractive"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			jobMarker := filepath.Join(dir, "job")
			freeMarker := filepath.Join(dir, "free")
			killOnCleanup(t, jobMarker)
			killOnCleanup(t, freeMarker)
			spec := expiryRunSpec(t)
			deadline := time.Now().Add(2500 * time.Millisecond)
			spec.ExpiryDeadline = deadline
			spec.Invocation.Args = []string{"-c",
				"trap '' HUP; " +
					"sleep 30 >/dev/null 2>&1 </dev/null & echo $! > " + jobMarker + "; " +
					"setsid sleep 30 >/dev/null 2>&1 </dev/null & echo $! > " + freeMarker + "; " +
					"exit 0"}
			start := time.Now()
			var err error
			if mode == "unrecorded" {
				_, err = RunUnrecorded(spec)
			} else {
				srv := newMockServer(t)
				spec.Config = testConfig(srv.addr)
				_, err = RunNonInteractive(t.Context(), spec)
			}
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 1500*time.Millisecond {
				t.Fatalf("session took %s: it waited for the background job", took)
			}
			job, free := readPIDFile(t, jobMarker), readPIDFile(t, freeMarker)
			if !alive(job) {
				t.Fatal("job died before the deadline")
			}
			waitGone(t, job, time.Until(deadline)+3*time.Second, "job after expiry")
			if !alive(free) {
				t.Fatal("setsid job left the session and must not be killed")
			}
		})
	}
}

// TestNoHandoffWhenNothingSurvives proves a shell that leaves nothing behind
// returns promptly and starts no supervisor.
func TestNoHandoffWhenNothingSurvives(t *testing.T) {
	spec := expiryRunSpec(t)
	spec.ExpiryDeadline = time.Now().Add(5 * time.Second)
	marker := filepath.Join(t.TempDir(), "sid")
	killSessionOnCleanup(t, marker)
	spec.Invocation.Args = []string{"-c", "echo $$ > " + marker + "; exit 0"}
	start := time.Now()
	if _, err := RunUnrecorded(spec); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("session did not return promptly")
	}
	sid := readPIDFile(t, marker)
	for range 2 {
		if supervisorFor(sid) {
			t.Fatal("a supervisor was started although nothing survived the shell")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// TestExpiryFreezesForkingSession proves that a session which keeps forking
// while it is being killed leaves no member behind.
func TestExpiryFreezesForkingSession(t *testing.T) {
	spec := expiryRunSpec(t)
	spec.ExpiryDeadline = time.Now().Add(time.Second)
	marker := filepath.Join(t.TempDir(), "sid")
	killSessionOnCleanup(t, marker)
	// Bounded: 300 iterations of a ~10ms pause outlast the 1s deadline, and each
	// leaves a sleeper behind that would otherwise live 30s.
	spec.Invocation.Args = []string{"-c", "trap '' HUP TERM; echo $$ > " + marker + "; i=0; " +
		"while [ $i -lt 300 ]; do sleep 30 >/dev/null 2>&1 </dev/null & i=$((i+1)); sleep 0.01; done; wait"}
	start := time.Now()
	out, err := RunUnrecorded(spec)
	assertExpiryOutcome(t, out, err, start)
	sid := readPIDFile(t, marker)
	until := time.Now().Add(2 * time.Second)
	for {
		left := sessionMembers(sid)
		if len(left) == 0 {
			return
		}
		if time.Now().After(until) {
			t.Fatalf("session %d members survived expiry: %v", sid, left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestExpiryWithSlaveHeldOutsideKillSet proves expiry does not hang when a
// process outside the session (setsid) keeps the inner pty slave open.
func TestExpiryWithSlaveHeldOutsideKillSet(t *testing.T) {
	for _, recorded := range []bool{false, true} {
		name := "unrecorded"
		if recorded {
			name = "recorded"
		}
		t.Run(name, func(t *testing.T) {
			spec := expiryRunSpec(t)
			spec.ExpiryDeadline = time.Now().Add(time.Second)
			_, slave := outerTerminal(t)
			spec.Std.In = slave
			marker := filepath.Join(t.TempDir(), "free")
			killOnCleanup(t, marker)
			spec.Invocation.Args = []string{"-c",
				"trap '' HUP TERM; setsid sleep 30 & echo $! > " + marker + "; sleep 30"}
			start := time.Now()
			var err error
			if recorded {
				srv := newMockServer(t)
				spec.Config = testConfig(srv.addr)
				_, err = RunRecorded(t.Context(), spec, TerminalIO{In: slave, Out: devNullFile(t)})
			} else {
				_, err = RunUnrecorded(spec)
			}
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 4*time.Second {
				t.Fatalf("session hung %s with a slave held outside the kill set", took)
			}
		})
	}
}

func devNullFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestExpirySparesJobThatLeavesAfterPinning proves a job pinned while it was
// still in the session -- the shell exited before the job's setsid ran -- is
// not killed at expiry once it has left. A pin proves identity, not
// membership. The ordinary job keeps the session anchored, which is what made
// the pinned-but-departed job reachable before membership was rechecked.
func TestExpirySparesJobThatLeavesAfterPinning(t *testing.T) {
	dir := t.TempDir()
	jobMarker := filepath.Join(dir, "job")
	freeMarker := filepath.Join(dir, "free")
	killOnCleanup(t, jobMarker)
	killOnCleanup(t, freeMarker)
	spec := expiryRunSpec(t)
	deadline := time.Now().Add(1500 * time.Millisecond)
	spec.ExpiryDeadline = deadline
	spec.Invocation.Args = []string{"-c",
		"trap '' HUP; sleep 30 >/dev/null 2>&1 </dev/null & echo $! > " + jobMarker + "; " +
			"(sleep 0.3; exec setsid sleep 30) >/dev/null 2>&1 </dev/null & echo $! > " + freeMarker + "; exit 0"}
	if _, err := RunUnrecorded(spec); err != nil {
		t.Fatal(err)
	}
	job, free := readPIDFile(t, jobMarker), readPIDFile(t, freeMarker)
	waitGone(t, job, time.Until(deadline)+3*time.Second, "job after expiry")
	if !alive(free) {
		t.Fatal("a job that left the session after being pinned was killed")
	}
	if procState(free) == "T" {
		t.Fatal("a job that left the session was left stopped")
	}
}
