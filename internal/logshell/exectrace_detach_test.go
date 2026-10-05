// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/exectrace_detach_test.go
package logshell

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func stopped(sig syscall.Signal, event int) syscall.WaitStatus {
	return syscall.WaitStatus(0x7f | uint32(sig)<<8 | uint32(event)<<16)
}

func TestDetachSignal(t *testing.T) {
	tests := []struct {
		name string
		ws   syscall.WaitStatus
		want uintptr
	}{
		{"signal-delivery SIGHUP", stopped(syscall.SIGHUP, 0), uintptr(syscall.SIGHUP)},
		{"signal-delivery SIGINT", stopped(syscall.SIGINT, 0), uintptr(syscall.SIGINT)},
		{"plain SIGTRAP stop", stopped(syscall.SIGTRAP, 0), 0},
		{"SIGTRAP|0x80 syscall stop", stopped(syscall.SIGTRAP|0x80, 0), 0},
		{"PTRACE_EVENT_STOP with SIGTRAP", stopped(syscall.SIGTRAP, ptraceEventStop), 0},
		{"PTRACE_EVENT_STOP with SIGSTOP", stopped(syscall.SIGSTOP, ptraceEventStop), 0},
		{"exec event", stopped(syscall.SIGTRAP, ptraceEventExec), 0},
		{"fork event", stopped(syscall.SIGTRAP, ptraceEventFork), 0},
		{"vfork event", stopped(syscall.SIGTRAP, ptraceEventVfork), 0},
		{"exit event", stopped(syscall.SIGTRAP, ptraceEventExit), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detachSignal(tt.ws); got != tt.want {
				t.Errorf("detachSignal(%#x) = %d, want %d", uint32(tt.ws), got, tt.want)
			}
		})
	}
}

// TestTracedSessionDetachesBackgroundChild checks that a shell leaving a
// background job behind neither delays the session's return nor leaves the job
// traced.
func TestTracedSessionDetachesBackgroundChild(t *testing.T) {
	srv := newMockServer(t)
	_, slave := outerTerminal(t)
	cl := newCaptureLog(t)

	pidFile := filepath.Join(t.TempDir(), "pid")
	// HUP is ignored so the job survives the hangup the kernel sends when the
	// shell exits, and is still running when we detach.
	inv := Invocation{Name: "lsh", Args: []string{"-c",
		"/bin/sh -c 'trap \"\" HUP; echo $$ > " + pidFile + "; exec /bin/sleep 30 </dev/null >/dev/null 2>&1' & " +
			"while [ ! -s " + pidFile + " ]; do :; done"}}

	start := time.Now()
	if _, err := RunRecorded(t.Context(), RunSpec{
		Config:     tracingConfig(srv.addr),
		Invocation: inv,
		ShellPath:  "/bin/sh",
		EnvShell:   "/bin/sh",
		CmdLog:     cl.CommandLog,
	}, TerminalIO{In: slave, Out: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunRecorded: %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("session took %v to return; the detach loop is not bounded", d)
	}

	pid := waitForPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Skipf("background child already gone: %v", err)
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "TracerPid:"); ok {
			if strings.TrimSpace(v) != "0" {
				t.Errorf("background child still traced by %s", strings.TrimSpace(v))
			}
			return
		}
	}
	t.Fatal("no TracerPid line in /proc status")
}
