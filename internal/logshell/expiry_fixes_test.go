// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	pb "sudosrv/pkg/sudosrv_proto"
)

// reapedPidfd returns a pidfd whose process has already been reaped.
func reapedPidfd(t *testing.T) int {
	t.Helper()
	fd := -1
	c := exec.Command("/bin/true")
	c.SysProcAttr = &syscall.SysProcAttr{PidFD: &fd}
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	if fd < 0 {
		t.Skip("pidfd unavailable")
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

func TestSessionPinsRefuseUnanchoredScan(t *testing.T) {
	root := reapedPidfd(t)
	marker := filepath.Join(t.TempDir(), "other")
	other := exec.Command("/bin/bash", "-c", "sleep 30 & echo $! > "+marker+"; wait")
	other.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-other.Process.Pid, syscall.SIGKILL); _ = other.Wait() })
	job := readPIDFile(t, marker)

	pins := newSessionPins(other.Process.Pid)
	t.Cleanup(pins.close)
	r := pins.refresh(root)
	if r.anchored || r.added != 0 || r.unproven < 1 {
		t.Fatalf("refresh = %+v, want unanchored with unproven members", r)
	}
	if len(pins.fds) != 0 {
		t.Fatalf("untrusted scan pinned processes: %v", pins.fds)
	}
	rep := pins.terminate(1, root)
	if rep.complete || rep.unproven < 1 {
		t.Fatalf("report = %+v, want incomplete with unproven", rep)
	}
	time.Sleep(50 * time.Millisecond)
	if !alive(job) {
		t.Fatal("terminate killed a process it could not prove was a member")
	}
}

func TestSessionPinsRunningExcludesZombies(t *testing.T) {
	fd := -1
	c := exec.Command("/bin/sh", "-c", "exit 0")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, PidFD: &fd}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if fd < 0 {
		_ = c.Wait()
		t.Skip("pidfd unavailable")
	}
	t.Cleanup(func() { _ = c.Wait() })
	pins := newSessionPins(c.Process.Pid)
	pins.fds[fd] = c.Process.Pid
	t.Cleanup(pins.close)
	until := time.Now().Add(2 * time.Second)
	for procState(c.Process.Pid) != "Z" {
		if time.Now().After(until) {
			t.Fatal("child never became a zombie")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := pins.running(); len(got) != 0 {
		t.Fatalf("running() = %v, want zombies excluded", got)
	}
	if got := pins.handles(); len(got) != 1 {
		t.Fatalf("handles() = %v, want the zombie kept as an anchor", got)
	}
}

func TestSessionPinsTerminateKillsSession(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ready")
	rootFD := -1
	c := exec.Command("/bin/bash", "-c", "trap '' HUP TERM; sleep 30 & sleep 30 & echo ok > "+marker+"; wait")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, PidFD: &rootFD}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	if rootFD < 0 {
		_ = c.Process.Kill()
		_ = c.Wait()
		t.Skip("pidfd unavailable")
	}
	sid := c.Process.Pid
	t.Cleanup(func() {
		for _, pid := range sessionMembers(sid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		_ = c.Wait()
		_ = syscall.Close(rootFD)
	})
	until := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("session did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	pins := newSessionPins(sid)
	t.Cleanup(pins.close)
	rep := pins.terminate(9, rootFD)
	if len(rep.failed) != 0 || !rep.complete || rep.signalled < 3 {
		t.Fatalf("report = %+v, want a complete kill of leader and two sleepers", rep)
	}
	until = time.Now().Add(2 * time.Second)
	for len(sessionMembers(sid)) > 0 {
		if time.Now().After(until) {
			t.Fatalf("members survived: %v", sessionMembers(sid))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunExpirySupervisorValidatesArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"1", "2", "3"},
		{"1", "2", "3", "4", "5"},
		{"abc", "1", "0", "0"},
		{"2000", "abc", "0", "0"},
		{"2000", "1", "-1", "0"},
		{"2000", "1", "0", "x"},
		{"1", "1", "0", "0"},
		{"0", "1", "0", "0"},
		{"-5", "1", "0", "0"},
		{"2000", "1", "0", "-1"},
		{"2000", "1", "0", "99999999"},
	} {
		if got := RunExpirySupervisor(args); got != 2 {
			t.Errorf("RunExpirySupervisor(%q) = %d, want 2", args, got)
		}
	}
}

func TestRunExpirySupervisorPastDeadlineReturnsPromptly(t *testing.T) {
	start := time.Now()
	if got := RunExpirySupervisor([]string{"4000000", "1", "0", "0"}); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	if time.Since(start) > time.Second {
		t.Fatal("past-deadline supervisor was not prompt")
	}
}

func TestUntilWall(t *testing.T) {
	if got := untilWall(time.Now().Add(time.Hour)); got != wallClockRecheck {
		t.Fatalf("far deadline = %s, want cap %s", got, wallClockRecheck)
	}
	got := untilWall(time.Now().Add(200 * time.Millisecond))
	if got <= 0 || got > 200*time.Millisecond {
		t.Fatalf("near deadline = %s, want the remaining time", got)
	}
	if got := untilWall(time.Now().Add(-time.Minute)); got > 0 {
		t.Fatalf("past deadline = %s, want non-positive", got)
	}
}

// TestPTYCloseInterruptsBlockedMasterRead proves the master stays pollable, even
// after SetWinSize, so Close can wake a read while the slave is still open.
func TestPTYCloseInterruptsBlockedMasterRead(t *testing.T) {
	p, err := OpenPTY()
	if err != nil {
		t.Fatal(err)
	}
	slave, err := p.OpenSlave()
	if err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	defer func() { _ = slave.Close() }()
	if err := p.SetWinSize(WinSize{Rows: 30, Cols: 100}); err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := p.Master.Read(make([]byte, 16))
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = p.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt a blocked master Read")
	}
}

func TestMetadataNestedInteractiveRecordsOuterTerminal(t *testing.T) {
	srv := newMockServer(t)
	spec := expiryRunSpec(t)
	spec.Config = testConfig(srv.addr)
	_, slave := outerTerminal(t)
	spec.Std.In = slave
	outerName := TTYNameOf(slave.Fd())
	if outerName == "" {
		t.Fatal("no outer terminal name")
	}
	if _, err := RunMetadataOnly(t.Context(), spec, Nesting{Kind: NestedSudo}); err != nil {
		t.Fatal(err)
	}
	waitForExit(t, srv)
	_, _, _, _, acc := srv.snapshot()
	if got := infoValue(acc, "ttyname"); got != outerName {
		t.Fatalf("ttyname = %q, want the outer terminal %q", got, outerName)
	}
}

func TestMetadataNestedInteractiveSendsNoIOEvents(t *testing.T) {
	srv := newMockServer(t)
	spec := expiryRunSpec(t)
	spec.Config = testConfig(srv.addr)
	spec.ExpiryDeadline = time.Now().Add(1500 * time.Millisecond)
	outer, slave := outerTerminal(t)
	spec.Std.In = slave
	type result struct {
		out Outcome
		err error
	}
	res := make(chan result, 1)
	start := time.Now()
	go func() {
		out, err := RunMetadataOnly(context.Background(), spec, Nesting{Kind: NestedSudo})
		res <- result{out, err}
	}()
	time.Sleep(500 * time.Millisecond)
	_ = SetWinSize(outer.Master.Fd(), WinSize{Rows: 40, Cols: 120})
	_ = syscall.Kill(os.Getpid(), syscall.SIGWINCH)
	time.Sleep(100 * time.Millisecond)
	_ = syscall.Kill(os.Getpid(), syscall.SIGWINCH)
	r := <-res
	assertExpiryOutcome(t, r.out, r.err, start)
	waitForExit(t, srv)
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.winsizes) != 0 || len(srv.suspend) != 0 {
		t.Fatalf("event-only session received winsize=%d suspend=%d events", len(srv.winsizes), len(srv.suspend))
	}
}

func eventOnlyAccept() *pb.ClientMessage {
	return &pb.ClientMessage{Type: &pb.ClientMessage_AcceptMsg{AcceptMsg: &pb.AcceptMessage{ExpectIobufs: false}}}
}

func TestOpenSinkIgnoresUnmarkedDeadline(t *testing.T) {
	srv := newMockServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	sink, err := OpenSink(ctx, testConfig(srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	if _, err := sink.Start(ctx, eventOnlyAccept()); err != nil {
		t.Fatal(err)
	}
	cancel()
	exit := &pb.ClientMessage{Type: &pb.ClientMessage_ExitMsg{ExitMsg: &pb.ExitMessage{}}}
	if err := sink.Send(exit); err != nil {
		t.Fatalf("Send after the connect context ended: %v", err)
	}
	if err := sink.Finish(t.Context(), 0); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	waitForExit(t, srv)
	stream := streamSinkOf(t, sink)
	if stream.lifetime != nil {
		t.Fatal("an unmarked caller deadline became the sink lifetime")
	}
}

func TestOpenSinkAdoptsMarkedLifetime(t *testing.T) {
	srv := newMockServer(t)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), recordingLifetimeKey{}, true))
	defer cancel()
	sink, err := OpenSink(ctx, testConfig(srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	stream := streamSinkOf(t, sink)
	if stream.lifetime != ctx {
		t.Fatal("a recordingLifetimeKey context was not adopted as the sink lifetime")
	}
}

// streamSinkOf unwraps the stream sink OpenSink returns behind its buffer.
func streamSinkOf(t *testing.T, sink Sink) *streamSink {
	t.Helper()
	buffered, ok := sink.(*bufferedSink)
	if !ok {
		t.Fatalf("OpenSink returned %T, want *bufferedSink", sink)
	}
	stream, ok := buffered.inner.(*streamSink)
	if !ok {
		t.Fatalf("buffered sink wraps %T, want *streamSink", buffered.inner)
	}
	return stream
}
