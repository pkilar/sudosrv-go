// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/exectrace.go
package logshell

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// Exec tracing: one record per execve inside the recorded session's process
// tree, obtained with ptrace.
//
// WHY PTRACE AND NOT THE SHELL. logsh relays a byte stream; it has no idea what
// the shell executed. The cheap alternative is a shell hook (bash's DEBUG trap,
// zsh's preexec) reporting each command as typed, but that only sees what is
// typed at a prompt, misses everything a script runs, and any user can switch it
// off with `trap - DEBUG`. Tracing execve catches every command in the tree --
// from scripts, from subshells, from inside vim -- and cannot be disabled from
// inside the session. It is also shell-agnostic, so dash and fish are covered
// for free.
//
// WHAT IT COSTS, stated plainly because operators will hit all three:
//
//   - Every exec stops the process until logsh resumes it. Unmeasurable in an
//     interactive session; noticeable in a build that spawns 100k processes.
//   - A process can have only ONE tracer, so strace and gdb DO NOT WORK inside a
//     traced session. For an admin shell that is a real loss.
//   - Yama ptrace_scope of 2 or 3 blocks it outright. logsh runs unprivileged, so
//     there is no way around that; it warns and carries on with session recording
//     intact rather than refusing the login.
//
// It records executions, not commands as typed: a pipeline is three records, and
// `ls` is one record for /usr/bin/ls.

// ptrace requests and event codes that Go's syscall package does not export.
const (
	ptraceSeize     = 0x4206
	ptraceInterrupt = 0x4207
	ptraceListen    = 0x4208

	ptraceEventFork      = 1
	ptraceEventVfork     = 2
	ptraceEventClone     = 3
	ptraceEventExec      = 4
	ptraceEventVforkDone = 5
	ptraceEventExit      = 6
	// ptraceEventStop only ever arrives for a SEIZEd tracee. It is what makes
	// group-stop distinguishable from an ordinary signal-delivery-stop, which
	// under classic PTRACE_ATTACH it is not -- ptrace(2) calls that situation "a
	// mess" and recommends SEIZE for exactly this reason.
	ptraceEventStop = 128
)

// waitAll matches Wait4 against every child, threads included.
const waitAll = 0x40000000 // __WALL

// ExecEvent is one observed execve.
type ExecEvent struct {
	PID  int
	Exe  string   // resolved binary, from /proc/<pid>/exe
	Argv []string // from /proc/<pid>/cmdline
}

func ptraceRaw(req, pid int, addr, data uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE,
		uintptr(req), uintptr(pid), addr, data, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// isStopSignal reports the four signals that produce a group-stop.
func isStopSignal(s syscall.Signal) bool {
	switch s {
	case syscall.SIGSTOP, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU:
		return true
	}
	return false
}

// readExecEvent reads the new process image while the tracee is stopped at its
// exec. Stopped is the only safe moment: a microsecond later the process may
// have rewritten its own argv.
func readExecEvent(pid int) ExecEvent {
	ev := ExecEvent{PID: pid}
	base := "/proc/" + strconv.Itoa(pid)

	if raw, err := os.ReadFile(base + "/cmdline"); err == nil {
		for arg := range bytes.SplitSeq(raw, []byte{0}) {
			if len(arg) > 0 {
				ev.Argv = append(ev.Argv, string(arg))
			}
		}
	}
	if exe, err := os.Readlink(base + "/exe"); err == nil {
		ev.Exe = exe
	}
	return ev
}

// tracedChild is a child process running under exec tracing.
type tracedChild struct {
	outcome chan Outcome
}

// Wait blocks until the top-level process has exited.
func (t *tracedChild) Wait() Outcome { return <-t.outcome }

// startTraced starts cmd under ptrace and begins the wait loop.
//
// The entire child lifecycle -- fork, exec, and every subsequent ptrace and
// wait4 call -- happens on ONE locked OS thread. The kernel requires ptrace
// operations to come from the thread that attached, and a Go goroutine migrates
// between threads freely, so without LockOSThread the loop fails with ESRCH the
// first time the scheduler moves it.
func startTraced(cmd *exec.Cmd, onExec func(ExecEvent), hooks ...childStartHooks) (*tracedChild, error) {
	started := make(chan error, 1)
	tc := &tracedChild{outcome: make(chan Outcome, 1)}

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		// Ptrace makes the child PTRACE_TRACEME before exec, so it stops at the
		// shell's own execve. That stop is the synchronisation point: it
		// guarantees we are attached before the shell has run anything at all,
		// including its rc files. Seizing after a plain Start would leave a
		// window -- small, but a hostile .bashrc lives exactly there.
		cmd.SysProcAttr.Ptrace = true

		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		for _, hook := range hooks {
			if hook.started != nil {
				hook.started(cmd)
			}
		}
		pid := cmd.Process.Pid

		if err := upgradeToSeize(pid); err != nil {
			// Nothing has been recorded yet and the shell is still stopped;
			// killing it is the only honest outcome, since the caller asked for
			// a traced session and cannot be given one.
			_ = cmd.Process.Kill()
			_, _ = syscall.Wait4(pid, nil, 0, nil)
			started <- err
			return
		}
		started <- nil

		tc.outcome <- traceLoop(pid, onExec, func() {
			for _, hook := range hooks {
				if hook.exiting != nil {
					hook.exiting(cmd)
				}
			}
		})
	}()

	if err := <-started; err != nil {
		return nil, err
	}
	return tc, nil
}

// upgradeToSeize converts the initial PTRACE_TRACEME attachment into a SEIZE
// attachment, which is the only one with usable group-stop semantics.
//
// The dance is: consume the exec stop, detach while delivering SIGSTOP so the
// process stays put, confirm it stopped, seize it, then let it go. Every step
// happens with the process stopped, so there is no window for it to run
// untraced.
func upgradeToSeize(pid int) error {
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("waiting for the initial trace stop: %w", err)
	}
	if !ws.Stopped() {
		return fmt.Errorf("the shell did not stop for tracing (status %v)", ws)
	}

	// Detach, delivering SIGSTOP: the process leaves ptrace-stop and immediately
	// enters group-stop instead of running.
	if err := ptraceRaw(syscall.PTRACE_DETACH, pid, 0, uintptr(syscall.SIGSTOP)); err != nil {
		return fmt.Errorf("detaching before seize: %w", err)
	}
	// WUNTRACED because we are now its plain parent, not its tracer.
	if _, err := syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil); err != nil {
		return fmt.Errorf("waiting for the stop before seize: %w", err)
	}

	opts := uintptr(syscall.PTRACE_O_TRACEEXEC |
		syscall.PTRACE_O_TRACEFORK |
		syscall.PTRACE_O_TRACEVFORK |
		syscall.PTRACE_O_TRACECLONE |
		syscall.PTRACE_O_TRACEEXIT)
	if err := ptraceRaw(ptraceSeize, pid, 0, opts); err != nil {
		// The usual cause is Yama ptrace_scope >= 2, which logsh cannot work
		// around because it runs unprivileged.
		return fmt.Errorf("PTRACE_SEIZE failed (kernel.yama.ptrace_scope may be 2 or 3): %w", err)
	}
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return fmt.Errorf("resuming the shell after seize: %w", err)
	}
	return nil
}

// traceLoop is the tracer. It returns once the top-level process has exited.
func traceLoop(top int, onExec func(ExecEvent), beforeExit ...func()) Outcome {
	tracked := map[int]bool{top: true}
	var outcome Outcome

	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, waitAll, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			// ECHILD: everything is gone.
			break
		}

		if ws.Exited() || ws.Signaled() {
			delete(tracked, pid)
			if pid == top {
				outcome = outcomeFromStatus(ws)
				break
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}
		tracked[pid] = true

		sig := ws.StopSignal()
		switch event := int(ws) >> 16; event {
		case ptraceEventExec:
			onExec(readExecEvent(pid))
			_ = ptraceRaw(syscall.PTRACE_CONT, pid, 0, 0)

		case ptraceEventFork, ptraceEventVfork, ptraceEventClone:
			// Track the new tracee immediately, even if the shell exits before
			// its initial stop has been consumed by this loop.
			if child, err := syscall.PtraceGetEventMsg(pid); err == nil {
				tracked[int(child)] = true
			}
			_ = ptraceRaw(syscall.PTRACE_CONT, pid, 0, 0)

		case ptraceEventVforkDone:
			_ = ptraceRaw(syscall.PTRACE_CONT, pid, 0, 0)

		case ptraceEventExit:
			if pid == top {
				for _, fn := range beforeExit {
					fn()
				}
			}
			_ = ptraceRaw(syscall.PTRACE_CONT, pid, 0, 0)

		case ptraceEventStop:
			// Either a group-stop or a newly attached tracee reporting in.
			// A group-stop must be LEFT stopped -- resuming it here is what
			// silently breaks ^Z inside a recorded session.
			if isStopSignal(sig) {
				if err := ptraceRaw(ptraceListen, pid, 0, 0); err != nil {
					_ = ptraceRaw(syscall.PTRACE_CONT, pid, 0, 0)
				}
			} else {
				_ = ptraceRaw(syscall.PTRACE_CONT, pid, 0, 0)
			}

		default:
			// Signal-delivery-stop: pass the signal through, or the traced
			// session would swallow every SIGINT the user sends.
			inject := uintptr(sig)
			if sig == syscall.SIGTRAP {
				inject = 0
			}
			_ = ptraceRaw(syscall.PTRACE_CONT, pid, 0, inject)
		}
	}

	detachTracees(tracked, top)
	return outcome
}

// detachDeadline bounds how long the tracer spends releasing tracees after the
// session ends. A tracee that never reaches a ptrace stop (uninterruptible I/O
// on a hung mount, say) must not be able to hold up logsh, and with it the SSH
// connection and the recording.
const detachDeadline = 2 * time.Second

// detachPollInterval is the pause between collection rounds when no tracee
// reported a stop.
const detachPollInterval = 5 * time.Millisecond

// detachSignal returns the signal to hand to PTRACE_DETACH for a tracee that
// stopped with ws. A signal-delivery-stop must re-inject its signal: detaching
// with 0 would suppress it, so a job the kernel just sent SIGHUP (the shell's
// exit hangs up the foreground group) would keep running. Every event stop --
// PTRACE_EVENT_STOP from our interrupt or a group-stop, exec/fork/exit and
// friends, a new tracee's initial stop -- carries no signal worth delivering.
func detachSignal(ws syscall.WaitStatus) uintptr {
	if int(ws)>>16 != 0 {
		return 0
	}
	sig := ws.StopSignal()
	if sig == syscall.SIGTRAP || sig == syscall.SIGTRAP|0x80 {
		return 0
	}
	return uintptr(sig)
}

// detachTracees lets everything still alive run free. A backgrounded process
// must outlive the session rather than being frozen by a tracer that has gone
// away.
//
// PTRACE_DETACH requires a ptrace stop. Leaving a running task attached would
// strand it at a later exit event, including SIGKILL from the certificate
// expiry supervisor. So every tracee is interrupted first, then all of them are
// polled without blocking. Polling every one each round matters: a process
// inside vfork cannot reach its interrupt stop until its child, itself parked in
// an unconsumed exec stop, has been detached. Blocking on one pid at a time
// deadlocks on exactly that pair.
func detachTracees(tracked map[int]bool, top int) {
	pending := make(map[int]bool, len(tracked))
	for pid := range tracked {
		if pid == top {
			continue
		}
		pending[pid] = true
		// Errors are ignored: ESRCH means the task is gone or was never ours.
		_ = ptraceRaw(ptraceInterrupt, pid, 0, 0)
	}

	deadline := time.Now().Add(detachDeadline)
	for len(pending) > 0 && time.Now().Before(deadline) {
		progressed := false
		for pid := range pending {
			var ws syscall.WaitStatus
			wpid, err := syscall.Wait4(pid, &ws, waitAll|syscall.WNOHANG, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if err != nil {
				delete(pending, pid) // ECHILD or similar: not ours to detach.
				progressed = true
				continue
			}
			if wpid == 0 {
				continue // no status change yet
			}
			progressed = true
			if !ws.Stopped() {
				delete(pending, pid) // exited or was killed
				continue
			}
			switch int(ws) >> 16 {
			case ptraceEventFork, ptraceEventVfork, ptraceEventClone:
				// The new child is auto-attached and must be detached too. Read
				// it before detaching the parent. It starts with a stop already
				// pending, so it needs no interrupt of its own.
				if child, err := syscall.PtraceGetEventMsg(pid); err == nil && !pending[int(child)] {
					pending[int(child)] = true
				}
			}
			_ = ptraceRaw(syscall.PTRACE_DETACH, pid, 0, detachSignal(ws))
			delete(pending, pid)
		}
		if !progressed {
			time.Sleep(detachPollInterval)
		}
	}
	// Anything left is deliberately not waited for. logsh is about to exit and
	// no PTRACE_O_EXITKILL is set, so the kernel detaches the remaining tracees
	// itself.
}

// outcomeFromStatus translates a raw wait status, matching waitOutcome's
// conventions so a traced and an untraced session report identically.
func outcomeFromStatus(ws syscall.WaitStatus) Outcome {
	if ws.Signaled() {
		sig := ws.Signal()
		return Outcome{
			ExitCode:   128 + int(sig),
			Signal:     signalName(sig),
			CoreDumped: ws.CoreDump(),
		}
	}
	return Outcome{ExitCode: ws.ExitStatus()}
}
