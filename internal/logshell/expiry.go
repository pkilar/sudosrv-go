// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrSessionExpired means the credential deadline passed before a child started.
var ErrSessionExpired = errors.New("SSH certificate expired")

func (spec RunSpec) checkExpiry() error {
	if !spec.ExpiryDeadline.IsZero() && !time.Now().Before(spec.ExpiryDeadline) {
		return ErrSessionExpired
	}
	return nil
}

// startSessionChild keeps the root's pidfd open until the expiry watcher has
// stopped. Signalling uses process handles rather than recycled numeric PIDs.
// A separate session lets discovery include the shell's job-control groups.
func startSessionChild(build func() *exec.Cmd, spec RunSpec, interruptDrain func(), beforeStart ...func() error) (childProc, func(), error) {
	if err := spec.checkExpiry(); err != nil {
		return nil, nil, err
	}
	if spec.ExpiryDeadline.IsZero() {
		var hooks []childStartHooks
		for _, fn := range beforeStart {
			hooks = append(hooks, childStartHooks{before: fn})
		}
		child, err := startChild(build, spec.Config, spec.CmdLog, hooks...)
		return child, func() {}, err
	}
	// Refuse before launching user code when the kernel or sandbox cannot supply
	// the identity-safe signalling needed by this certificate policy.
	probe, err := openProcessFD(os.Getpid())
	if err != nil {
		return nil, nil, fmt.Errorf("certificate expiry supervision requires Linux pidfd support: %w", err)
	}
	err = unix.PidfdSendSignal(probe, 0, nil, 0)
	_ = syscall.Close(probe)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate expiry supervision cannot signal pidfds: %w", err)
	}
	rootFD := -1
	stopWatcher := func() {}
	captureMembers := func() {}
	var cmd *exec.Cmd
	wrapped := func() *exec.Cmd {
		stopWatcher()
		if rootFD >= 0 {
			_ = syscall.Close(rootFD)
			rootFD = -1
		}
		cmd = build()
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		}
		cmd.SysProcAttr.PidFD = &rootFD
		return cmd
	}
	hook := childStartHooks{
		before: func() error {
			for _, fn := range beforeStart {
				if err := fn(); err != nil {
					return err
				}
			}
			return spec.checkExpiry()
		},
		started: func(cmd *exec.Cmd) {
			if rootFD >= 0 {
				stopWatcher, captureMembers = watchExpiry(cmd.Process.Pid, rootFD, spec.ExpiryDeadline, interruptDrain)
			}
		},
		exiting: func(*exec.Cmd) { captureMembers() },
	}
	child, err := startChild(wrapped, spec.Config, spec.CmdLog, hook)
	if err != nil {
		stopWatcher()
		if rootFD >= 0 {
			_ = syscall.Close(rootFD)
		}
		return nil, nil, err
	}
	if rootFD < 0 {
		// Go's os.Process uses a pidfd when supported too, but a session-wide expiry
		// must not fall back to numeric PID signalling after the root was reaped.
		_ = cmd.Process.Kill()
		_ = child.Wait()
		return nil, nil, fmt.Errorf("certificate expiry supervision requires Linux pidfd support")
	}
	var once sync.Once
	return child, func() { once.Do(func() { stopWatcher(); _ = syscall.Close(rootFD) }) }, nil
}

// Start the watcher immediately after fork/exec, including while ptrace startup
// waits for stop events. Failed tracing attempts stop their watcher before retry.
func watchExpiry(sid, rootFD int, deadline time.Time, interruptDrain func()) (func(), func()) {
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var members []int
	exiting := false
	expired := false
	// Pin identities before the leader is reaped. Once it exits, numeric session
	// IDs alone are insufficient authority to signal newly discovered processes.
	capture := func() {
		mu.Lock()
		defer mu.Unlock()
		exiting = true
		current := pinSession(sid)
		if expired {
			for _, fd := range current {
				_ = killProcessFD(fd)
			}
		}
		members = append(members, current...)
	}
	go func() {
		defer close(done)
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-stop:
			return
		case <-timer.C:
			mu.Lock()
			expired = true
			if !exiting {
				// The before-reap hook needs this same lock, so the original
				// leader cannot be reaped while this snapshot is taken.
				if processFDID(rootFD) == sid {
					current := pinSession(sid)
					// Failed tracer startup can reap outside the normal exit hook.
					// Retain the snapshot only if the pinned leader still exists.
					if processFDID(rootFD) == sid {
						members = append(members, current...)
					} else {
						for _, fd := range current {
							_ = syscall.Close(fd)
						}
					}
				}
			}
			_ = killProcessFD(rootFD)
			for _, fd := range members {
				_ = killProcessFD(fd)
			}
			mu.Unlock()
			if interruptDrain != nil {
				interruptDrain()
			}
		}
	}()
	return func() {
		once.Do(func() {
			close(stop)
			<-done
			mu.Lock()
			defer mu.Unlock()
			for _, fd := range members {
				_ = syscall.Close(fd)
			}
			members = nil
		})
	}, capture
}

// A pidfd pins process identity even after exit and PID reuse.
func openProcessFD(pid int) (int, error) {
	return unix.PidfdOpen(pid, 0)
}

func processFDID(fd int) int {
	raw, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return -1
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if value, ok := strings.CutPrefix(line, "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil {
				return pid
			}
		}
	}
	return -1
}
func killProcessFD(fd int) error {
	return unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0)
}

// pinSession snapshots and pins members while the leader has not been reaped. Rechecking
// session membership after opening each handle prevents a reused PID from
// adding an unrelated process. Processes that explicitly detach with setsid
// are outside this session; this is not a cgroup or descendant containment.
func pinSession(sid int) []int {
	entries, _ := os.ReadDir("/proc")
	var handles []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == sid || processSession(pid) != sid {
			continue
		}
		fd, err := openProcessFD(pid)
		if err != nil {
			continue
		}
		if processSession(pid) != sid {
			_ = syscall.Close(fd)
			continue
		}
		handles = append(handles, fd)
	}
	return handles
}

func processSession(pid int) int {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return -1
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return -1
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 4 {
		return -1
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return -1
	}
	return sid
}

// RunUnrecorded runs a session without a recorder while retaining an expiry
// supervisor. The caller should keep using Exec when expiry enforcement is off.
func RunUnrecorded(spec RunSpec) (Outcome, error) {
	if err := spec.checkExpiry(); err != nil {
		return Outcome{}, err
	}
	if spec.Config == nil {
		spec.Config = &Config{}
	}
	cfg := *spec.Config
	cfg.CommandLog.Enabled, cfg.CommandLog.Required = false, false
	spec.Config, spec.CmdLog = &cfg, nil
	var inner *PTY
	var slave *os.File
	var err error
	var owned []*os.File
	defer func() { closeAll(owned) }()
	output := spec.Std.Out
	input := spec.Std.In
	if spec.Std.In != nil && IsTerminal(spec.Std.In.Fd()) {
		inner, err = OpenPTY()
		if err != nil {
			return Outcome{}, err
		}
		defer func() { _ = inner.Close() }()
		input, err = expiryFile(spec.Std.In, os.O_RDONLY, &owned)
		if err != nil {
			return Outcome{}, err
		}
		slave, err = inner.OpenSlave()
		if err != nil {
			return Outcome{}, err
		}
		defer func() { _ = slave.Close() }()
		size, _ := GetWinSize(spec.Std.In.Fd())
		_ = SetWinSize(inner.Master.Fd(), size)
		output, err = expiryFile(spec.Std.Out, os.O_WRONLY, &owned)
		if err != nil {
			return Outcome{}, err
		}
	}
	stopNotice := startTerminalExpiryNotice(spec.ExpiryDeadline, spec.Std.In, &owned)
	defer stopNotice()
	var running *exec.Cmd
	build := func() *exec.Cmd {
		cmd := exec.Command(spec.ShellPath) // #nosec G204 -- resolved shell/forced command
		cmd.Args = append([]string{ChildArgv0(spec.ShellPath, spec.Invocation.LoginShell)}, spec.Invocation.Args...)
		cmd.Env = PrepareEnv(os.Environ(), spec.EnvShell)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Std.In, spec.Std.Out, spec.Std.Err
		if inner != nil {
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		}
		running = cmd
		return cmd
	}
	child, stop, err := startSessionChild(build, spec, func() {
		closeAll(owned)
		if inner != nil {
			_ = inner.Close()
		}
	})
	if err != nil {
		return Outcome{}, err
	}
	defer stop()
	if inner != nil {
		_ = slave.Close()
		saved, err := MakeRaw(spec.Std.In.Fd())
		if err == nil {
			defer func() { _ = SetTermios(spec.Std.In.Fd(), saved) }()
		}
		stopWinch := watchWindowSize(spec.Std.In, inner, nil)
		defer stopWinch()
		relayInput(input, inner.Master, nil)
		relayOutput(inner.Master, output, nil)
	} else {
		stopSignals := forwardSignals(running)
		defer stopSignals()
	}
	outcome := child.Wait()
	stopNotice()
	stop()
	return outcome, nil
}

// expiryFile opens a pollable, independently closeable view of an SSH pipe or
// terminal. Reopening through /proc avoids changing O_NONBLOCK on the child's
// inherited open-file description. Regular files cannot stall a pipe relay and
// retain their existing offset. The caller owns only descriptors added to owned.
func expiryFile(f *os.File, flags int, owned *[]*os.File) (*os.File, error) {
	if f == nil {
		return nil, nil
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode().IsRegular() || st.Mode()&os.ModeCharDevice != 0 && !IsTerminal(f.Fd()) {
		return f, nil
	}
	copy, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), flags|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open interruptible session stream: %w", err)
	}
	*owned = append(*owned, copy)
	return copy, nil
}
