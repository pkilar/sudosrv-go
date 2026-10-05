// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"errors"
	"fmt"
	"log/syslog"
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
	if spec.Lease != nil {
		if spec.Lease.expire() {
			return ErrSessionExpired
		}
		return nil
	}
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
				stopWatcher, captureMembers = watchLeaseExpiry(cmd.Process.Pid, rootFD, spec.Lease, spec.ExpiryDeadline, spec.Info.Auth.Serial, interruptDrain)
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
	return watchLeaseExpiry(sid, rootFD, nil, deadline, 0, interruptDrain)
}

// watchLeaseExpiry supervises one session until its returned stop function is
// called. The second function is the before-reap hook: it must run while the
// leader is still an unreaped zombie, because that zombie is what proves the
// session number still names this session (see sessionPins).
//
// serial identifies the certificate in the audit lines; zero when there is none.
func watchLeaseExpiry(sid, rootFD int, lease *SessionLease, deadline time.Time, serial uint64, interruptDrain func()) (func(), func()) {
	if lease == nil {
		lease = NewSessionLease(deadline)
	}
	w := &expiryWatch{
		sid:    sid,
		rootFD: rootFD,
		lease:  lease,
		serial: serial,
		pins:   newSessionPins(sid),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go w.run(interruptDrain)
	return w.close, w.capture
}

type expiryWatch struct {
	sid, rootFD int
	lease       *SessionLease
	serial      uint64
	stop, done  chan struct{}
	once        sync.Once

	// mu serialises the expiry transition with the before-reap hook, so the
	// leader cannot be reaped while a kill is under way.
	mu      sync.Mutex
	pins    *sessionPins
	exiting bool
	expired bool
}

func (w *expiryWatch) run(interruptDrain func()) {
	defer close(w.done)
	for {
		deadline, changed, _ := w.lease.snapshot()
		timer := time.NewTimer(untilWall(deadline))
		select {
		case <-w.stop:
			timer.Stop()
			return
		case <-changed:
			timer.Stop()
			continue
		case <-timer.C:
			// Also the recheck untilWall relies on: a timer that fired early
			// against the wall clock simply re-arms.
			if !w.lease.expire() {
				continue
			}
			w.mu.Lock()
			report := w.expireLocked()
			w.mu.Unlock()
			if interruptDrain != nil {
				interruptDrain()
			}
			// Logged after the drain is interrupted: syslog can be slow, and the
			// session's teardown should not wait on it.
			report.log()
			return
		}
	}
}

// expireLocked kills the whole session. The leader's pidfd joins the anchors:
// until the before-reap hook has run, the leader is unreaped, and it is the one
// member certain to prove the session number has not been reused.
func (w *expiryWatch) expireLocked() expiryReport {
	w.expired = true
	return w.pins.terminate(w.serial, w.rootFD)
}

// capture is the before-reap hook. It pins every member the leader leaves
// behind, so that they can still be told apart from strangers once the leader is
// reaped and the session number alone no longer proves anything.
func (w *expiryWatch) capture() {
	w.mu.Lock()
	w.exiting = true
	if !w.expired {
		w.pins.refresh(w.rootFD)
		w.mu.Unlock()
		return
	}
	// Expiry already fired; anything forked since its last scan dies too.
	report := w.pins.terminate(w.serial, w.rootFD)
	w.mu.Unlock()
	report.logFailures()
}

// close stops the watcher. When the leader exited on its own and members of its
// session are still running -- `nohup job &` and log out -- enforcement must
// outlive this process, so the pinned members are handed to a detached
// supervisor that kills them at the deadline. Without the handoff anything that
// survived the shell would run on indefinitely past certificate expiry.
func (w *expiryWatch) close() {
	w.once.Do(func() {
		close(w.stop)
		<-w.done
		w.mu.Lock()
		report := w.handoffLocked()
		w.pins.close()
		w.mu.Unlock()
		if report != nil {
			report.log()
		}
	})
}

// handoffLocked does close's work under mu. It returns a report only when it had
// to carry out the expiry itself.
func (w *expiryWatch) handoffLocked() *expiryReport {
	if !w.exiting || w.expired {
		// Not started, retried, or already killed: nothing to hand on.
		return nil
	}
	if w.lease.expire() {
		// The deadline passed between the shell's exit and now.
		report := w.expireLocked()
		return &report
	}
	r := w.pins.refresh()
	if !r.anchored {
		if r.unproven > 0 {
			expiryAuditf(syslog.LOG_WARNING,
				"session_expiry_tracking_lost serial=%d sid=%d processes=%d: they will outlive the certificate",
				w.serial, w.sid, r.unproven)
		}
		return nil
	}
	running := len(w.pins.running())
	if running == 0 {
		return nil
	}
	deadline := w.lease.Deadline()
	if err := startExpirySupervisor(w.sid, w.pins.handles(), deadline, w.serial); err != nil {
		expiryAuditf(syslog.LOG_ERR,
			"session_expiry_handoff_failed serial=%d sid=%d processes=%d deadline=%s error=%q: they will outlive the certificate",
			w.serial, w.sid, running, deadline.UTC().Format(time.RFC3339), err)
	}
	return nil
}

// A pidfd pins process identity even after exit and PID reuse.
func openProcessFD(pid int) (int, error) {
	return unix.PidfdOpen(pid, 0)
}

// processFDID is the PID a pidfd refers to, or -1 once that process has been
// reaped (or fd is not a pidfd). A zombie still reports its PID.
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

// pinSession opens a pidfd for every process now in session sid except the
// leader (pid == sid, which the caller holds already) and those in skip.
// Rechecking membership after opening each handle stops a reused PID from adding
// an unrelated process. The caller must still prove the session NUMBER denotes
// the original session (sessionPins.refresh) before trusting the result.
// Processes that explicitly detach with setsid are outside this session; this is
// not a cgroup or descendant containment.
func pinSession(sid int, skip map[int]bool) map[int]int {
	entries, _ := os.ReadDir("/proc")
	handles := map[int]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == sid || skip[pid] || processSession(pid) != sid {
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
		handles[fd] = pid
	}
	return handles
}

func processSession(pid int) int {
	_, sid := processStat(pid)
	return sid
}

// processStat returns a process's state letter and session ID from
// /proc/<pid>/stat, or (0, -1) if it cannot be read.
func processStat(pid int) (byte, int) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, -1
	}
	// The command name is parenthesised and may itself contain ") ", so parse
	// from the LAST one.
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, -1
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 4 || len(fields[0]) != 1 {
		return 0, -1
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0, -1
	}
	return fields[0][0], sid
}

// RunUnrecorded runs a session without a recorder while retaining an expiry
// supervisor. The caller should keep using Exec when expiry enforcement is off.
func RunUnrecorded(spec RunSpec) (Outcome, error) {
	cleanupRenewal, renewalErr := spec.prepareRenewal()
	if renewalErr != nil {
		return Outcome{}, renewalErr
	}
	defer cleanupRenewal()
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
		_ = inner.SetWinSize(size)
		output, err = expiryFile(spec.Std.Out, os.O_WRONLY, &owned)
		if err != nil {
			return Outcome{}, err
		}
	}
	stopNotice := spec.startTerminalExpiryNotice(spec.Std.In, &owned, spec.Config)
	defer stopNotice()
	var running *exec.Cmd
	build := func() *exec.Cmd {
		cmd := exec.Command(spec.ShellPath) // #nosec G204 -- resolved shell/forced command
		cmd.Args = append([]string{ChildArgv0(spec.ShellPath, spec.Invocation.LoginShell)}, spec.Invocation.Args...)
		cmd.Env = spec.childEnv(PrepareEnv(os.Environ(), spec.EnvShell))
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
