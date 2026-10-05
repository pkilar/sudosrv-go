// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"log/syslog"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ExpirySupervisorArg is the internal subcommand (`logsh __expiry-supervisor`)
// that runs a detached expiry supervisor. It is not for people to type; the
// binary re-executes itself with it when a session's shell exits while members
// of its session are still running.
const ExpirySupervisorArg = "__expiry-supervisor"

// expirySupervisorPath is the binary started for the handoff. /proc/self/exe
// still works if the installed binary has since been replaced or deleted by a
// package upgrade, which a path from os.Executable would not.
var expirySupervisorPath = "/proc/self/exe"

// expirySupervisorRescan bounds how long the detached supervisor goes without
// rescanning the session. A member exiting wakes it at once (its pidfd turns
// readable); the rescan is for the case it cannot see -- a member forking a
// child and exiting -- where the child must be pinned while some pinned member
// still anchors the session number.
const expirySupervisorRescan = time.Second

// startExpirySupervisor hands the pinned members of session sid to a detached
// process that kills the session at deadline. It is a new process because the
// supervisor must outlive logsh: sshd reports the session's exit status only
// once logsh exits, so logsh cannot stay behind to wait for the deadline.
func startExpirySupervisor(sid int, fds []int, deadline time.Time, serial uint64) error {
	files := make([]*os.File, 0, len(fds))
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, fd := range fds {
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		files = append(files, os.NewFile(uintptr(dup), "pidfd"))
	}
	cmd := exec.Command(expirySupervisorPath) // #nosec G204 -- this binary, fixed arguments
	cmd.Args = []string{AdminName, ExpirySupervisorArg,
		strconv.Itoa(sid),
		strconv.FormatInt(deadline.UnixNano(), 10),
		strconv.FormatUint(serial, 10),
		strconv.Itoa(len(files)),
	}
	// Nothing from the user's environment: the supervisor needs none of it.
	cmd.Env = []string{}
	// The pinned members arrive as fds 3.. -- the only authority the supervisor
	// has to signal anything.
	cmd.ExtraFiles = files
	// Its own session: it is not one of the members it supervises, and it is not
	// hung up when the SSH session ends. Stdio is /dev/null, so it holds no SSH
	// channel open.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// RunExpirySupervisor is the detached supervisor: `logsh __expiry-supervisor
// <sid> <deadline-unix-nanoseconds> <serial> <count>`, with count pidfds from fd 3. It
// returns once the session is empty, cannot be tracked any further, or has been
// killed at the deadline.
//
// It runs as the session's own user and can signal nothing that user could not:
// a pidfd confers no permission, and every kill still goes through the kernel's
// ordinary check.
func RunExpirySupervisor(args []string) int {
	if len(args) != 4 {
		return 2
	}
	sid, errSID := strconv.Atoi(args[0])
	unixNano, errDeadline := strconv.ParseInt(args[1], 10, 64)
	serial, errSerial := strconv.ParseUint(args[2], 10, 64)
	count, errCount := strconv.Atoi(args[3])
	if errSID != nil || errDeadline != nil || errSerial != nil || errCount != nil || sid <= 1 || count < 0 || count > 1<<16 {
		return 2
	}
	// Nanoseconds, so a renewed or test deadline is not rounded down and the
	// supervisor never kills early.
	deadline := time.Unix(0, unixNano)

	pins := newSessionPins(sid)
	defer pins.close()
	for fd := 3; fd < 3+count; fd++ {
		if pid := processFDID(fd); pid > 0 {
			pins.fds[fd] = pid
		} else {
			_ = syscall.Close(fd)
		}
	}

	for {
		if !time.Now().Before(deadline) {
			pins.terminate(serial).log()
			return 0
		}
		r := pins.refresh()
		if !r.anchored {
			// Every pinned member is gone. Ordinarily that is the session
			// ending; a process still carrying the number can no longer be told
			// apart from a stranger that reused it, so it cannot be touched.
			if r.unproven > 0 {
				expiryAuditf(syslog.LOG_ERR, "session_expiry_tracking_lost serial=%d sid=%d processes=%d: they outlive the certificate",
					serial, sid, r.unproven)
			}
			return 0
		}
		running := pins.running()
		if len(running) == 0 {
			// Only zombies remain: nothing left can outlive the certificate.
			return 0
		}
		polls := make([]unix.PollFd, len(running))
		for i, fd := range running {
			polls[i] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
		}
		// EINTR and a timeout both just mean "look again".
		_, _ = unix.Poll(polls, expiryPollTimeout(min(untilWall(deadline), expirySupervisorRescan)))
	}
}
