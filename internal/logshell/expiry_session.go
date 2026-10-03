// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"errors"
	"fmt"
	"log/syslog"
	"maps"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// expiryKillRounds bounds each phase of sessionPins.terminate. Every round
// either pins processes the previous scan missed or ends the phase, so only a
// session forking faster than /proc can be scanned exhausts them.
const expiryKillRounds = 64

// sessionPins is the set of processes known to belong to one Linux session, each
// held by a pidfd so that signalling can never reach a process that merely
// reused a member's PID.
//
// The session NUMBER is not authority on its own. A session ID stays allocated
// for as long as any process -- even an unreaped zombie -- is in it, and a
// process can leave a session but never join an existing one. So while some
// pinned member is unreaped and still in sid, every process whose session is sid
// is provably in the original session. Once the last pinned member is reaped,
// the number can be handed to an unrelated session, and a scan by number could
// kill a stranger. Every scan is therefore checked against a surviving pin --
// an anchor -- before its results are trusted.
type sessionPins struct {
	sid int
	fds map[int]int // pidfd -> PID when pinned
}

func newSessionPins(sid int) *sessionPins {
	return &sessionPins{sid: sid, fds: map[int]int{}}
}

// memberOf reports whether the process behind pidfd fd is unreaped and in sid.
func memberOf(fd, sid int) bool {
	pid := processFDID(fd)
	if pid <= 0 || processSession(pid) != sid {
		return false
	}
	// The stat just read belonged to a process that reused pid only if ours was
	// reaped in between, and then the pidfd no longer names pid.
	return processFDID(fd) == pid
}

// anchored reports whether a pinned member, or one of extra, still proves that
// sid denotes the original session.
func (p *sessionPins) anchored(extra ...int) bool {
	for _, fd := range extra {
		if fd >= 0 && memberOf(fd, p.sid) {
			return true
		}
	}
	for fd := range p.fds {
		if memberOf(fd, p.sid) {
			return true
		}
	}
	return false
}

// prune releases the pins of processes that have been reaped.
func (p *sessionPins) prune() {
	for fd := range p.fds {
		if processFDID(fd) < 0 {
			_ = syscall.Close(fd)
			delete(p.fds, fd)
		}
	}
}

type pinRefresh struct {
	added    int  // newly pinned members
	unproven int  // processes in sid that could not be proven to be members
	anchored bool // whether the scan could be trusted at all
}

// refresh pins every current member not already pinned. The anchor is checked
// AFTER the scan: a pin that was in sid before the scan and is still in it after
// was in it throughout, so the session number named this session the whole time
// the candidates were being read.
func (p *sessionPins) refresh(extra ...int) pinRefresh {
	p.prune()
	known := make(map[int]bool, len(p.fds))
	for _, pid := range p.fds {
		known[pid] = true
	}
	fresh := pinSession(p.sid, known)
	if !p.anchored(extra...) {
		for fd := range fresh {
			_ = syscall.Close(fd)
		}
		return pinRefresh{unproven: len(fresh)}
	}
	maps.Copy(p.fds, fresh)
	return pinRefresh{added: len(fresh), anchored: true}
}

// running returns the pidfds of pinned members that are alive, not zombies.
func (p *sessionPins) running() []int {
	var fds []int
	for fd := range p.fds {
		pid := processFDID(fd)
		if pid <= 0 {
			continue
		}
		if state, _ := processStat(pid); state != 'Z' && state != 0 && processFDID(fd) == pid {
			fds = append(fds, fd)
		}
	}
	return fds
}

// handles returns every pinned pidfd, zombies included: a zombie still anchors.
func (p *sessionPins) handles() []int {
	return slices.Collect(maps.Keys(p.fds))
}

func (p *sessionPins) close() {
	for fd := range p.fds {
		_ = syscall.Close(fd)
	}
	clear(p.fds)
}

// signal sends sig to every pinned member and to extra. It returns how many were
// signalled and, by PID, the failures other than ESRCH (already reaped).
func (p *sessionPins) signal(sig syscall.Signal, extra ...int) (int, map[int]error) {
	sent := 0
	var failed map[int]error
	for _, fd := range append(slices.Clone(extra), p.handles()...) {
		if fd < 0 {
			continue
		}
		err := unix.PidfdSendSignal(fd, sig, nil, 0)
		switch {
		case err == nil:
			sent++
		case errors.Is(err, syscall.ESRCH):
		default:
			if failed == nil {
				failed = map[int]error{}
			}
			failed[processFDID(fd)] = err
		}
	}
	return sent, failed
}

// terminate SIGKILLs the whole session, extra (the leader's pidfd, while it is
// unreaped) included.
//
// It freezes before it kills. One scan followed by one kill misses every child
// forked between the two -- a busy `make -j` or a forking loop -- and those are
// reparented to init and run on. A stopped process cannot fork, so repeated
// scan-and-SIGSTOP rounds can only find children forked before their parent
// stopped, and they converge. A stopped process is also never reaped, so it
// keeps anchoring the session number for the next scan; a killed one may be
// reaped by init at once, taking with it the only proof that a child it just
// forked belongs here.
func (p *sessionPins) terminate(serial uint64, extra ...int) expiryReport {
	report := expiryReport{serial: serial, sid: p.sid, complete: true}
	for range expiryKillRounds {
		r := p.refresh(extra...)
		_, _ = p.signal(syscall.SIGSTOP, extra...)
		report.unproven = r.unproven
		if !r.anchored || r.added == 0 {
			break
		}
	}
	report.signalled, report.failed = p.signal(syscall.SIGKILL, extra...)
	// Sweep up anything that slipped the freeze -- a traced member resumed by
	// its tracer -- for as long as the session can still be proven to be ours.
	for range expiryKillRounds {
		r := p.refresh(extra...)
		if !r.anchored || r.added == 0 {
			report.unproven += r.unproven
			break
		}
		n, failed := p.signal(syscall.SIGKILL, extra...)
		report.signalled = max(report.signalled, n)
		for pid, err := range failed {
			if report.failed == nil {
				report.failed = map[int]error{}
			}
			report.failed[pid] = err
		}
	}
	report.complete = len(report.failed) == 0 && report.unproven == 0
	return report
}

// expiryReport is what a session termination did, for the audit log.
type expiryReport struct {
	serial    uint64
	sid       int
	signalled int
	unproven  int
	failed    map[int]error
	complete  bool
}

// log records a termination. Without it an expiry kill is indistinguishable in
// the record from the user's own `kill -9` (exit 137), and a member that
// survived it -- a setuid process logsh may not signal -- would go unnoticed.
func (r expiryReport) log() {
	// Nothing signalled means nothing was left to end: no line, rather than a
	// termination record for a session that had already finished.
	if r.signalled > 0 {
		expiryAuditf(syslog.LOG_WARNING, "session_expired serial=%d sid=%d processes=%d",
			r.serial, r.sid, r.signalled)
	}
	r.logFailures()
}

func (r expiryReport) logFailures() {
	for _, pid := range slices.Sorted(maps.Keys(r.failed)) {
		expiryAuditf(syslog.LOG_ERR, "session_expiry_kill_failed serial=%d sid=%d pid=%d error=%q: it outlives the certificate",
			r.serial, r.sid, pid, r.failed[pid])
	}
	if r.unproven > 0 {
		expiryAuditf(syslog.LOG_ERR, "session_expiry_tracking_lost serial=%d sid=%d processes=%d: they outlive the certificate",
			r.serial, r.sid, r.unproven)
	}
}

// expiryAuditf records an expiry event in syslog only. Alertf would also write
// to stderr, which here is the terminal of a session being torn down -- or
// /dev/null in the detached supervisor -- and a client that has stopped reading
// would block that write, and the teardown with it.
func expiryAuditf(p syslog.Priority, format string, args ...any) {
	if w, err := syslog.New(p|syslog.LOG_AUTHPRIV, SyslogTag); err == nil {
		_, _ = fmt.Fprintf(w, format, args...)
		_ = w.Close()
	}
}

// expiryPollTimeout converts a wait into poll(2) milliseconds, rounding up so a
// sub-millisecond remainder does not become a busy loop of zero-length polls.
func expiryPollTimeout(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Millisecond - 1) / time.Millisecond)
}
