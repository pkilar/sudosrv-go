// SPDX-License-Identifier: Apache-2.0
package logshell

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Notices go to the user's terminal, independently of the program's streams.
// Failure to display an informational notice must not disable expiry enforcement.
func startTerminalExpiryNotice(deadline time.Time, terminal *os.File, owned *[]*os.File, cfg *Config) func() {
	if deadline.IsZero() || terminal == nil || !IsTerminal(terminal.Fd()) {
		return func() {}
	}
	out, err := expiryFile(terminal, os.O_WRONLY, owned)
	if err != nil {
		return func() {}
	}
	return startExpiryNotice(deadline, out, cfg)
}

func startExpiryNotice(deadline time.Time, out io.Writer, cfg *Config) func() {
	if deadline.IsZero() || out == nil || !time.Now().Before(deadline) {
		return func() {}
	}
	if cfg == nil {
		cfg = DefaultConfig()
	}
	intervals, err := cfg.ExpirationReminderIntervals()
	if err != nil {
		// Configuration loading rejects malformed intervals. A caller supplying
		// an unchecked config must still retain expiry enforcement.
		intervals = nil
	}
	started := time.Now()
	stamp := deadline.UTC().Format("2006-01-02 15:04:05 UTC")
	if cfg.SessionExpirationTimezone == "local" {
		stamp = deadline.In(time.Local).Format("2006-01-02 15:04:05 MST (UTC-07:00)")
	}
	writeExpiryNotice(out, deadline, fmt.Sprintf(
		"\r\nlogsh: This session will automatically terminate when your SSH certificate expires.\r\n"+
			"logsh: Expiration: %s (%s remaining).\r\n", stamp, expiryRemaining(time.Until(deadline))))
	warn := func() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		writeExpiryNotice(out, deadline, fmt.Sprintf(
			"\r\nlogsh: WARNING: this session will automatically terminate in %s (SSH certificate expiration: %s).\r\n",
			expiryRemaining(remaining), stamp))
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		for _, interval := range intervals {
			at := deadline.Add(-interval)
			// The startup banner already gives the current remaining time.
			// Do not replay reminders whose thresholds passed before login.
			if !at.After(started) {
				continue
			}
			timer := time.NewTimer(time.Until(at))
			select {
			case <-stop:
				timer.Stop()
				return
			case <-timer.C:
				warn()
			}
		}
	}()
	return func() { once.Do(func() { close(stop); <-done }) }
}

func writeExpiryNotice(out io.Writer, deadline time.Time, message string) {
	if bounded, ok := out.(interface{ SetWriteDeadline(time.Time) error }); ok {
		// A client that stops reading must not hold startup or the warning watcher
		// open. The terminal descriptor is private to this notice writer.
		limit := time.Now().Add(250 * time.Millisecond)
		if deadline.Before(limit) {
			limit = deadline
		}
		if err := bounded.SetWriteDeadline(limit); err != nil {
			return
		}
		defer func() { _ = bounded.SetWriteDeadline(time.Time{}) }()
	}
	_, _ = io.WriteString(out, message)
}

// Round up so a newly reached warning threshold displays a full minute rather
// than understating the remaining time by a second.
func expiryRemaining(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++
	}
	var parts []string
	if hours := seconds / 3600; hours != 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes := seconds / 60 % 60; minutes != 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds %= 60; seconds != 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	return strings.Join(parts, " ")
}

// startTerminalExpiryNotice follows the lease so extension replaces all old reminders.
func (spec RunSpec) startTerminalExpiryNotice(terminal *os.File, owned *[]*os.File, cfg *Config) func() {
	if spec.Lease == nil {
		return startTerminalExpiryNotice(spec.ExpiryDeadline, terminal, owned, cfg)
	}
	if terminal == nil || !IsTerminal(terminal.Fd()) {
		return func() {}
	}
	out, err := expiryFile(terminal, os.O_WRONLY, owned)
	if err != nil {
		return func() {}
	}
	return spec.startLeaseExpiryNotice(out, cfg)
}

func (spec RunSpec) startLeaseExpiryNotice(out io.Writer, cfg *Config) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	deadline, changed, _ := spec.Lease.snapshot()
	stopNotice := startExpiryNotice(deadline, out, cfg)
	if spec.renewSocket != "" {
		writeExpiryNotice(out, deadline, "\r\nlogsh: To extend this session, run: cssh --extend\r\n")
	}
	go func() {
		defer close(done)
		defer func() { stopNotice() }()
		for {
			select {
			case <-stop:
				return
			case <-changed:
				stopNotice()
				deadline, changed, _ = spec.Lease.snapshot()
				stamp := deadline.UTC().Format("2006-01-02 15:04:05 UTC")
				if cfg != nil && cfg.SessionExpirationTimezone == "local" {
					stamp = deadline.In(time.Local).Format("2006-01-02 15:04:05 MST (UTC-07:00)")
				}
				writeExpiryNotice(out, deadline, fmt.Sprintf("\r\nlogsh: Session extended until %s.\r\n", stamp))
				stopNotice = startExpiryNotice(deadline, out, cfg)
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-done }) }
}
