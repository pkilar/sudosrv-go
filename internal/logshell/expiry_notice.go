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
func startTerminalExpiryNotice(deadline time.Time, terminal *os.File, owned *[]*os.File) func() {
	if deadline.IsZero() || terminal == nil || !IsTerminal(terminal.Fd()) {
		return func() {}
	}
	out, err := expiryFile(terminal, os.O_WRONLY, owned)
	if err != nil {
		return func() {}
	}
	return startExpiryNotice(deadline, out)
}

func startExpiryNotice(deadline time.Time, out io.Writer) func() {
	if deadline.IsZero() || out == nil || !time.Now().Before(deadline) {
		return func() {}
	}
	stamp := deadline.UTC().Format("2006-01-02 15:04:05 UTC")
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
	if time.Until(deadline) <= time.Minute {
		warn()
		return func() {}
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		timer := time.NewTimer(time.Until(deadline.Add(-time.Minute)))
		defer timer.Stop()
		select {
		case <-stop:
		case <-timer.C:
			warn()
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
