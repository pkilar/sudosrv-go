// SPDX-License-Identifier: Apache-2.0
package logshell

import "time"

// wallClockRecheck bounds how long a wait for a wall-clock instant may sleep
// before reading the wall clock again.
//
// Certificate deadlines are wall-clock instants (ValidBefore is Unix time), but
// Go timers run on CLOCK_MONOTONIC, which stops while the host is suspended or
// the VM is paused. A single timer armed for the whole interval therefore fires
// late by however long the machine slept: an hour left, a three-hour suspend,
// and the session outlives its certificate by three hours. Re-arming at most
// this far ahead caps that lateness at one recheck interval.
const wallClockRecheck = time.Second

// untilWall is how long to sleep before re-examining a wall-clock deadline:
// the remaining time, capped at wallClockRecheck. A caller loops until the wall
// clock -- not the timer -- says the deadline has passed.
//
// deadline must carry no monotonic reading (time.Unix values do not), or
// time.Until would measure on the clock this exists to avoid.
func untilWall(deadline time.Time) time.Duration {
	return min(time.Until(deadline), wallClockRecheck)
}
