// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/main_test.go

package logshell

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain checks for leaked goroutines, matching the convention in the other
// packages here.
//
// It is worth more than usual in this one. relayInput deliberately runs forever
// on its own goroutine -- a read on the user's terminal blocks until they type,
// so waiting for it would leave a session hanging after the shell had already
// exited. In production that goroutine dies with the process moments later, but
// a test that failed to close its end of the pty would accumulate one per run,
// and goleak is what says so.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
