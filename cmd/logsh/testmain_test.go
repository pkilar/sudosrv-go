// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"sudosrv/internal/logshell"
	"testing"
)

// TestMain lets a session test that hands survivors to the detached expiry
// supervisor re-execute this test binary (/proc/self/exe) as that supervisor,
// instead of the binary re-running the whole suite.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == logshell.ExpirySupervisorArg {
		os.Exit(logshell.RunExpirySupervisor(os.Args[2:]))
	}
	os.Exit(m.Run())
}
