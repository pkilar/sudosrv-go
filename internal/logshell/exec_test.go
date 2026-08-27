// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/exec_test.go
package logshell

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestExecPublishesTheGivenEnvShell pins the R11 fix: the value Exec publishes
// as $SHELL comes from its envShell parameter, not from path -- the program it
// actually execs.
//
// A forced-command route may exec sftp-server or rrsync. Publishing
// SHELL=/usr/lib/ssh/sftp-server to those is a claim scripts act on -- they
// test $SHELL against /etc/shells, parse its basename to choose syntax, and
// spawn it for vim's :sh, tmux and git rebase. Before this fix, Exec derived
// $SHELL from its own exec target and the caller's envShell was ignored.
//
// Exec calls syscall.Exec, which replaces the calling process on success, so it
// cannot be invoked from this test directly without killing the test binary.
// This re-execs the test binary as a subprocess instead -- the standard way to
// test code that calls exec or os.Exit: TestExecHelperProcess is that
// subprocess, and Exec's real execve replaces IT, not this process. What comes
// back on its stdout is /bin/sh reporting the $SHELL it actually inherited.
func TestExecPublishesTheGivenEnvShell(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecHelperProcess$")
	cmd.Env = append(os.Environ(), "LOGSH_WANT_EXEC_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper subprocess: %v\noutput: %s", err, out)
	}

	const want = "SHELL=/not/the/real/shell/marker"
	if got := string(out); got != want {
		t.Errorf("Exec published %q, want %q -- envShell must reach $SHELL, not "+
			"the exec target (/bin/sh)", got, want)
	}
}

// TestExecHelperProcess is not a real test. Run under a normal `go test`, it
// checks LOGSH_WANT_EXEC_HELPER and returns immediately, so it contributes
// nothing and shows as a trivial pass. It only does anything when spawned as a
// subprocess by TestExecPublishesTheGivenEnvShell, which sets that variable --
// because Exec's execve must replace a disposable process, not the test binary
// that is running the actual assertions.
func TestExecHelperProcess(t *testing.T) {
	if os.Getenv("LOGSH_WANT_EXEC_HELPER") != "1" {
		return
	}
	err := Exec("/bin/sh", "sh", "/not/the/real/shell/marker",
		[]string{"-c", `printf 'SHELL=%s' "$SHELL"`}, os.Environ())
	// Only reached if the exec itself failed to start.
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
