// SPDX-License-Identifier: Apache-2.0

package connection

import (
	"fmt"
	"os"
	"slices"
	"testing"

	"go.uber.org/goleak"
)

// TestMain checks for leaked goroutines and for leaked FILES.
//
// The second check exists because this package once wrote session trees into its
// own source directory on every run, and four of them were committed before
// anyone noticed. handleReject builds a UUID-hierarchy path directly under
// LocalStorage.LogDirectory, so a test config that leaves that field zero gets a
// path relative to the process working directory -- which for `go test` is the
// package directory.
//
// Nothing announces that. The tests pass, the artefacts accumulate untracked,
// and `git status` slowly fills with noise until someone commits it by accident.
// A guard here turns it into a failure the first time it happens.
//
// The goleak call is spelled out rather than using VerifyTestMain because that
// helper calls os.Exit itself, leaving nowhere to run a second check.
func TestMain(m *testing.M) {
	before, err := packageDirEntries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot snapshot the package directory: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	// Only worth reporting on an otherwise green run: a failing test may well
	// have left debris behind, and that is not the interesting finding.
	if code == 0 {
		if leakErr := goleak.Find(); leakErr != nil {
			fmt.Fprintf(os.Stderr, "goroutine leak: %v\n", leakErr)
			code = 1
		}
		if stray := strayEntries(before); len(stray) > 0 {
			fmt.Fprintf(os.Stderr,
				"tests wrote %v into the package source directory.\n"+
					"Give every config in this package a LogDirectory under t.TempDir(): an empty\n"+
					"one makes handler paths relative to the test's working directory.\n",
				stray)
			code = 1
		}
	}
	os.Exit(code)
}

// packageDirEntries lists the test's working directory, which for `go test` is
// the package directory.
func packageDirEntries() ([]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names, nil
}

// strayEntries reports what appeared since the snapshot.
func strayEntries(before []string) []string {
	after, err := packageDirEntries()
	if err != nil {
		return nil
	}
	var stray []string
	for _, name := range after {
		if !slices.Contains(before, name) {
			stray = append(stray, name)
		}
	}
	return stray
}
