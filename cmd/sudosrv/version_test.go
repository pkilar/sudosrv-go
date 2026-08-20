// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/sudosrv/version_test.go
package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// versionFile is the single place the version is written. Every build target
// and all three packaging recipes derive from it; nothing restates it.
const versionFile = "../../VERSION"

// TestVersionIsNotHardcoded is the regression guard for a drift that had
// already happened: appVersion was the literal "1.0.0" while VERSION said
// 0.1.0, so `sudosrv -version` reported a release that had never shipped.
//
// A plain `go test` does not inject anything, so appVersion must still read as
// unset here. Writing a number back into the source fails this.
func TestVersionIsNotHardcoded(t *testing.T) {
	if appVersion != versionUnset {
		t.Errorf("appVersion is %q in an uninjected build, want %q -- a version "+
			"written into the source drifts from VERSION and misreports releases",
			appVersion, versionUnset)
	}
}

// TestVersionUnsetIsNotAReleaseNumber keeps the fallback unmistakable. A
// default like "0.0.0" would still look like a version to whoever reads
// `-version` output in a bug report.
func TestVersionUnsetIsNotAReleaseNumber(t *testing.T) {
	if regexp.MustCompile(`^v?\d`).MatchString(versionUnset) {
		t.Errorf("versionUnset is %q, which reads as a release number", versionUnset)
	}
}

// TestVersionFileIsWellFormed guards the file every format derives from. A
// stray "v", a second line or a trailing comment would be copied verbatim into
// an RPM Version: field and a Debian changelog entry, where each fails
// differently and none of them fails clearly.
func TestVersionFileIsWellFormed(t *testing.T) {
	raw, err := os.ReadFile(versionFile)
	if err != nil {
		t.Fatalf("reading VERSION: %v", err)
	}
	text := string(raw)

	if strings.Count(strings.TrimRight(text, "\n"), "\n") != 0 {
		t.Errorf("VERSION holds more than one line: %q", text)
	}
	version := strings.TrimSpace(text)
	if strings.HasPrefix(version, "v") {
		t.Errorf("VERSION is %q; the leading v belongs on the git tag, not the file", version)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		t.Errorf("VERSION is %q, want MAJOR.MINOR.PATCH", version)
	}
}
