// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/buildmatrix_test.go
package logshell

import (
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The generated pb.go is committed. Regenerating it while building a package
// needs protoc, which no RHEL-family repository carries, and risks producing a
// different file than the one committed -- the drift the CI protoc pin exists
// to prevent. Freshness is asserted in CI instead, where protoc is pinned to
// the version the committed file was generated with.
func TestNoRecipeRegeneratesProtobuf(t *testing.T) {
	for format, files := range recipeFiles {
		for _, f := range files {
			for line := range strings.SplitSeq(readPackaging(t, f), "\n") {
				code := strings.TrimSpace(line)
				if strings.HasPrefix(code, "#") {
					continue
				}
				if strings.Contains(code, "make proto") ||
					strings.Contains(code, "$(MAKE) proto") {
					t.Errorf("%s (%s) regenerates protobuf at package-build time: %s",
						f, format, code)
				}
			}
		}
	}
}

// protobuf-compiler is absent from UBI 9, UBI 10 and Rocky 9, so declaring it
// makes every RHEL-family target unbuildable. The RPM spec declared it without
// ever invoking protoc.
func TestNoRecipeRequiresProtobufCompiler(t *testing.T) {
	for _, f := range []string{
		"../../packaging/rpm/sudosrv.spec",
		"../../packaging/debian/control",
		"../../packaging/arch/PKGBUILD",
	} {
		for line := range strings.SplitSeq(readPackaging(t, f), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") {
				continue
			}
			if strings.Contains(code, "protobuf-compiler") ||
				strings.Contains(code, "'protobuf'") {
				t.Errorf("%s declares a protobuf compiler; the committed pb.go makes "+
					"it unnecessary and no RHEL-family repo provides it: %s", f, code)
			}
		}
	}
}

const targetsScript = "../../packaging/targets.sh"
const targetsManifest = "../../packaging/targets.tsv"

// runTargets executes targets.sh and returns stdout and the exit code.
func runTargets(t *testing.T, args ...string) (string, int) {
	t.Helper()
	abs, err := filepath.Abs(targetsScript)
	if err != nil {
		t.Fatalf("resolving %s: %v", targetsScript, err)
	}
	cmd := exec.Command(abs, args...)
	out, err := cmd.Output()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %s %v: %v", abs, args, err)
	}
	return string(out), code
}

func TestTargetsManifestIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	formats := map[string]bool{"rpm": true, "deb": true, "arch": true}
	arches := map[string]bool{"amd64": true, "arm64": true}

	for _, line := range strings.Split(readPackaging(t, targetsManifest), "\n") {
		row := strings.TrimSpace(line)
		if row == "" || strings.HasPrefix(row, "#") {
			continue
		}
		f := strings.Fields(row)
		if len(f) != 4 {
			t.Errorf("row must have 4 fields (id format image arches), got %d: %q", len(f), row)
			continue
		}
		id, format, archList := f[0], f[1], f[3]
		if seen[id] {
			t.Errorf("duplicate target id %q", id)
		}
		seen[id] = true
		if !formats[format] {
			t.Errorf("target %q has unknown format %q", id, format)
		}
		if archList == "" {
			t.Errorf("target %q declares no arches", id)
		}
		for _, a := range strings.Split(archList, ",") {
			if !arches[a] {
				t.Errorf("target %q declares unknown arch %q", id, a)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("manifest declares no targets")
	}
}

// The official archlinux image publishes amd64 only, verified against the
// registry manifest list. Without this the CI matrix would schedule an Arch leg
// onto an ARM runner and fail for a reason unrelated to the packaging.
func TestArchTargetIsAmd64Only(t *testing.T) {
	out, code := runTargets(t, "get", "arch")
	if code != 0 {
		t.Fatalf("targets.sh get arch exited %d", code)
	}
	f := strings.Fields(out)
	if len(f) != 3 {
		t.Fatalf("expected format/image/arches, got %q", out)
	}
	if f[2] != "amd64" {
		t.Errorf("arch target must be amd64-only, got %q", f[2])
	}
}

func TestTargetsGetRejectsUnknownID(t *testing.T) {
	_, code := runTargets(t, "get", "no-such-target")
	if code != 2 {
		t.Errorf("unknown id must exit 2, got %d", code)
	}
}

func TestTargetsSupports(t *testing.T) {
	if _, code := runTargets(t, "supports", "arch", "amd64"); code != 0 {
		t.Errorf("arch/amd64 must be supported, exit %d", code)
	}
	if _, code := runTargets(t, "supports", "arch", "arm64"); code != 1 {
		t.Errorf("arch/arm64 must be unsupported with exit 1, got %d", code)
	}
}

func TestTargetsJSONFiltersByArch(t *testing.T) {
	out, code := runTargets(t, "json", "--arches", "amd64")
	if code != 0 {
		t.Fatalf("targets.sh json exited %d", code)
	}
	var m struct {
		Include []struct {
			ID     string `json:"id"`
			Format string `json:"format"`
			Image  string `json:"image"`
			Arch   string `json:"arch"`
			Runner string `json:"runner"`
		} `json:"include"`
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, out)
	}
	if len(m.Include) == 0 {
		t.Fatal("matrix is empty")
	}
	sawArch := false
	for _, r := range m.Include {
		if r.Arch != "amd64" {
			t.Errorf("--arches amd64 emitted a %q row for %q", r.Arch, r.ID)
		}
		if r.Runner != "ubuntu-latest" {
			t.Errorf("amd64 must map to ubuntu-latest, got %q", r.Runner)
		}
		if r.ID == "arch" {
			sawArch = true
		}
	}
	if !sawArch {
		t.Error("amd64 matrix should include the arch target")
	}
}

func TestTargetsJSONOmitsUnsupportedPairs(t *testing.T) {
	out, _ := runTargets(t, "json", "--arches", "arm64")
	var m struct {
		Include []struct {
			ID string `json:"id"`
		} `json:"include"`
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("json output does not parse: %v", err)
	}
	for _, r := range m.Include {
		if r.ID == "arch" {
			t.Error("arm64 matrix must not include the amd64-only arch target")
		}
	}
}
