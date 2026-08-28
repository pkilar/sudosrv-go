// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/buildmatrix_test.go
package logshell

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
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

	for line := range strings.SplitSeq(readPackaging(t, targetsManifest), "\n") {
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
		for a := range strings.SplitSeq(archList, ",") {
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

const driverScript = "../../packaging/build-in-container.sh"

func runDriver(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	abs, err := filepath.Abs(driverScript)
	if err != nil {
		t.Fatalf("resolving %s: %v", driverScript, err)
	}
	cmd := exec.Command(abs, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := 0
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %s %v: %v", abs, args, err)
	}
	return stdout.String(), stderr.String(), code
}

func TestDriverRejectsUnknownTarget(t *testing.T) {
	_, errOut, code := runDriver(t, "no-such-target", "--dry-run")
	if code != 2 {
		t.Errorf("unknown target must exit 2, got %d", code)
	}
	if !strings.Contains(errOut, "no-such-target") {
		t.Errorf("error should name the target, got %q", errOut)
	}
}

// Refusing an impossible pair is what keeps "we never emulate" true: the only
// other way to satisfy the request would be to emulate it.
func TestDriverRefusesUnsupportedHostArch(t *testing.T) {
	out, errOut, code := runDriver(t, "arch", "--dry-run")
	host := runtime.GOARCH
	if host == "amd64" {
		if code != 0 {
			t.Errorf("arch/amd64 is supported, expected exit 0, got %d (%s)", code, errOut)
		}
		if !strings.Contains(out, "target=arch") {
			t.Errorf("dry run should name the target, got %q", out)
		}
		return
	}
	if code != 2 {
		t.Errorf("arch on %s must exit 2, got %d", host, code)
	}
	if !strings.Contains(errOut, "amd64") {
		t.Errorf("refusal should say which arches are supported, got %q", errOut)
	}
}

func TestDriverDryRunResolvesImage(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("no targets declared for %s", runtime.GOARCH)
	}
	out, errOut, code := runDriver(t, "rhel9", "--dry-run")
	if code != 0 {
		t.Fatalf("dry run exited %d: %s", code, errOut)
	}
	for _, want := range []string{
		"target=rhel9", "format=rpm", "image=registry.access.redhat.com/ubi9/ubi",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run missing %q; got %q", want, out)
		}
	}
}

// The driver must never hand an architecture to the container engine: doing so
// is how a build silently starts emulating.
func TestDriverNeverPassesPlatform(t *testing.T) {
	body := readPackaging(t, "../../packaging/build-in-container.sh")
	for _, banned := range []string{"--platform", "--arch", "qemu"} {
		for line := range strings.SplitSeq(body, "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") {
				continue
			}
			if strings.Contains(code, banned) {
				t.Errorf("driver references %q outside a comment, which would "+
					"reintroduce emulation: %s", banned, code)
			}
		}
	}
}

// One container-build path, not two. The retired script hardcoded a single
// image per format, which is exactly what the manifest replaces.
func TestLintPackagingScriptIsRetired(t *testing.T) {
	if _, err := os.Stat("../../packaging/lint-packaging.sh"); err == nil {
		t.Error("packaging/lint-packaging.sh still exists; build-in-container.sh " +
			"replaces it, and keeping both leaves two container-build paths that drift")
	}
	mk := readPackaging(t, "../../Makefile")
	if strings.Contains(mk, "lint-packaging.sh") {
		t.Error("Makefile still references the retired lint-packaging.sh")
	}
	if !strings.Contains(mk, "build-in-container.sh") {
		t.Error("Makefile should drive builds through build-in-container.sh")
	}
}

// CI must derive its matrix from the manifest. A restated list is a list that
// drifts, and the drift is invisible until a target silently stops being built.
func TestCIDerivesItsMatrixFromTheManifest(t *testing.T) {
	body := readPackaging(t, "../../.github/workflows/makefile.yml")

	var wf struct {
		Jobs map[string]struct {
			RunsOn   string `yaml:"runs-on"`
			Strategy struct {
				FailFast *bool `yaml:"fail-fast"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(body), &wf); err != nil {
		t.Fatalf("workflow does not parse: %v", err)
	}
	job, ok := wf.Jobs["packages"]
	if !ok {
		t.Fatal("workflow has no 'packages' job")
	}
	if job.Strategy.FailFast == nil || *job.Strategy.FailFast {
		t.Error("packages job must set fail-fast: false, so one distribution's " +
			"failure cannot hide another's")
	}
	if !strings.Contains(body, "targets.sh json") {
		t.Error("CI must build its matrix from targets.sh, not restate the target list")
	}
	for _, id := range []string{"fedora", "rhel9", "debian-stable"} {
		if strings.Contains(body, "- "+id) {
			t.Errorf("workflow hardcodes target %q; it must come from the manifest", id)
		}
	}
}
