// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/packaging_test.go
package logshell

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The install script decides whether a packaging mistake costs an audit gap or
// costs every administrator on the fleet their login. It is shell, so it is
// tested the only way shell can be: run it against a scratch root and inspect
// what it did.

const installScript = "../../packaging/logsh/logsh-install.sh"

type fakeRoot struct {
	dir        string
	sbin, conf string
	shells     string
	passwd     string
}

// newFakeRoot builds a miniature filesystem: /usr/sbin with a stand-in logsh,
// /etc/shells, /etc/passwd with three accounts.
//
// The stand-in exits 0 for -validate and -selftest, so the sequencing can be
// tested without building the real binary. verifyFails() swaps in one that
// fails, which is how the "verify gates enable" property is checked.
func newFakeRoot(t *testing.T) *fakeRoot {
	t.Helper()
	dir := t.TempDir()
	fr := &fakeRoot{
		dir:    dir,
		sbin:   filepath.Join(dir, "usr", "sbin"),
		conf:   filepath.Join(dir, "etc", "logsh"),
		shells: filepath.Join(dir, "etc", "shells"),
		passwd: filepath.Join(dir, "etc", "passwd"),
	}
	for _, d := range []string{fr.sbin, fr.conf, filepath.Dir(fr.shells)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	fr.writeLogsh(t, 0)
	if err := os.WriteFile(fr.shells, []byte("/bin/sh\n/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fr.passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"+
			"bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fr.conf, "logsh.yaml"), []byte("record_users: [root]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return fr
}

func (fr *fakeRoot) writeLogsh(t *testing.T, rc int) {
	t.Helper()
	body := "#!/bin/sh\nexit " + itoa(rc) + "\n"
	if err := os.WriteFile(filepath.Join(fr.sbin, "logsh"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (fr *fakeRoot) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	abs, err := filepath.Abs(installScript)
	if err != nil {
		t.Fatal(err)
	}
	// Executed directly via its shebang rather than through an interpreter: the
	// args are fixed test literals, but there is no reason to introduce a shell.
	cmd := exec.Command(abs, args...)
	cmd.Env = append(os.Environ(),
		"ROOT="+fr.dir,
		"SBINDIR=/usr/sbin",
		"CONFDIR=/etc/logsh",
		"SHELLS_FILE=/etc/shells",
		"PASSWD_FILE=/etc/passwd",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (fr *fakeRoot) read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fr.dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// shellOf returns an account's login shell from the scratch passwd file.
func (fr *fakeRoot) shellOf(t *testing.T, user string) string {
	t.Helper()
	for line := range strings.SplitSeq(fr.read(t, "etc/passwd"), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 7 && f[0] == user {
			return f[6]
		}
	}
	t.Fatalf("no such account in the scratch passwd: %s", user)
	return ""
}

// TestInstallChangesNoAccount is the property that keeps `apt upgrade` safe.
//
// Installing the package must put the machinery in place and switch nobody. A
// package that enabled itself would turn the first bad config into a fleet-wide
// lockout at upgrade time, with no operator in the loop.
func TestInstallChangesNoAccount(t *testing.T) {
	fr := newFakeRoot(t)
	before := fr.read(t, "etc/passwd")

	if out, err := fr.run(t, "install"); err != nil {
		t.Fatalf("install failed: %v\n%s", err, out)
	}

	if after := fr.read(t, "etc/passwd"); after != before {
		t.Errorf("install modified /etc/passwd:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	for _, name := range []string{"lsh", "lbash", "lzsh", "ldash"} {
		if _, err := os.Lstat(filepath.Join(fr.sbin, name)); err != nil {
			t.Errorf("install did not create the %s symlink: %v", name, err)
		}
		if !strings.Contains(fr.read(t, "etc/shells"), "/usr/sbin/"+name) {
			t.Errorf("install did not register /usr/sbin/%s in /etc/shells; chsh and several "+
				"daemons would refuse an account using it", name)
		}
	}
}

// TestInstallIsIdempotent covers the upgrade path: packaging reruns this on
// every version bump, and /etc/shells must not grow a duplicate each time.
func TestInstallIsIdempotent(t *testing.T) {
	fr := newFakeRoot(t)
	for range 3 {
		if out, err := fr.run(t, "install"); err != nil {
			t.Fatalf("install failed: %v\n%s", err, out)
		}
	}
	if n := strings.Count(fr.read(t, "etc/shells"), "/usr/sbin/lbash\n"); n != 1 {
		t.Errorf("/etc/shells contains %d copies of /usr/sbin/lbash after three installs, want 1", n)
	}
}

// TestEnableRefusesWhenVerifyFails is the gate that makes the whole sequence
// safe. If a broken config could still be enabled, the operator would find out
// at their next login attempt -- by which point they may have no way in.
func TestEnableRefusesWhenVerifyFails(t *testing.T) {
	fr := newFakeRoot(t)
	if out, err := fr.run(t, "install"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	fr.writeLogsh(t, 1) // -validate / -selftest now fail

	out, err := fr.run(t, "enable", "alice", "lbash")
	if err == nil {
		t.Fatalf("enable succeeded although verify failed:\n%s", out)
	}
	if got := fr.shellOf(t, "alice"); got != "/bin/bash" {
		t.Errorf("alice's shell was changed to %q despite a failing verify", got)
	}
}

// TestEnableTouchesOnlyTheTargetAccount guards the passwd rewrite. An awk
// mistake here corrupts every account on the host at once.
func TestEnableTouchesOnlyTheTargetAccount(t *testing.T) {
	fr := newFakeRoot(t)
	if out, err := fr.run(t, "install"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if out, err := fr.run(t, "enable", "alice", "lbash"); err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}

	if got := fr.shellOf(t, "alice"); got != "/usr/sbin/lbash" {
		t.Errorf("alice's shell = %q, want /usr/sbin/lbash", got)
	}
	if got := fr.shellOf(t, "root"); got != "/bin/bash" {
		t.Errorf("root's shell was changed to %q; enable must touch one account", got)
	}
	if got := fr.shellOf(t, "bob"); got != "/bin/zsh" {
		t.Errorf("bob's shell was changed to %q; enable must touch one account", got)
	}
	// Every other field of the rewritten line must survive intact.
	if !strings.Contains(fr.read(t, "etc/passwd"), "alice:x:1000:1000:Alice:/home/alice:/usr/sbin/lbash") {
		t.Errorf("the rewritten passwd line lost a field:\n%s", fr.read(t, "etc/passwd"))
	}
}

// TestUninstallRestoresEveryAccountItSwitched is the disaster this script exists
// to prevent: a package removal that deletes the symlinks and leaves accounts
// pointing at them. Those accounts then have a login shell that does not exist,
// on every host the package was removed from, simultaneously, with no way back
// in over ssh. A postrm that is just `rm -f` does exactly this.
//
// The restore is driven by scanning /etc/passwd rather than by the symlinks
// still being present, so it is order-independent -- reversing the two loops in
// cmd_uninstall changes nothing. That robustness is deliberate: a half-completed
// previous removal must still be recoverable.
func TestUninstallRestoresEveryAccountItSwitched(t *testing.T) {
	fr := newFakeRoot(t)
	if out, err := fr.run(t, "install"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	for _, u := range []string{"alice", "root"} {
		if out, err := fr.run(t, "enable", u, "lbash"); err != nil {
			t.Fatalf("enable %s: %v\n%s", u, err, out)
		}
	}

	if out, err := fr.run(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}

	for _, u := range []string{"alice", "root"} {
		got := fr.shellOf(t, u)
		if strings.Contains(got, "/usr/sbin/l") {
			t.Errorf("%s still points at %q after uninstall; that account cannot log in", u, got)
		}
		if _, err := os.Stat(filepath.Join(fr.dir, got)); err != nil && !os.IsNotExist(err) {
			t.Errorf("%s: unexpected error checking restored shell %q: %v", u, got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(fr.sbin, "lbash")); !os.IsNotExist(err) {
		t.Error("uninstall left the lbash symlink behind")
	}
	if strings.Contains(fr.read(t, "etc/shells"), "/usr/sbin/lbash") {
		t.Error("uninstall left /usr/sbin/lbash in /etc/shells")
	}
	// The pre-existing entries must survive.
	if !strings.Contains(fr.read(t, "etc/shells"), "/bin/bash") {
		t.Error("uninstall removed an /etc/shells entry it did not add")
	}
}

// TestDisableWorksWithoutTheBinary matters because disable is the recovery path.
// It must not depend on logsh being installed, runnable, or correctly
// configured -- those are exactly the conditions under which it gets used.
func TestDisableWorksWithoutTheBinary(t *testing.T) {
	fr := newFakeRoot(t)
	if out, err := fr.run(t, "install"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if out, err := fr.run(t, "enable", "alice", "lbash"); err != nil {
		t.Fatalf("enable: %v\n%s", err, out)
	}

	if err := os.Remove(filepath.Join(fr.sbin, "logsh")); err != nil {
		t.Fatal(err)
	}

	if out, err := fr.run(t, "disable", "alice", "/bin/bash"); err != nil {
		t.Fatalf("disable failed with the binary gone: %v\n%s", err, out)
	}
	if got := fr.shellOf(t, "alice"); got != "/bin/bash" {
		t.Errorf("alice's shell = %q, want /bin/bash", got)
	}
}
