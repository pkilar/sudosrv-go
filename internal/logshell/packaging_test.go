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
	for _, name := range []string{"lsh", "lbash", "lzsh"} {
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

// TestInstallDoesNotRecreateARetiredName guards the other half of retiring a
// multi-call name: `install` runs on every upgrade, so a name left in SYMLINKS
// by accident would be silently reintroduced on every host in the fleet.
func TestInstallDoesNotRecreateARetiredName(t *testing.T) {
	fr := newFakeRoot(t)
	if out, err := fr.run(t, "install"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if _, err := os.Lstat(filepath.Join(fr.sbin, "ldash")); !os.IsNotExist(err) {
		t.Error("install created an ldash symlink; dash was retired from the shipped set")
	}
	if strings.Contains(fr.read(t, "etc/shells"), "/usr/sbin/ldash") {
		t.Error("install registered /usr/sbin/ldash in /etc/shells")
	}
}

// TestUninstallRestoresAccountsOnRetiredNames covers the upgrade path that
// retiring a name opens up.
//
// An account switched to ldash by an older version keeps working after the
// upgrade, because `install` only adds symlinks and never prunes them. Removal
// is where it breaks: if the restore sweep only walks the names this build
// still installs, that account is left pointing at a symlink whose target has
// just been deleted -- a login nobody can use, which is precisely what
// cmd_uninstall's ordering exists to prevent. LEGACY_SYMLINKS is what keeps it
// in scope.
func TestUninstallRestoresAccountsOnRetiredNames(t *testing.T) {
	fr := newFakeRoot(t)
	if out, err := fr.run(t, "install"); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}

	// Stand in for a host installed by a version that still shipped ldash: the
	// symlink AND the /etc/shells entry, since the old install created both and
	// `enable` rightly refuses a shell that is not registered.
	if err := os.Symlink("logsh", filepath.Join(fr.sbin, "ldash")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fr.shells,
		[]byte(fr.read(t, "etc/shells")+"/usr/sbin/ldash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := fr.run(t, "enable", "alice", "ldash"); err != nil {
		t.Fatalf("enable alice ldash: %v\n%s", err, out)
	}
	if got := fr.shellOf(t, "alice"); got != "/usr/sbin/ldash" {
		t.Fatalf("setup failed: alice is on %q, want /usr/sbin/ldash", got)
	}

	if out, err := fr.run(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}

	if got := fr.shellOf(t, "alice"); strings.Contains(got, "/usr/sbin/l") {
		t.Errorf("alice still points at %q after uninstall; that account cannot log in", got)
	}
	if _, err := os.Lstat(filepath.Join(fr.sbin, "ldash")); !os.IsNotExist(err) {
		t.Error("uninstall left the retired ldash symlink behind, pointing at a removed binary")
	}
	if strings.Contains(fr.read(t, "etc/shells"), "/usr/sbin/ldash") {
		t.Error("uninstall left /usr/sbin/ldash in /etc/shells")
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

// The distribution maintainer scripts are guarded here because the two mistakes
// available in them are both fleet-wide and both silent until it is too late:
// restoring accounts from the wrong hook (by which time the symlinks are gone
// and nobody can log in), and restoring them on UPGRADE (which switches
// recording off on every package update and nobody notices until they go
// looking for a transcript).

const (
	debPostinst = "../../packaging/debian/logsh.postinst"
	debPrerm    = "../../packaging/debian/logsh.prerm"
	rpmSpec     = "../../packaging/rpm/sudosrv.spec"
	archInstall = "../../packaging/arch/logsh.install"
	installVerb = "logsh-install.sh uninstall"
	enableVerb  = "logsh-install.sh enable"
)

func readPackaging(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

// section returns the text between start and the first occurrence of end after
// it, so a single case arm or spec scriptlet can be examined on its own.
func section(t *testing.T, body, start, end string) string {
	t.Helper()
	i := strings.Index(body, start)
	if i < 0 {
		t.Fatalf("could not find %q", start)
	}
	rest := body[i+len(start):]
	if head, _, ok := strings.Cut(rest, end); ok {
		return head
	}
	return rest
}

// TestRemovalRestoresAccountsFromThePreRemovalHook is the lockout guard.
//
// By the time a post-removal hook runs, the binary and the symlinks are gone,
// so any account still pointing at /usr/sbin/lbash has a login shell that does
// not exist -- on every host the package was removed from, at once.
func TestRemovalRestoresAccountsFromThePreRemovalHook(t *testing.T) {
	// Debian: prerm, and only for `remove`.
	prerm := readPackaging(t, debPrerm)
	if !strings.Contains(section(t, prerm, "remove)", ";;"), installVerb) {
		t.Errorf("%s: the remove) arm does not restore accounts", debPrerm)
	}
	if strings.Contains(readPackaging(t, debPostinst), installVerb) {
		t.Errorf("%s: postinst restores accounts; that belongs in prerm", debPostinst)
	}

	// RPM: %preun, not %postun.
	spec := readPackaging(t, rpmSpec)
	if !strings.Contains(section(t, spec, "%preun -n logsh", "\n%files"), installVerb) {
		t.Errorf("%s: the logsh %%preun does not restore accounts", rpmSpec)
	}
	if strings.Contains(section(t, spec, "%post -n logsh", "\n%preun"), installVerb) {
		t.Errorf("%s: the logsh %%post restores accounts; that belongs in %%preun", rpmSpec)
	}

	// Arch: pre_remove.
	arch := readPackaging(t, archInstall)
	if !strings.Contains(section(t, arch, "pre_remove()", "\n}"), installVerb) {
		t.Errorf("%s: pre_remove does not restore accounts", archInstall)
	}
}

// TestUpgradeDoesNotRestoreAccounts is the other half. An upgrade that restored
// accounts would silently switch recording off on every package update.
func TestUpgradeDoesNotRestoreAccounts(t *testing.T) {
	// Debian: prerm runs on `upgrade` too, so the arm must be a no-op.
	prerm := readPackaging(t, debPrerm)
	if strings.Contains(section(t, prerm, "upgrade|deconfigure|failed-upgrade)", ";;"), installVerb) {
		t.Errorf("%s: the upgrade arm restores accounts; every apt upgrade would disable "+
			"recording", debPrerm)
	}

	// RPM: %preun runs on upgrade with $1 == 1, so the call must be guarded.
	preun := section(t, readPackaging(t, rpmSpec), "%preun -n logsh", "\n%files")
	if !strings.Contains(preun, `[ "$1" = 0 ]`) {
		t.Errorf("%s: the logsh %%preun is not guarded on $1 == 0, so a yum update would "+
			"restore every account and disable recording", rpmSpec)
	}

	// Arch: pacman routes upgrades to pre_upgrade, so pre_remove is not called.
	// What must hold is that post_upgrade does not undo anything.
	arch := readPackaging(t, archInstall)
	if strings.Contains(section(t, arch, "post_upgrade()", "\n}"), installVerb) {
		t.Errorf("%s: post_upgrade restores accounts", archInstall)
	}
}

// executable strips the lines of a shell script that do not run anything:
// comments, and echoes that merely tell an operator what to type next.
//
// Both of those legitimately mention `logsh-install.sh enable`, and a plain
// substring search over the whole file flags them -- which it did, on the first
// version of the test below. What matters is whether a script CALLS enable, not
// whether it names it.
func executable(body string) string {
	var kept []string
	for line := range strings.SplitSeq(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "echo ") {
			continue
		}
		kept = append(kept, t)
	}
	return strings.Join(kept, "\n")
}

// TestNoMaintainerScriptEnablesAnAccount pins the property that keeps package
// installation safe: the machinery goes in, and switching an account to it stays
// a deliberate per-host decision. A package that enabled itself would turn the
// first bad config into a fleet-wide lockout at upgrade time.
func TestNoMaintainerScriptEnablesAnAccount(t *testing.T) {
	for _, path := range []string{debPostinst, debPrerm, archInstall} {
		if strings.Contains(executable(readPackaging(t, path)), enableVerb) {
			t.Errorf("%s enables an account; installation must switch nobody", path)
		}
	}
	spec := readPackaging(t, rpmSpec)
	for _, scriptlet := range []string{"%post -n logsh", "%preun -n logsh"} {
		if strings.Contains(executable(section(t, spec, scriptlet, "\n%files")), enableVerb) {
			t.Errorf("%s: %s enables an account", rpmSpec, scriptlet)
		}
	}
}

// The shared-asset tier: one copy of each file, installed by every format that
// needs it. Everything below was a real divergence before it was a test.
//
// The Debian package used to install ./config.yaml -- untracked and gitignored
// -- so it failed to build from a clean checkout and, on a maintainer machine,
// shipped that machine's local config to every user. It shipped no logrotate
// config at all. It created the sudosrv account nowhere, while installing a
// unit with User=sudosrv, so the daemon could not start on Debian or Ubuntu.
// None of those is visible in a diff of the format you happen to be editing,
// which is why this is a test and not a review checklist.
var recipeFiles = map[string][]string{
	// Debian's recipe is several files: debhelper takes manpages from a
	// per-package .manpages file rather than from rules, and the sysusers and
	// tmpfiles files must be staged by build-deb.sh before dpkg-buildpackage
	// runs, because dh skips commands whose inputs do not yet exist when it
	// plans its sequence.
	"deb": {
		"../../packaging/debian/rules",
		"../../packaging/debian/build-deb.sh",
		"../../packaging/debian/sudosrv.manpages",
		"../../packaging/debian/logsh.manpages",
	},
	"rpm":  {rpmSpec, "../../packaging/rpm/build-rpm.sh"},
	"arch": {"../../packaging/arch/PKGBUILD"},
}

// sharedAssets maps each file in the shared tier to the formats that must
// install it. Where a format is absent the reason is recorded, because an
// unexplained absence is exactly what this test exists to catch.
var sharedAssets = map[string][]string{
	"packaging/config/sudosrv.yaml":         {"deb", "rpm", "arch"},
	"packaging/systemd/sudosrv.service":     {"deb", "rpm", "arch"},
	"packaging/logrotate/sudosrv.logrotate": {"deb", "rpm", "arch"},
	"packaging/man/sudosrv.8":               {"deb", "rpm", "arch"},
	"packaging/man/logsh.8":                 {"deb", "rpm", "arch"},
	"packaging/logsh/logsh-install.sh":      {"deb", "rpm", "arch"},
	"examples/logsh.yaml":                   {"deb", "rpm", "arch"},
	"docs/logsh-deployment.md":              {"deb", "rpm", "arch"},
	// All three, since the RPM stopped hand-rolling groupadd/useradd: without a
	// shipped sysusers file rpm generates Requires: user(sudosrv) from the
	// %attr entries and nothing provides it, so the package will not install.
	"packaging/sysusers/sudosrv.conf": {"deb", "rpm", "arch"},
	"packaging/tmpfiles/sudosrv.conf": {"deb", "rpm", "arch"},
}

func TestEveryFormatInstallsTheSharedAssets(t *testing.T) {
	recipes := map[string]string{}
	for format, files := range recipeFiles {
		var joined strings.Builder
		for _, f := range files {
			joined.WriteString(readPackaging(t, f))
		}
		recipes[format] = joined.String()
	}

	for asset, formats := range sharedAssets {
		for _, format := range formats {
			if !strings.Contains(recipes[format], asset) {
				t.Errorf("the %s recipe does not install %s; every format that "+
					"ships it must reference the one shared copy", format, asset)
			}
		}
	}
}

// TestNoSharedAssetIsOrphaned makes adding a file to the shared tier a
// deliberate act. Without it, a new shared asset that no recipe installs looks
// exactly like one that every recipe installs.
func TestNoSharedAssetIsOrphaned(t *testing.T) {
	for _, dir := range []string{"config", "logrotate", "systemd", "sysusers", "tmpfiles", "man", "logsh"} {
		entries, err := os.ReadDir(filepath.Join("../../packaging", dir))
		if err != nil {
			t.Fatalf("reading shared asset dir %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			rel := filepath.ToSlash(filepath.Join("packaging", dir, e.Name()))
			if _, ok := sharedAssets[rel]; !ok {
				t.Errorf("%s is in the shared tier but no format is recorded as "+
					"installing it; add it to sharedAssets with the formats that do", rel)
			}
		}
	}
}

// TestNoRecipeInstallsAnUntrackedConfig is the specific regression guard for
// the defect above: a recipe reaching for a bare config.yaml at the repo root,
// which is gitignored, so the package either fails to build or ships whoever
// built it their own settings.
func TestNoRecipeInstallsAnUntrackedConfig(t *testing.T) {
	for format, files := range recipeFiles {
		for _, f := range files {
			for line := range strings.SplitSeq(readPackaging(t, f), "\n") {
				code := strings.TrimSpace(line)
				if strings.HasPrefix(code, "#") || !strings.Contains(code, "install ") {
					continue
				}
				for _, bad := range []string{" config.yaml", "/config.yaml "} {
					if strings.Contains(code, bad) && !strings.Contains(code, "packaging/config/") {
						t.Errorf("%s (%s) installs a repo-root config.yaml, which is "+
							"gitignored: %s", f, format, code)
					}
				}
			}
		}
	}
}
