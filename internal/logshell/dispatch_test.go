// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/dispatch_test.go
package logshell

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestParseInvocation pins the argv[0] decomposition.
//
// The login-dash cases are the ones that matter. sshd marks a login shell by
// prepending "-" to the basename, so a recorded account arrives as "-lbash". If
// the dash is not stripped before the map lookup the shell never resolves; if it
// is not RESTORED on the child's argv[0], /etc/profile and ~/.bash_profile
// silently stop running for every account on the fleet.
func TestParseInvocation(t *testing.T) {
	tests := []struct {
		name      string
		argv      []string
		wantName  string
		wantLogin bool
		wantArgs  []string
	}{
		{
			name:      "sshd login shell",
			argv:      []string{"-lbash"},
			wantName:  "lbash",
			wantLogin: true,
			wantArgs:  []string{},
		},
		{
			name:      "direct invocation",
			argv:      []string{"lbash"},
			wantName:  "lbash",
			wantLogin: false,
			wantArgs:  []string{},
		},
		{
			name:      "absolute path",
			argv:      []string{"/usr/sbin/lzsh"},
			wantName:  "lzsh",
			wantLogin: false,
			wantArgs:  []string{},
		},
		{
			// login(1) and some su implementations pass the full path with the
			// dash glued on. Taking the basename before stripping would leave
			// "-usr" or miss the dash entirely.
			name:      "login shell spelled with a path",
			argv:      []string{"-/usr/sbin/lbash"},
			wantName:  "lbash",
			wantLogin: true,
			wantArgs:  []string{},
		},
		{
			name:      "non-interactive command is passed through verbatim",
			argv:      []string{"-lbash", "-c", "scp -t /tmp/x"},
			wantName:  "lbash",
			wantLogin: true,
			wantArgs:  []string{"-c", "scp -t /tmp/x"},
		},
		{
			name:      "own name selects admin mode",
			argv:      []string{"/usr/sbin/logsh", "-validate"},
			wantName:  AdminName,
			wantLogin: false,
			wantArgs:  []string{"-validate"},
		},
		{
			// A bare "-" leaves nothing after stripping. Falling back to the
			// admin name yields a clear diagnostic instead of an empty map key.
			name:      "bare dash",
			argv:      []string{"-"},
			wantName:  AdminName,
			wantLogin: true,
			wantArgs:  []string{},
		},
		{
			name:      "empty argv",
			argv:      nil,
			wantName:  AdminName,
			wantLogin: false,
			wantArgs:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseInvocation(tt.argv)
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.LoginShell != tt.wantLogin {
				t.Errorf("LoginShell = %v, want %v", got.LoginShell, tt.wantLogin)
			}
			if len(got.Args) != len(tt.wantArgs) {
				t.Fatalf("Args = %q, want %q", got.Args, tt.wantArgs)
			}
			for i := range got.Args {
				if got.Args[i] != tt.wantArgs[i] {
					t.Errorf("Args[%d] = %q, want %q", i, got.Args[i], tt.wantArgs[i])
				}
			}
		})
	}
}

// TestChildArgv0 pins the dash convention every shell reads to decide whether it
// is a login shell. It must be the BASENAME with the dash, matching what sshd
// itself builds -- "-bash", never "-/bin/bash".
func TestChildArgv0(t *testing.T) {
	if got := ChildArgv0("/bin/bash", true); got != "-bash" {
		t.Errorf("login ChildArgv0 = %q, want %q; profile scripts would not run", got, "-bash")
	}
	if got := ChildArgv0("/bin/bash", false); got != "bash" {
		t.Errorf("non-login ChildArgv0 = %q, want %q", got, "bash")
	}
	if got := ChildArgv0("/usr/bin/fish", true); got != "-fish" {
		t.Errorf("ChildArgv0 = %q, want %q", got, "-fish")
	}
}

// TestParseInvocationRoundTripsThroughChildArgv0 is the property that actually
// matters: whatever sshd hands us, the shell we exec must see the same
// login-ness it would have seen without logsh in the picture.
func TestParseInvocationRoundTripsThroughChildArgv0(t *testing.T) {
	inv := ParseInvocation([]string{"-lbash"})
	if got := ChildArgv0("/bin/bash", inv.LoginShell); got != "-bash" {
		t.Errorf("sshd passed -lbash but the shell would be exec'd as %q, not %q", got, "-bash")
	}

	inv = ParseInvocation([]string{"/usr/sbin/lbash", "-c", "id"})
	if got := ChildArgv0("/bin/bash", inv.LoginShell); got != "bash" {
		t.Errorf("a non-login invocation would be exec'd as %q, not %q", got, "bash")
	}
}

func TestResolveShell(t *testing.T) {
	dir := t.TempDir()
	realShell := filepath.Join(dir, "myshell")
	if err := os.WriteFile(realShell, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	notExec := filepath.Join(dir, "notexec")
	if err := os.WriteFile(notExec, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Shells: map[string]string{
		"lmine":    realShell,
		"lnotexec": notExec,
		"lmissing": filepath.Join(dir, "absent"),
	}}

	if got, err := cfg.ResolveShell("lmine"); err != nil || got != realShell {
		t.Errorf("ResolveShell(lmine) = %q, %v; want %q, nil", got, err, realShell)
	}

	// The allowlist is the whole point: an operator-created symlink named after
	// something not in the map must not become a way to exec it.
	if _, err := cfg.ResolveShell("lrm"); err == nil {
		t.Error("an unmapped invocation name resolved; the shells map is supposed to be an allowlist")
	}
	if _, err := cfg.ResolveShell("lnotexec"); err == nil {
		t.Error("a non-executable shell resolved")
	}
	if _, err := cfg.ResolveShell("lmissing"); err == nil {
		t.Error("a missing shell resolved")
	}
}

func TestPrepareEnvOverridesSHELL(t *testing.T) {
	// The stale value is what sshd sets from the passwd entry: the logsh
	// symlink. Leaving it makes vim's :sh, tmux and screen each start a nested
	// recorder inside the session already being recorded.
	env := []string{"PATH=/bin", "SHELL=/usr/sbin/lbash", "TERM=xterm"}
	got := PrepareEnv(env, "/bin/bash")

	var shell string
	seen := map[string]bool{}
	for _, kv := range got {
		seen[kv] = true
		if len(kv) > 6 && kv[:6] == "SHELL=" {
			if shell != "" {
				t.Fatalf("PrepareEnv produced two SHELL entries: %q", got)
			}
			shell = kv[6:]
		}
	}
	if shell != "/bin/bash" {
		t.Errorf("SHELL = %q, want /bin/bash", shell)
	}
	if !seen["PATH=/bin"] || !seen["TERM=xterm"] {
		t.Errorf("PrepareEnv disturbed unrelated variables: %q", got)
	}
}

func TestPrepareEnvAddsSHELLWhenAbsent(t *testing.T) {
	got := PrepareEnv([]string{"PATH=/bin"}, "/bin/zsh")
	found := false
	for _, kv := range got {
		if kv == "SHELL=/bin/zsh" {
			found = true
		}
	}
	if !found {
		t.Errorf("PrepareEnv did not add SHELL: %q", got)
	}
}

// TestNamesInUseMatchesOnTheBasename underpins the selftest rule that decides
// whether an unresolvable shell mapping is fatal.
//
// Failing on any absent shell would make -selftest unusable as a package
// postinst check: the shipped map lists lksh, and /bin/ksh is not present on a
// great many hosts. Only a mapping some account is ACTUALLY using can break a
// login, so only that one is fatal.
func TestNamesInUseMatchesOnTheBasename(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(
		"root:x:0:0::/root:/usr/sbin/lbash\n"+
			"alice:x:1000:1000::/home/alice:/bin/bash\n"+
			"bob:x:1001:1001::/home/bob:/opt/custom/sbin/lzsh\n"+ // a different install prefix
			"carol:x:1002:1002::/home/carol:-lsh\n"+ // a login-dash form
			"broken:x:1003:1003::/home/broken\n"), 0o644); err != nil { // too few fields
		t.Fatal(err)
	}

	cfg := &Config{Shells: map[string]string{
		"lsh": "/bin/sh", "lbash": "/bin/bash", "lzsh": "/bin/zsh", "lksh": "/bin/ksh",
	}}
	inUse, err := cfg.NamesInUse(passwd)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"lbash", "lzsh", "lsh"} {
		if !inUse[want] {
			t.Errorf("%s is some account's login shell but was not reported in use", want)
		}
	}
	// lzsh proves the match does not depend on the install prefix, which logsh
	// has no way to learn.
	if inUse["lksh"] {
		t.Error("lksh is nobody's login shell but was reported in use; an absent /bin/ksh " +
			"would then fail a package postinst on every host that lacks it")
	}
	if len(inUse) != 3 {
		t.Errorf("in-use set = %v, want exactly lsh, lbash, lzsh", inUse)
	}
}

// TestNamesInUseIgnoresShellsOutsideTheMap keeps ordinary accounts from being
// mistaken for logsh users.
func TestNamesInUseIgnoresShellsOutsideTheMap(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(
		"a:x:1:1::/:/bin/bash\nb:x:2:2::/:/usr/bin/less\nc:x:3:3::/:/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Shells: map[string]string{"lbash": "/bin/bash", "lsh": "/bin/sh"}}
	inUse, err := cfg.NamesInUse(passwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(inUse) != 0 {
		t.Errorf("in-use set = %v, want empty; no account uses a logsh symlink here", inUse)
	}
}

// TestIsEntry pins the forced-command invocation name.
//
// sshd runs a ForceCommand through the user's login shell with -c, so argv[0]
// is the only channel logsh controls and there is never a leading dash. The
// name has to be recognised before any flag parsing is reached: a mode selected
// by a flag would be a mode reachable from a config path, and this one must not
// be.
func TestIsEntry(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want bool
	}{
		{"absolute path, as sshd invokes it", []string{"/usr/sbin/logsh-entry"}, true},
		{"bare name", []string{"logsh-entry"}, true},
		{"admin invocation is not the entry point", []string{"/usr/sbin/logsh"}, false},
		{"a login shell is not the entry point", []string{"-lbash"}, false},
		{"a lookalike does not match", []string{"logsh-entrypoint"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseInvocation(tt.argv).IsEntry(); got != tt.want {
				t.Errorf("IsEntry(%q) = %v, want %v", tt.argv, got, tt.want)
			}
		})
	}
}

// TestEntryIsNotAdmin guards the dispatch order in main: the two predicates
// must be mutually exclusive, or the entry point falls through to the flag
// parser.
func TestEntryIsNotAdmin(t *testing.T) {
	inv := ParseInvocation([]string{"/usr/sbin/logsh-entry"})
	if inv.IsAdmin() {
		t.Error("logsh-entry must not be treated as an admin invocation")
	}
}

// writePasswd drops a passwd fixture into a temp dir and returns its path.
func writePasswd(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPasswdShell reads the field os/user cannot supply.
//
// user.User has no Shell member, so there is no standard-library route to this
// value. Matching on the uid as well as the name is the same accommodation
// ShouldRecord makes: logsh is built CGO_ENABLED=0, so os/user cannot resolve an
// NSS account and the caller may have no name to pass.
func TestPasswdShell(t *testing.T) {
	body := "root:x:0:0:root:/root:/bin/zsh\n" +
		"noshell:x:1001:1001::/home/noshell:\n" +
		"alice:x:1002:1002::/home/alice:/bin/bash\n"
	path := writePasswd(t, body)

	tests := []struct {
		name     string
		username string
		uid      int
		want     string
		wantErr  bool
	}{
		{"by name", "root", 0, "/bin/zsh", false},
		{"by uid when the name is unknown", "", 1002, "/bin/bash", false},
		{"empty shell field is not an error", "noshell", 1001, "", false},
		{"absent account", "nobody-here", 4242, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PasswdShell(path, tt.username, tt.uid)
			if tt.wantErr {
				if !errors.Is(err, ErrNoPasswdEntry) {
					t.Fatalf("want ErrNoPasswdEntry, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("PasswdShell = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestResolveEntryShellUsesTheAccountsOwnShell is the whole point of §7.3.
//
// A configured fleet-wide shell would silently replace root's shell on every
// host where root's shell is something else -- and would leave a console login
// and an SSH login giving different shells for the same account. Reading the
// passwd entry is what sshd itself would have done, so enabling the recorder
// changes which shell runs on no host.
func TestResolveEntryShellUsesTheAccountsOwnShell(t *testing.T) {
	cfg := DefaultConfig()
	path := writePasswd(t, "root:x:0:0:root:/root:/bin/sh\n")

	got, err := cfg.ResolveEntryShell(path, "root", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/bin/sh" {
		t.Errorf("ResolveEntryShell = %q, want /bin/sh", got)
	}
}

// TestResolveEntryShellUnwrapsALogshSymlink covers the host that runs BOTH
// deployments: ForceCommand here, and logsh as root's passwd shell.
//
// Left alone, the forced command would exec /usr/sbin/lbash, which is logsh
// again -- a second recorder and a second pty for one session. Resolving the
// basename through the shells map yields the real shell instead, so the two
// deployments compose. Matching a passwd basename against Shells is the same
// test NamesInUse already performs.
func TestResolveEntryShellUnwrapsALogshSymlink(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Shells = map[string]string{"lbash": "/bin/sh"} // /bin/sh so the test does not need bash
	path := writePasswd(t, "root:x:0:0:root:/root:/usr/sbin/lbash\n")

	got, err := cfg.ResolveEntryShell(path, "root", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/bin/sh" {
		t.Errorf("ResolveEntryShell = %q, want the mapped shell /bin/sh", got)
	}
}

// TestResolveEntryShellUnwrapsADashPrefixedSymlink exercises the same basename
// normalization that NamesInUse applies: a passwd shell field recorded in the
// dash-prefixed form that NamesInUse recognizes as "this mapping is in use"
// must also unwrap through the shells map in ResolveEntryShell.
func TestResolveEntryShellUnwrapsADashPrefixedSymlink(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Shells = map[string]string{"lbash": "/bin/sh"} // /bin/sh so the test does not need bash
	path := writePasswd(t, "root:x:0:0:root:/root:-lbash\n")

	got, err := cfg.ResolveEntryShell(path, "root", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/bin/sh" {
		t.Errorf("ResolveEntryShell = %q, want the mapped shell /bin/sh", got)
	}
}

// TestResolveEntryShellEmptyFieldFallsBackToSh matches sshd, which uses
// _PATH_BSHELL when pw_shell is empty.
func TestResolveEntryShellEmptyFieldFallsBackToSh(t *testing.T) {
	cfg := DefaultConfig()
	path := writePasswd(t, "root:x:0:0:root:/root:\n")

	got, err := cfg.ResolveEntryShell(path, "root", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/bin/sh" {
		t.Errorf("ResolveEntryShell = %q, want /bin/sh", got)
	}
}

// TestResolveEntryShellRejectsAnUnusableShell.
//
// There is nothing to fall back to here, so the caller exits rather than
// exec'ing something else. Substituting a different shell would be worse than
// refusing: the operator would get a working login running the wrong thing, and
// sshd would equally have failed to exec this entry.
func TestResolveEntryShellRejectsAnUnusableShell(t *testing.T) {
	cfg := DefaultConfig()
	for _, tt := range []struct{ name, body string }{
		{"missing binary", "root:x:0:0:root:/root:/nonexistent/shell\n"},
		{"relative path", "root:x:0:0:root:/root:bash\n"},
		{"a directory", "root:x:0:0:root:/root:/tmp\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := cfg.ResolveEntryShell(writePasswd(t, tt.body), "root", 0); err == nil {
				t.Error("want an error, got nil")
			}
		})
	}
}

// TestResolveEntryShellHonoursTheOverride.
//
// force_command.shell is the escape hatch for a host whose passwd shell is
// unsuitable. It wins over the passwd entry, which is exactly why Warnings
// flags it: applied fleet-wide it silently replaces the account's real shell.
func TestResolveEntryShellHonoursTheOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ForceCommand.Shell = "/bin/sh"
	path := writePasswd(t, "root:x:0:0:root:/root:/nonexistent/zsh\n")

	got, err := cfg.ResolveEntryShell(path, "root", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/bin/sh" {
		t.Errorf("ResolveEntryShell = %q, want the override /bin/sh", got)
	}
}

// TestResolveEntryShellOverrideIsStillChecked. An override naming something
// unexecutable must fail like any other unusable shell, not be trusted because
// an operator wrote it down.
func TestResolveEntryShellOverrideIsStillChecked(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ForceCommand.Shell = "/nonexistent/shell"
	path := writePasswd(t, "root:x:0:0:root:/root:/bin/sh\n")

	if _, err := cfg.ResolveEntryShell(path, "root", 0); err == nil {
		t.Error("want an error for an unexecutable override, got nil")
	}
}
