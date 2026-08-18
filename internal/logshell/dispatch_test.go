// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/dispatch_test.go
package logshell

import (
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
