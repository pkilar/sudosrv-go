# logsh ForceCommand Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach `logsh` to run natively as an sshd `ForceCommand`, so root SSH sessions are recorded and attributed to the human whose certificate authenticated them, without breaking `sftp`, `scp` or `rsync`.

**Architecture:** A third invocation mode, selected by a `/usr/sbin/logsh-entry` symlink, reads `SSH_ORIGINAL_COMMAND` and `SSH_USER_AUTH`. A literal-allowlist routing table decides *what* to run; the account's own `/etc/passwd` shell decides *which shell*; the existing recorders decide *how it is captured*. Certificate identity lands in `submituser`, mirroring what `ApplyNesting` already does under `sudo -i`.

**Tech Stack:** Go 1.27, `CGO_ENABLED=0`, `gopkg.in/yaml.v3`, `google.golang.org/protobuf`, and one new dependency: `golang.org/x/crypto/ssh` for certificate parsing. Tests are standard-library `testing`, table-driven, no assertion library.

**Spec:** [`docs/superpowers/specs/2026-08-26-logsh-forcecommand-design.md`](../specs/2026-08-26-logsh-forcecommand-design.md)

## Global Constraints

- **This code runs before anything else in an SSH session.** A bug is either a lockout or an unrecorded root session. Review it as security-relevant code.
- **Every path must terminate in exec-a-resolved-target or `refuse()`.** No fall-through. A forced command that exits 0 on an unhandled branch silently grants an unrecorded session.
- **Nothing from the client is ever interpolated into an argv.** `SSH_ORIGINAL_COMMAND` may become one `-c` argument or nothing. Never a route's argv, never a filename, never a shell fragment.
- **No branch may be more permissive than the no-`ForceCommand` baseline.** Enabling the recorder must not enlarge what root can do over SSH.
- Build must stay `CGO_ENABLED=0`. `os/user` therefore cannot consult NSS; resolve accounts by numeric uid as well as by name, per the reasoning in `Config.ShouldRecord`.
- Go formatting (`gofmt`) on every touched file. Structured logs via `slog`; operator-facing alerts via `logshell.Alertf`.
- Every new exported identifier gets a doc comment saying *why*, matching the density of the surrounding package.
- Run `make test` before each commit. Targeted runs during a task are fine; the commit gate is the full suite.
- File header on every new file: `// SPDX-License-Identifier: Apache-2.0` then `// Filename: <path>`.

---

## File Structure

**Create:**
- `internal/logshell/authinfo.go` — `AuthInfo`, `ReadAuthInfo`, `ParseAuthInfo`. Certificate identity, nothing else.
- `internal/logshell/authinfo_test.go`
- `internal/logshell/testdata/authinfo/` — committed `ssh-keygen` fixtures.
- `internal/logshell/route.go` — `ForceCommandConfig`, `Route`, `RouteKind`, `Target`, `Resolve`. The routing table and nothing else; this is the file a security reviewer reads first.
- `internal/logshell/route_test.go`
- `cmd/logsh/entry.go` — `runForceCommand`. Kept out of `main.go`, which is already 545 lines.
- `cmd/logsh/entry_test.go`
- `docs/logsh-forcecommand.md` — deployment runbook.
- `docs/superpowers/plans/2026-08-27-logsh-forcecommand.md` — this file.

**Modify:**
- `internal/logshell/dispatch.go` — `EntryName`, `IsEntry`, `PasswdShell`, `ResolveEntryShell`. Invocation and exec-target resolution already live here.
- `internal/logshell/config.go` — `ForceCommand` field, defaults, `Validate`, `Warnings`.
- `internal/logshell/record.go` — `SessionInfo`, `SessionMeta.ApplyAuthInfo`, new info keys.
- `internal/logshell/relay.go` — `RunRecorded` takes a `RunSpec`.
- `internal/logshell/nonint.go` — `RunSpec.Info`, `RunSpec.EnvShell`.
- `internal/logshell/exec.go` — `PrepareEnv` skips the `SHELL` rewrite for an empty path.
- `cmd/logsh/main.go` — dispatch, `execTarget`, `refuse`, selftest output.
- `examples/logsh.yaml`, `README.md`, `docs/logsh-deployment.md` (F-3), `packaging/logsh/logsh-install.sh`, `go.mod`, `go.sum`.

---

## Task 1: The `logsh-entry` invocation name

**Files:**
- Modify: `internal/logshell/dispatch.go` (after `AdminName`, line 15, and after `IsAdmin`, line 56)
- Modify: `internal/logshell/config.go` (`Validate`, around line 344)
- Test: `internal/logshell/dispatch_test.go`, `internal/logshell/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `logshell.EntryName` (`const string = "logsh-entry"`); `func (Invocation) IsEntry() bool`.

- [ ] **Step 1: Write the failing test**

Append to `internal/logshell/dispatch_test.go`:

```go
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
```

Append to `internal/logshell/config_test.go`:

```go
// TestValidateRejectsEntryNameAsShell stops one name meaning two things.
//
// logsh-entry selects the forced-command mode from argv[0]. A shells mapping
// under the same key would make the same symlink also resolvable as a login
// shell, and which one won would depend on the order of two predicates in main.
func TestValidateRejectsEntryNameAsShell(t *testing.T) {
	_, err := load(writeConfig(t, "record_users: [root]\nshells:\n  logsh-entry: /bin/bash\n"), selfUID(t))
	if err == nil {
		t.Fatal("want an error for shells[logsh-entry], got nil")
	}
	if !strings.Contains(err.Error(), EntryName) {
		t.Errorf("error should name %q, got: %v", EntryName, err)
	}
}
```

Add `"strings"` to `config_test.go`'s imports if absent.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/logshell/ -run 'TestIsEntry|TestEntryIsNotAdmin|TestValidateRejectsEntryNameAsShell' -v`
Expected: FAIL — `inv.IsEntry undefined`, `undefined: EntryName`.

- [ ] **Step 3: Add the constant and the predicate**

In `internal/logshell/dispatch.go`, after the `AdminName` const block:

```go
// EntryName is the name logsh is invoked under when sshd runs it as a forced
// command. /usr/sbin/logsh-entry is a symlink to the binary, and that path is
// what sshd_config's ForceCommand and the force-command critical option on a
// privileged certificate both name.
//
// A name rather than a flag, for two reasons. sshd invokes a forced command as
// `$SHELL -c "<command>"`, so argv[0] is the only thing logsh controls; and
// dispatching on it happens before any flag parsing, which keeps -config
// unreachable on a path that runs before any user code in a root session.
const EntryName = "logsh-entry"
```

After `IsAdmin`:

```go
// IsEntry reports whether sshd is running logsh as a forced command, as opposed
// to as a login shell or an administrative invocation.
func (i Invocation) IsEntry() bool { return i.Name == EntryName }
```

In `internal/logshell/config.go`, inside `Validate`, immediately after the existing `for name, shell := range c.Shells` loop:

```go
	// One name, one meaning. EntryName selects the forced-command mode from
	// argv[0]; a mapping under the same key would make that symlink resolvable
	// as a login shell too, and which behaviour won would depend on the order of
	// two predicates in main rather than on anything the operator wrote.
	if _, ok := c.Shells[EntryName]; ok {
		return fmt.Errorf("shells[%s]: %s names the forced-command entry point and cannot also be a shell mapping", EntryName, EntryName)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run 'TestIsEntry|TestEntryIsNotAdmin|TestValidateRejectsEntryNameAsShell' -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and commit**

```bash
make test
git add internal/logshell/dispatch.go internal/logshell/dispatch_test.go internal/logshell/config.go internal/logshell/config_test.go
git commit -m "feat(logsh): recognise the logsh-entry invocation name

Adds EntryName and Invocation.IsEntry, and refuses a shells mapping under the
same key so one name cannot mean two things. Nothing dispatches to it yet."
```

---

## Task 2: Resolve the session shell from `/etc/passwd`

**Files:**
- Modify: `internal/logshell/dispatch.go` (after `NamesInUse`)
- Test: `internal/logshell/dispatch_test.go`

**Interfaces:**
- Consumes: `PasswdPath`, `Config.Shells` (existing).
- Produces:
  - `var ErrNoPasswdEntry error`
  - `func PasswdShell(passwdPath, username string, uid int) (string, error)`
  - `func (c *Config) ResolveEntryShell(passwdPath, username string, uid int) (string, error)`

This implements spec §7.3. `force_command.shell` does not exist yet — Task 5 adds it — so this task reads only the passwd path and Task 5 wires the override in.

- [ ] **Step 1: Write the failing test**

Append to `internal/logshell/dispatch_test.go`:

```go
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
```

Add `"errors"` to `dispatch_test.go`'s imports.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/logshell/ -run 'TestPasswdShell|TestResolveEntryShell' -v`
Expected: FAIL — `undefined: PasswdShell`, `undefined: ErrNoPasswdEntry`.

- [ ] **Step 3: Implement**

Append to `internal/logshell/dispatch.go`:

```go
// ErrNoPasswdEntry reports that an account has no line in the passwd file.
var ErrNoPasswdEntry = errors.New("no passwd entry")

// PasswdShell returns an account's login shell field.
//
// os/user cannot supply this: user.User carries Uid, Gid, Username, Name and
// HomeDir, and no shell. So the file is parsed directly, which this package
// already does in NamesInUse.
//
// The account is matched by name OR by uid, the same accommodation ShouldRecord
// makes and for the same reason: logsh is built CGO_ENABLED=0, so os/user cannot
// resolve an NSS account and the caller may reach here with no name at all.
// Matching on the uid keeps the lookup working with an empty name, which is what
// stops an unresolvable name becoming a refused login.
//
// An account whose shell field is EMPTY returns "" and no error. That is a
// distinct state from an absent account, and sshd handles it specifically.
func PasswdShell(passwdPath, username string, uid int) (string, error) {
	raw, err := os.ReadFile(passwdPath) // #nosec G304 -- caller-supplied, root-owned system file
	if err != nil {
		return "", err
	}
	want := strconv.Itoa(uid)
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		if (username != "" && fields[0] == username) || fields[2] == want {
			return fields[6], nil
		}
	}
	return "", fmt.Errorf("%w for %q (uid %d) in %s", ErrNoPasswdEntry, username, uid, passwdPath)
}

// ResolveEntryShell picks the shell a forced-command session runs.
//
// The account's OWN shell, not a configured one. §4.10 of the session-logging
// design commits that this deployment does not change root's login shell -- that
// is its central advantage over installing logsh as the passwd shell. A shell
// named in logsh.yaml would be applied to every host sharing that file and would
// silently replace root's shell wherever the two disagreed, leaving a console
// login and an SSH login giving different shells for the same account. Reading
// the passwd entry is exactly what sshd would have done without ForceCommand, so
// enabling the recorder changes which shell runs on no host.
//
// The shells allowlist is deliberately NOT applied to the result. That list
// exists to stop a stray symlink becoming an exec primitive by INFERENCE; there
// is no inference here, the value is read from a root-owned field, and gating on
// it would refuse root's login on any host whose shell simply has no mapping --
// a lockout for no security gain.
func (c *Config) ResolveEntryShell(passwdPath, username string, uid int) (string, error) {
	shell, err := PasswdShell(passwdPath, username, uid)
	if err != nil {
		return "", err
	}
	if shell == "" {
		// sshd's own fallback: session.c substitutes _PATH_BSHELL when pw_shell
		// is empty rather than failing the session.
		shell = "/bin/sh"
	}
	// The account's shell may itself be a logsh multi-call symlink, on a host
	// that also runs the login-shell deployment. Exec'ing it would start a
	// second recorder and a second pty for one session. Resolving the basename
	// through the shells map yields the real shell, so the two deployments
	// compose instead of nesting -- and this is the same basename-against-Shells
	// test NamesInUse uses to decide the very same question.
	if real, ok := c.Shells[filepath.Base(shell)]; ok {
		shell = real
	}
	if !filepath.IsAbs(shell) {
		return "", fmt.Errorf("shell %q for %q is not an absolute path", shell, username)
	}
	st, err := os.Stat(shell)
	if err != nil {
		return "", fmt.Errorf("shell %s for %q: %w", shell, username, err)
	}
	if st.IsDir() || st.Mode()&0111 == 0 {
		return "", fmt.Errorf("shell %s for %q is not executable", shell, username)
	}
	return shell, nil
}
```

Add `"errors"` and `"strconv"` to `dispatch.go`'s imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run 'TestPasswdShell|TestResolveEntryShell' -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and commit**

```bash
make test
git add internal/logshell/dispatch.go internal/logshell/dispatch_test.go
git commit -m "feat(logsh): resolve a forced-command session's shell from /etc/passwd

os/user has no Shell field, so the file is parsed directly beside NamesInUse.
A passwd entry that is itself a logsh symlink resolves through the shells map,
so a host running both deployments gets one recorder rather than two."
```

---

## Task 3: Read the authenticating certificate

**Files:**
- Create: `internal/logshell/authinfo.go`, `internal/logshell/authinfo_test.go`
- Create: `internal/logshell/testdata/authinfo/` (fixtures)
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type AuthInfo struct { Method, KeyID string; Serial uint64; Principals []string; CAFingerprint, KeyFingerprint string }`
  - `const AuthMethodCert = "publickey-cert"`, `const AuthMethodKey = "publickey"`
  - `func ReadAuthInfo(path string) (AuthInfo, error)`
  - `func ParseAuthInfo(raw []byte) (AuthInfo, error)`

- [ ] **Step 1: Generate and commit the fixtures**

These are committed rather than generated at test time so the suite does not need `ssh-keygen` on the runner.

```bash
mkdir -p internal/logshell/testdata/authinfo
cd internal/logshell/testdata/authinfo
ssh-keygen -q -t ed25519 -N '' -f ca -C ca
for t in ed25519 rsa ecdsa; do ssh-keygen -q -t $t -N '' -f user-$t -C user-$t; done
for t in ed25519 rsa ecdsa; do
  ssh-keygen -q -s ca -I 'jsmith@CORP.EXAMPLE.COM' -n root-web,root-everywhere \
    -z 20260819000137 -V -5m:+8h -O clear -O permit-pty \
    -O force-command=/usr/sbin/logsh-entry user-$t.pub
done
# One auth-info file per case, in the format sshd's ExposeAuthInfo writes.
for t in ed25519 rsa ecdsa; do
  printf 'publickey %s\n' "$(cut -d' ' -f1,2 user-$t-cert.pub)" > cert-$t.authinfo
done
printf 'publickey %s\n' "$(cut -d' ' -f1,2 user-ed25519.pub)" > plainkey.authinfo
printf 'publickey %s\npublickey %s\n' \
  "$(cut -d' ' -f1,2 user-ed25519.pub)" "$(cut -d' ' -f1,2 user-ed25519-cert.pub)" > key-then-cert.authinfo
printf 'garbage\npublickey ssh-ed25519 not-base64!!\n' > junk.authinfo
: > empty.authinfo
rm -f ca ca.pub user-ed25519 user-rsa user-ecdsa
cd -
```

Confirm `cert-ed25519.authinfo` is one line beginning `publickey ssh-ed25519-cert-v01@openssh.com AAAA`.

- [ ] **Step 2: Write the failing test**

Create `internal/logshell/authinfo_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/authinfo_test.go
package logshell

import (
	"path/filepath"
	"testing"
)

func authinfoPath(name string) string { return filepath.Join("testdata", "authinfo", name) }

// TestReadAuthInfoCertificates is the attribution requirement, R-2.
//
// A session running AS root learns which human opened it from the certificate
// sshd exposes via SSH_USER_AUTH. The key ID and serial live inside the base64
// certificate blob, which is why the reference shell wrapper in the design
// document could not actually do this and why it is in Go.
//
// All three key algorithms are exercised because the certificate's key-specific
// fields differ per algorithm, and getting that wrong yields plausible garbage
// rather than an error.
func TestReadAuthInfoCertificates(t *testing.T) {
	for _, name := range []string{"cert-ed25519.authinfo", "cert-rsa.authinfo", "cert-ecdsa.authinfo"} {
		t.Run(name, func(t *testing.T) {
			got, err := ReadAuthInfo(authinfoPath(name))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Method != AuthMethodCert {
				t.Errorf("Method = %q, want %q", got.Method, AuthMethodCert)
			}
			if got.KeyID != "jsmith@CORP.EXAMPLE.COM" {
				t.Errorf("KeyID = %q, want jsmith@CORP.EXAMPLE.COM", got.KeyID)
			}
			if got.Serial != 20260819000137 {
				t.Errorf("Serial = %d, want 20260819000137", got.Serial)
			}
			if len(got.Principals) != 2 || got.Principals[0] != "root-web" {
				t.Errorf("Principals = %v, want [root-web root-everywhere]", got.Principals)
			}
			if len(got.CAFingerprint) < 8 || got.CAFingerprint[:7] != "SHA256:" {
				t.Errorf("CAFingerprint = %q, want a SHA256: fingerprint", got.CAFingerprint)
			}
		})
	}
}

// TestReadAuthInfoPlainKeyIsASignalNotAnError.
//
// A root SSH login that presents a plain key rather than a certificate is
// exactly what the certificate migration intends to eliminate: the break-glass
// account, or a key the fallback audit missed. It is recorded as a fact with no
// key ID, so a SIEM rule can fire on it.
func TestReadAuthInfoPlainKeyIsASignalNotAnError(t *testing.T) {
	got, err := ReadAuthInfo(authinfoPath("plainkey.authinfo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Method != AuthMethodKey {
		t.Errorf("Method = %q, want %q", got.Method, AuthMethodKey)
	}
	if got.KeyID != "" {
		t.Errorf("KeyID = %q, want empty for a plain key", got.KeyID)
	}
	if got.KeyFingerprint == "" {
		t.Error("KeyFingerprint must be recorded so the credential is identifiable")
	}
}

// TestReadAuthInfoPrefersTheCertificate.
//
// sshd may list several credentials. A certificate names a human and a plain key
// does not, so the certificate wins regardless of line order.
func TestReadAuthInfoPrefersTheCertificate(t *testing.T) {
	got, err := ReadAuthInfo(authinfoPath("key-then-cert.authinfo"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Method != AuthMethodCert || got.KeyID != "jsmith@CORP.EXAMPLE.COM" {
		t.Errorf("got %+v, want the certificate", got)
	}
}

// TestReadAuthInfoFailuresAreErrorsNotPanics.
//
// Every one of these must return an error the caller can log and carry on from.
// Attribution failure warns and proceeds: an unattributed recording beats no
// recording, so nothing here may be fatal.
func TestReadAuthInfoFailuresAreErrorsNotPanics(t *testing.T) {
	for _, tt := range []struct{ name, path string }{
		{"unset SSH_USER_AUTH", ""},
		{"missing file", authinfoPath("does-not-exist.authinfo")},
		{"empty file", authinfoPath("empty.authinfo")},
		{"unparseable content", authinfoPath("junk.authinfo")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadAuthInfo(tt.path)
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if got.Method != "" {
				t.Errorf("want a zero AuthInfo on failure, got %+v", got)
			}
		})
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/logshell/ -run TestReadAuthInfo -v`
Expected: FAIL — `undefined: ReadAuthInfo`.

- [ ] **Step 4: Add the dependency**

```bash
go get golang.org/x/crypto/ssh
go mod tidy
```

Expected: `go.mod` gains `golang.org/x/crypto` with `golang.org/x/sys` indirect.

- [ ] **Step 5: Implement**

Create `internal/logshell/authinfo.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/authinfo.go
package logshell

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Authentication methods recorded with a session.
const (
	// AuthMethodCert means an SSH certificate authenticated the session, so a
	// human is named in its key ID.
	AuthMethodCert = "publickey-cert"
	// AuthMethodKey means a plain public key did. Under the certificate design
	// this is the break-glass account or a key the fallback audit missed, and it
	// is worth alerting on rather than treating as normal.
	AuthMethodKey = "publickey"
)

// AuthInfo is the credential that opened this session.
//
// It exists because direct root login destroys the attribution sudo gets for
// free: the account is root, and the only place a human's name survives is the
// certificate. sshd writes the credentials it accepted to the file named by
// SSH_USER_AUTH when ExposeAuthInfo is on, and this is that file, parsed.
type AuthInfo struct {
	// Method is one of the AuthMethod* constants, or "" when nothing was read.
	Method string

	// KeyID is the certificate's key ID: the human, typically a Kerberos
	// principal. Empty for a plain key.
	KeyID string

	// Serial is the certificate serial, the join key between the CA's issuance
	// log and this host's sshd auth log.
	Serial uint64

	// Principals are the certificate's valid principals, e.g. root-web.
	Principals []string

	// CAFingerprint identifies the signing CA, which is what distinguishes a
	// normal issuance from the emergency CA.
	CAFingerprint string

	// KeyFingerprint identifies the presented credential itself, and is the only
	// identifier available when it was a plain key.
	KeyFingerprint string
}

// ErrNoCredential reports that nothing in the auth-info file parsed as a public
// credential.
var ErrNoCredential = errors.New("no public credential found")

// ReadAuthInfo parses the file sshd names in SSH_USER_AUTH.
//
// Every failure here is reportable, never fatal. The caller logs at crit and
// carries on: a session recorded without attribution is enormously better than a
// session refused because attribution could not be read, and refusing would put
// a file sshd wrote on the critical path of every root login.
func ReadAuthInfo(path string) (AuthInfo, error) {
	if path == "" {
		return AuthInfo{}, errors.New("SSH_USER_AUTH is not set (is ExposeAuthInfo enabled?)")
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from sshd, read as the session user
	if err != nil {
		return AuthInfo{}, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseAuthInfo(raw)
}

// ParseAuthInfo parses auth-info content. Split from ReadAuthInfo so the format
// can be tested without a file.
//
// Each line is "<method> <keytype> <base64>". The method field is not matched
// against a list: OpenSSH has added method names over time, and a line whose
// third field decodes to a public key is a credential whatever the first field
// says. A line that does not decode is skipped rather than failing the file,
// because one unparseable line must not discard a certificate on the next.
//
// A certificate always wins over a plain key, regardless of order: only the
// certificate names a human, which is the entire purpose of reading this.
func ParseAuthInfo(raw []byte) (AuthInfo, error) {
	var plain AuthInfo
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			continue
		}
		pub, err := ssh.ParsePublicKey(blob)
		if err != nil {
			continue
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			return AuthInfo{
				Method:         AuthMethodCert,
				KeyID:          cert.KeyId,
				Serial:         cert.Serial,
				Principals:     cert.ValidPrincipals,
				CAFingerprint:  ssh.FingerprintSHA256(cert.SignatureKey),
				KeyFingerprint: ssh.FingerprintSHA256(cert),
			}, nil
		}
		if plain.Method == "" {
			plain = AuthInfo{Method: AuthMethodKey, KeyFingerprint: ssh.FingerprintSHA256(pub)}
		}
	}
	if plain.Method != "" {
		return plain, nil
	}
	return AuthInfo{}, ErrNoCredential
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run TestReadAuthInfo -v`
Expected: PASS, all subtests.

- [ ] **Step 7: Confirm the static build still works and measure the cost**

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o /tmp/logsh-sized ./cmd/logsh && ls -l /tmp/logsh-sized
```
Expected: builds clean, at roughly 8.43 MB, up from 8.37 MB — about +64 KB. Only the SSH wire format and key-type dispatch link in; `logsh` already pulls `crypto/tls`, so the underlying primitives are present either way, and the linker drops the ssh transport because nothing here dials or accepts a connection. A figure near 10 MB would mean the transport stack got linked in after all — investigate before continuing.

- [ ] **Step 8: Commit**

```bash
make test
git add go.mod go.sum internal/logshell/authinfo.go internal/logshell/authinfo_test.go internal/logshell/testdata/authinfo
git commit -m "feat(logsh): read the authenticating certificate from SSH_USER_AUTH

Extracts key ID, serial, principals and CA fingerprint. The key ID and serial
live inside the base64 certificate blob, which is why this cannot be done in
shell. A plain key is recorded as a fact rather than an error: under the
certificate design it is the break-glass account or a missed key.

Adds golang.org/x/crypto for certificate parsing; logsh grows 8.37 to 8.43 MB.
The linker only pulls in public-key parsing and fingerprinting, not the ssh
transport stack, since nothing here dials or accepts a connection."
```

---

## Task 4: Land attribution in the session record

**Files:**
- Modify: `internal/logshell/record.go` (`SessionMeta` ~line 27, after `ApplyNesting` ~line 208, `InfoMessages` ~line 221)
- Test: `internal/logshell/record_test.go`

**Interfaces:**
- Consumes: `AuthInfo`, `AuthMethodCert` (Task 3).
- Produces:
  - `type SessionInfo struct { Auth AuthInfo; SSHCommand, SSHClient string }`
  - `func (m *SessionMeta) ApplyAuthInfo(info SessionInfo)`
  - `SessionMeta.Info SessionInfo` field
  - Info keys: `logsh_auth_method`, `logsh_cert_keyid`, `logsh_cert_serial`, `logsh_cert_ca`, `logsh_cert_principals`, `logsh_ssh_command`, `logsh_ssh_client`, and `logsh_auth_key` (the credential fingerprint — see below)

`logsh_auth_key` is the eighth key and the one most easily missed. The design's key table lists only the
certificate keys, but a plain-key root login is forbidden from naming anyone in `submituser`, so this
fingerprint is the ONLY thing in the record identifying which credential opened that session — and a
plain-key root login is exactly what the certificate migration exists to eliminate, so a SIEM rule is
meant to fire on it. Test it like the other seven: assert it carries the fingerprint when set, assert it
is omitted when unset, and assert the plain-key record shape end to end (`logsh_auth_key` present AND
`logsh_cert_keyid` absent, together, from a real `InfoMessages()` call).

- [ ] **Step 1: Write the failing test**

Append to `internal/logshell/record_test.go`:

```go
// infoValue pulls a scalar info key out of a rendered message set.
func infoValue(t *testing.T, msgs []*pb.InfoMessage, key string) (string, bool) {
	t.Helper()
	for _, m := range msgs {
		if m.Key != key {
			continue
		}
		if s, ok := m.Value.(*pb.InfoMessage_Strval); ok {
			return s.Strval, true
		}
		t.Fatalf("info key %q is not a strval", key)
	}
	return "", false
}

// TestApplyAuthInfoNamesTheHumanInSubmituser is R-2 and R-4 together.
//
// The session RUNS as root; a person authenticated it. This is the same
// correction ApplyNesting makes under `sudo -i`, where the session runs as root
// but alice is at the keyboard -- and it is why sudolens shows the human with no
// change to the frontend. A record naming root in both fields cannot answer the
// only question anybody asks of it.
func TestApplyAuthInfoNamesTheHumanInSubmituser(t *testing.T) {
	meta := SessionMeta{User: "root", UID: 0, SubmitUser: "root", SubmitUID: 0}
	meta.ApplyAuthInfo(SessionInfo{Auth: AuthInfo{
		Method:        AuthMethodCert,
		KeyID:         "jsmith@CORP.EXAMPLE.COM",
		Serial:        20260819000137,
		Principals:    []string{"root-web"},
		CAFingerprint: "SHA256:abc",
	}})

	if meta.SubmitUser != "jsmith@CORP.EXAMPLE.COM" {
		t.Errorf("SubmitUser = %q, want the certificate key ID", meta.SubmitUser)
	}
	if meta.User != "root" {
		t.Errorf("User = %q, want root: the session still RUNS as root", meta.User)
	}
	// There is no local uid for the human, so the ids keep describing the
	// process. Consumers joining on submituid must not read it as a person.
	if meta.SubmitUID != 0 {
		t.Errorf("SubmitUID = %d, want 0", meta.SubmitUID)
	}
}

// TestApplyAuthInfoPlainKeyDoesNotRewriteSubmituser.
//
// A plain key names nobody. Putting a fingerprint in submituser would assert an
// identity the credential does not carry.
func TestApplyAuthInfoPlainKeyDoesNotRewriteSubmituser(t *testing.T) {
	meta := SessionMeta{User: "root", SubmitUser: "root"}
	meta.ApplyAuthInfo(SessionInfo{Auth: AuthInfo{Method: AuthMethodKey, KeyFingerprint: "SHA256:xyz"}})

	if meta.SubmitUser != "root" {
		t.Errorf("SubmitUser = %q, want root", meta.SubmitUser)
	}
}

// TestInfoMessagesCarryCertificateKeys.
func TestInfoMessagesCarryCertificateKeys(t *testing.T) {
	meta := SessionMeta{User: "root", SubmitUser: "root"}
	meta.ApplyAuthInfo(SessionInfo{
		Auth: AuthInfo{
			Method:        AuthMethodCert,
			KeyID:         "jsmith@CORP.EXAMPLE.COM",
			Serial:        20260819000137,
			Principals:    []string{"root-web", "root-everywhere"},
			CAFingerprint: "SHA256:abc",
		},
		SSHCommand: "internal-sftp -l INFO",
		SSHClient:  "10.20.30.41 51234",
	})
	msgs := meta.InfoMessages()

	for key, want := range map[string]string{
		"logsh_auth_method":  AuthMethodCert,
		"logsh_cert_keyid":   "jsmith@CORP.EXAMPLE.COM",
		"logsh_cert_serial":  "20260819000137",
		"logsh_cert_ca":      "SHA256:abc",
		"logsh_ssh_command":  "internal-sftp -l INFO",
		"logsh_ssh_client":   "10.20.30.41 51234",
	} {
		got, ok := infoValue(t, msgs, key)
		if !ok {
			t.Errorf("info key %q is missing", key)
			continue
		}
		if got != want {
			t.Errorf("info key %q = %q, want %q", key, got, want)
		}
	}

	// Principals are a list, matching runargv and runenv, so log.json holds a
	// JSON array rather than a string a consumer has to re-split.
	var principals []string
	for _, m := range msgs {
		if m.Key == "logsh_cert_principals" {
			if l, ok := m.Value.(*pb.InfoMessage_Strlistval); ok {
				principals = l.Strlistval.Strings
			}
		}
	}
	if len(principals) != 2 || principals[1] != "root-everywhere" {
		t.Errorf("logsh_cert_principals = %v, want [root-web root-everywhere]", principals)
	}
}

// TestInfoMessagesOmitEmptyAuthKeys.
//
// The server copies every key it receives straight into log.json, so an empty
// string would assert "this session had no certificate key ID" rather than "this
// was not determined". The existing `source` key omits for exactly this reason.
func TestInfoMessagesOmitEmptyAuthKeys(t *testing.T) {
	msgs := SessionMeta{User: "root", SubmitUser: "root"}.InfoMessages()
	for _, key := range []string{
		"logsh_auth_method", "logsh_cert_keyid", "logsh_cert_serial",
		"logsh_cert_ca", "logsh_cert_principals", "logsh_ssh_command", "logsh_ssh_client",
	} {
		if _, ok := infoValue(t, msgs, key); ok {
			t.Errorf("info key %q must be omitted when unset", key)
		}
	}
}

// TestApplyAuthInfoTruncatesTheClientCommand.
//
// SSH_ORIGINAL_COMMAND is attacker-controlled and unbounded. An enormous value
// must not bloat every session record.
func TestApplyAuthInfoTruncatesTheClientCommand(t *testing.T) {
	meta := SessionMeta{}
	meta.ApplyAuthInfo(SessionInfo{SSHCommand: strings.Repeat("x", DefaultCommandLogMaxLen*3)})

	if len(meta.Info.SSHCommand) > DefaultCommandLogMaxLen {
		t.Errorf("SSHCommand length %d, want <= %d", len(meta.Info.SSHCommand), DefaultCommandLogMaxLen)
	}
	if !strings.HasSuffix(meta.Info.SSHCommand, "...") {
		t.Error("truncation must be visible in the value")
	}
}
```

Ensure `record_test.go` imports `"strings"` and `pb "sudosrv/pkg/sudosrv_proto"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/logshell/ -run 'TestApplyAuthInfo|TestInfoMessages' -v`
Expected: FAIL — `undefined: SessionInfo`, `meta.ApplyAuthInfo undefined`.

- [ ] **Step 3: Implement**

In `internal/logshell/record.go`, add above `SessionMeta`:

```go
// SessionInfo is what the forced-command entry point learns from sshd.
//
// It is separate from SessionMeta because it arrives from a different place --
// sshd's environment rather than the process's own identity -- and because the
// login-shell path has none of it. A zero value stamps nothing, which is what
// keeps every existing caller unchanged.
type SessionInfo struct {
	// Auth is the credential that opened the session.
	Auth AuthInfo

	// SSHCommand is the client's requested command, verbatim, truncated by
	// ApplyAuthInfo. It answers R-5's "what command" for a non-interactive
	// session, and is kept separate from `command`/`runargv` so those keep
	// meaning what they mean for a sudo record: the program actually exec'd.
	SSHCommand string

	// SSHClient is the source address and port from SSH_CONNECTION.
	SSHClient string
}
```

Add to the `SessionMeta` struct, after `SessionID`:

```go
	// Info is what sshd told us about this session, when logsh was invoked as a
	// forced command. Zero for a login-shell session.
	Info SessionInfo
```

Add after `ApplyNesting`:

```go
// ApplyAuthInfo records what sshd reported and, for a certificate, names the
// human in submituser.
//
// The same correction ApplyNesting makes under sudo, for the same reason: the
// session RUNS as root, but a person authenticated it, and a record naming root
// in both fields cannot answer the only question anybody asks of it. Under a
// certificate that person is the key ID.
//
// SubmitUID is deliberately NOT changed. There is no local uid for
// jsmith@CORP.EXAMPLE.COM, so the numeric ids go on describing the process while
// the name describes the authenticated identity. This is a real asymmetry with
// sudo's records, where submituid is the invoking human's uid, and consumers
// joining on submituid must not read it as identifying a person.
func (m *SessionMeta) ApplyAuthInfo(info SessionInfo) {
	info.SSHCommand = truncateForRecord(info.SSHCommand)
	m.Info = info

	if info.Auth.Method == AuthMethodCert && info.Auth.KeyID != "" {
		m.SubmitUser = info.Auth.KeyID
	}
}

// truncateForRecord bounds an attacker-controlled string, visibly.
//
// SSH_ORIGINAL_COMMAND has no length limit worth relying on, and this value goes
// into every session record. The budget is the command log's, so one over-long
// value cannot be recorded two different ways by the two paths.
func truncateForRecord(s string) string {
	if len(s) <= DefaultCommandLogMaxLen {
		return s
	}
	return s[:DefaultCommandLogMaxLen-3] + "..."
}
```

In `InfoMessages`, immediately before the `submitenv` append at the end:

```go
	// Attribution. Each key is OMITTED when unset, for the same reason `source`
	// is: the server copies every key it receives into log.json, so an empty
	// value asserts "determined to be nothing" rather than "not determined".
	if m.Info.Auth.Method != "" {
		msgs = append(msgs, strInfo("logsh_auth_method", m.Info.Auth.Method))
	}
	if m.Info.Auth.KeyID != "" {
		msgs = append(msgs, strInfo("logsh_cert_keyid", m.Info.Auth.KeyID))
	}
	if m.Info.Auth.Serial != 0 {
		// A string, not a numval: serials are uint64 and numInfo takes int64, so
		// a serial past 2^63 would silently wrap into a negative number.
		msgs = append(msgs, strInfo("logsh_cert_serial", strconv.FormatUint(m.Info.Auth.Serial, 10)))
	}
	if m.Info.Auth.CAFingerprint != "" {
		msgs = append(msgs, strInfo("logsh_cert_ca", m.Info.Auth.CAFingerprint))
	}
	if m.Info.Auth.KeyFingerprint != "" {
		msgs = append(msgs, strInfo("logsh_auth_key", m.Info.Auth.KeyFingerprint))
	}
	if len(m.Info.Auth.Principals) > 0 {
		msgs = append(msgs, &pb.InfoMessage{Key: "logsh_cert_principals", Value: &pb.InfoMessage_Strlistval{
			Strlistval: &pb.InfoMessage_StringList{Strings: m.Info.Auth.Principals},
		}})
	}
	if m.Info.SSHCommand != "" {
		msgs = append(msgs, strInfo("logsh_ssh_command", m.Info.SSHCommand))
	}
	if m.Info.SSHClient != "" {
		msgs = append(msgs, strInfo("logsh_ssh_client", m.Info.SSHClient))
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run 'TestApplyAuthInfo|TestInfoMessages' -v`
Expected: PASS

- [ ] **Step 5: Run the full suite and commit**

```bash
make test
git add internal/logshell/record.go internal/logshell/record_test.go
git commit -m "feat(logsh): stamp certificate attribution into the session record

submituser carries the certificate key ID while runuser stays root, the same
shape ApplyNesting produces under sudo -i, so sudolens names the human with no
frontend change. submituid keeps describing the process: there is no local uid
for a Kerberos principal.

New info keys are omitted when unset, matching how source already behaves."
```

---

## Task 5: The routing table

**Files:**
- Create: `internal/logshell/route.go`, `internal/logshell/route_test.go`
- Modify: `internal/logshell/config.go` (`Config` struct, `DefaultConfig`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type ForceCommandConfig struct { Shell string; Routes map[string]Route }`
  - `type Route struct { Exec []string; Command string }`
  - `type RouteKind int` with `RouteInteractive`, `RouteExec`, `RouteCommand`, `RouteDefault`
  - `type Target struct { Kind RouteKind; Path string; Args []string; Original string }`
  - `func (f ForceCommandConfig) Resolve(original string) Target`
  - `func (t Target) NeedsShell() bool`
  - `Config.ForceCommand ForceCommandConfig` (yaml `force_command`)
  - Extends `Config.ResolveEntryShell` (Task 2) to consult `ForceCommand.Shell` first

- [ ] **Step 1: Write the failing test**

Create `internal/logshell/route_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/route_test.go
package logshell

import (
	"slices"
	"strings"
	"testing"
)

func testRoutes() ForceCommandConfig {
	return ForceCommandConfig{Routes: map[string]Route{
		"internal-sftp": {Exec: []string{"/usr/lib/ssh/sftp-server", "-l", "INFO"}},
		"rsync":         {Exec: []string{"/usr/bin/rrsync", "-no-del", "/srv"}},
		"git-shell":     {Command: "/usr/bin/git-shell"},
	}}
}

// TestResolveRoutes is acceptance test T-1: every branch goes where it should,
// and no branch falls through to an unrecorded shell.
func TestResolveRoutes(t *testing.T) {
	f := testRoutes()
	tests := []struct {
		name     string
		original string
		wantKind RouteKind
		wantPath string
		wantArgs []string
	}{
		{
			// No command requested. The routes are not consulted at all; the
			// caller fills Path in with the account's own shell.
			name: "empty is interactive", original: "",
			wantKind: RouteInteractive, wantPath: "", wantArgs: nil,
		},
		{
			// The one command that genuinely needs translating: internal-sftp is
			// in-process inside sshd and has no binary to exec.
			name: "internal-sftp translates to the real binary", original: "internal-sftp -l INFO -f AUTH",
			wantKind: RouteExec, wantPath: "/usr/lib/ssh/sftp-server", wantArgs: []string{"-l", "INFO"},
		},
		{
			// The client's arguments are DISCARDED. The argv comes from the
			// root-owned config, never from the client.
			name: "route args come from config, not the client", original: "internal-sftp -l DEBUG3 -d /",
			wantKind: RouteExec, wantPath: "/usr/lib/ssh/sftp-server", wantArgs: []string{"-l", "INFO"},
		},
		{
			// Basename matching, using a path whose basename IS a route key.
			// Note that a path-qualified REAL binary (e.g. /usr/lib/ssh/sftp-server,
			// basename "sftp-server") is not a key here and correctly falls to the
			// default route -- per spec 5.1, such a command needs no translation.
			name: "a path-qualified program matches on its basename", original: "/usr/lib/ssh/internal-sftp -l INFO",
			wantKind: RouteExec, wantPath: "/usr/lib/ssh/sftp-server", wantArgs: []string{"-l", "INFO"},
		},
		{
			// rrsync reads $SSH_ORIGINAL_COMMAND itself, so a fixed argv suffices.
			name: "rsync routes to rrsync with a fixed argv", original: "rsync --server --sender -vlogDtpre.iLsfxCIvu . /srv/x",
			wantKind: RouteExec, wantPath: "/usr/bin/rrsync", wantArgs: []string{"-no-del", "/srv"},
		},
		{
			name: "a command route passes the original as one -c argument", original: "git-upload-pack 'repo.git'",
			wantKind: RouteDefault, wantPath: "", wantArgs: []string{"-c", "git-upload-pack 'repo.git'"},
		},
		{
			name: "git-shell matches the command route", original: "git-shell -c whatever",
			wantKind: RouteCommand, wantPath: "/usr/bin/git-shell", wantArgs: []string{"-c", "git-shell -c whatever"},
		},
		{
			// Pre-9.0 scp arrives as an ordinary command and needs no route.
			name: "old-style scp falls to the default route", original: "scp -t /tmp/x",
			wantKind: RouteDefault, wantPath: "", wantArgs: []string{"-c", "scp -t /tmp/x"},
		},
		{
			name: "an ordinary command falls to the default route", original: "id; hostname",
			wantKind: RouteDefault, wantPath: "", wantArgs: []string{"-c", "id; hostname"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.Resolve(tt.original)
			if got.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
			if !slices.Equal(got.Args, tt.wantArgs) {
				t.Errorf("Args = %q, want %q", got.Args, tt.wantArgs)
			}
			if got.Original != tt.original {
				t.Errorf("Original = %q, want %q", got.Original, tt.original)
			}
		})
	}
}

// TestResolveHostileCommands is acceptance test T-2, and the security core.
//
// SSH_ORIGINAL_COMMAND is entirely attacker-controlled. Two properties have to
// hold for every input:
//
//   - Nothing from the client is ever interpolated into a route's argv. A route
//     runs the argv written in the root-owned config and nothing else.
//   - An unmatched command reaches the DEFAULT route as ONE -c argument. That is
//     exactly what sshd would have done with no ForceCommand at all, so no branch
//     is more permissive than the baseline.
//
// Note what the metacharacter cases prove. "sftp-server; rm -rf /" does NOT
// match the sftp route, because field 0 is "sftp-server;" and matching is exact.
// It falls to the default route and the shell handles the whole string as it
// always would. A matcher that stripped punctuation before comparing would match
// the route and SILENTLY DISCARD the rest of the command -- a semantic change
// invisible to both the client and the transcript.
func TestResolveHostileCommands(t *testing.T) {
	f := testRoutes()
	hostile := []string{
		"sftp-server; rm -rf /",
		"internal-sftp && curl evil.example",
		"internal-sftp | tee /tmp/x",
		"$(internal-sftp)",
		"`internal-sftp`",
		"'internal-sftp'",
		`"internal-sftp"`,
		"internal-sftp\nrm -rf /",
		"FOO=1 rsync --server",
		"../../bin/sh",
		"rsync\x00--server",
		strings.Repeat("A", 64*1024),
		"   ",
		"\t\t",
	}
	for _, original := range hostile {
		t.Run(strings.ToValidUTF8(original[:min(len(original), 32)], ""), func(t *testing.T) {
			got := f.Resolve(original)

			if got.Kind == RouteInteractive {
				t.Fatalf("a non-empty command must never be treated as interactive: %q", original)
			}
			if got.Kind == RouteDefault {
				if !slices.Equal(got.Args, []string{"-c", original}) {
					t.Errorf("default route Args = %q, want exactly [-c <original>]", got.Args)
				}
				return
			}
			// A matched route: its argv must be byte-identical to the config's,
			// with nothing from the client anywhere in it.
			for _, arg := range got.Args {
				if strings.Contains(original, arg) && !slices.Contains([]string{"-l", "INFO", "-no-del", "/srv"}, arg) {
					t.Errorf("client text leaked into route argv: %q", arg)
				}
			}
		})
	}
}

// TestResolveRelativeAndTraversalPathsMatchOnBasename.
//
// Only the basename is compared and the route's argv comes from the config, so a
// traversal in field 0 selects a route at most -- it can never influence what
// that route runs.
func TestResolveRelativeAndTraversalPathsMatchOnBasename(t *testing.T) {
	f := testRoutes()
	for _, original := range []string{"./internal-sftp", "../../internal-sftp", "/tmp/evil/internal-sftp"} {
		got := f.Resolve(original)
		if got.Kind != RouteExec || got.Path != "/usr/lib/ssh/sftp-server" {
			t.Errorf("Resolve(%q) = %v %q, want the configured sftp route", original, got.Kind, got.Path)
		}
		if !slices.Equal(got.Args, []string{"-l", "INFO"}) {
			t.Errorf("Resolve(%q).Args = %q, want the configured argv", original, got.Args)
		}
	}
}

// TestResolveWithNoRoutesAlwaysReachesTheDefault.
//
// An empty table is a valid deployment -- correct for a host whose sshd_config
// names an external sftp-server binary -- and must still never fall through.
func TestResolveWithNoRoutesAlwaysReachesTheDefault(t *testing.T) {
	var f ForceCommandConfig
	if got := f.Resolve(""); got.Kind != RouteInteractive {
		t.Errorf("empty command with no routes: Kind = %v, want interactive", got.Kind)
	}
	if got := f.Resolve("internal-sftp"); got.Kind != RouteDefault {
		t.Errorf("unmatched command with no routes: Kind = %v, want default", got.Kind)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/logshell/ -run TestResolve -v`
Expected: FAIL — `undefined: ForceCommandConfig`.

- [ ] **Step 3: Implement**

Create `internal/logshell/route.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Filename: internal/logshell/route.go
package logshell

import (
	"path/filepath"
	"strings"
)

// ForceCommandConfig configures the forced-command entry point.
//
// SECURITY: everything in this file runs before any user code in a root SSH
// session, on a string the client chose. Read it as security-relevant code.
type ForceCommandConfig struct {
	// Shell overrides the account's own shell for the interactive and default
	// routes. NORMALLY EMPTY.
	//
	// Empty means the session runs the shell in the account's passwd entry --
	// what sshd would have exec'd without ForceCommand, so enabling the recorder
	// changes which shell runs on no host. Setting this pins one shell for every
	// host sharing the file, which will differ from the account's real shell
	// wherever the two disagree and from what a console login gives. Warnings
	// says so.
	Shell string `yaml:"shell"`

	// Routes maps a program basename to what should run instead.
	//
	// It is a LITERAL ALLOWLIST, not a pattern language: keys are matched exactly
	// against the basename of the first whitespace-separated field of
	// SSH_ORIGINAL_COMMAND. No globs, no regular expressions, no prefix matching,
	// no case folding. See Resolve for why that is the safe shape.
	Routes map[string]Route `yaml:"routes"`
}

// Route is one entry in the table. Exactly one of Exec and Command is set;
// Config.Validate enforces that.
type Route struct {
	// Exec is a complete argv, taken verbatim from the configuration file. The
	// client's command reaches the program only through the inherited
	// SSH_ORIGINAL_COMMAND variable -- which is exactly how rrsync expects it,
	// and how sshd would have delivered it.
	Exec []string `yaml:"exec"`

	// Command names a program run as `prog -c "<SSH_ORIGINAL_COMMAND>"`, with the
	// command as ONE argv element that is never re-split and never passed
	// through a shell by logsh. This is the shape git-shell expects.
	Command string `yaml:"command"`
}

// RouteKind is what a resolved target turns out to be.
type RouteKind int

const (
	// RouteInteractive means the client requested no command. The caller runs
	// the account's shell with no arguments -- and decides recorded-versus-not
	// from whether a terminal is attached, NEVER from this kind.
	RouteInteractive RouteKind = iota
	// RouteExec means a route matched and named a complete argv.
	RouteExec
	// RouteCommand means a route matched and named a program to pass the
	// original command to.
	RouteCommand
	// RouteDefault means nothing matched: the account's shell runs the original
	// command, exactly as it would with no ForceCommand present.
	RouteDefault
)

func (k RouteKind) String() string {
	switch k {
	case RouteInteractive:
		return "interactive"
	case RouteExec:
		return "exec"
	case RouteCommand:
		return "command"
	default:
		return "default"
	}
}

// Target is a resolved thing to run.
type Target struct {
	// Kind is which branch was taken.
	Kind RouteKind

	// Path is the program to exec, EMPTY for RouteInteractive and RouteDefault.
	// Those two run the account's shell, which routing does not resolve --
	// Config.ResolveEntryShell does, and the caller fills it in.
	Path string

	// Args are the arguments after argv[0].
	Args []string

	// Original is SSH_ORIGINAL_COMMAND verbatim, for the session record.
	Original string
}

// NeedsShell reports whether the caller must resolve the account's shell to
// complete this target.
func (t Target) NeedsShell() bool { return t.Path == "" }

// Resolve decides what a forced-command session runs.
//
// The matching rule, in full:
//
//  1. An EMPTY original means no command was requested: interactive. The routes
//     are not consulted. Note that this is not the same question as "is there a
//     terminal" -- the caller settles that separately, because `ssh -t host cmd`
//     supplies both.
//  2. Otherwise: split on whitespace, take field 0, take its basename, and look
//     that up as an EXACT map key.
//  3. No match: the default route, `shell -c "<original>"`.
//
// Why exact basename matching is the safe shape. The only two things that can
// happen to an unrecognised client string are that it becomes a single -c
// argument, or nothing -- so NO BRANCH IS MORE PERMISSIVE than a host with no
// ForceCommand at all. Metacharacters defeat matching rather than exploiting it:
// "sftp-server; rm -rf /" has field 0 "sftp-server;", which is not the key
// "sftp-server", so it falls to the default route and the shell handles the whole
// string as it always would.
//
// That failure direction is deliberate. A matcher that stripped punctuation
// before comparing would match the sftp route and silently DISCARD the rest of
// the command -- a change in meaning invisible to the client and absent from the
// transcript. Refusing to match is the honest outcome.
func (f ForceCommandConfig) Resolve(original string) Target {
	if original == "" {
		return Target{Kind: RouteInteractive}
	}

	// strings.Fields on a whitespace-only string yields nothing, which falls
	// through to the default route -- correct, since the client did send a
	// command and the shell should see exactly what they sent.
	if fields := strings.Fields(original); len(fields) > 0 {
		if r, ok := f.Routes[filepath.Base(fields[0])]; ok {
			if len(r.Exec) > 0 {
				// The argv is the CONFIG's, verbatim. Nothing from the client
				// appears in it; the client's string travels in the inherited
				// SSH_ORIGINAL_COMMAND, as sshd would have delivered it.
				return Target{
					Kind:     RouteExec,
					Path:     r.Exec[0],
					Args:     append([]string(nil), r.Exec[1:]...),
					Original: original,
				}
			}
			return Target{
				Kind:     RouteCommand,
				Path:     r.Command,
				Args:     []string{"-c", original},
				Original: original,
			}
		}
	}
	return Target{Kind: RouteDefault, Args: []string{"-c", original}, Original: original}
}
```

In `internal/logshell/config.go`, add to the `Config` struct after `CommandLog`:

```go
	// ForceCommand configures the sshd ForceCommand entry point: which shell an
	// interactive root SSH session runs, and what a client's requested command
	// is routed to. Only consulted when logsh is invoked as EntryName.
	ForceCommand ForceCommandConfig `yaml:"force_command"`
```

`DefaultConfig` needs no entry: the zero `ForceCommandConfig` is the documented default (no override, no routes). Add a comment saying so, beside `BreakGlassMarker`:

```go
		// ForceCommand is deliberately zero: no shell override (so the account's
		// own passwd shell is used) and no routes (so every command reaches the
		// default route). That is the correct posture for a host that has not
		// enabled the forced-command entry point at all.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run TestResolve -v`
Expected: PASS, all subtests including every hostile input.

- [ ] **Step 5: Write the failing test for the shell override**

`ForceCommandConfig.Shell` now exists, so `ResolveEntryShell` (Task 2) can honour it. Append to `internal/logshell/dispatch_test.go`:

```go
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
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./internal/logshell/ -run TestResolveEntryShellHonours -v`
Expected: FAIL — the override is ignored and the passwd entry is used.

- [ ] **Step 7: Wire the override into `ResolveEntryShell`**

In `internal/logshell/dispatch.go`, replace the opening of `ResolveEntryShell`'s body so the passwd lookup runs only when no override is set.

**Do not transcribe the snippet below over the live function verbatim.** It was written before Task 2's fix commit
`6324b7d`, which added `strings.TrimPrefix(filepath.Base(shell), "-")` to the `Shells` lookup. Read the current
function first and preserve that `TrimPrefix`; a literal transcription silently reverts it and breaks
`TestResolveEntryShellUnwrapsADashPrefixedSymlink`. The change you want is only the `ForceCommand.Shell` wrapper:

```go
func (c *Config) ResolveEntryShell(passwdPath, username string, uid int) (string, error) {
	shell := c.ForceCommand.Shell
	if shell == "" {
		var err error
		shell, err = PasswdShell(passwdPath, username, uid)
		if err != nil {
			return "", err
		}
		if shell == "" {
			// sshd's own fallback: session.c substitutes _PATH_BSHELL when
			// pw_shell is empty rather than failing the session.
			shell = "/bin/sh"
		}
		// The account's shell may itself be a logsh multi-call symlink, on a
		// host that also runs the login-shell deployment. Exec'ing it would
		// start a second recorder and a second pty for one session. Resolving
		// the basename through the shells map yields the real shell, so the two
		// deployments compose instead of nesting -- and this is the same
		// basename-against-Shells test NamesInUse uses for the same question.
		//
		// The unwrap applies only to a passwd-derived value. An override is
		// already a real shell path, checked against the allowlist by Validate.
		if real, ok := c.Shells[filepath.Base(shell)]; ok {
			shell = real
		}
	}
	// ... the absolute-path, stat and executability checks are unchanged
```

Also update the doc comment's opening to say the override is consulted first, and that an unset override — the normal case — is what makes the passwd entry authoritative.

- [ ] **Step 8: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run TestResolveEntryShell -v`
Expected: PASS, including the Task 2 cases which must still resolve from passwd when no override is set.

- [ ] **Step 9: Run the full suite and commit**

```bash
make test
git add internal/logshell/route.go internal/logshell/route_test.go internal/logshell/config.go internal/logshell/dispatch.go internal/logshell/dispatch_test.go
git commit -m "feat(logsh): route SSH_ORIGINAL_COMMAND through a literal allowlist

Keys are matched exactly against the basename of field 0. A route's argv comes
from the root-owned config and never from the client, and an unmatched command
becomes one -c argument -- so no branch is more permissive than a host with no
ForceCommand at all.

Metacharacters defeat matching rather than exploiting it: 'sftp-server; rm -rf
/' does not match 'sftp-server' and falls to the default route, where the shell
handles the whole string. A matcher that stripped punctuation would match and
silently drop the rest."
```

---

## Task 6: Validation, warnings and selftest

**Files:**
- Modify: `internal/logshell/config.go` (`Validate`, `Warnings`)
- Modify: `cmd/logsh/main.go` (`runSelftest`, ~line 471)
- Test: `internal/logshell/config_test.go`

**Interfaces:**
- Consumes: `ForceCommandConfig`, `Route` (Task 5); `ResolveEntryShell` (Task 2).
- Produces: no new exported identifiers; extends `Validate` and `Warnings` behaviour.

- [ ] **Step 1: Write the failing test**

Append to `internal/logshell/config_test.go`:

```go
// TestValidateForceCommandRoutes.
//
// Each of these is an error rather than a warning because each produces a
// SILENT recording gap or a broken session: a route that can never match, a
// route with no program, or a program logsh cannot exec.
func TestValidateForceCommandRoutes(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			// Matching is on the basename of field 0, so a key containing a
			// slash could never match anything. It would look configured and
			// route nothing.
			name: "key with a slash",
			body: "record_users: [root]\nforce_command:\n  routes:\n    /usr/bin/rsync:\n      command: /bin/sh\n",
			want: "basename",
		},
		{
			name: "key with whitespace",
			body: "record_users: [root]\nforce_command:\n  routes:\n    \"rsync --server\":\n      command: /bin/sh\n",
			want: "basename",
		},
		{
			name: "neither exec nor command",
			body: "record_users: [root]\nforce_command:\n  routes:\n    rsync: {}\n",
			want: "exactly one",
		},
		{
			name: "both exec and command",
			body: "record_users: [root]\nforce_command:\n  routes:\n    rsync:\n      exec: [/usr/bin/rrsync]\n      command: /bin/sh\n",
			want: "exactly one",
		},
		{
			name: "relative program",
			body: "record_users: [root]\nforce_command:\n  routes:\n    rsync:\n      exec: [rrsync, -no-del]\n",
			want: "absolute path",
		},
		{
			// The override is a config value like any other, so the shells
			// allowlist applies to it -- unlike a passwd-derived shell, where
			// applying it would be a lockout for no gain.
			name: "shell override outside the allowlist",
			body: "record_users: [root]\nforce_command:\n  shell: /bin/evil\n",
			want: "shells",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(writeConfig(t, tt.body), selfUID(t))
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error should mention %q, got: %v", tt.want, err)
			}
		})
	}
}

// TestValidateAcceptsAGoodForceCommandConfig, so the errors above are not
// simply rejecting everything.
func TestValidateAcceptsAGoodForceCommandConfig(t *testing.T) {
	body := "record_users: [root]\n" +
		"force_command:\n" +
		"  routes:\n" +
		"    internal-sftp:\n" +
		"      exec: [/usr/lib/ssh/sftp-server, -l, INFO]\n" +
		"    git-shell:\n" +
		"      command: /usr/bin/git-shell\n"
	cfg, err := load(writeConfig(t, body), selfUID(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ForceCommand.Routes) != 2 {
		t.Errorf("got %d routes, want 2", len(cfg.ForceCommand.Routes))
	}
}

// TestWarningsForceCommandWithoutRootRecorded is the likeliest single
// misconfiguration, and the most silent: sessions would be routed correctly and
// recorded not at all.
func TestWarningsForceCommandWithoutRootRecorded(t *testing.T) {
	body := "record_users: [alice]\n" +
		"force_command:\n  routes:\n    internal-sftp:\n      exec: [/usr/lib/ssh/sftp-server]\n"
	cfg, err := load(writeConfig(t, body), selfUID(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.ContainsFunc(cfg.Warnings(), func(w string) bool { return strings.Contains(w, "record_users") }) {
		t.Errorf("want a record_users warning, got %v", cfg.Warnings())
	}
}

// TestWarningsShellOverride makes the footgun visible: pinning one shell
// fleet-wide diverges from the account's real shell and from a console login.
func TestWarningsShellOverride(t *testing.T) {
	body := "record_users: [root]\nforce_command:\n  shell: /bin/bash\n"
	cfg, err := load(writeConfig(t, body), selfUID(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.ContainsFunc(cfg.Warnings(), func(w string) bool { return strings.Contains(w, "force_command.shell") }) {
		t.Errorf("want a force_command.shell warning, got %v", cfg.Warnings())
	}
}
```

Add `"slices"` to `config_test.go`'s imports if absent.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/logshell/ -run 'TestValidateForceCommand|TestValidateAcceptsAGood|TestWarningsForceCommand|TestWarningsShellOverride' -v`
Expected: FAIL — good configs rejected is fine; bad configs accepted is the failure to fix.

- [ ] **Step 3: Implement validation**

In `Validate`, before the final `return nil`:

```go
	for name, r := range c.ForceCommand.Routes {
		// The key is matched against the BASENAME of the first field of
		// SSH_ORIGINAL_COMMAND, so a key holding whitespace or a slash can never
		// match anything. It would look configured and route nothing, which is a
		// silent gap rather than a visible failure -- hence an error.
		if name == "" || strings.ContainsAny(name, " \t/") {
			return fmt.Errorf("force_command.routes[%q]: a key is matched against the basename of the client's command, so it cannot be empty or contain whitespace or a slash", name)
		}
		hasExec, hasCommand := len(r.Exec) > 0, r.Command != ""
		if hasExec == hasCommand {
			return fmt.Errorf("force_command.routes[%s]: set exactly one of exec or command", name)
		}
		prog := r.Command
		if hasExec {
			prog = r.Exec[0]
		}
		if !filepath.IsAbs(prog) {
			return fmt.Errorf("force_command.routes[%s]: %q is not an absolute path", name, prog)
		}
	}

	// The override is a configuration value, so the shells allowlist applies to
	// it. A passwd-derived shell is deliberately NOT gated the same way: see
	// ResolveEntryShell.
	if c.ForceCommand.Shell != "" {
		allowed := false
		for _, shell := range c.Shells {
			if shell == c.ForceCommand.Shell {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("force_command.shell: %q is not one of the shells map's values", c.ForceCommand.Shell)
		}
	}
```

Add `"strings"` to `config.go`'s imports.

- [ ] **Step 4: Implement warnings**

In `Warnings`, before `return w`:

```go
	if c.ForceCommand.Shell != "" {
		w = append(w, fmt.Sprintf(
			"force_command.shell is set to %s: forced-command sessions run it instead of the "+
				"account's own shell from %s, so they will differ from a console login on any host "+
				"where the two disagree. Leave it unset unless that is what you want.",
			c.ForceCommand.Shell, PasswdPath))
	}
	if len(c.ForceCommand.Routes) > 0 || c.ForceCommand.Shell != "" {
		if !c.ShouldRecord("root", 0) {
			w = append(w, "force_command is configured but record_users names neither root nor 0: "+
				"forced-command sessions would be routed correctly and recorded not at all")
		}
		if _, ok := c.ForceCommand.Routes["internal-sftp"]; !ok {
			w = append(w, "force_command.routes has no internal-sftp entry: if sshd_config says "+
				"`Subsystem sftp internal-sftp`, sftp and modern scp will fail for forced-command "+
				"sessions. logsh cannot read sshd_config, so this is only a warning.")
		}
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run 'TestValidateForceCommand|TestValidateAcceptsAGood|TestWarningsForceCommand|TestWarningsShellOverride' -v`
Expected: PASS

- [ ] **Step 6: Report the resolved shell and routes in selftest**

In `cmd/logsh/main.go`, in `runSelftest`, after the `for name := range cfg.Shells` loop:

```go
	// The question an operator most needs answered before enabling a host: what
	// will a forced-command root session actually run here? The shell comes from
	// this host's passwd file, so it can differ from host to host, and printing
	// it is what makes that visible before it matters.
	if len(cfg.ForceCommand.Routes) > 0 || cfg.ForceCommand.Shell != "" {
		shell, err := cfg.ResolveEntryShell(logshell.PasswdPath, "root", 0)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "FAIL  force_command: cannot resolve root's shell: %v\n", err)
			failed = true
		case cfg.ForceCommand.Shell != "":
			fmt.Printf("ok    force_command: interactive shell for root: %s (from force_command.shell)\n", shell)
		default:
			fmt.Printf("ok    force_command: interactive shell for root: %s (from %s)\n", shell, logshell.PasswdPath)
		}

		for name, r := range cfg.ForceCommand.Routes {
			prog := r.Command
			if len(r.Exec) > 0 {
				prog = r.Exec[0]
			}
			st, statErr := os.Stat(prog)
			if statErr != nil || st.IsDir() || st.Mode()&0o111 == 0 {
				fmt.Fprintf(os.Stderr, "FAIL  force_command.routes[%s]: %s is missing or not executable\n", name, prog)
				failed = true
				continue
			}
			fmt.Printf("ok    force_command.routes[%s]: %s\n", name, prog)
		}
	}
```

- [ ] **Step 7: Verify selftest by hand**

```bash
go build -o /tmp/logsh ./cmd/logsh
printf 'record_users: [root]\nforce_command:\n  routes:\n    internal-sftp:\n      exec: [/bin/echo, -l, INFO]\n' > /tmp/lc.yaml
/tmp/logsh -selftest -config /tmp/lc.yaml
```
Expected: an `ok force_command: interactive shell for root: … (from /etc/passwd)` line naming *this host's* root shell, and an `ok force_command.routes[internal-sftp]: /bin/echo` line.

- [ ] **Step 8: Commit**

```bash
make test
git add internal/logshell/config.go internal/logshell/config_test.go cmd/logsh/main.go
git commit -m "feat(logsh): validate the force-command config and report it in selftest

Structural route problems are errors, not warnings: a key that can never match
looks configured and routes nothing, which is a silent gap. selftest prints the
shell a root session will actually run on THIS host, and checks every route
program is executable before the host is enabled."
```

---

## Task 7: Give the recorders a `RunSpec`

**Files:**
- Modify: `internal/logshell/nonint.go` (`RunSpec`, ~line 43), `internal/logshell/relay.go` (`RunRecorded`, line 93)
- Modify: `cmd/logsh/main.go` (the two `RunRecorded` call sites, lines ~150 and ~346)
- Test: `internal/logshell/relay_test.go`

**Interfaces:**
- Consumes: `SessionInfo` (Task 4).
- Produces:
  - `RunSpec.Info SessionInfo`
  - `RunSpec.EnvShell string`
  - `func RunRecorded(ctx context.Context, spec RunSpec, tio TerminalIO) (Outcome, error)` — **signature change**

This is the interface reshaping that lets both entry points share the recorders. It mirrors the refactor the non-interactive path already had (`refactor/nonint-runspec`).

- [ ] **Step 1: Add the fields to RunSpec**

In `internal/logshell/nonint.go`, add to `RunSpec` after `CmdLog`:

```go
	// Info is what sshd told us about this session: the credential that
	// authenticated it, the client's requested command, the source address. Its
	// zero value stamps nothing, which is what leaves the login-shell path
	// unchanged.
	Info SessionInfo

	// EnvShell is the value to publish as $SHELL, or "" to leave the inherited
	// value alone.
	//
	// It is NOT simply ShellPath. A forced-command route may exec something that
	// is not a shell at all -- sftp-server, rrsync -- and publishing
	// SHELL=/usr/lib/ssh/sftp-server to it would be a lie that scripts read.
	//
	// Like Std, this is a field whose absence does not announce itself: leaving
	// it empty on a shell session silently stops $SHELL being corrected, which
	// is the bug PrepareEnv exists to prevent. Set it whenever ShellPath is a
	// shell.
	EnvShell string
```

- [ ] **Step 2: Make PrepareEnv respect an empty path**

In `internal/logshell/exec.go`, at the top of `PrepareEnv`:

```go
	// An empty shellPath means "publish nothing": the caller is exec'ing
	// something that is not a shell, and asserting SHELL=/usr/lib/ssh/sftp-server
	// would be worse than leaving sshd's own value in place.
	if shellPath == "" {
		return slices.Clone(env)
	}
```

Add `"slices"` to `exec.go`'s imports. Update its doc comment to mention the empty case.

In `internal/logshell/nonint.go`, change the env line in `runPassthrough`'s `build` closure:

```go
			cmd.Env = WithSessionEnv(PrepareEnv(os.Environ(), spec.EnvShell), spec.CmdLog.SessionID())
```

- [ ] **Step 3: Write the failing test for the new RunRecorded signature**

Append to `internal/logshell/relay_test.go`:

```go
// TestPrepareEnvEmptyPathPublishesNothing.
//
// A forced-command route may exec sftp-server or rrsync. Neither is a shell, and
// SHELL=/usr/lib/ssh/sftp-server is a claim that scripts testing $SHELL against
// /etc/shells will act on.
func TestPrepareEnvEmptyPathPublishesNothing(t *testing.T) {
	in := []string{"SHELL=/bin/bash", "PATH=/usr/bin"}
	got := PrepareEnv(in, "")
	if !slices.Equal(got, in) {
		t.Errorf("PrepareEnv(env, \"\") = %v, want the environment unchanged", got)
	}
}

// TestPrepareEnvStillCorrectsShellWhenGivenOne guards the login-shell behaviour
// the empty-path case must not have broken.
func TestPrepareEnvStillCorrectsShellWhenGivenOne(t *testing.T) {
	got := PrepareEnv([]string{"SHELL=/usr/sbin/lbash"}, "/bin/bash")
	if !slices.Contains(got, "SHELL=/bin/bash") {
		t.Errorf("PrepareEnv = %v, want SHELL rewritten to the real shell", got)
	}
}
```

Add `"slices"` to `relay_test.go`'s imports.

- [ ] **Step 4: Run to verify the new tests fail and the suite still builds**

Run: `go test ./internal/logshell/ -run TestPrepareEnv -v`
Expected: FAIL on the empty-path case until Step 2's change is in; PASS after.

- [ ] **Step 5: Change the RunRecorded signature**

In `internal/logshell/relay.go`, replace the signature and the first lines of the body:

```go
// RunRecorded records an interactive session through a second pty.
//
// It takes a RunSpec rather than positional arguments for the same reason the
// non-interactive path does: the two entry points -- a login shell and an sshd
// forced command -- differ only in how they resolve what to run, and threading
// each new field through six positional parameters is how the two drift apart.
func RunRecorded(ctx context.Context, spec RunSpec, tio TerminalIO) (Outcome, error) {
	cfg, inv, shellPath, cmdLog := spec.Config, spec.Invocation, spec.ShellPath, spec.CmdLog
	stdin := tio.In
	// ... body unchanged from here
```

After the existing `meta.ApplyNesting(DetectNesting())` line, add:

```go
	meta.ApplyAuthInfo(spec.Info)
```

And in `runPassthrough` (`nonint.go`), after the existing `meta.ApplyNesting(nesting)` line:

```go
	meta.ApplyAuthInfo(spec.Info)
```

- [ ] **Step 6: Update the call sites**

In `cmd/logsh/main.go`, `runShell`: move the `spec` construction above the `switch`, add `EnvShell`, and use it for both branches.

```go
	spec := logshell.RunSpec{
		Config:     cfg,
		Invocation: inv,
		ShellPath:  shellPath,
		Std:        logshell.StdStreams(),
		CmdLog:     cmdLog,
		EnvShell:   shellPath, // a login shell: $SHELL must name the real shell
	}
```

and the default branch becomes:

```go
		default:
			if logshell.IsTerminal(os.Stdin.Fd()) {
				outcome, err = logshell.RunRecorded(ctx, spec, logshell.StdTerminal())
			} else {
				outcome, err = logshell.RunNonInteractive(ctx, spec)
			}
```

In `runRecord`:

```go
	inv := logshell.Invocation{Name: filepath.Base(shellPath), Args: args}
	outcome, err := logshell.RunRecorded(context.Background(), logshell.RunSpec{
		Config:     cfg,
		Invocation: inv,
		ShellPath:  shellPath,
		Std:        logshell.StdStreams(),
		EnvShell:   shellPath,
	}, logshell.StdTerminal())
```

- [ ] **Step 7: Fix remaining call sites and run the full suite**

Run: `go build ./... && make test`
Expected: the compiler names every remaining `RunRecorded` call site (mostly in `internal/logshell/*_test.go`); convert each to the `RunSpec` form, setting `EnvShell: <shellPath>` so existing behaviour is preserved. All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/logshell/nonint.go internal/logshell/relay.go internal/logshell/relay_test.go internal/logshell/exec.go cmd/logsh/main.go
git commit -m "refactor(logsh): give RunRecorded a RunSpec, and PrepareEnv an opt-out

Both recorders now take the same value, so a second entry point can supply
sshd's session info without threading it through six positional parameters.

PrepareEnv with an empty path publishes no SHELL: a forced-command route may
exec sftp-server or rrsync, and SHELL=/usr/lib/ssh/sftp-server is a claim
scripts testing \$SHELL against /etc/shells will act on."
```

---

## Task 8: Make `refuse` and `passthrough` work on a target

**Files:**
- Modify: `cmd/logsh/main.go` (`passthrough` ~line 186, `refuse` ~line 201, `runShell` call sites)
- Test: `cmd/logsh/main_test.go`

**Interfaces:**
- Consumes: `logshell.Target`, `logshell.ChildArgv0`, `logshell.Exec`.
- Produces (package-private to `cmd/logsh`):
  - `type execTarget struct { path, argv0 string; args []string; envShell string }`
  - `func targetFromInvocation(inv logshell.Invocation, shellPath string) *execTarget`
  - `func targetFromRoute(t logshell.Target) *execTarget`
  - `func passthrough(tgt *execTarget) int`
  - `func refuse(cfg *logshell.Config, tgt *execTarget, reason string) int`

- [ ] **Step 1: Write the failing test**

Append to `cmd/logsh/main_test.go`:

```go
// TestTargetFromRouteBuildsTheRightArgv.
//
// The interactive route must produce a LOGIN argv[0] -- "-bash", not "bash".
// sshd marks a login shell that way and every shell decides from argv[0][0]
// alone, so getting it wrong stops /etc/profile and ~/.bash_profile running,
// fleet-wide, with no error anywhere. This is acceptance test T-3's mechanism.
func TestTargetFromRouteBuildsTheRightArgv(t *testing.T) {
	tests := []struct {
		name      string
		target    logshell.Target
		wantArgv0 string
		wantArgs  []string
		wantEnv   string
	}{
		{
			name:      "interactive is a login shell",
			target:    logshell.Target{Kind: logshell.RouteInteractive, Path: "/bin/bash"},
			wantArgv0: "-bash",
			wantArgs:  nil,
			wantEnv:   "/bin/bash",
		},
		{
			name:      "default route runs the shell with -c",
			target:    logshell.Target{Kind: logshell.RouteDefault, Path: "/bin/bash", Args: []string{"-c", "id"}},
			wantArgv0: "bash",
			wantArgs:  []string{"-c", "id"},
			wantEnv:   "/bin/bash",
		},
		{
			// Not a shell. Publishing SHELL=/usr/lib/ssh/sftp-server would be a
			// lie, so envShell stays empty.
			name:      "exec route is not a shell",
			target:    logshell.Target{Kind: logshell.RouteExec, Path: "/usr/lib/ssh/sftp-server", Args: []string{"-l", "INFO"}},
			wantArgv0: "sftp-server",
			wantArgs:  []string{"-l", "INFO"},
			wantEnv:   "",
		},
		{
			name:      "command route is not a shell either",
			target:    logshell.Target{Kind: logshell.RouteCommand, Path: "/usr/bin/git-shell", Args: []string{"-c", "git-upload-pack x"}},
			wantArgv0: "git-shell",
			wantArgs:  []string{"-c", "git-upload-pack x"},
			wantEnv:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := targetFromRoute(tt.target)
			if got.path != tt.target.Path {
				t.Errorf("path = %q, want %q", got.path, tt.target.Path)
			}
			if got.argv0 != tt.wantArgv0 {
				t.Errorf("argv0 = %q, want %q", got.argv0, tt.wantArgv0)
			}
			if !slices.Equal(got.args, tt.wantArgs) {
				t.Errorf("args = %q, want %q", got.args, tt.wantArgs)
			}
			if got.envShell != tt.wantEnv {
				t.Errorf("envShell = %q, want %q", got.envShell, tt.wantEnv)
			}
		})
	}
}

// TestRefuseWithNoTargetRefuses.
//
// A nil target means there is nothing to exec, so neither fail-open nor
// break-glass can rescue the session. It must refuse rather than return success,
// because a forced command that exits 0 on an unhandled branch silently grants
// an unrecorded root session.
func TestRefuseWithNoTargetRefuses(t *testing.T) {
	cfg := logshell.DefaultConfig()
	cfg.FailClosed = false // even fail-open cannot help with nothing to run
	if got := refuse(cfg, nil, "test"); got != exitRefused {
		t.Errorf("refuse(cfg, nil) = %d, want exitRefused (%d)", got, exitRefused)
	}
}
```

Ensure `cmd/logsh/main_test.go` imports `"slices"` and `"sudosrv/internal/logshell"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/logsh/ -run 'TestTargetFromRoute|TestRefuseWithNoTarget' -v`
Expected: FAIL — `undefined: targetFromRoute`.

- [ ] **Step 3: Implement**

In `cmd/logsh/main.go`, replace `passthrough` and `refuse` with:

```go
// execTarget is a resolved program plus the argv and $SHELL value to run it
// with. It is what both entry points hand to passthrough and to break-glass, so
// an unrecorded session runs exactly what a recorded one would have.
type execTarget struct {
	path     string
	argv0    string
	args     []string
	envShell string // "" publishes no SHELL; see logshell.RunSpec.EnvShell
}

// targetFromInvocation builds the login-shell path's target.
func targetFromInvocation(inv logshell.Invocation, shellPath string) *execTarget {
	if shellPath == "" {
		return nil
	}
	return &execTarget{
		path:     shellPath,
		argv0:    logshell.ChildArgv0(shellPath, inv.LoginShell),
		args:     inv.Args,
		envShell: shellPath,
	}
}

// targetFromRoute builds the forced-command path's target.
//
// The interactive route is exec'd as a LOGIN shell -- argv[0] "-bash", not
// "bash". sshd marks a login shell that way and every shell decides from
// argv[0][0] alone; dropping the dash stops /etc/profile and ~/.bash_profile
// running fleet-wide, with no error anywhere, and users notice weeks later as
// "my PATH is wrong on the new boxes". Passing "-l" instead would work on bash
// and fail on shells that do not accept it.
//
// $SHELL is published only for the two routes that actually run a shell. An
// exec or command route may run sftp-server or rrsync, which are not shells.
func targetFromRoute(t logshell.Target) *execTarget {
	if t.Path == "" {
		return nil
	}
	isShell := t.Kind == logshell.RouteInteractive || t.Kind == logshell.RouteDefault
	tgt := &execTarget{
		path:  t.Path,
		argv0: logshell.ChildArgv0(t.Path, t.Kind == logshell.RouteInteractive),
		args:  t.Args,
	}
	if isShell {
		tgt.envShell = t.Path
	}
	return tgt
}

// passthrough execs the target with no recording. It returns only on failure.
func passthrough(tgt *execTarget) int {
	if tgt == nil {
		logshell.Alertf(syslog.LOG_ERR, "nothing to exec")
		return exitGeneral
	}
	if err := logshell.Exec(tgt.path, tgt.argv0, tgt.args, os.Environ()); err != nil {
		logshell.Alertf(syslog.LOG_ERR, "%v", err)
		return exitGeneral
	}
	return exitOK // unreachable: Exec replaced the process
}

// refuse applies the failure policy when a session that should be recorded
// cannot be.
//
// Order matters. An explicit fail_closed: false is the operator saying "keep
// sessions working", and is honoured without needing a marker file. The
// break-glass marker is the escape hatch for the default posture. Only when
// neither applies is the session actually refused.
//
// Both fallbacks exec the RESOLVED TARGET, not a shell. An sftp session that
// degraded into an interactive shell would be a broken transfer, not a graceful
// failure -- and for a forced command it would also hand the client something
// they did not ask for.
func refuse(cfg *logshell.Config, tgt *execTarget, reason string) int {
	if cfg != nil && !cfg.FailClosed && tgt != nil {
		logshell.Alertf(syslog.LOG_ERR,
			"proceeding UNRECORDED because fail_closed is disabled: %s", reason)
		return passthrough(tgt)
	}

	if logshell.BreakGlassActive(cfg) && tgt != nil {
		logshell.Alertf(syslog.LOG_CRIT,
			"proceeding UNRECORDED via break-glass marker %s: %s",
			logshell.BreakGlassPath(cfg), reason)
		fmt.Fprint(os.Stderr, logshell.BreakGlassBanner)
		return passthrough(tgt)
	}

	logshell.Alertf(syslog.LOG_ERR, "session REFUSED for uid %d: %s", os.Getuid(), reason)
	fmt.Fprintf(os.Stderr,
		"logsh: this session cannot be recorded, and this host is configured to refuse\n"+
			"       sessions it cannot record. Contact your administrator.\n")
	return exitRefused
}
```

- [ ] **Step 4: Update `runShell`'s call sites**

Replace each `refuse(cfg, inv, shellPath, ...)` with `refuse(cfg, targetFromInvocation(inv, shellPath), ...)`, each `refuse(nil, inv, "", ...)` with `refuse(nil, nil, ...)`, and each `passthrough(inv, shellPath)` with `passthrough(targetFromInvocation(inv, shellPath))`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./cmd/logsh/ -v && make test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/logsh/main.go cmd/logsh/main_test.go
git commit -m "refactor(logsh): express passthrough and refuse over a resolved target

Break-glass and fail_closed:false must exec what the session was going to run,
not a shell: an sftp session that degrades into an interactive shell is a broken
transfer, not a graceful failure. A nil target refuses, because a forced command
that exits 0 on an unhandled branch silently grants an unrecorded root session."
```

---

## Task 9: Wire up `runForceCommand`

**Files:**
- Create: `cmd/logsh/entry.go`, `cmd/logsh/entry_test.go`
- Modify: `cmd/logsh/main.go` (`main`, line 59)

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Produces:
  - `func sessionInfoFromEnv() logshell.SessionInfo`
  - `func runForceCommand(inv logshell.Invocation, cfg *logshell.Config) int`

**Second defect found during Task 9's implementation, fixed here.** The signature above is corrected from what this section originally specified: `func runForceCommand(inv logshell.Invocation, configPath string) int`, which had `runForceCommand` call `logshell.Load(configPath)` itself. That made the route test's success path depend on a config file passing `Load`'s root-ownership gate (`logshell.RequiredOwnerUID`) -- something no unprivileged test process can produce for a file it created itself (`chown` to a uid you do not hold requires `CAP_CHOWN`). The only way to make that version of the route test run unprivileged was to depend on a real, already-root-owned system file, which reintroduces exactly the host-dependence the first defect note below removes. `runForceCommand` now takes an already-loaded `*logshell.Config`, and `main` calls `logshell.Load(logshell.DefaultConfigPath)` itself, handling the error *before* `runForceCommand` is ever invoked. The ownership gate stays on the one production path, in `main`; `runForceCommand` trusts the config it is handed because `main` is its only production caller. A test hands it a config built with `logshell.LoadUnchecked` instead -- content validation only, no ownership gate -- and now runs for real, unprivileged, with no skip.

- [ ] **Step 1: Write the failing test**

Create `cmd/logsh/entry_test.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/entry_test.go
package main

import (
	"os"
	"strings"
	"sudosrv/internal/logshell"
	"testing"
)

// TestSessionInfoFromEnvReadsWhatSshdWrote.
//
// SSH_ORIGINAL_COMMAND and SSH_CONNECTION are set by sshd, not by the client
// directly: PermitUserEnvironment defaults to no and AcceptEnv is a narrow
// allowlist. They are still attacker-INFLUENCED -- the client chooses the
// command -- which is why the command is only ever recorded and passed as one
// -c argument, never parsed for meaning.
func TestSessionInfoFromEnvReadsWhatSshdWrote(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "internal-sftp -l INFO")
	t.Setenv("SSH_CONNECTION", "10.20.30.41 51234 10.20.30.9 22")
	t.Setenv("SSH_USER_AUTH", "")

	got := sessionInfoFromEnv()
	if got.SSHCommand != "internal-sftp -l INFO" {
		t.Errorf("SSHCommand = %q", got.SSHCommand)
	}
	// Source address and port only. The destination is this host, which the
	// record already names, and carrying it twice is noise.
	if got.SSHClient != "10.20.30.41 51234" {
		t.Errorf("SSHClient = %q, want \"10.20.30.41 51234\"", got.SSHClient)
	}
}

// TestSessionInfoFromEnvSurvivesAnEmptyEnvironment.
//
// Attribution failure warns and proceeds. Nothing here may be fatal: an
// unattributed recording beats no recording, and this code runs before anything
// else in a root session.
func TestSessionInfoFromEnvSurvivesAnEmptyEnvironment(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_USER_AUTH", "")

	got := sessionInfoFromEnv()
	if got.SSHCommand != "" || got.SSHClient != "" || got.Auth.Method != "" {
		t.Errorf("want a zero SessionInfo, got %+v", got)
	}
}

// TestSessionInfoFromEnvMalformedSshConnection guards against an index panic on
// a value that is not ours to trust the shape of.
func TestSessionInfoFromEnvMalformedSshConnection(t *testing.T) {
	t.Setenv("SSH_USER_AUTH", "")
	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	for _, v := range []string{"10.20.30.41", "", "   ", "a b c d e f g"} {
		t.Setenv("SSH_CONNECTION", v)
		_ = sessionInfoFromEnv() // must not panic
	}
}

// TestEntryNameDispatchesAwayFromAdmin.
//
// If logsh-entry ever reached the admin flag parser it would print usage and
// exit non-zero, which for a ForceCommand means root cannot log in.
func TestEntryNameDispatchesAwayFromAdmin(t *testing.T) {
	inv := logshell.ParseInvocation([]string{"/usr/sbin/logsh-entry"})
	if inv.IsAdmin() {
		t.Fatal("logsh-entry must not reach runAdmin")
	}
	if !inv.IsEntry() {
		t.Fatal("logsh-entry must be recognised as the entry point")
	}
}
```

**No `TestRunForceCommandRefusesWithoutAConfig` here.** An earlier version of this step had one, covering "no configuration means `runForceCommand` refuses". Now that config acquisition has moved to `main` (see the defect note above), that behaviour is `main`'s own `refuse(nil, nil, ...)` call on a `logshell.Load` failure -- not something `runForceCommand` does anymore -- and it is already pinned by `TestRefuseWithNoTargetRefuses` in `main_test.go`, which asserts `refuse(cfg, nil, "test")` returns `exitRefused` even with `cfg.FailClosed = false`. `refuse`'s own logic makes both of its fail-open branches conditional on `tgt != nil`, so that assertion covers `refuse(nil, nil, ...)` too: whether `cfg` is nil or merely permissive, a nil target is what forces the refusal, and that is true either way.

The imports this file actually needs are `"sudosrv/internal/logshell"` and `"testing"`. `t.Setenv` needs no `os` import.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/logsh/ -run 'TestSessionInfo|TestRunForceCommand|TestEntryNameDispatches' -v`
Expected: FAIL — `undefined: sessionInfoFromEnv`, `undefined: runForceCommand`.

- [ ] **Step 3: Implement**

Create `cmd/logsh/entry.go`:

```go
// SPDX-License-Identifier: Apache-2.0
// Filename: cmd/logsh/entry.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"sudosrv/internal/logshell"
)

// sessionInfoFromEnv gathers what sshd told us about this session.
//
// Every field is optional and no failure here is fatal. Attribution failure
// warns and proceeds: an unattributed recording is enormously better than a
// refused login, and putting a file sshd wrote on the critical path of every
// root login is exactly the fragility this design avoids elsewhere.
func sessionInfoFromEnv() logshell.SessionInfo {
	info := logshell.SessionInfo{SSHCommand: os.Getenv("SSH_ORIGINAL_COMMAND")}

	// SSH_CONNECTION is "<client ip> <client port> <server ip> <server port>".
	// Only the client half is kept: the server half is this host, which the
	// record already names. Indexing is guarded because the shape of this value
	// is sshd's promise, not ours to assume.
	if fields := strings.Fields(os.Getenv("SSH_CONNECTION")); len(fields) >= 2 {
		info.SSHClient = fields[0] + " " + fields[1]
	}

	auth, err := logshell.ReadAuthInfo(os.Getenv("SSH_USER_AUTH"))
	if err != nil {
		logshell.Alertf(syslog.LOG_CRIT,
			"no usable SSH_USER_AUTH (%v): this root session will be recorded without "+
				"certificate attribution. Is ExposeAuthInfo enabled?", err)
		return info
	}
	if auth.Method == logshell.AuthMethodKey {
		// Under the certificate design this is the break-glass account or a key
		// the fallback audit missed. Worth saying out loud, not just recording.
		logshell.Alertf(syslog.LOG_CRIT,
			"root SSH session authenticated by a plain key (%s), not a certificate: "+
				"no human is named in this session's credential", auth.KeyFingerprint)
	}
	info.Auth = auth
	return info
}

// runForceCommand is the path taken when sshd runs logsh as a forced command.
//
// REVIEW THIS AS SECURITY-RELEVANT CODE. It runs before anything else in the
// session, on a command string the client chose. A bug here is either a lockout
// or an unrecorded root session.
//
// Every path below ends in exec-a-resolved-target or refuse(). There is no
// fall-through: a forced command that returns 0 without exec'ing anything hands
// the client a session that nothing recorded.
//
// cfg is a parameter rather than a path this function loads itself: acquiring
// it -- via logshell.Load, which enforces logshell.RequiredOwnerUID -- is main's
// job, before runForceCommand is ever called. This function TRUSTS cfg without
// re-checking ownership, because main is the only production caller and main
// obtained cfg through that gate. A test may hand it a config built with
// logshell.LoadUnchecked instead, which validates content but skips the gate --
// deliberately, since exercising routing here is not exercising the
// authentication path's file-selection decision, and an unprivileged test
// process cannot manufacture a root-owned file to satisfy Load in the first
// place (chown to a uid you do not hold requires CAP_CHOWN). There is
// deliberately NO environment override anywhere in this chain: this runs with
// an environment the client influences, at the start of a root session, and the
// file main loads decides both which binary gets exec'd and whether the session
// is recorded at all.
func runForceCommand(inv logshell.Invocation, cfg *logshell.Config) int {
	// Read the credential before anything else: sshd removes the file at session
	// end, and every later moment is another chance for it to be gone.
	info := sessionInfoFromEnv()

	target := cfg.ForceCommand.Resolve(info.SSHCommand)

	uid := os.Getuid()
	username := lookupUsername(uid)

	// The interactive and default routes run the account's own shell, which
	// routing does not resolve. An exec or command route named its own program.
	if target.NeedsShell() {
		shell, shellErr := cfg.ResolveEntryShell(logshell.PasswdPath, username, uid)
		if shellErr != nil {
			// Distinct from every other failure: there is no shell to fall back
			// to, so neither fail-open nor break-glass can rescue this. sshd
			// would equally have failed to exec this entry. Same treatment
			// runShell gives an unresolvable shell.
			logshell.Alertf(syslog.LOG_ERR, "cannot resolve a shell: %v", shellErr)
			return exitConfig
		}
		target.Path = shell
	}

	tgt := targetFromRoute(target)

	if !cfg.ShouldRecord(username, uid) {
		return passthrough(tgt)
	}

	ctx := context.Background()

	cmdLog, cmdLogErr := logshell.OpenCommandLog(cfg)
	if cmdLogErr != nil {
		if cfg.CommandLog.Required {
			return refuse(cfg, tgt, fmt.Sprintf("command log unavailable: %v", cmdLogErr))
		}
		logshell.Alertf(syslog.LOG_WARNING, "command log unavailable, continuing without it: %v", cmdLogErr)
	}
	defer func() { _ = cmdLog.Close() }()

	spec := logshell.RunSpec{
		Config: cfg,
		// The route's argv, expressed as an Invocation so the recorders build
		// argv[0] the one way ChildArgv0 knows.
		Invocation: logshell.Invocation{
			Name:       filepath.Base(tgt.path),
			LoginShell: target.Kind == logshell.RouteInteractive,
			Args:       tgt.args,
		},
		ShellPath: tgt.path,
		Std:       logshell.StdStreams(),
		CmdLog:    cmdLog,
		Info:      info,
		EnvShell:  tgt.envShell,
	}

	var outcome logshell.Outcome
	var err error
	// Interactive or not is decided by whether a terminal is attached, NEVER by
	// the route kind. `ssh -t root@host /bin/bash` supplies a command AND
	// allocates a pty; keying off the route would classify it as non-interactive
	// and hand the user a fully interactive, entirely unrecorded shell. This is
	// the same rule runShell applies, for the same reason.
	if logshell.IsTerminal(os.Stdin.Fd()) {
		outcome, err = logshell.RunRecorded(ctx, spec, logshell.StdTerminal())
	} else {
		outcome, err = logshell.RunNonInteractive(ctx, spec)
	}

	if err != nil {
		if errors.Is(err, logshell.ErrRecordingUnavailable) {
			// No child was ever started, so the failure policy still has a
			// meaningful choice to make.
			return refuse(cfg, tgt, err.Error())
		}
		// The child ran. The audit gap has already happened and cannot be undone
		// by refusing; the user's exit status is a fact they are owed.
		logshell.Alertf(syslog.LOG_CRIT,
			"forced-command session for uid %d ran but was NOT durably recorded: %v", uid, err)
	}
	return outcome.ExitCode
}
```

In `cmd/logsh/main.go`, replace `main`:

```go
func main() {
	inv := logshell.ParseInvocation(os.Args)
	switch {
	case inv.IsAdmin():
		os.Exit(runAdmin(inv))
	case inv.IsEntry():
		// The root-ownership gate belongs here, on the one production path, and
		// nowhere inside runForceCommand: see that function's doc comment.
		cfg, err := logshell.Load(logshell.DefaultConfigPath)
		if err != nil {
			// No configuration means we cannot tell whether this account should
			// be recorded, so the safe answer is the same as "recording failed".
			// There is nothing resolved to exec, so no target.
			os.Exit(refuse(nil, nil, fmt.Sprintf("configuration is unusable: %v", err)))
		}
		os.Exit(runForceCommand(inv, cfg))
	}
	os.Exit(runShell(inv))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/logsh/ -v`
Expected: PASS

- [ ] **Step 5: Add a subprocess test that actually execs each route**

`runForceCommand` ends in `syscall.Exec` for the unrecorded path, which would replace the test process. `record_users` is left empty so every session takes the unrecorded passthrough and no log server is needed.

**Defect found during Task 9's implementation, fixed here.** The original version of this step built the `logsh` binary, symlinked it as `logsh-entry`, and drove `main`'s own dispatch through a `configPathForEntry()` hook that read `$LOGSH_CONFIG_FOR_TEST` -- but only when the compiled-in `/etc/logsh/logsh.yaml` was *absent*, "so it can never shadow a deployed file". That precondition makes the test's own outcome depend on whether the host running it happens to have logsh installed: on a machine with a real `/etc/logsh/logsh.yaml` already in place (this repo's own dev host has one, unrelated to this plan), the override is silently ignored, the test's own routes are never read, and the `exec route ignores the client's arguments` subtest fails for a reason that has nothing to do with the code being tested. That is the wrong property for a test to have, and worse, it required an environment-readable config selector to exist on `main`'s authentication path at all -- exactly what the preamble above already says must not exist.

The fix drops `configPathForEntry` entirely and never builds a binary or touches `main`'s dispatch here. `runForceCommand` already takes its config path as a parameter, which is the seam: drive it through the `os.Args[0]` re-exec idiom `cmd/logsh/main_test.go` already established for the same reason (`TestPassthroughForwardsTargetEnvShell` / `TestPassthroughHelperProcess` -- `passthrough` also ends in an exec that would replace the test binary). The parent process re-execs the test binary with `-test.run` anchored exactly to a helper test, passes the temp config path and `SSH_ORIGINAL_COMMAND` through the environment, and the helper calls `runForceCommand` directly. This costs the "exercises the real `main` dispatch through a `logsh-entry` symlink" property; `TestEntryNameDispatchesAwayFromAdmin` already covers that a `logsh-entry` invocation is recognised and never reaches `runAdmin`, which is what that dispatch actually decides.

Append to `cmd/logsh/entry_test.go`:

```go
// TestForcedCommandRoutesExec is acceptance tests T-1 and T-2 against
// runForceCommand: every branch execs what it should, no branch falls through
// to an unrecorded shell, and hostile input never reaches a route's argv.
//
// record_users is empty, so each session takes the unrecorded passthrough --
// which is the path that proves routing, since it execs the resolved target
// directly with nothing in between. That passthrough ends in syscall.Exec,
// which replaces the calling process on success, so each case is driven
// through the os.Args[0] re-exec idiom already established by
// TestPassthroughForwardsTargetEnvShell / TestPassthroughHelperProcess in
// main_test.go: the parent re-execs this test binary with -test.run anchored
// exactly to the helper below, and the helper loads the temp config with
// logshell.LoadUnchecked and calls runForceCommand directly with the result.
//
// This deliberately does NOT build the binary and drive it through a
// logsh-entry symlink, and deliberately does NOT go anywhere near
// logshell.Load. runForceCommand takes an already-loaded *logshell.Config
// rather than a path precisely so a test can hand it one built with
// LoadUnchecked -- content validation only, no root-ownership gate -- since an
// unprivileged test process cannot manufacture a root-owned file to satisfy
// Load in the first place (chown to a uid you do not hold requires CAP_CHOWN).
// That gate now lives in main, on the one production path, and stays real:
// internal/logshell's own TestLoadRequiresRootOwnership pins that Load actually
// enforces uid 0. Going through main's actual argv0 dispatch is covered
// separately by TestEntryNameDispatchesAwayFromAdmin, which pins that a
// logsh-entry invocation is recognised as IsEntry() and never reaches
// runAdmin; what happens once runForceCommand has a config in hand is exactly
// what this test checks, directly, with no skip and no host dependence.
func TestForcedCommandRoutesExec(t *testing.T) {
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "logsh.yaml")
	cfg := "record_users: []\n" +
		"force_command:\n" +
		"  routes:\n" +
		"    internal-sftp:\n" +
		"      exec: [/bin/echo, SFTP-ROUTE]\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		original   string
		wantOut    string
		wantAbsent string
		wantCode   int
	}{
		{
			name: "default route runs the command through the shell",
			original: "echo hello", wantOut: "hello", wantCode: 0,
		},
		{
			// The CONFIG's argv wins; the client's arguments are discarded.
			name: "exec route ignores the client's arguments",
			original: "internal-sftp -l DEBUG3", wantOut: "SFTP-ROUTE", wantAbsent: "DEBUG3", wantCode: 0,
		},
		{
			// The security property: field 0 is "internal-sftp;", not
			// "internal-sftp", so this must NOT match the route. It falls to the
			// default route and the shell runs the whole string -- which is what
			// a host with no ForceCommand would have done.
			name: "a metacharacter defeats matching rather than exploiting it",
			original: "internal-sftp; echo FELL-THROUGH",
			wantOut: "FELL-THROUGH", wantAbsent: "SFTP-ROUTE", wantCode: 0,
		},
		{
			name: "exit status passes through",
			original: "exit 42", wantCode: 42,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestForcedCommandRoutesHelperProcess$")
			cmd.Env = append(os.Environ(),
				"LOGSH_WANT_FORCECOMMAND_HELPER=1",
				"LOGSH_FORCECOMMAND_HELPER_CONFIG="+cfgPath,
				"SSH_ORIGINAL_COMMAND="+tt.original,
				"SSH_USER_AUTH=",
			)
			out, err := cmd.CombinedOutput()

			code := 0
			if ee, ok := errors.AsType[*exec.ExitError](err); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("run: %v\n%s", err, out)
			}
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d (output: %s)", code, tt.wantCode, out)
			}
			if tt.wantOut != "" && !strings.Contains(string(out), tt.wantOut) {
				t.Errorf("output %q does not contain %q", out, tt.wantOut)
			}
			if tt.wantAbsent != "" && strings.Contains(string(out), tt.wantAbsent) {
				t.Errorf("output %q must not contain %q", out, tt.wantAbsent)
			}
		})
	}
}

// TestForcedCommandRoutesHelperProcess is not a real test. Run under a normal
// `go test`, it checks LOGSH_WANT_FORCECOMMAND_HELPER and returns immediately,
// so it contributes nothing and shows as a trivial pass. It only does anything
// when spawned as a subprocess by TestForcedCommandRoutesExec, which sets that
// variable -- because runForceCommand's unrecorded routes end in an execve that
// must replace a disposable process, not the test binary running the actual
// assertions.
func TestForcedCommandRoutesHelperProcess(t *testing.T) {
	if os.Getenv("LOGSH_WANT_FORCECOMMAND_HELPER") != "1" {
		return
	}
	// LoadUnchecked, not Load: this is a temp file the test process itself
	// wrote, so it is owned by the test's own uid, not root, and Load's
	// ownership gate would refuse it regardless of content. That gate belongs
	// on main's production path, not here -- see runForceCommand's doc comment.
	cfg, err := logshell.LoadUnchecked(os.Getenv("LOGSH_FORCECOMMAND_HELPER_CONFIG"))
	if err != nil {
		t.Fatalf("test helper: LoadUnchecked: %v", err)
	}
	inv := logshell.Invocation{Name: logshell.EntryName}
	// Only returns on failure; on success runForceCommand's own passthrough has
	// already replaced this process and nothing below runs.
	os.Exit(runForceCommand(inv, cfg))
}
```

`main`'s entry case now loads and error-checks the config itself (see the `main` replacement in Step 3) and calls `os.Exit(runForceCommand(inv, cfg))` -- no hook, no override, no path parameter at all on this function anymore. There is nothing further to add to `main` for this step.

Add `"errors"`, `"os"`, `"os/exec"`, `"path/filepath"` and `"strings"` to `entry_test.go`'s imports (`"path/filepath"` was dropped from Step 1's list along with `TestRunForceCommandRefusesWithoutAConfig`, and is needed again here for `cfgPath := filepath.Join(cfgDir, "logsh.yaml")`).

- [ ] **Step 5a: Run the subprocess test**

Run: `go test ./cmd/logsh/ -run TestForcedCommandRoutesExec -v`
Expected: PASS, all four subtests. The metacharacter subtest is the important one — if `SFTP-ROUTE` appears in its output, matching is not exact and the rest of the command was silently discarded.

- [ ] **Step 6: Commit**

```bash
make test
git add cmd/logsh/entry.go cmd/logsh/entry_test.go cmd/logsh/main.go
git commit -m "feat(logsh): run as an sshd ForceCommand

Reads SSH_ORIGINAL_COMMAND and SSH_USER_AUTH natively, replacing the shell
wrapper the session-logging analysis proposed (finding F-2). Routes the client's
command, resolves the account's own shell for the interactive and default
routes, and stamps the certificate's key ID into submituser.

Every path ends in exec-a-target or refuse: a forced command that returns 0
without exec'ing anything grants a session nothing recorded. A plain-key root
login is alerted on, since the certificate design intends to eliminate it."
```

---

## Task 10: Packaging

**Files:**
- Modify: `packaging/logsh/logsh-install.sh`
- Test: `internal/logshell/packaging_test.go`

**Interfaces:**
- Consumes: `logshell.EntryName`.
- Produces: `/usr/sbin/logsh-entry` symlink; an uninstall guard.

- [ ] **Step 1: Write the failing test**

Append to `internal/logshell/packaging_test.go`:

```go
// TestInstallScriptShipsTheEntrySymlink.
//
// The forced-command entry point is a symlink like lbash, with one critical
// difference: it must NOT be registered in /etc/shells. It is not a shell, and
// listing it there would let an account be chsh'd to it.
func TestInstallScriptShipsTheEntrySymlink(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/logsh/logsh-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)

	if !strings.Contains(script, "ENTRY_SYMLINKS=\""+EntryName+"\"") {
		t.Errorf("install script must declare ENTRY_SYMLINKS=%q", EntryName)
	}
	// The /etc/shells registration loop must not reach the entry name.
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "add_shell") && strings.Contains(line, "ENTRY_SYMLINKS") {
			t.Errorf("the entry symlink must never be registered in /etc/shells: %q", line)
		}
	}
	if !strings.Contains(script, "sshd_config") {
		t.Error("uninstall must check sshd_config before removing the entry symlink")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/logshell/ -run TestInstallScriptShipsTheEntrySymlink -v`
Expected: FAIL — `ENTRY_SYMLINKS` absent.

- [ ] **Step 3: Implement**

In `packaging/logsh/logsh-install.sh`, after the `LEGACY_SYMLINKS` block:

```sh
# The forced-command entry point. Installed as a symlink like the shell names
# above, but deliberately NOT registered in /etc/shells: it is not a shell, and
# listing it there would let an account be chsh'd to it.
ENTRY_SYMLINKS="logsh-entry"

# Files searched for a live ForceCommand reference before the entry symlink is
# removed. See cmd_uninstall.
SSHD_CONFIGS="/etc/ssh/sshd_config /etc/ssh/sshd_config.d"
```

In `cmd_install`, after the existing `for name in $SYMLINKS` loop:

```sh
	for name in $ENTRY_SYMLINKS; do
		ln -sf logsh "$(r "$SBINDIR/$name")"
	done
```

Add before `cmd_uninstall`:

```sh
# entry_in_sshd_config prints every sshd config line naming the entry symlink.
#
# Removing the package deletes /usr/sbin/logsh-entry. On a host whose sshd_config
# says `ForceCommand /usr/sbin/logsh-entry`, that is root's SSH access to the
# host, gone -- and unlike the passwd-shell case, no account is switched, so the
# existing restore-before-remove ordering does not cover it.
entry_in_sshd_config() {
	for path in $SSHD_CONFIGS; do
		_p="$(r "$path")"
		[ -e "$_p" ] || continue
		grep -rn "logsh-entry" "$_p" 2>/dev/null || true
	done
}
```

At the top of `cmd_uninstall`, before anything is removed:

```sh
	_hits="$(entry_in_sshd_config)"
	if [ -n "$_hits" ] && [ "${1:-}" != "--force" ]; then
		printf 'logsh-install: refusing to uninstall: sshd still references logsh-entry\n' >&2
		printf '%s\n' "$_hits" >&2
		printf 'logsh-install: remove the Match block and reload sshd first, or pass --force\n' >&2
		exit 1
	fi
```

In `cmd_uninstall`'s symlink removal, extend the loop to cover `$ENTRY_SYMLINKS` — after the accounts have been restored, matching the existing ordering.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/logshell/ -run TestInstallScript -v`
Expected: PASS

- [ ] **Step 5: Exercise install and uninstall against a scratch root**

```bash
rm -rf /tmp/fakeroot && mkdir -p /tmp/fakeroot/usr/sbin /tmp/fakeroot/etc/ssh
touch /tmp/fakeroot/etc/shells /tmp/fakeroot/etc/passwd
go build -o /tmp/fakeroot/usr/sbin/logsh ./cmd/logsh

ROOT=/tmp/fakeroot packaging/logsh/logsh-install.sh install
ls -l /tmp/fakeroot/usr/sbin/logsh-entry           # exists
grep -c logsh-entry /tmp/fakeroot/etc/shells       # 0

printf 'Match User root\n    ForceCommand /usr/sbin/logsh-entry\n' > /tmp/fakeroot/etc/ssh/sshd_config
ROOT=/tmp/fakeroot packaging/logsh/logsh-install.sh uninstall; echo "refused=$?"
```

Expected: the symlink exists; `/etc/shells` contains no `logsh-entry`; uninstall exits non-zero naming the sshd_config line.

- [ ] **Step 6: Commit**

```bash
make test
git add packaging/logsh/logsh-install.sh internal/logshell/packaging_test.go
git commit -m "feat(logsh): install the logsh-entry symlink, and guard its removal

Installed like lbash but never registered in /etc/shells: it is not a shell, and
listing it there would let an account be chsh'd to it.

Uninstall now refuses while sshd_config still names logsh-entry. Removing the
package on an enrolled host deletes the forced command and takes root's SSH
access with it, and no account is switched, so the existing
restore-before-remove ordering does not cover that case."
```

---

## Task 11: Documentation

**Files:**
- Create: `docs/logsh-forcecommand.md`
- Modify: `examples/logsh.yaml`, `README.md`, `docs/logsh-deployment.md` (F-3), `internal/logshell/config.go` (F-3)
- Test: `internal/logshell/config_test.go` (`TestShippedExampleConfigIsValid` already covers the example)

**Interfaces:** none.

- [ ] **Step 1: Fix F-3 — the `nested_sessions` default**

Three places claim `metadata`; `DefaultConfig()` and `examples/logsh.yaml` say `record`. An operator reading the runbook expects no second transcript and gets one.

- `docs/logsh-deployment.md:275` — move the `*(default)*` marker off `metadata` and onto the `record` row.
- `docs/logsh-deployment.md:279` — the sentence beginning "The default is `metadata` rather than `skip` deliberately". Replace with the reasoning `Config.NestedSessions`'s doc comment already gives: the default is `record`, deliberately the wasteful option, because on a host whose sudoers rule lacks `log_output` a `metadata` default leaves the root session captured by nothing. Duplication is recoverable via the shared UUID; a transcript nobody took is gone.
- `internal/logshell/config.go:102` — "Default metadata." becomes "Default record."

Verify no other occurrence survives:

```bash
grep -rn "metadata" docs/logsh-deployment.md internal/logshell/config.go | grep -i default
```
Expected: no line claiming `metadata` is the default.

- [ ] **Step 2: Add the `force_command` section to the shipped example**

Append to `examples/logsh.yaml`:

```yaml
# Forced-command mode: sshd runs logsh via `ForceCommand /usr/sbin/logsh-entry`.
#
# Only consulted when logsh is invoked through the logsh-entry symlink. It does
# not affect the login-shell deployment at all.
#
# See docs/logsh-forcecommand.md.
force_command:
  # NORMALLY LEAVE THIS UNSET.
  #
  # Unset means the session runs the account's OWN shell from /etc/passwd --
  # exactly what sshd would have exec'd without ForceCommand, so enabling the
  # recorder changes which shell runs on no host. Setting it pins one shell for
  # every host sharing this file: root would get bash here even where root's
  # shell is zsh, and an SSH login would then differ from a console login on the
  # same account. `logsh -validate` warns when it is set.
  # shell: /bin/bash

  # Routes map a program basename to what should run instead.
  #
  # This is a LITERAL ALLOWLIST, not a pattern language. A key is matched
  # exactly against the basename of the first whitespace-separated field of
  # SSH_ORIGINAL_COMMAND -- no globs, no regular expressions, no prefix
  # matching. A route's argv comes from THIS FILE and never from the client; the
  # client's command reaches the program only through $SSH_ORIGINAL_COMMAND, as
  # sshd would have delivered it.
  #
  # Anything that does not match runs as `<shell> -c "<the client's command>"`,
  # which is what sshd does with no ForceCommand at all. So the table is for
  # commands that cannot run as-is -- not for restricting what root may do.
  routes:
    # The one entry most deployments need. internal-sftp is implemented
    # in-process inside sshd and has no binary to exec, so it must be
    # translated. Without this, sftp and modern scp (OpenSSH >= 9.0 routes scp
    # over SFTP) fail for forced-command sessions.
    #
    # -l INFO is load-bearing: the default is ERROR, and sshd_config's LogLevel
    # does NOT apply to the sftp server. At INFO you get per-operation records
    # with paths -- a file-level audit trail, not content capture.
    #
    # The path differs by distribution:
    #   /usr/libexec/openssh/sftp-server   RHEL, Fedora
    #   /usr/lib/openssh/sftp-server       Debian, Ubuntu
    #   /usr/lib/ssh/sftp-server           Arch
    internal-sftp:
      exec: [/usr/lib/ssh/sftp-server, -l, INFO]

    # Optional. rrsync reads $SSH_ORIGINAL_COMMAND itself, so a fixed argv is
    # all it needs. This CONFINES rsync to one subtree, which is a policy
    # decision and not a logging one -- leave it out unless you want that.
    # rsync:
    #   exec: [/usr/bin/rrsync, -no-del, /srv]

    # Optional. Runs: git-shell -c "<the client's command>"
    # git-shell:
    #   command: /usr/bin/git-shell
```

- [ ] **Step 3: Verify the example still validates**

Run: `go test ./internal/logshell/ -run TestShippedExampleConfigIsValid -v`
Expected: PASS. If the `sftp-server` path does not exist on the build host that is fine — `Validate` checks the path is absolute, and executability is a `-selftest` concern.

- [ ] **Step 4: Write the runbook**

Create `docs/logsh-forcecommand.md` covering, in this order:

1. **What this mode is for** — the audit gap a `root` certificate principal opens, and why the recorder attaches to sshd rather than to root's login shell (`/etc/passwd` is untouched, so console, serial, single-user mode, rescue, `su -` and `sudo -i` are unaffected).
2. **sshd_config** — the `Match User root` block, `ExposeAuthInfo yes`, and `Subsystem sftp internal-sftp -l INFO -f AUTH`. State that `sshd -t` gates every push, that reload is never restart, and that `sshd_config`'s `ForceCommand` supersedes a certificate's.
3. **Certificate critical options** — `-O clear -O permit-pty -O force-command=/usr/sbin/logsh-entry`, and the byte-identical rule against any existing `authorized_keys` `command=`.
4. **logsh.yaml** — the `force_command` section, and that `record_users` must name `root` or `0` or nothing is recorded.
5. **What gets recorded** — interactive sessions get a full `ttyout` transcript; everything else gets an attributable metadata record plus, for sftp, the sftp server's own per-operation syslog. Say plainly that `log_ttyin: false` does **not** mean keystrokes go unrecorded, because terminal echo puts them in `ttyout`; what it protects is echo-off prompts.
6. **The session record** — the `logsh_cert_*` keys, and that `submituser` carries the key ID while `submituid` stays 0 because there is no local uid for a certificate principal. Note that a session with `logsh_auth_method: publickey` and no key ID is a root login that arrived without a certificate, and is worth a SIEM rule.
7. **Which shell runs** — the account's own, from `/etc/passwd`; `logsh -selftest` prints it per host.
8. **Enabling a host** — `logsh -validate`, then `logsh -selftest`, then the sshd_config push, then a fresh login from a second terminal *before* closing the first.
9. **Removing it — ordering matters.** Remove the `Match User root` block and reload sshd **before** removing the package. `logsh-install.sh uninstall` refuses while sshd_config still names `logsh-entry`, because deleting the symlink under a live `ForceCommand` takes root's SSH access to the host with it.
10. **Break-glass** — the root-owned marker file, and the second uid-0 account that `Match User root` does not apply to.
11. **Known residual** — `SSH_USER_AUTH` is forgeable by root outside sshd, so a root user can self-misattribute a record. Consistent with the design's stated position that recording buys accountability, not containment.

- [ ] **Step 5: Update the README**

In the `logsh` section, add the third invocation mode beside the login-shell one: `/usr/sbin/logsh-entry` as an sshd `ForceCommand`, one sentence on what it covers that a login shell cannot (subsystems, so sftp and modern scp), and a link to `docs/logsh-forcecommand.md`.

- [ ] **Step 6: Commit**

```bash
make test
git add docs/logsh-forcecommand.md docs/logsh-deployment.md examples/logsh.yaml README.md internal/logshell/config.go
git commit -m "docs(logsh): document forced-command mode, and fix the nested_sessions default

Adds the deployment runbook, the shipped force_command example, and the README
entry for the third invocation mode.

Fixes finding F-3: docs/logsh-deployment.md and the NestedSessions doc comment
said the default was metadata while DefaultConfig and examples/logsh.yaml said
record. An operator reading the runbook expected no second transcript and got
one."
```

---

## Verification

Run before declaring the work complete:

```bash
make test
CGO_ENABLED=0 go build -ldflags="-s -w" -o /tmp/logsh ./cmd/logsh && ls -l /tmp/logsh
gofmt -l cmd internal
go vet ./...
```

Expected: all tests pass; `logsh` builds statically at roughly 8.43 MB; `gofmt -l` prints nothing; `go vet` is clean.

**Acceptance tests from the source document that this plan covers:** T-1, T-2 (Task 5 and Task 9 step 5), T-3 (Task 8), T-4 (Tasks 3 and 4), T-9 (Task 9), plus `-validate`/`-selftest` coverage (Task 6).

**Acceptance tests that need a real host and are out of this plan's scope:** T-5 to T-8 and T-10 to T-26 — they need sshd, a CA, a live log server or a package upgrade. They belong to the pilot in the source document's Stage B.
