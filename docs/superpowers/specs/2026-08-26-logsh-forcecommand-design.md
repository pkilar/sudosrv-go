# logsh: native `ForceCommand` support

**Status:** design, approved for planning
**Date:** 2026-08-26
**Component:** `sudosrv-go` — `cmd/logsh`, `internal/logshell`, `packaging/logsh`
**Driver:** *Session Logging for Direct Root SSH Access — Part 1*, Appendix C finding **F-2**

---

## 1. Context

The SSH certificate migration creates a route to root that does not pass through
`sudo`, and so is unrecorded. The accepted fix binds a recorder to `sshd` rather
than to root's login shell:

```
# /etc/ssh/sshd_config
Match User root
    ForceCommand /usr/sbin/logsh-entry
```

with the same value carried as a `force-command` critical option on privileged
certificates. Neither enforcement point captures anything by itself; both
guarantee that `logsh` runs.

`ForceCommand` "applies to shell, command, or subsystem execution" and puts the
client's request in `SSH_ORIGINAL_COMMAND`. A forced command that unconditionally
starts an interactive recorder therefore breaks SFTP and, since OpenSSH 9.0,
`scp`. Separately, a session running *as* root has no idea which human's
certificate opened it; `ExposeAuthInfo yes` supplies that in `SSH_USER_AUTH`.

`logsh` today reads neither variable. Finding F-2 records this and proposes a
`/bin/sh` wrapper (`logsh-entry`, Appendix A.4) as the interim answer, while
stating the durable one plainly:

> Preferably, delete this file. Adding native `SSH_ORIGINAL_COMMAND` and
> `SSH_USER_AUTH` handling to logsh puts this logic in tested Go rather than in
> shell on the authentication path.

This document specifies that native handling. **The wrapper is not implemented.**

### 1.1 Three defects in the reference wrapper that motivate doing this in Go

1. **It does not perform attribution.** A.4 copies the whole `SSH_USER_AUTH` file
   into `LOGSH_AUTH_INFO`. That file holds
   `publickey ssh-ed25519-cert-v01@openssh.com AAAA…`; the key ID and serial are
   inside the base64 certificate blob. §4.7 promises the wrapper "extracts the
   certificate's key ID and serial". A shell script cannot.
2. **The `sftp-server` path is not portable.** A.4 hardcodes
   `/usr/libexec/openssh/sftp-server` (RHEL). Debian uses `/usr/lib/openssh/`,
   Arch `/usr/lib/ssh/`.
3. **`-l` is the wrong fix for the login-shell problem.** A.4 passes `-l` to
   `bash`. The actual convention is `argv[0] == "-bash"`, which is what `sshd`
   itself does and what `ChildArgv0` already implements. `-l` also fails on
   shells that do not accept it.

### 1.2 What already works and is not being rebuilt

`RunNonInteractive` (`internal/logshell/nonint.go`) already handles
`ssh host cmd`, `scp` and `rsync`: it passes the three streams through as raw
`*os.File` descriptors — no pipe, no copying goroutine — and keeps a
metadata-only record. Acceptance test T-8 (1 GB `scp` within 5% of baseline) is a
property the current code was deliberately written to have. Signal forwarding,
exit-status passthrough, fail-closed, break-glass and journalling are likewise
present and unchanged.

---

## 2. Scope

**In scope.** A third invocation mode for `logsh`; a routing table over
`SSH_ORIGINAL_COMMAND`; certificate attribution from `SSH_USER_AUTH`; the
configuration, validation, packaging, tests and documentation for all three.
Plus finding **F-3** (documentation inconsistency), folded in because this work
touches the same documents.

**Out of scope.** `sshd_config` and Cerberus configuration (Appendices A.1/A.2
are not this repository). Findings F-1, F-4, F-5 (Cerberus). Installing `logsh`
as root's login shell (Option B, deferred by the source document). Recording
SFTP payload content. Finding F-6 (`record_users` and NSS) beyond the one
warning in §7.2.

---

## 3. Decisions

| # | Decision | Rationale |
|---|---|---|
| D-1 | Mode selected by a `/usr/sbin/logsh-entry` symlink | Matches the existing multi-call design and Appendices A.1/A.2 verbatim, so neither `sshd_config` nor the Cerberus critical option changes. Dispatch happens before any flag parsing, so `-config` is unreachable on this path. |
| D-2 | Certificates parsed with `golang.org/x/crypto/ssh` | Verified against ed25519, RSA and ECDSA certificates issued by `ssh-keygen`. Handles every algorithm including `sk-*`, and distinguishes plain keys from certificates. Cost measured below. |
| D-3 | `submituser` carries the certificate key ID | `SessionMeta` already separates `SubmitUser` from `User`, and `ApplyNesting` already rewrites it to the escalating human under `sudo -i`. A certificate-authenticated root session is the same shape, so R-2 and R-4 are satisfied together and `sudolens` needs no change. |
| D-4 | Routing is a configurable literal allowlist | Operator-extensible without a code change (`rrsync`, `git-shell`, future subsystems). Constrained to exact basename matching against a root-owned table so it is not a pattern engine on the authentication path — see §5.2. |
| D-5 | The interactive and default routes run **the account's own `/etc/passwd` shell**, not a configured one | §4.10 commits that this design does not change root's login shell — that is Option C's central advantage over Option B. A fleet-wide configured shell silently breaks that commitment on any host where root's shell is not the configured value, and splits behaviour by entry route (console gives zsh, SSH gives bash, same account). See §7.3. |

### 3.1 Measured cost of D-2

`golang.org/x/crypto v0.55.0` plus indirect `golang.org/x/sys v0.47.0`.
`logsh` grows **8.37 MB → 8.43 MB** (`CGO_ENABLED=0`, `-ldflags="-s -w"`) — measured at implementation, +64 KB.

An earlier estimate here said ≈10.3 MB. That was wrong: it added a standalone probe binary's *total* size to logsh's total, rather than measuring the marginal cost. `logsh` already links `crypto/tls` for its mTLS connection to the log server, so ed25519, RSA, ECDSA and SHA-256 are present either way; `x/crypto/ssh` contributes only the SSH wire format and key-type dispatch, and the linker drops the transport, cipher and key-exchange machinery because nothing here dials or accepts a connection.

### 3.2 Rejected alternatives

- **Hand-rolled certificate parser.** Avoids the dependency, but
  requires a per-algorithm table of key-field counts that is silently wrong when
  an unlisted algorithm appears. Rejected: correctness on the authentication path
  outweighs binary size — and the measured size cost turned out to be +64 KB, so
  there was less to weigh than the rejection assumed.
- **Auto-detecting force-command mode from `SSH_CONNECTION`.** Takes an authority
  decision from the environment and would change behaviour for existing
  login-shell deployments.
- **Default-deny routing.** §1.6 and R-8 are explicit that this is a logging
  control and not containment; containment is `-O clear` at the certificate
  layer. A deny list evaluated before any user code runs is a lockout generator.
- **A single configured interactive shell, with no passwd lookup.** Considered
  first and rejected: see D-5 and §7.3. The objection that killed it is that
  `force_command.shell: /bin/bash` applied fleet-wide silently replaces root's
  shell on every host where root's shell is something else, which is precisely
  the change §4.10 promises this design does not make. The "loop guard"
  argument raised in its favour turns out to argue the other way — a passwd
  entry pointing at a `logsh` symlink resolves cleanly through the existing
  `shells` map, so the two deployments compose (§7.3).

---

## 4. Dispatch

`logsh` forks two ways today. Add a third.

```
argv[0] basename == "logsh"        -> runAdmin        (unchanged)
argv[0] basename == "logsh-entry"  -> runForceCommand (new)
otherwise                          -> runShell        (unchanged)
```

`ParseInvocation` needs no change: it strips a leading dash and takes the
basename, and `sshd` invokes a forced command via `$SHELL -c` so there is no dash
to strip. Add `Invocation.IsEntry()` beside `IsAdmin()`, and
`const EntryName = "logsh-entry"` beside `AdminName`.

`Config.Validate` rejects `shells["logsh-entry"]`, so the name can never mean two
things on one host.

---

## 5. Routing

### 5.1 Why the table is small

Under `ForceCommand`, a *subsystem* request arrives with `SSH_ORIGINAL_COMMAND`
set to the subsystem command line from `sshd_config`. So a host configured with
`Subsystem sftp /usr/lib/ssh/sftp-server -l INFO` needs no special handling at
all — that is already a real command and the default route runs it correctly.

Only `internal-sftp` genuinely requires translation, because it is implemented
in-process inside `sshd` and has no binary to exec. `sshd_config(5)` confirms:
"Specifying a command of `internal-sftp` will force the use of an in-process SFTP
server."

Everything else — `rsync --server`, pre-9.0 `scp -t`, `ssh host cmd` — is already
served by the default route.

### 5.2 Matching rules

The table is a **literal allowlist keyed by program basename**. It is not a
pattern engine.

1. `SSH_ORIGINAL_COMMAND` empty or unset → **interactive**. Routes are not
   consulted.
2. Otherwise: split on ASCII whitespace, take field 0, take `filepath.Base` of
   it, and look that up as an **exact map key**. No globs, no regular
   expressions, no prefix matching, no case folding.
3. `exec:` runs a **fixed argv taken from the root-owned configuration file**.
   Nothing from the client is interpolated into it. The client's string reaches
   the program only through the inherited `SSH_ORIGINAL_COMMAND` variable —
   exactly as `sshd` would have delivered it. This is what makes `rrsync` work
   unchanged, since `rrsync` reads that variable itself.
4. `command: /path/to/prog` runs `prog -c "<SSH_ORIGINAL_COMMAND>"` with the
   command as a single argv element, never re-split and never passed through a
   shell by `logsh`.
5. No match → the default route: `force_command.shell -c "<SSH_ORIGINAL_COMMAND>"`.

`exec` and `command` are mutually exclusive within a route; setting both is a
validation error.

### 5.3 The safety argument

An unrecognised client string can only become a single `-c` argument or nothing.
**No branch is more permissive than the no-`ForceCommand` baseline**, which is
the property to hold onto: enabling the recorder must not enlarge what root can
do over SSH.

Shell metacharacters defeat matching rather than exploiting it.
`SSH_ORIGINAL_COMMAND="sftp-server; rm -rf /"` has field 0 `sftp-server;`, which
is not the key `sftp-server`, so it falls to the default route and the shell
handles it exactly as it would with no `ForceCommand` at all.

This is the desired failure direction. A matcher that stripped punctuation before
comparing would match the sftp route and **silently discard the rest of the
command** — a semantic change invisible to both the client and the transcript.

Two further cases follow from the same rule and need no special code: a leading
environment assignment (`FOO=1 rsync --server …` → field 0 `FOO=1`, no match) and
a path-qualified program (`/usr/lib/ssh/sftp-server -l INFO` → basename
`sftp-server`, matches). Path traversal in field 0 is harmless because only the
basename is compared and the route's argv comes from the config, never from the
client.

### 5.4 Recording per route

| Route kind | Recording |
|---|---|
| interactive | Full PTY transcript (`ttyout`), per `log_ttyout` |
| `exec` | Metadata only, streams passed through (`RunNonInteractive`) |
| `command` | Metadata only, streams passed through |
| default | Metadata only, streams passed through |

Recording is **never** disableable per route. A route selects *what to run*, not
*whether it is recorded*.

---

## 6. Attribution

### 6.1 Reading `SSH_USER_AUTH`

New file `internal/logshell/authinfo.go`.

```go
type AuthInfo struct {
    Method        string   // "publickey-cert" | "publickey" | "" (unknown)
    KeyID         string   // certificate key ID: the human
    Serial        uint64
    Principals    []string
    CAFingerprint string   // SHA256:… of the signing CA key
    KeyFingerprint string  // SHA256:… of the presented key or certificate
}

func ReadAuthInfo(path string) (AuthInfo, error)
```

Each line is `<method> <keytype> <base64>`. Fields 1 and 2 are decoded with
`ssh.ParsePublicKey`; a result that type-asserts to `*ssh.Certificate` yields the
key ID, serial, principals and CA fingerprint. The first line producing a
certificate wins.

**Failure is never fatal.** An absent, unreadable or unparseable
`SSH_USER_AUTH` logs at `LOG_CRIT` and the session proceeds unattributed — A.4's
rule, kept: an unattributed recording beats no recording.

### 6.2 A plain key is a signal, not an error

A line that parses to a plain public key rather than a certificate yields
`Method: "publickey"` and no key ID. That is exactly the signature of a root SSH
login that arrived **without** a certificate — the break-glass account, or a key
the certificate project's fallback audit missed. It is recorded rather than
treated as a failure, and is worth a SIEM rule. Verified: `ssh.ParsePublicKey`
distinguishes the two cleanly.

### 6.3 Where it lands

`SessionMeta` gains an `Auth AuthInfo` field and an `ApplyAuthInfo(AuthInfo)`
method, called from the same place `ApplyNesting` is called. When a certificate
was seen and its key ID is non-empty, `ApplyAuthInfo` sets
`SubmitUser = Auth.KeyID`.

New info keys, each **omitted when empty** (following the existing `source`
precedent, so an absent value never asserts "unknown"):

| Key | Example |
|---|---|
| `logsh_cert_keyid` | `jsmith@CORP.EXAMPLE.COM` |
| `logsh_cert_serial` | `20260819000137` |
| `logsh_cert_ca` | `SHA256:FF270WGkZMiYH/uz…` |
| `logsh_cert_principals` | `["root-web","root-everywhere"]` — sent as a `strlistval`, matching `runargv`/`runenv`, so it lands in `log.json` as a JSON array rather than a string needing re-splitting |
| `logsh_auth_method` | `publickey-cert` |
| `logsh_ssh_command` | `internal-sftp -l INFO -f AUTH` |
| `logsh_ssh_client` | `10.20.30.41 51234` (from `SSH_CONNECTION`) |

Resulting record for a certificate-authenticated interactive root session:

```
submituser              jsmith@CORP.EXAMPLE.COM
submituid               0
runuser                 root
runuid                  0
logsh_cert_keyid        jsmith@CORP.EXAMPLE.COM
logsh_cert_serial       20260819000137
logsh_cert_ca           SHA256:FF270WGkZMiYH/uz…
logsh_auth_method       publickey-cert
```

### 6.4 Two consequences, stated rather than discovered

- **`submituid` stays 0 while `submituser` names the human.** There is no local
  uid for `jsmith@CORP.EXAMPLE.COM`. This is honest — the numeric ids describe
  the process, the name describes the authenticated identity — but it is a real
  asymmetry with `sudo`'s records, where `submituid` is the invoking human's uid.
  Consumers joining on `submituid` must not assume it identifies a person.
- **`logsh_ssh_command` is truncated** at `DefaultCommandLogMaxLen`, with the
  truncation marked, so a hostile or merely enormous client command cannot bloat
  the session record.

### 6.5 Residual: `SSH_USER_AUTH` is forgeable outside `sshd`

A root user can set `SSH_USER_AUTH` to a file naming somebody else's certificate
and run `/usr/sbin/logsh-entry` by hand, producing a misattributed record. This is
accepted and consistent with §1.6 ("session recording does not prevent a hostile
root user from doing anything"). It is documented in the runbook rather than
mitigated, because any mitigation available to a process running as root is
defeatable by that same process.

---

## 7. Configuration

### 7.1 Schema

```yaml
force_command:
  # OPTIONAL OVERRIDE, normally left unset.
  #
  # Unset (the default) means the interactive and default routes run the
  # account's own shell from /etc/passwd -- exactly what sshd would have
  # exec'd without ForceCommand. See §7.3.
  #
  # Setting it pins one shell for every host sharing this file, which will
  # differ from the account's real shell wherever the two disagree, and from
  # what a console login gives. -validate warns when it is set. When set it
  # must appear as a VALUE in the `shells` map, reusing that allowlist so a
  # typo cannot become an arbitrary exec primitive.
  # shell: /bin/bash

  routes:
    # internal-sftp is in-process inside sshd and has no binary, so it is the
    # one command that genuinely requires translation.
    internal-sftp:
      exec: [/usr/lib/ssh/sftp-server, -l, INFO]

    # Optional. rrsync reads $SSH_ORIGINAL_COMMAND itself, so a fixed argv is
    # sufficient and nothing from the client is interpolated.
    # rsync:
    #   exec: [/usr/bin/rrsync, -no-del, /srv]

    # Optional. Runs: git-shell -c "<SSH_ORIGINAL_COMMAND>"
    # git-shell:
    #   command: /usr/bin/git-shell
```

Defaults: `force_command.shell` is unset (§7.3); `routes` is empty. An empty or
absent `force_command` section is valid and means "the account's own shell, plus
the default route" — correct for a host whose `sshd_config` names an external
`sftp-server` binary.

The `sftp-server` path is **not** auto-detected at runtime. Packaging picks the
correct path for the distribution when it writes the example configuration; a
runtime search would make the same configuration behave differently across hosts.

### 7.2 Validation (`-validate`) and gating (`-selftest`)

Errors — these prevent a working deployment or create a silent recording gap:

- a route key containing whitespace or a slash (it could never match, since
  matching is on the basename of field 0)
- a route with both `exec` and `command`, or with neither
- a route program that is not an absolute path
- `force_command.shell`, **when set**, not present among the values of `shells`
- `shells["logsh-entry"]` present

Errors under `-selftest` only, where the host is the one being enabled:

- a route program that is missing or not executable
- the resolved interactive shell (§7.3) missing or not executable

Warnings:

- `force_command.shell` is set. It pins one shell for every host sharing this
  configuration, so it will differ from the account's real shell wherever the two
  disagree, and from what a console login gives. Name the account and both
  shells in the warning.

- `force_command` is configured but `record_users` contains neither `root` nor
  `0` — the most likely single misconfiguration, and silent: sessions would be
  routed correctly and recorded not at all. (This is the F-6 failure mode
  narrowed to the case this feature creates.)
- no `internal-sftp` route is defined — harmless if `sshd_config` names an
  external `sftp-server`, and a broken SFTP subsystem if it does not. `logsh`
  cannot read `sshd_config`, so this can only be a warning.

`-selftest` additionally **prints the resolved interactive shell and where it came
from**, so an operator can see what will actually run before enabling the host:

```
ok    force_command: interactive shell for root: /bin/zsh (from /etc/passwd)
ok    force_command: routes[internal-sftp]: /usr/lib/ssh/sftp-server -l INFO
```

### 7.3 Which shell the interactive and default routes run

The problem this solves: root's shell is `/bin/zsh` on one host and `/bin/bash`
on another. A single configured value silently replaces it on one of them, which
is the change §4.10 promises this design does not make (D-5).

Resolution order:

1. **`force_command.shell`, if set** — the explicit override. Must be a value in
   `shells`; warned about at validation.
2. **Otherwise, the invoking account's shell field in `/etc/passwd`.** This is
   exactly what `sshd` would have exec'd with no `ForceCommand` present, so
   enabling the recorder changes which shell runs on no host.
   - If its basename is a key in `shells` — root's shell is itself a `logsh`
     symlink, i.e. the host also runs the Option B deployment — resolve it
     **through the `shells` map** to the real shell. The two deployments then
     compose: one recorder, one PTY, the right shell. This is the loop guard,
     and it is the same map lookup `runShell` already performs.
   - If the passwd shell field is empty, use `/bin/sh`. This matches `sshd`,
     which falls back to `_PATH_BSHELL` when `pw_shell` is empty.
3. If the result is not an absolute path, or is missing or not executable, log at
   `LOG_ERR` and exit `exitConfig` **without** exec'ing anything. This matches
   `runShell`'s existing treatment of an unresolvable shell: there is nothing to
   fall back to, so neither fail-open nor break-glass can rescue it. It also
   matches the baseline — `sshd` would equally have failed to exec that shell.

The `shells` allowlist is deliberately **not** applied to a passwd-derived shell.
The allowlist exists to stop a stray symlink becoming an exec primitive by
*inference*; there is no inference here, the value is read from a root-owned
field, and gating on it would refuse root's login on any host whose shell simply
has no mapping — a lockout for no security gain. It **is** applied to the
`force_command.shell` override, which is a config value like any other.

**Implementation note.** `os/user.User` has no `Shell` field, so this requires
parsing `/etc/passwd` directly. `dispatch.go` already defines `PasswdPath` and
parses that file in `NamesInUse`; the field extractor belongs beside it.

This also removes work elsewhere: `PrepareEnv` sets `SHELL=<resolved shell>`,
which now agrees with what `sshd` set from the same passwd entry, instead of
overwriting it with a different shell's path.

---

## 8. Session flow

```
runForceCommand():
  1. cfg = Load(DefaultConfigPath)         -- compiled in, never overridable
       failure -> refuse(nil, ...)
  2. auth = ReadAuthInfo($SSH_USER_AUTH)   -- never fatal; LOG_CRIT on failure
  3. route = cfg.ForceCommand.Route($SSH_ORIGINAL_COMMAND)
       -- total: a validated config always yields a route, since an unmatched
       -- command falls to the default. Cannot fail here; a missing or
       -- non-executable route program surfaces at exec in step 6.
  4. if !cfg.ShouldRecord(user, uid) -> exec the route, unrecorded
  5. open command log (policy identical to runShell)
  6. dispatch:
       interactive -> resolve shell (§7.3); RunRecorded, Invocation{LoginShell: true}
       exec        -> RunNonInteractive, fixed argv from config
       command     -> RunNonInteractive, prog -c "<original>"
       default     -> resolve shell (§7.3); RunNonInteractive, shell -c "<original>"
  7. error handling identical to runShell
```

Steps 1, 4, 5 and 7 are exactly `runShell`'s. The two entry points differ only in
how they resolve *what to run* and whether the session is interactive.

### 8.1 The one refactor

Extract that shared spine so it is written once. `runShell` and
`runForceCommand` become thin resolvers that hand a common runner a resolved
target. `AGENTS.md` asks that changes stay scoped and unrelated refactors be
avoided; this refactor is *caused* by the second caller, so it is in scope, and
nothing outside `cmd/logsh/main.go` and the two entry points changes shape.

### 8.2 Three concrete deltas to existing code

- **`refuse()` takes a route, not a `shellPath`.** Break-glass and
  `fail_closed: false` must exec *the resolved route* — an SFTP session that
  falls back to an interactive shell is a broken transfer, not a graceful
  degradation.
- **`PrepareEnv` must not rewrite `SHELL` for a non-shell route.** It currently
  sets `SHELL=<ShellPath>` unconditionally, which for an `exec` route would
  publish `SHELL=/usr/lib/ssh/sftp-server`. The rewrite applies only when the
  target is the resolved shell (§7.3), where it is a no-op anyway because `sshd`
  already set `SHELL` from the same passwd entry.
- **`RunNonInteractive` itself needs no change.** An `exec` route is expressed as
  `RunSpec{ShellPath: "/usr/lib/ssh/sftp-server", Invocation: {Name: "sftp-server",
  Args: ["-l","INFO"]}}`, and `runPassthrough` already builds argv from exactly
  those fields and hands the child the real descriptors.

### 8.3 Interactive branch

Synthesizes `Invocation{Name: base(shell), LoginShell: true, Args: nil}`, so
`ChildArgv0` produces `-bash` — the mechanism `sshd` itself uses, and the correct
fix for A.4's `-l`. This is what acceptance test T-3 checks by asserting `$PATH`
proves the profile ran.

### 8.4 The audit-gap guarantee

Every path through `runForceCommand` terminates in either *exec the resolved
route* or *`refuse()`*. There is no fall-through, which is A.4's own rule ("the
wrapper itself should never exit 0 on an unhandled branch") made structural
rather than conventional.

---

## 9. Packaging

`packaging/logsh/logsh-install.sh` installs `SYMLINKS="lsh lbash lzsh"`, and for
each one does both `ln -sf` **and** `add_shell` (registering it in
`/etc/shells`).

`logsh-entry` must get the symlink but **must not** be registered in
`/etc/shells`: it is not a shell, and listing it there would let an account be
`chsh`'d to it. So it needs a separate list, installed with `ln -sf` only, and
removed by `cmd_uninstall`.

### 9.1 A removal hazard the source document does not cover

§5.3 Option C discusses the blast radius of a *bad `sshd_config`*. It does not
discuss package removal. On an enrolled host, `sshd_config` contains
`ForceCommand /usr/sbin/logsh-entry`; removing the package deletes that symlink
and **root can no longer log in over SSH to that host**.

The existing uninstall ordering — restore accounts first, then remove symlinks —
protects passwd shells and does nothing for this, because no passwd entry is
involved.

Mitigation, in the same spirit as the existing pre-removal hook:

- `cmd_uninstall` greps `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*` for
  `logsh-entry` and, on a hit, refuses by default with a message naming the file
  and the line. `logsh-install.sh uninstall --force` overrides, for automation
  that has already removed the block.
- The runbook states the order plainly: remove the `Match User root` block and
  reload `sshd` **before** removing the package.

This is a genuine finding against our own packaging and should be carried back
into the source document's Appendix C.

---

## 10. Failure behaviour

Unchanged from the login-shell path, and inherited rather than re-implemented:

```
journal_directory usable?     -> journal locally, forward at logout
otherwise, server reachable?  -> stream live
neither                       -> session REFUSED (fail_closed: true)
```

`fail_closed: false` and the root-owned break-glass marker both continue to work,
and both now exec the resolved route (§8.2). `BreakGlassActive(nil)` already
falls back to the compiled-in marker path, so break-glass works with the
configuration file broken or absent — which is the case that matters.

---

## 11. Testing

Appendix B of the source document already specifies the acceptance tests. Mapping
them to this implementation:

| Test | Coverage |
|---|---|
| T-1 | Table-driven router unit tests: every route kind, every branch |
| T-2 | Hostile `SSH_ORIGINAL_COMMAND`: `;`, `$(…)`, backticks, single and double quotes, embedded newlines and NULs, leading and trailing whitespace, tabs, `FOO=1 rsync`, `./sftp-server`, `../../bin/sh`, a 64 KB string, and the empty-vs-unset distinction. Asserts the §5.3 property: unmatched input reaches the default route as one `-c` argument, never a matched branch and never a bare shell |
| T-3 | e2e: interactive branch execs with `argv[0] == "-<shell basename>"` |
| — | Shell resolution (§7.3), against a fixture `/etc/passwd`: a bash account, a zsh account, an account whose shell is a `logsh` symlink (resolves through `shells`), an empty shell field (→ `/bin/sh`), a missing account, a nonexistent shell (→ `exitConfig`, nothing exec'd), and the `force_command.shell` override winning over all of them |
| T-4 | Certificate fixtures (ed25519, RSA, ECDSA, plus a plain key) → asserted info keys |
| T-8, T-9 | Extends the existing `e2e_test.go` harness for `exec` and default routes |
| T-13, T-14 | Already covered by existing journal/refuse tests; extended to the entry path |
| — | `-validate` and `-selftest` golden tests for each error and warning in §7.2 |

Fixtures are generated by `ssh-keygen` and committed, not generated at test time,
so the suite does not require `ssh-keygen` on the runner.

---

## 12. Documentation

- **New** `docs/logsh-forcecommand.md` — deployment runbook for this mode:
  `sshd_config` block, certificate critical options, the routing table, the
  attribution keys, the removal ordering from §9.1, and the §6.5 residual.
- `examples/logsh.yaml` — commented `force_command:` section.
- `README.md` — the third invocation mode.
- **F-3 fix.** Three places state that `nested_sessions` defaults to `metadata`
  while `DefaultConfig()` and `examples/logsh.yaml` say `record`. An operator
  reading the runbook expects no second transcript and gets one. Correct all
  three to `record`:
  - `docs/logsh-deployment.md:275` — the `*(default)*` marker in the mode table
  - `docs/logsh-deployment.md:279` — "The default is `metadata` rather than `skip`"
  - `internal/logshell/config.go:102` — "Default metadata." in the doc comment

---

## 13. Risks

| # | Risk | Mitigation |
|---|---|---|
| R-a | A bug here is a lockout or an unrecorded root session. It runs before anything else in the session. | Every path terminates in exec-a-route or `refuse()` (§8.4). `-selftest` gates enabling. Break-glass works with the config broken. Reviewed as security-relevant code, per A.4's own instruction. |
| R-b | New dependency on the authentication path, to track for CVEs. | Parsing only; no transport code reachable. Pinned in `go.mod`; covered by existing dependency scanning. |
| R-c | Route misconfiguration is a silent recording gap. | Structural errors are validation errors, not warnings; `-selftest` checks executability; the `record_users` warning covers the likeliest mistake (§7.2). |
| R-d | Package removal locks root out of SSH on an enrolled host. | §9.1: uninstall refuses on a live `sshd_config` reference; runbook states the ordering. |
| R-e | `SSH_USER_AUTH` forgeable by root outside `sshd`. | Accepted and documented (§6.5). Consistent with §1.6. |

---

## 14. Open questions

Not blocking implementation; each has a defensible default already chosen.

- **Q-a** Should `logsh_ssh_client` be recorded at all? It is cheap and
  forensically useful, but it is one more field, and `sshd`'s own auth log
  already carries the source address. Default: record it.
- **Q-b** Should a `publickey` (non-certificate) root login be a warning at
  `LOG_CRIT` as well as an info key? It is the signature of a login the
  certificate migration intends to eliminate. Default: yes, warn.
- **Q-c** Does `PermitRootLogin forced-commands-only` accept a certificate's
  `force-command`? This is the source document's T-24 / Q-9 and is a property of
  `sshd`, not of `logsh`. It affects the runbook's hardening section only.
