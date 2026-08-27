# logsh in forced-command mode

How to record SSH sessions that authenticate **as root**, by attaching logsh to
`sshd` rather than to root's login shell.

This is a different deployment from [logsh-deployment.md](logsh-deployment.md),
which covers installing logsh as an account's shell in `/etc/passwd`. The two are
independent and can coexist; read that document first if you have not.

## 1. What this is for

An SSH certificate carrying the principal `root` authenticates straight into the
root account. `sudo` is not in that path, so nothing records the session — the
transcript you would get from `sudo`'s I/O logging simply does not exist.

The fix attaches the recorder to `sshd`:

```
# /etc/ssh/sshd_config
Match User root
    ForceCommand /usr/sbin/logsh-entry
```

`ForceCommand` runs before any user code, ignores the command the client asked
for and `~/.ssh/rc`, and applies to shell, command **and subsystem** execution.
No client option or dotfile overrides it.

**root's `/etc/passwd` entry is not touched.** That is the point of doing it this
way rather than making logsh root's login shell: console login, serial and IPMI,
single-user mode, rescue boot, `su -` and `sudo -i` all behave exactly as they do
today. The worst realistic failure is "root cannot log in over SSH on this host",
with the console, any non-root account, and the untouched sudo path all still
available.

What this does **not** cover, deliberately: console, serial and IPMI logins, and
`su -`. Those are unrecorded today and are not made worse. It also does not
prevent a determined root user from evading recording — see §11.

## 2. sshd configuration

```
# --- Attribution: expose the authenticating certificate to the session ------
# Writes a temporary file listing the credentials used to authenticate, and
# names it in $SSH_USER_AUTH. This is how a session running AS root learns
# WHICH HUMAN's certificate opened it. Without it every transcript is
# attributed to "root" and to nothing else.
ExposeAuthInfo yes

# --- File transfer: logged, not transcribed ---------------------------------
# -l INFO is load-bearing; the default is ERROR, so without it you get nothing.
# sshd_config's own LogLevel and SyslogFacility do NOT apply to the sftp
# server -- they must be passed as arguments here.
Subsystem sftp internal-sftp -l INFO -f AUTH

# --- Direct root login over SSH: recorded -----------------------------------
Match User root
    ForceCommand         /usr/sbin/logsh-entry
    AllowTcpForwarding   no
    AllowAgentForwarding no
    X11Forwarding        no
    PermitTunnel         no
    PermitTTY            yes
```

Deploy this the way you deploy any `sshd_config` change and no other way:
package it, gate it on `sshd -t`, **reload rather than restart**, canary one
host, then stage the rollout. A `ForceCommand` pointing at a missing binary makes
root's SSH login fail on that host.

`AllowTcpForwarding no` and its neighbours matter because port forwarding is the
one exfiltration path no terminal recorder can see. Refusing it beats recording
it badly.

## 3. Certificate critical options

The same value can be carried by the credential, so it applies on a host whose
configuration management has not converged yet:

```
ssh-keygen -s ca_key \
  -I "jsmith@CORP.EXAMPLE.COM" \
  -n root-web \
  -O clear \
  -O permit-pty \
  -O force-command=/usr/sbin/logsh-entry \
  user_key.pub
```

Three things to know:

- **`sshd_config`'s `ForceCommand` supersedes the certificate's.** That ordering
  is what you want — the host-level setting is the one configuration management
  owns and can fix in a hurry — but it means a host-level misconfiguration can
  silently defeat the credential-level one.
- **If an `authorized_keys` entry also carries a `command=`, the two must be
  byte-identical**, or `sshd` refuses the certificate. Audit the estate for
  existing `command=` entries — backup keys, `rrsync` wrappers, monitoring —
  before issuing certificates with `force-command`.
- **Keep the path stable.** `/usr/sbin/logsh-entry`, never a versioned path:
  rotating the forced command means reissuing certificates.

Unknown critical options cause a certificate to be *refused* rather than ignored,
so this fails closed on an sshd too old to understand it.

## 4. logsh configuration

Add a `force_command` section to `/etc/logsh/logsh.yaml`. The shipped
[examples/logsh.yaml](../examples/logsh.yaml) carries a fully commented copy.

```yaml
record_users:
  - root            # WITHOUT THIS NOTHING IS RECORDED. See below.

force_command:
  routes:
    internal-sftp:
      exec: [/usr/lib/ssh/sftp-server, -l, INFO]
```

`record_users` must name `root` or `0`. This is the single most likely
misconfiguration and the most silent one: sessions are routed correctly and
recorded not at all. `logsh -validate` warns about it.

The `sftp-server` path differs by distribution:

| Distribution | Path |
|---|---|
| RHEL, Fedora | `/usr/libexec/openssh/sftp-server` |
| Debian, Ubuntu | `/usr/lib/openssh/sftp-server` |
| Arch | `/usr/lib/ssh/sftp-server` |

## 5. Routing, and why the table is small

`ForceCommand` intercepts subsystems as well as commands, so a forced command
that unconditionally started an interactive recorder would break SFTP and modern
`scp` — OpenSSH 9.0 and later route `scp` over the SFTP protocol. logsh therefore
routes on `$SSH_ORIGINAL_COMMAND`.

The table is a **literal allowlist**, not a pattern language. A key is matched
exactly against the basename of the first whitespace-separated field: no globs,
no regular expressions, no prefix matching, no case folding.

| Client asked for | What runs |
|---|---|
| nothing | the account's own shell, as a login shell, with a full transcript |
| `internal-sftp …` | the `sftp-server` binary named in the route |
| anything else | `<shell> -c "<the client's command>"`, metadata-only record |

Only `internal-sftp` genuinely needs a route, because it is implemented
in-process inside `sshd` and has no binary to exec. A host whose `sshd_config`
names an external `sftp-server` binary needs no routes at all — that is already a
real command and the default route runs it.

**A route's argv comes from the configuration file and never from the client.**
The client's command reaches the program only through `$SSH_ORIGINAL_COMMAND` in
the environment, which is how `sshd` would have delivered it and how `rrsync`
expects to receive it.

Two consequences worth understanding before you extend the table:

- **An unmatched command is not restricted.** It reaches the default route as a
  single `-c` argument, which is exactly what `sshd` does with no `ForceCommand`
  at all. The table exists for commands that *cannot run as-is*, not to limit
  what root may do. Restriction belongs in the certificate's critical options.
- **Metacharacters defeat matching rather than exploiting it.**
  `internal-sftp; rm -rf /` has a first field of `internal-sftp;`, which is not
  the key `internal-sftp`, so it does not match — it falls to the default route
  and the shell handles the whole string as it always would. This is deliberate:
  a matcher that stripped punctuation first would match the route and silently
  discard the rest of the command, a change in meaning invisible to both the
  client and the transcript.

## 6. Which shell runs

The interactive and default routes run **the account's own shell, from its
`/etc/passwd` entry** — exactly what `sshd` would have exec'd had `ForceCommand`
not been there. So enabling the recorder changes which shell runs on no host.

This matters more than it looks. A single shell configured in `logsh.yaml` and
deployed fleet-wide would silently replace root's shell on every host where
root's shell is something else, and would leave an SSH login and a console login
giving different shells for the same account.

`force_command.shell` exists as an override for a host whose passwd shell is
unsuitable. It is normally unset, and `logsh -validate` warns when it is set. When
set, it must be one of the **values** in the `shells` map — that allowlist is what
stops an override naming a logsh symlink, which would make logsh exec itself and
record the session twice.

If root's passwd shell *is* a logsh symlink — a host running both deployments —
it is resolved through the `shells` map to the real shell, so the two compose into
one recorder rather than nesting a second.

`logsh -selftest` prints what will actually run, per host:

```
ok    force_command: interactive shell for root: /bin/zsh (from /etc/passwd)
ok    force_command.routes[internal-sftp]: /usr/lib/ssh/sftp-server
```

## 7. What gets recorded

| Session | Record |
|---|---|
| interactive | full `ttyout` transcript with timing, replayable with `sudoreplay` |
| `ssh root@host cmd`, `scp`, `rsync` | attributable metadata: who, what command, when, exit status |
| sftp | metadata, plus the sftp server's own per-operation syslog at `-l INFO` |

Non-interactive sessions pass their streams through untouched — no pipe, no
copying goroutine — so a large transfer is byte-exact and full speed, and does
not produce a transcript the size of the payload.

**`log_ttyin: false` does not mean keystrokes go unrecorded.** Terminal echo puts
nearly everything typed into the `ttyout` stream regardless. What the setting
protects is the moments echo is *off* — password and passphrase prompts — which is
the material worth keeping out of a transcript store. Say that plainly in any
user-facing notice; the opposite claim is a promise the software does not keep.

## 8. The session record

A certificate-authenticated root session carries the human in `submituser`, the
same field `sudo` uses for the account that escalated:

```
submituser              jsmith@CORP.EXAMPLE.COM
submituid               0
runuser                 root
runuid                  0
logsh_cert_keyid        jsmith@CORP.EXAMPLE.COM
logsh_cert_serial       20260819000137
logsh_cert_ca           SHA256:FF270WGkZMiYH/uz…
logsh_cert_principals   ["root-web","root-everywhere"]
logsh_auth_method       publickey-cert
logsh_ssh_command       internal-sftp -l INFO
logsh_ssh_client        10.20.30.41 51234
```

Note that **`submituid` stays 0** while `submituser` names a person. There is no
local uid for a certificate principal. The numeric ids describe the process; the
name describes the authenticated identity. Anything joining on `submituid` must
not read it as identifying a human.

**A session with `logsh_auth_method: publickey` and no key ID is a root login
that arrived without a certificate** — the break-glass account, or a key a
fallback audit missed. Its credential is identified by `logsh_auth_key` alone.
That is worth a SIEM rule: it is precisely what a certificate migration means to
eliminate.

Attribution failure is never fatal. If `SSH_USER_AUTH` is missing or unreadable,
logsh logs at `crit` and records the session unattributed — an unattributed
recording beats a refused root login.

## 9. Enabling a host

In this order:

```bash
logsh -validate                    # config content and permissions
logsh -selftest                    # what will actually run on THIS host
```

`-selftest` fails if a route's program is missing or not executable, so a package
postinst can gate on it. Read its `interactive shell for root:` line and confirm
it is the shell you expect.

Then push the `sshd_config` change, and **before closing your existing session**,
open a fresh `ssh root@host` from a second terminal. Confirm you get a shell,
that `$PATH` looks right — which proves the profile ran, i.e. the shell was
exec'd as a login shell — and that `sftp` and `scp` still work.

## 10. Removing it — ordering matters

**Remove the `Match User root` block and reload `sshd` before removing the
package.**

On an enrolled host, `sshd_config` names `/usr/sbin/logsh-entry`. Removing the
package deletes that symlink, and root can no longer log in over SSH to that
host. Unlike the login-shell deployment, no `/etc/passwd` entry is involved, so
the installer's restore-accounts-first ordering does not protect you here.

`logsh-install.sh uninstall` refuses while `sshd_config` or `sshd_config.d/`
still mentions `logsh-entry`, naming the file and line. Pass `--force` only when
automation has already removed the block. (`--force` is not listed in the
script's `usage` output; the refusal message names it.)

Note that the check is a substring match, so a commented-out `ForceCommand` line
or a stale `.bak` file under `sshd_config.d/` will also trip it. That direction is
deliberate — it over-refuses rather than under-refuses — and `--force` is the
escape hatch.

## 11. Break-glass, and the residual

Two paths, both to be drilled before any widening:

- **Recording is broken, host reachable.** The root-owned marker file
  `/etc/logsh/bypass`. While it exists, sessions proceed unrecorded with a loud
  banner on the terminal and a `crit` syslog entry. It is honoured only if root
  owns it and nobody else can write it.
- **Host unreachable.** A second uid-0 account with a distinct username, so
  `Match User root` does not apply to it, key-only, gated to a bastion, alerting
  on every authentication.

State the trade plainly: a break-glass path that bypasses recording is a path
that bypasses recording. Keep it available but expensive, and test it quarterly —
an untested break-glass path is a fiction.

**Known residual.** `SSH_USER_AUTH` is an environment variable, so a root user
running `/usr/sbin/logsh-entry` by hand outside `sshd` can point it at a file
naming somebody else's certificate and produce a misattributed record. This is
accepted rather than mitigated: any mitigation available to a process running as
root is defeatable by that same process. Session recording buys accountability
and forensics within a bounded tampering window; it does not buy containment. The
control that actually bounds the window is getting records off the host quickly
and alerting when one does not arrive.
