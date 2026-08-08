# Deploying logsh

`logsh` is a recording login shell. Setting it as an account's shell in
`/etc/passwd` makes that account's sessions record to a sudosrv log server, in
the same sudoreplay-compatible format sudo produces.

It is also the only component in this repository that can lock an administrator
out of a host. Read the rollout section before deploying to anything you cannot
walk up to.

---

## What it does and does not record

**Records:** interactive SSH sessions, local console logins, `su -`, `sudo -i` —
anything that execs the shell named in the account's passwd entry. Non-interactive
sessions (`ssh host cmd`, scp, rsync, git-over-ssh) are recorded as a
metadata-only record naming the command.

**Does not record:**

- **sftp via `internal-sftp`** — no shell is exec'd, so logsh never runs. Not
  broken, invisible. Audit file transfer some other way if you need it.
- **Port forwards and tunnels** — `ssh -N`, `-L`, `-R`, `-D`, agent forwarding.
  A tunnel to a production database is a real exfiltration path this cannot see.
- **Anything not reached through a login shell** — cron, systemd units, `at`,
  `docker exec`, `kubectl exec`.
- **Syscall-level activity.** This is a terminal recorder, not auditd.

**`log_ttyin: false` does not mean "we do not record what you type."** Terminal
echo puts nearly every keystroke into the `ttyout` stream regardless. Disabling
ttyin protects only the moments echo is off — password prompts. Any notice you
show users must say this; claiming otherwise is a promise the software does not
keep.

**A known regression, inherent to every second-PTY recorder** (`tlog`,
`script(1)`, and sudo-inside-SSH all share it): sshd emits `SSH_MSG_IGNORE`
padding against keystroke-timing traffic analysis only while the PTY has `ECHO`
off *and* `ICANON` on (`channels.c:2339-2352`). Raw mode clears both, so that
countermeasure silently stops firing for the whole session. There is no
recorder-level fix.

**root can turn it off.** root can edit `/etc/passwd`. The act is recorded if
recording is up when it happens, and relay mode makes after-the-fact log
tampering hard, but this is an accountability control, not containment — the same
property sudo has.

---

## Topology

Run a sudosrv in **relay mode on loopback** on each recorded host:

```
logsh (as the user) --127.0.0.1--> sudosrv relay (as root) --mTLS--> central sudosrv
```

This is not optional if you use TLS client certificates. logsh runs as the
logging-in user — it is their login shell, exec'd after sshd drops privileges —
so any key it can read, that user can read, and can then use to forge or suppress
audit records at the central server. The local relay holds the host credentials
and the spool as root. `logsh -validate` warns if you configure certs directly.

Leave `server.journal_directory` empty in that topology: the relay already
spools.

---

## Rollout

The install script enforces the ordering. Use it rather than doing these by hand.

```sh
packaging/logsh/logsh-install.sh install            # binary, symlinks, /etc/shells
packaging/logsh/logsh-install.sh verify             # -validate and -selftest
packaging/logsh/logsh-install.sh enable root lbash  # ONE account
```

`install` deliberately switches **no** account. A package that enabled itself
would turn the first bad config into a fleet-wide lockout at `apt upgrade` time
with no operator in the loop.

### The rule that matters

**Keep an open, working root session in another terminal until you have
confirmed a fresh login works.** Every lockout story starts with someone
skipping this.

1. Deploy to one canary host.
2. `enable` one account.
3. From a **second** terminal, log in fresh. Confirm you get a shell, that
   `~/.bash_profile` ran (check `$PATH`), and that `echo $SHELL` shows the real
   shell, not the logsh symlink.
4. Confirm the session appears on the log server and replays:
   `sudoreplay -d <logdir> -l` then `sudoreplay -d <logdir> <id>`.
5. Run `scp` a file both ways. Confirm it still works and is byte-exact.
6. **Run the break-glass drill below.** Do not skip it.
7. Only then widen.

### Break-glass drill — mandatory before fleet rollout

Untested break-glass is not break-glass. Both paths must be exercised on the
canary, by the person who will be woken up at 3am.

**Path 1 — marker file.** Covers "the box is reachable but recording is broken."

```sh
touch /etc/logsh/bypass && chmod 0600 /etc/logsh/bypass
```

Log in fresh. You must get a shell, a loud banner on the terminal, and a
`crit`-priority syslog entry. Then remove the marker and confirm recording
resumes. The marker is honoured only if root owns it and nobody else can write
it — otherwise any user could switch off their own recording.

**Path 2 — second uid-0 account.** Covers "the box is not reachable and you
cannot create the marker."

Create a second uid-0 account with a plain shell, key-only authentication,
`AllowUsers`-gated to a bastion, alerting on every authentication. Log in with
it. Confirm the alert fires.

Neither path substitutes for the other: the marker is useless if you cannot reach
the host, and the account is useless if you have lost the key.

---

## Nested sessions (`sudo -i` and friends)

`sudo -i` runs the **target** account's passwd shell. Once logsh is root's shell,
the same session is captured twice — three times when the invoking account also
uses logsh:

```
sshd pty
└─ logsh(alice)      pty #2  ← transcript 1
   └─ bash(alice)
      └─ sudo -i     pty #3  ← transcript 2 (if sudoers has log_output)
         └─ logsh(root) pty #4  ← transcript 3
            └─ bash(root)
```

Four pseudo-terminals for one session, the same keystrokes stored three times,
and the raw-mode keystroke-timing regression stacked at every layer.

`nested_sessions` controls it. Detection is by **process ancestry** (walking the
`PPid` chain), not by environment: sudo's `env_reset` strips `LOGSH_SESSION`, and
`SUDO_USER` — which sudo sets *after* the reset, so it does survive — is
forgeable by anyone who controls their environment. The ancestry walk is not.

**Inside another logsh it always skips**, whatever the setting says. There is no
ambiguity: the outer logsh is certainly recording, because the bytes pass through
its pty to reach here.

**Under sudo it is a judgement call, and logsh cannot make it.** sudo records I/O
only when the matched sudoers rule carries `log_output`, and nothing visible from
inside the session reveals whether it did. Determining it would mean
reimplementing the policy engine.

| Value | Behaviour |
|---|---|
| `metadata` *(default)* | No second pty, no transcript, but a record is kept: who escalated, what shell, when, exit status, and both session UUIDs. If sudo was not logging you still know the session happened. |
| `skip` | Plain exec through. Nothing recorded, nothing emitted. Only safe when **every** sudoers rule reaching a shell has `log_output` — otherwise a root session is recorded by nobody and nothing says so. |
| `record` | Full second transcript. Never a gap, at the cost of duplication and the extra pty. De-duplicate downstream on the shared UUID. |

The default is `metadata` rather than `skip` deliberately: a de-duplication
feature that manufactures a silent audit gap is worse than the duplication it
removes. `logsh -validate` warns when `skip` is set.

**Who escalated.** Under sudo, logsh records `submituser` as the account that
escalated (alice) and `runuser` as the account the session runs as (root),
matching sudo's own convention. Before this, both said root, and the record could
not answer the only question anybody asks of it.

---

## Command log (optional, off by default)

One syslog record per command executed in the session, independent of session
recording — separate toggle, local syslog rather than the log server, and it runs
whether the session is recorded, journalled, or not recorded at all.

```
SESSION=<uuid> ; USER=root ; UID=0 ; TTY=pts/3 ; PID=4711 ; CMD=/usr/bin/vi /etc/passwd
```

Every record carries `SESSION=<uuid>`, and the same uuid is attached to the
recorded session as `logsh_session` in its `log.json`, so a command record and
the transcript it came from join on one field.

It is implemented with **ptrace** over the session's whole process tree. That
buys what no shell hook can — commands run from scripts, from subshells and from
inside editors are all caught, and it cannot be switched off from within the
session — at three costs you must accept deliberately:

- **`strace` and `gdb` do not work inside a recorded session.** A process can
  have only one tracer. For an admin shell this is a real loss, and it is the
  most common reason to leave the command log off.
- **Every exec stops the process briefly.** Invisible interactively; measurable
  in a build spawning 100k processes.
- **`kernel.yama.ptrace_scope` of 2 or 3 blocks it entirely.** logsh runs
  unprivileged and cannot work around it. It warns to syslog, emits a `note`
  record in the command stream, and carries on with session recording intact —
  unless `command_log.required: true`, which refuses the session instead.

It records *executions*, not commands as typed: a pipeline produces three
records, and `ls` produces one for `/usr/bin/ls`. If you want commands as the
user typed them, this is the wrong mechanism.

`logsh -validate` warns whenever it is enabled, so the costs are stated at
deploy time rather than discovered later.

---

## Failure behaviour

Recording is refused only when **both** paths fail:

```
journal_directory usable?     -> journal, forward at logout
otherwise, server reachable?  -> stream live
neither                       -> session REFUSED (fail_closed: true)
```

A network blip alone never refuses a session — that is what the journal absorbs.
Were it otherwise, one outage would lock every recorded account out of the whole
fleet at the same moment.

Once the shell has already run, a delivery failure is **not** treated as a
refusable session. The audit gap has happened and cannot be undone by refusing;
logsh parks the journal, alerts at `crit`, and returns the user's real exit
status.

Undelivered journals become `*.journal.undelivered` and are **never pruned** —
each is the only copy of a session that never reached a server. Sweep them with a
timer. **Never point logrotate at the spool directory.**

---

## Recovery

`disable` works with the binary deleted, the config broken, and the log server
gone — those are precisely the conditions under which it is needed:

```sh
packaging/logsh/logsh-install.sh disable root /bin/bash
```

Removing the package restores every account it switched before deleting
anything:

```sh
packaging/logsh/logsh-install.sh uninstall
```

Config and spooled journals are left in place deliberately.

---

## Known interactions

- **Double recording.** `sudo -i` inside a recorded session produces two
  transcripts — sudo's, with the privilege metadata, and logsh's, with the full
  session context. Both are legitimate. logsh reports the *inner* pty as
  `ttyname`, which is what makes them correlatable.
- **`$SHELL`** is rewritten to the real shell before exec, so vim's `:sh`, tmux
  and screen do not each start a nested recorder.
- **NSS accounts.** logsh is built `CGO_ENABLED=0` so a broken dynamic linker
  cannot make a login shell unexecutable. `os/user` then cannot consult NSS, so
  list LDAP/SSSD accounts in `record_users` by **numeric uid**, not by name, or
  they will silently go unrecorded.

---

## Remaining packaging work

The install script and this runbook are distribution-independent. Wiring them
into the `deb/`, `rpm/` and `archlinux/` trees as a separate `logsh` package —
logsh belongs on every managed host, the daemon does not — is not done yet.
Whatever does it must call `install` + `verify` from postinst and `uninstall`
from **prerm**, never postrm: by postrm time the files are already gone.
