# sudo_logsrvd Reference & Conformance

This directory is a **specification of the reference implementation** — Todd Miller's
C `sudo_logsrvd` — written down in enough detail that this Go server can be checked
against it mechanically, repeatedly, and years from now.

It exists because `sudosrv` is a from-scratch reimplementation of a protocol whose only
real specification is the C source. The protobuf schema and the `sudo_logsrv.proto(5)`
man page describe the *messages*; they say almost nothing about the *behavior* —
when a `commit_point` is due, what clock it carries, what the timing-file markers mean,
how `%{seq}` expands. Those are the things that break real clients, and they only exist
in `logsrvd/*.c`.

## Provenance

Every document here is pinned to a specific sudo revision, recorded in its header:

| | |
|---|---|
| **Reference version** | sudo 1.9.18 |
| **Git revision** | `36f7128256a93571ec378daa5c209d6883036d31` (2026-07-19) |
| **`git describe`** | `TAG-1125-g36f712825` |
| **Source tree used** | `~/Devel/sudo` |
| **Verified against** | `sudosrv` — all 312 requirements re-derived; see `git log docs/logsrvd-reference/` |

If the header of an individual document disagrees with this table, that document is
stale — it was not refreshed in the last pass. Trust the per-document header.

## Layout

| File | Prefix | Reqs | Covers |
|---|---|--:|---|
| [`01-architecture.md`](01-architecture.md) | `ARCH-` | 45 | Daemon startup, event loop, connection lifecycle, shutdown |
| [`02-protocol.md`](02-protocol.md) | `PROTO-` | 53 | Wire framing, message semantics, state machine, `commit_point` |
| [`03-configuration.md`](03-configuration.md) | `CONF-` | 68 | Every `sudo_logsrvd.conf` setting, default, and validation rule |
| [`04-local-storage.md`](04-local-storage.md) | `IOLOG-` | 51 | On-disk I/O log format, escape expansion, sequence numbers |
| [`05-relay.md`](05-relay.md) | `RELAY-` | 54 | Relay mode, journalling, queue, retry policy |
| [`06-tls-and-security.md`](06-tls-and-security.md) | `TLS-` | 41 | TLS setup, peer verification, privilege posture |
| [`CONFORMANCE.md`](CONFORMANCE.md) | — | 312 | The matrix: requirement → Go location → verdict |
| [`conformance-data.json`](conformance-data.json) | — | 312 | The verdicts the matrix is rendered from |
| [`generate-conformance.py`](generate-conformance.py) | — | — | Renders `CONFORMANCE.md` from that data |

`CONFORMANCE.md` is **generated**, not hand-written. To re-grade a requirement, edit its
entry in `conformance-data.json` and re-run:

```bash
python3 docs/logsrvd-reference/generate-conformance.py
```

> **One-time data loss, recorded so nobody hunts for it.** The verdict data originally
> lived in a session scratchpad rather than in the repository, so once that session expired
> the matrix could no longer be regenerated. `conformance-data.json` was reconstructed from
> the last rendered table, which means **185 of the 312 notes survive only in their clipped
> form** (they end in `…`). The verdicts, severities and Go locations are intact; only the
> tail of some prose is gone. Rows re-graded since then carry full text again.

## Where conformance stands

All 312 requirements were re-verified against the current tree and every non-`MATCH`
verdict independently challenged: **114 `MATCH`**, 27 `INTENTIONAL`, 87 `PARTIAL`,
36 `DIVERGENT`, 33 `ABSENT`, 15 `NA`.

**Nothing is graded `medium`, `high` or `breaking`.** Every requirement that named a defect
has been closed. What remains is `low` (154) or `informational` (29), and the largest
single movement has been from `PARTIAL`/`ABSENT` into `INTENTIONAL` — divergences that are
now deliberate and have their reasons recorded in the code they describe.

Two structural facts bound everything else:

- **The protobuf schema is field-for-field identical.** All 16 messages and 55 fields
  match the C `log_server.proto` in name, number, type, label, and `oneof` membership,
  with no extras on either side — the `diff` in the refresh procedure below returns clean.
- **Framing and the timing-file markers match exactly:** a 4-byte big-endian length
  prefix, a 2 MiB ceiling (C `logsrv_util.h:36`, Go `processor.go:20`), and
  `IO_EVENT_*` 0–7 including the legacy `TTYOUT_1_8_7 = 6`.

`PARTIAL` at 87 is the largest non-`MATCH` bucket, and that is expected rather than
alarming: most are a supported main path plus an unimplemented option or edge case. Read
the severity, not the verdict.

## Requirement IDs are a contract

Each numbered requirement (`PROTO-014`, `IOLOG-032`, …) is a **stable identifier**.
`CONFORMANCE.md`, commit messages, issues, and code comments all reference them.

When refreshing:

- **Never renumber.** A given ID means the same behavior forever.
- **Never reuse.** If a behavior disappears upstream, mark the requirement
  `_(retired in sudo X.Y.Z)_` and leave the ID in place. Do not hand its number to
  something else.
- **Append** new behaviors at the end of that document's sequence.
- If a behavior *changes* upstream, update the requirement text in place and note the
  change — the ID still identifies "the thing sudo does here", which is what
  `CONFORMANCE.md` needs to point at.

## Refreshing against a new sudo release

```bash
# 1. Update the reference tree and record exactly what you are pinning to.
cd ~/Devel/sudo
git fetch --tags && git checkout SUDO_1_9_XX
git log -1 --format='%H %ad' --date=short
git describe --tags

# 2. What actually changed in the daemon since the pinned revision?
git diff --stat <OLD_SHA>..HEAD -- logsrvd/ lib/logsrv/ lib/iolog/ lib/eventlog/ \
    docs/sudo_logsrvd.conf.man.in docs/sudo_logsrvd.man.in docs/sudo_logsrv.proto.man.in
```

Step 2 is the whole point of pinning. An empty diff for a subsystem means that
document is still correct and needs only a header bump — no re-reading required.
Only re-analyze the subsystems whose files actually moved.

```bash
# 3. Confirm the protobuf schema itself has not drifted.
diff <(grep -vE '^\s*(//|/\*|\*)' ~/Devel/sudo/lib/logsrv/log_server.proto) \
     <(grep -vE '^\s*(//|/\*|\*)' pkg/sudosrv_proto/sudo_logsrv.proto)
```

A difference here is a schema change and takes priority over everything else — it means
regenerating `sudo_logsrv.pb.go` (`make proto`) before any behavioral comparison is
meaningful.

Then, per changed subsystem: re-read the C, update that document's requirements and its
header, and re-verify the affected rows of `CONFORMANCE.md`.

## Verdict vocabulary

`CONFORMANCE.md` uses exactly these:

| Verdict | Meaning |
|---|---|
| `MATCH` | Observable behavior is equivalent. Implementation shape may differ freely. |
| `PARTIAL` | Mostly equivalent, with a real gap in a specific case. |
| `DIVERGENT` | Different observable behavior. Not deliberate — a bug or an unimplemented detail. |
| `ABSENT` | Not implemented at all. |
| `INTENTIONAL` | Deliberately different, with the reason recorded in the repo (comment, config option, or test). |
| `NA` | No meaning for a Go implementation and no external contract. |

The distinction that matters is `DIVERGENT` vs `INTENTIONAL`: a deviation is only
`INTENTIONAL` if the *repository* says so somewhere a future reader will find it. "It
seemed reasonable" is `DIVERGENT`.

## Scope boundary

These documents describe **`sudo_logsrvd`, the server**. Client behavior
(`plugins/sudoers/log_client.c`, `logsrvd/sendlog.c`) appears only where it constrains
the server — most importantly what the client blocks on during teardown. This is not a
specification of sudo's client side, and it is not a specification of `sudosrv`'s own
additions (the management API, the YAML config format, the password filter), which have
no C counterpart and are documented in the top-level `README.md`.
