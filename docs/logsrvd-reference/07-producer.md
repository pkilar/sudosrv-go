# 07. Producer-Side Recording & Timing

> **Reference:** sudo 1.9.18 — `36f7128256a93571ec378daa5c209d6883036d31` (2026-07-19)
> **C sources:** `plugins/sudoers/iolog.c` (the sudoers I/O-logging plugin: delay measurement and the `last_time` chain), `lib/iolog/iolog_timing.c` (timing-record format and its stated meaning), `plugins/sudoers/sudoreplay.c` (the replay contract these records are written against), `src/exec_pty.c` (when the plugin's log hooks fire relative to terminal delivery), `logsrvd/sendlog.c` (the reference client that ships the same delays over the wire)
> **Requirement prefix:** `PROD-`
> **Refresh:** see [README.md](README.md)

## Overview

Every other document here specifies the **server**. This one specifies the **producer** —
the side that decides what delay each I/O record carries before anything is transmitted or
written. It exists because `sudosrv` grew one: `logsh`, the recording login shell in
`internal/logshell`, occupies the role C fills with `plugins/sudoers/iolog.c`.

The distinction matters more than it looks. [IOLOG-032](04-local-storage.md) requires only
that the server transcribe the client's `delay` **unmodified** — it presupposes that
somebody upstream computed a correct delay, and says nothing about what "correct" means.
Under the server-only corpus a producer could stamp delays one record out of step and
violate no requirement in this repository, while every recording it made replayed wrong.
That is not hypothetical: it is exactly the failure mode this family was written after.

### The replay contract

Everything below follows from one sentence in the C reader, `lib/iolog/iolog_timing.c:172-173`:

> Where type is `IO_EVENT_*`, `sleep_time` is the number of seconds to sleep **before**
> writing the data and `num_bytes` is the number of bytes to output.

A timing record is `<event> <delay> <len>`, and the delay is the pause that comes **before**
that record's own bytes. Replay is *sleep, then write* — never *write, then sleep*. The
consequence that catches people out is that a pause is always recorded on the event
**following** it, so the last output before a long idle carries a delay of ~0 and the first
output after it carries the whole idle.

The intuition runs the other way ("show this, then wait"), and reading a timing file under
that assumption makes every gap look one record late. Two independent things in the C tree
confirm the direction beyond the comment:

- `sudoreplay.c` schedules the delay from the record it just parsed (`:804-805`) and only
  writes that record's bytes once the timeout fires in `delay_cb` (`:877`, *"Called when the
  inter-record delay has expired"*). Record 1 is primed before `sudo_ev_dispatch`, so its
  delay is a real leading pause.
- To "ignore time spent suspended", `sudoreplay.c:820-828` discards the record that
  **follows** the `SIGCONT` — which is only coherent if the suspension's duration was
  stamped as that following record's leading delay.

---

### PROD-001 — A timing record's delay is the pause before its own bytes

- **C source:** `lib/iolog/iolog_timing.c:172-173`, `plugins/sudoers/sudoreplay.c:804-805,877,915`
- **Severity if divergent:** breaking

A producer MUST emit each I/O event with a delay equal to the idle that preceded that
event's bytes, so that a replayer sleeping the delay and then writing the bytes reproduces
the session. A producer MUST NOT record the pause that *follows* an event, and MUST NOT
emit an absolute timestamp in the delay field.

Divergence is silent at record time and total at replay: the byte stream, the record count
and the sum of the delay column are all unchanged, so only playback reveals it.

### PROD-002 — Measure, stamp, then advance

- **C source:** `plugins/sudoers/iolog.c:1070-1081`
- **Severity if divergent:** breaking

`sudoers_io_log` reads the clock, subtracts the previous event's timestamp, hands the
resulting delay to the call that writes **this** event, and only then advances `last_time`:

```c
sudo_timespecsub(&now, &last_time, &delay);
ret = io_operations.log(event, buf, len, &delay, &ioerror);
last_time.tv_sec  = now.tv_sec;
last_time.tv_nsec = now.tv_nsec;
```

A producer MUST follow this order. Computing the delay for event *N* and attaching it to
event *N+1* — a natural mistake when a record is buffered and flushed late — produces
exactly the PROD-001 divergence.

### PROD-003 — The delay chain is seeded before the command produces output

- **C source:** `plugins/sudoers/iolog.c:828`
- **Severity if divergent:** low

`last_time` is seeded by `sudo_gettime_awake()` in `sudoers_io_open`, before the log files
exist and before the command runs. The first record's delay is therefore measured from
session start and legitimately includes process startup. A producer MUST seed its chain no
later than session start, so no output escapes the timeline.

Note the clock: C uses `sudo_gettime_awake` (monotonic, excluding system suspend). A
producer MUST NOT measure deltas with a wall clock subject to NTP steps.

### PROD-004 — One delay chain spans every stream and event type

- **C source:** `plugins/sudoers/iolog.c:1076-1081,1202-1207,1305-1311`
- **Severity if divergent:** high

`ttyin`, `ttyout`, `stdin`, `stdout`, `stderr`, `change_winsize` and `command_suspend` all
subtract from, and all advance, the same `last_time`. A producer MUST maintain a single
chain across all of them. Per-stream chains would make each stream's delays measure from a
different origin, and interleaved playback would drift.

Where two streams can be recorded concurrently, the measurement and the advance MUST be
atomic with respect to each other, or two events can compute deltas from the same origin
and the recorded total will not match the session.

### PROD-005 — The timestamp is sampled before delivery, not after

- **C source:** `plugins/sudoers/iolog.c:1076-1081`
- **Severity if divergent:** high

`now` is sampled *before* `io_operations.log(...)` runs and that same pre-delivery value is
stored into `last_time`. Time spent inside delivery — writing a file, or a round trip to a
log server — therefore falls into the **next** event's delay.

This is deliberate and MUST be preserved. It looks like a defect ("backpressure inflates the
next gap"), and the tempting correction is to stamp `last_time` after delivery completes.
That is wrong: every delta would then measure from the end of the previous write rather than
its start, and any time the producer spent blocked would vanish from the transcript, making
the replay run faster than the session did.

### PROD-006 — A trailing idle with no following event is not recorded

- **C source:** `plugins/sudoers/iolog.c:1070-1081` (consequence), `lib/iolog/iolog_timing.c:172-173`
- **Severity if divergent:** medium

Because a delay is only ever written as part of the record that follows it, a session that
produces its last output and then idles before exiting MUST NOT record that trailing idle
anywhere in the timing file. There is no event to attach it to.

This is the cheapest available check on stamping direction, and it needs no per-record
bookkeeping: record `print X; sleep 1` and the timing total stays near zero, while
`print X; sleep 1; print Y` totals about a second. A producer that stamped the pause
following each event would total about a second in both.

### PROD-007 — I/O events are timestamped when observed, not when delivered onward

- **C source:** `src/exec_pty.c:367-432`
- **Severity if divergent:** low

In `read_callback`, sudo calls `iob->action(...)` — the plugin's `log_ttyin`/`log_ttyout`
hook — immediately after `read()` returns, and only afterwards enables the write event that
forwards the bytes to the user's terminal. The recorded timestamp is therefore independent
of how long delivery to the user takes.

A producer that records *after* writing to the user's terminal measures the terminal write
into the timing of the chunk that follows it. Over a congested link this inflates gaps that
did not exist in the session. The distortion is bounded and never displaces a delay onto a
different record, which is why this is `low` rather than `high`.

### PROD-008 — Suspend and resume are events on the delay chain

- **C source:** `plugins/sudoers/iolog.c:1287-1311`, `plugins/sudoers/sudoreplay.c:820-828`
- **Severity if divergent:** medium

`sudoers_io_suspend` records the signal name against the same chain as every other event, so
the wall-clock duration of a suspension lands on the record that follows the `SIGCONT`. A
producer that omits suspend records does not lose the elapsed time — it still accrues into
the next event's delay — but it does deny the replayer the ability to skip it, which
`sudoreplay` does by default unless `-S` is given.

Only names in C's `sig2str` set, without the `SIG` prefix, may be sent; the server rejects
anything else and a rejection tears down the session.
