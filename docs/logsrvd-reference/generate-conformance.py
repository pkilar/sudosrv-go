#!/usr/bin/env python3
"""Merge verdicts + adversarial challenges into docs/logsrvd-reference/CONFORMANCE.md."""
import json, glob, os, re, sys, collections

SC = "/tmp/claude-1000/-home-pkilar-Devel-sudosrv-go/9b6d7234-1ccb-4c29-b797-90de270c5e86/scratchpad"
DOCS = "/home/pkilar/Devel/sudosrv-go/docs/logsrvd-reference"

SUBSYS = [
    ("ARCH",  "01-architecture.md",     "Daemon Architecture & Connection Lifecycle"),
    ("PROTO", "02-protocol.md",         "Wire Protocol & Message State Machine"),
    ("CONF",  "03-configuration.md",    "Configuration Surface & Defaults"),
    ("IOLOG", "04-local-storage.md",    "Local I/O Log Storage Format"),
    ("RELAY", "05-relay.md",            "Relay Mode & Store-and-Forward"),
    ("TLS",   "06-tls-and-security.md", "TLS, Authentication & Security Posture"),
]
STATUSES = ["MATCH", "INTENTIONAL", "PARTIAL", "DIVERGENT", "ABSENT", "NA"]
SEVRANK = {"breaking": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "none": 5}


def load():
    verdicts = {}
    for f in glob.glob(f"{SC}/rv-*.json"):
        for v in json.load(open(f))["verdicts"]:
            verdicts[v["id"]] = v
    challenges = {}
    for f in glob.glob(f"{SC}/ch-*.json"):
        for c in json.load(open(f))["challenges"]:
            challenges[c["id"]] = c
    return verdicts, challenges


def titles():
    """Pull the human title of each requirement out of its reference document."""
    out = {}
    for _, doc, _ in SUBSYS:
        p = os.path.join(DOCS, doc)
        if not os.path.exists(p):
            continue
        for m in re.finditer(r"^### ([A-Z]+-\d{3}) — (.+?)\s*$", open(p).read(), re.M):
            out[m.group(1)] = m.group(2).strip()
    return out


def esc(s):
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def clip(s, n):
    s = esc(s)
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def main():
    verdicts, challenges = load()
    T = titles()
    if not verdicts:
        sys.exit("no verdict files found")

    rows = []
    for vid, v in verdicts.items():
        c = challenges.get(vid)
        status = (c or {}).get("final_status") or v["status"]
        sev = (c or {}).get("final_severity") or v.get("severity", "none")
        if status in ("MATCH", "NA"):
            sev = "none"
        rows.append({
            "id": vid,
            "prefix": vid.split("-")[0],
            "num": int(vid.split("-")[1]),
            "title": T.get(vid, ""),
            "status": status,
            "sev": sev,
            "go": v.get("go_source", "-"),
            "note": (c or {}).get("consequence") or v.get("notes", ""),
            "reason": (c or {}).get("reason", ""),
            "orig_status": v["status"],
            "orig_sev": v.get("severity", "none"),
            "verdict": (c or {}).get("verdict"),
        })
    rows.sort(key=lambda r: (r["prefix"], r["num"]))

    L = []
    A = L.append
    A("# Conformance Matrix — `sudosrv` vs. C `sudo_logsrvd`")
    A("")
    A("> **Reference:** sudo 1.9.18 — `36f7128256a93571ec378daa5c209d6883036d31` (2026-07-19)  ")
    A("> **Subject:** `sudosrv` @ `81be2ba`  ")
    A("> **Method:** every numbered requirement in [`01`](01-architecture.md)–[`06`](06-tls-and-security.md) "
      "was checked against the Go source, then every non-`MATCH` verdict was independently "
      "challenged by a second pass instructed to refute it. Verdict vocabulary is defined in "
      "[README.md](README.md#verdict-vocabulary).")

    A("")

    # ---- summary by subsystem -------------------------------------------------
    A("## Summary")
    A("")
    A("| Subsystem | Reqs | " + " | ".join(STATUSES) + " |")
    A("|---|--:|" + "--:|" * len(STATUSES))
    for pfx, doc, title in SUBSYS:
        sub = [r for r in rows if r["prefix"] == pfx]
        if not sub:
            continue
        c = collections.Counter(r["status"] for r in sub)
        A(f"| [{title}]({doc}) | {len(sub)} | " + " | ".join(str(c.get(s, 0)) for s in STATUSES) + " |")
    tot = collections.Counter(r["status"] for r in rows)
    A(f"| **Total** | **{len(rows)}** | " + " | ".join(f"**{tot.get(s,0)}**" for s in STATUSES) + " |")
    A("")

    sev = collections.Counter(r["sev"] for r in rows if r["status"] not in ("MATCH", "NA"))
    A("Severity of the " + str(sum(sev.values())) + " requirements that are not `MATCH`/`NA`:")
    A("")
    A("| breaking | high | medium | low | informational |")
    A("|--:|--:|--:|--:|--:|")
    A("| " + " | ".join(str(sev.get(k, 0)) for k in
                        ["breaking", "high", "medium", "low", "informational"]) + " |")
    A("")

    # ---- adversarial effect ---------------------------------------------------
    if challenges:
        vc = collections.Counter(c.get("verdict") for c in challenges.values())
        A("### Effect of the adversarial pass")
        A("")
        A(f"{len(challenges)} findings were challenged: "
          f"**{vc.get('UPHELD',0)} upheld**, **{vc.get('DOWNGRADED',0)} downgraded**, "
          f"**{vc.get('UPGRADED',0)} upgraded**, **{vc.get('REFUTED',0)} refuted outright**.")
        A("")
        moved = [r for r in rows if r["verdict"] in ("REFUTED", "DOWNGRADED", "UPGRADED")
                 and (SEVRANK[r["orig_sev"]] <= 1 or SEVRANK[r["sev"]] <= 1)]
        if moved:
            A("Findings whose grade moved into or out of the top two severities:")
            A("")
            A("| ID | Was | Now | Why the grade moved |")
            A("|---|---|---|---|")
            for r in sorted(moved, key=lambda r: SEVRANK[r["sev"]]):
                A(f"| `{r['id']}` | {r['orig_status']} / {r['orig_sev']} | "
                  f"{r['status']} / {r['sev']} | {clip(r['reason'], 200)} |")
            A("")

    # ---- priority findings ----------------------------------------------------
    top = sorted([r for r in rows if r["sev"] in ("breaking", "high")],
                 key=lambda r: (SEVRANK[r["sev"]], r["prefix"], r["num"]))
    A("## Priority findings")
    A("")
    A("> **The single highest-value fix is the idle-timeout default.** Three requirements "
      "in this list (`ARCH-024`, `ARCH-045`, `CONF-025`) are the same defect, reached "
      "independently from two subsystems. The chain, verified end to end in the reference "
      "sources:")
    A(">")
    A("> 1. `plugins/sudoers/defaults.c:610` — `def_ignore_iolog_errors = false` **by default**.")
    A("> 2. `plugins/sudoers/log_client.c:1919-1921` — on a log-server read failure the client "
      "calls `loopbreak()`, commented *\"Break out of sudo event loop and kill the command.\"*")
    A("> 3. `logsrvd/logsrvd.c:1372` — the C server arms **no** read timeout: "
      "*\"No read timeout, client messages may happen at arbitrary times.\"*")
    A("> 4. `internal/connection/handler.go:202-203` + `internal/config/config.go:136` — "
      "Go arms a **10-minute** read deadline by default.")
    A(">")
    A("> A user idle for 10 minutes at a `sudo -s` prompt therefore has the connection dropped "
      "and **their running command killed**. `idle_timeout: -1s` opts out; note that "
      "`idle_timeout: 0` silently restores 10m rather than disabling it.")
    A("")
    if not top:
        A("No requirement survived the adversarial pass at `breaking` or `high` severity.")
    else:
        A(f"{len(top)} requirements are graded `breaking` or `high` after adversarial review. "
          "These are the divergences worth acting on first.")
        A("")
        for r in top:
            A(f"### `{r['id']}` — {r['title']}")
            A("")
            A(f"**{r['status']}** · severity **{r['sev']}** · spec: "
              f"[{r['id']}]({dict((p, d) for p, d, _ in SUBSYS)[r['prefix']]}) · Go: `{r['go']}`")
            A("")
            A(f"{esc(r['note'])}")
            A("")
            if r["reason"]:
                A(f"<sub>Adversarial review ({r['verdict'] or 'n/a'}): {esc(r['reason'])}</sub>")
                A("")
    A("")

    # ---- full matrix ----------------------------------------------------------
    A("## Full matrix")
    A("")
    A("`MATCH` rows are listed for completeness — they are the evidence that the requirement "
      "was actually checked, not skipped.")
    A("")
    for pfx, doc, title in SUBSYS:
        sub = [r for r in rows if r["prefix"] == pfx]
        if not sub:
            continue
        A(f"### {title}")
        A("")
        A(f"Spec: [`{doc}`]({doc})")
        A("")
        A("| ID | Requirement | Verdict | Sev | Go source | Consequence |")
        A("|---|---|---|---|---|---|")
        for r in sub:
            note = "—" if r["status"] == "MATCH" else clip(r["note"], 190)
            go = f"`{clip(r['go'], 60)}`" if r["go"] and r["go"] != "-" else "—"
            A(f"| `{r['id']}` | {clip(r['title'], 60)} | {r['status']} | {r['sev']} | {go} | {note} |")
        A("")

    out = os.path.join(DOCS, "CONFORMANCE.md")
    open(out, "w").write("\n".join(L) + "\n")
    print(f"wrote {out}  ({len(L)} lines, {len(rows)} requirements, {len(challenges)} challenged)")
    print("status:", dict(tot))
    print("severity(non-match):", dict(sev))
    print("priority findings:", len(top))
    for r in top:
        print(f"   {r['id']:11s} {r['status']:11s} {r['sev']:8s} {r['title'][:60]}")


if __name__ == "__main__":
    main()
