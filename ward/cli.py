"""WARD command line.

    ward status              one-shot verdict, colourised
    ward scan [--json]       full finding list
    ward watch               live scan loop (foreground)
    ward daemon              the supervised background loop
    ward harden [--dry-run]  apply host hardening
    ward restore             undo journalled hardening
    ward firewall [--apply]  render / install the nftables table
    ward lockdown            maximum containment
    ward kill PID           terminate a process (with evidence)
    ward watch-wire [SECS]  live packet inspection for proxy protocols
    ward report              human-readable incident report
    ward events              tail the event log
    ward verify-log          prove the event chain is intact
    ward baseline [--reset]  learn / show the known-good inventory
    ward selftest            prove the detector actually fires
    ward tripwire            check the daemon heartbeat
    ward explain RULE        why a rule exists and what it catches
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import textwrap
import sys
import time
from typing import Any

from . import detect, firewall, harden, respond, signatures, sniff, util
from .config import load
from .daemon import HEARTBEAT, Runtime, install_signal_handlers, make_runtime
from .events import EventLog
from .util import now

# ------------------------------------------------------------------ colour

_TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str) -> str:
    if not _TTY:
        return text
    return f"\033[{code}m{text}\033[0m"


BOLD = "1"
DIM = "2"
RED = "1;31"
YELLOW = "1;33"
GREEN = "1;32"
CYAN = "36"
MAGENTA = "35"


def sev_colour(sev: str) -> str:
    return {
        "critical": RED,
        "high": RED,
        "medium": YELLOW,
        "low": CYAN,
        "info": DIM,
    }.get(sev, "")


def score_colour(score: int) -> str:
    if score >= 85:
        return RED
    if score >= 65:
        return RED
    if score >= 40:
        return YELLOW
    return GREEN


def sev_tag(sev: str) -> str:
    """Severity, padded only when colour is on (padding is invisible anyway)."""
    label = sev.upper()
    return c(label.ljust(8), sev_colour(sev)) if _TTY else label


#: Label column width, after the two-space indent. Every value starts here.
LABEL_W = 12


def row(label: str, value: str) -> str:
    return f"  {c(label.ljust(LABEL_W), DIM)}{value}"


# ------------------------------------------------------------------ helpers


def _load(args) -> Any:
    return load(getattr(args, "config", None))


def _log_for(config) -> EventLog:
    lc = config.section("log")
    return EventLog(
        lc.get("file", "/var/lib/ward/events.jsonl"),
        mode=lc.get("mode", "hashchain"),
        rotate_bytes=int(lc.get("rotate_bytes", 32 << 20)),
    )


def _verdict(config, **kw) -> detect.Verdict:
    return detect.scan(config, **kw)


def print_status(config, verdict: detect.Verdict) -> None:
    host = None
    try:
        from . import observe

        host = observe.observe_host()
    except Exception:
        host = None
    # The daemon publishes its own health and what it observed. Read it first:
    # a broken daemon reporting "no findings" is the worst failure mode here.
    published = _load_json(config.get("daemon.state", "/run/ward/state.json"))
    if not isinstance(published, dict):
        published = {}
    st = util.read_text(config.get("daemon.heartbeat", HEARTBEAT)).strip()
    hb = "no daemon heartbeat"
    hb_ts = 0.0
    if st:
        parts = st.split()
        if len(parts) >= 3:
            try:
                hb_ts = float(parts[0])
                hb = f"{util.ago(hb_ts)}, pid {parts[1]}, score {parts[2]}"
            except ValueError:
                hb = st
    print()
    print(c("  WARD", BOLD) + c("  residential-proxy defence", DIM))
    print(c("  " + "\u2500" * 66, DIM))
    tag = c(f"{verdict.score}", score_colour(verdict.score))
    # A broken daemon reporting "no findings" is the worst failure mode of a
    # defender: it looks like an all-clear. Check the daemon's own health
    # before presenting a score.
    errors = published.get("cycle_errors") if isinstance(published, dict) else None
    last_ok = published.get("last_ok") if isinstance(published, dict) else None
    stale = False
    if isinstance(last_ok, (int, float)) and last_ok:
        interval = float(config.get("detect.interval_seconds", 10.0))
        stale = (now() - last_ok) > interval * 4
    if errors:
        tag = c(str(verdict.score), RED)
        print(row("risk score", f"{tag} / 100   {c('DEFENDER BROKEN', RED)}"))
        print(row("", c(f"the daemon has failed {errors} cycle(s) in a row. "
                         f"this score is the last good one, not a current reading.", RED)))
        print(row("", c("sudo ward events --limit 5   to see the error", DIM)))
        print()
    elif stale or not hb_ts:
        print(row("risk score", c("unknown", RED) + c("   the daemon is not reporting.", DIM)))
        print(row("", c("sudo ward status   to scan on demand", DIM)))
        print()
    else:
        print(row("risk score", f"{tag} / 100   {sev_tag(verdict.severity)}"))
    print(row("mode", str(config.get("respond.mode"))))
    # Reading nftables needs CAP_NET_ADMIN, so a user cannot see the table
    # directly. The daemon can, and publishes what it saw. Prefer the live read,
    # fall back to the daemon's observation, and say how old it is. Never guess:
    # reporting "ABSENT" from an unread ruleset would send the operator off to
    # re-apply a firewall that is working.
    observed = published.get("host") if isinstance(published, dict) else None
    live = host.nft_table_present if host else None
    if live is True:
        fw_state = c("present", GREEN)
    elif live is False:
        fw_state = c("ABSENT -- run: sudo ward firewall --apply", RED)
    elif isinstance(observed, dict) and observed.get("firewall_table") is not None:
        age = util.ago(float(observed.get("checked", 0)))
        if observed["firewall_table"]:
            fw_state = c(f"present", GREEN) + c(f" (as of {age}, via the daemon)", DIM)
        else:
            fw_state = c(f"ABSENT as of {age}", RED)
    else:
        fw_state = c("unknown", YELLOW) + c(" -- no daemon observation; try sudo ward status", DIM)
    print(row("firewall", f"ward table {fw_state}"))
    print(row("heartbeat", hb))

    fwd_value = host.ip_forward if host else (
        observed.get("ip_forward") if isinstance(observed, dict) else None
    )
    if fwd_value is None:
        fwd = c("unknown", YELLOW)
    elif fwd_value == 0:
        fwd = "0 (good)"
    else:
        fwd = c(f"{fwd_value}  <-- this machine can route", RED)
    print(row("ip_forward", fwd))
    print()
    revoked = respond.quarantined_binaries()
    if revoked:
        print(row("revoked", f"{c(str(len(revoked)), YELLOW)} binary exec bits "
                              f"removed  (undo: sudo ward release <pid>)"))
        for item in revoked[:5]:
            original = item["original"] or "original not found"
            ok = item["original"] and os.access(item["original"], os.X_OK)
            print("    " + c(item["quarantined"].rsplit("/", 1)[-1].ljust(28), DIM)
                  + f"{original}  exec={'yes' if ok else c('NO', RED)}")
    if verdict.findings:
        print(c("  findings", BOLD))
        for f in verdict.findings[:12]:
            print(f"    {sev_tag(f.severity)} {c(str(f.score).rjust(3), score_colour(f.score))}  "
                  f"{c(f.rule.ljust(26), DIM)}{f.title}")
        if len(verdict.findings) > 12:
            print(c(f"    ... and {len(verdict.findings) - 12} more", DIM))
    else:
        print(c("  no findings. no relay software, no reachable doors, no forwarding.", GREEN))
    print()


def print_findings(verdict: detect.Verdict, as_json: bool) -> None:
    if as_json:
        print(util.canonical_json(verdict.to_dict()))
        return
    if not verdict.findings:
        print(c("clean", GREEN))
        return
    for f in verdict.findings:
        print()
        print(f"{sev_tag(f.severity)} {c(f'{f.score}', score_colour(f.score))} "
              f"{c(f.rule, DIM)}  {f.title}")
        for key, value in f.detail.items():
            rendered = (
                util.canonical_json(value)
                if isinstance(value, (dict, list))
                else str(value)
            )
            print(f"    {c(key + ':', DIM)} {util.truncate(rendered, 300)}")
        if f.subjects:
            print(f"    {c('subjects:', DIM)} {util.canonical_json(f.subjects)}")


# ------------------------------------------------------------------ commands


def cmd_status(args) -> int:
    config = _load(args)
    verdict = _verdict(config)
    if args.json:
        print(util.canonical_json(verdict.to_dict()))
    else:
        print_status(config, verdict)
    return 0 if verdict.score < 70 else 1


def cmd_scan(args) -> int:
    config = _load(args)
    log = _log_for(config)
    history: dict[int, dict[str, Any]] = {}
    verdict = detect.scan(
        config,
        history=history,
        stored_baseline=_load_json(config.get("baseline.file")),
        stored_integrity=_load_json("/var/lib/ward/integrity.json"),
        host_bytes=None,
        do_integrity=not args.fast,
    )
    print_findings(verdict, args.json)
    if not args.no_log:
        for f in verdict.findings[:20]:
            log.emit(
                "scan",
                f.to_dict(),
                score=f.score,
                rule=f.rule,
                title=f.title,
            )
    return 0 if verdict.score < 70 else 1


def _load_json(path: str) -> dict:
    text = util.read_text(path, 8 << 20)
    if not text:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def cmd_watch(args) -> int:
    config = _load(args)
    if args.once:
        verdict = _verdict(config)
        print_status(config, verdict)
        return 0
    rt = make_runtime(config)
    install_signal_handlers(rt)
    if args.max_cycles:
        rt.run(max_cycles=args.max_cycles)
    else:
        rt.run()
    return 0


def cmd_daemon(args) -> int:
    config = _load(args)
    if args.foreground:
        rt = make_runtime(config)
        install_signal_handlers(rt)
        rt.run()
        return 0
    # Double-fork style detach without importing anything outside stdlib.
    if os.fork() != 0:
        return 0
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    rt = make_runtime(config)
    install_signal_handlers(rt)
    rt.run()
    return 0


def cmd_harden(args) -> int:
    config = _load(args)
    util.require_root("harden")
    res = harden.harden(config, dry_run=args.dry_run)
    for action in res.actions:
        print(f"  {c('ok', GREEN)}   {action}")
    for failure in res.failures:
        print(f"  {c('FAIL', RED)} {failure}")
    if not args.dry_run:
        print(f"\n  restore with: {c('sudo ward restore', BOLD)}")
    return 1 if res.failures else 0


def cmd_restore(args) -> int:
    util.require_root("restore")
    out = harden.restore(dry_run=args.dry_run)
    if not out:
        print("  nothing journalled to restore")
        return 0
    for entry in out:
        if entry.get("kind") == "summary":
            continue
        colour = RED if entry["result"].startswith(("failed", "no undo handler")) else CYAN
        print(f"  {c(entry.get('result', '?'), colour)}  {c(entry.get('target') or '', DIM)}")
    summary = next((e for e in out if e.get("kind") == "summary"), None)
    if summary:
        print()
        unhandled = summary.get("unhandled_kinds") or []
        if unhandled:
            print(f"  {c('NOT restored', RED)}: {', '.join(unhandled)}")
            print("  those change kinds have no undo handler; see docs")
        else:
            print(f"  {c(summary['result'], GREEN)}")
        drift = [e for e in out if e.get("drift")]
        for entry in drift:
            for key, text in entry["drift"].items():
                print(f"  {c('drift', YELLOW)}  {key}: {text}")
    return 0


def cmd_firewall(args) -> int:
    config = _load(args)
    script = firewall.render(config)
    if args.json:
        print(util.canonical_json({"ruleset": script}))
        return 0
    if not args.apply:
        ok, msg = firewall.check(config)
        print(f"  validation: {c('ok', GREEN) if ok else c('FAILED', RED)}  {msg}")
        print()
        print(script)
        return 0 if ok else 1
    util.require_root("firewall")
    ok, msg = firewall.apply(
        config, persist=not args.no_persist,
        journal=harden.Journal(path="/var/lib/ward/restore-journal.jsonl"),
    )
    print(f"  {c('ok', GREEN) if ok else c('FAILED', RED)}  {msg}")
    if ok and not args.no_counters:
        counts = firewall.counters(config)
        if counts:
            print("  counters: " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0 if ok else 1

def cmd_counters(args) -> int:
    config = _load(args)
    try:
        counts = firewall.counters(config)
    except PermissionError:
        print(f"  {c('denied', YELLOW)}  reading nftables counters needs CAP_NET_ADMIN")
        print("  run it as root: sudo ward counters")
        return 1
    if not counts:
        print("  ward table has no counters yet (run: sudo ward firewall --apply)")
        return 1
    for key, value in sorted(counts.items()):
        print(f"  {key:<22} {value:>12,}")
    return 0


def cmd_seal(args) -> int:
    """Record hashes of WARD's own files.

    Called by install.sh. Without it the first daemon start writes the
    baseline itself, which means anything that modified WARD before that
    first start is baked in as the expected state.
    """
    util.require_root("seal")
    rt = make_runtime(_load(args))
    n = rt.record_self()
    if n < 0:
        print(f"  {c('FAIL', RED)}  could not write {rt.self_hashes_path}")
        print("        run it as root, and check that /var/lib/ward is writable")
        return 1
    print(f"  {c('ok', GREEN)}  sealed {n} file(s) -> {rt.self_hashes_path}")
    print("        any later change to these raises a self-integrity finding")
    return 0


def cmd_unquarantine(args) -> int:
    """Clear the port-quarantine table.

    A containment action that drops a port can be wrong. This is the undo, and
    it has to exist as a command rather than a function nobody can reach.
    """
    util.require_root("unquarantine")
    ok, msg = firewall.unquarantine()
    print(f"  {c('ok' if ok else 'FAIL', GREEN if ok else RED)}  {msg}")
    return 0 if ok else 1


def cmd_release(args) -> int:
    """Unfreeze a process WARD contained, and give its binary back exec.

    A false positive must be recoverable by a human without a reboot.
    """
    util.require_root("release")
    pid = args.pid
    ok1, msg1 = respond.unfreeze_cgroup(pid)
    restored = "no binary was revoked for that pid"
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = ""
    if exe and not os.access(exe, os.X_OK):
        ok2, restored = respond.restore_binary_exec(exe)
    print(f"  {c('ok' if ok1 else 'warn', GREEN if ok1 else YELLOW)}  {msg1}")
    print(f"        {restored}")
    return 0 if ok1 else 1


def cmd_lockdown(args) -> int:
    config = _load(args)
    verdict = _verdict(config)
    if not args.yes:
        print(c(f"  about to lockdown: score {verdict.score}, {len(verdict.findings)} findings",
              RED))
        print("  this kills nothing unless auto_kill is set, but closes all inbound")
        print("  except the allowlist and drops every relay port. Re-run with --yes.")
        if not sys.stdin.isatty():
            return 2
        try:
            answer = input("  proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            print("  aborted")
            return 2
    res = respond.lockdown(config, dry_run=args.dry_run)
    for action in res.actions:
        print(f"  {c('ok' if action.ok else 'FAIL', GREEN if action.ok else RED)}   {action.detail}")
    return 0 if all(a.ok for a in res.actions) else 1


def cmd_kill(args) -> int:
    util.require_root("kill")
    pid = args.pid
    exe = ""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = util.read_text(f"/proc/{pid}/comm", 64).strip()
    if signatures.is_protected(os.path.basename(exe)):
        print(f"  {c('refusing', RED)} to kill protected process {exe}")
        return 1
    if args.evidence:
        config = _load(args)
        verdict = detect.Verdict(
            score=100, severity="critical", findings=[], reasons=[f"manual kill of {exe}"]
        )
        dest = respond.snapshot(config, verdict, f"kill-{pid}")
        print(f"  evidence: {dest}")
    results = respond.kill_process_tree(pid, grace=args.grace, dry_run=args.dry_run)
    for target, ok, msg in results:
        print(f"  {c('ok', GREEN) if ok else c('FAIL', RED)}   {msg}")
    return 0 if all(ok for _t, ok, _m in results) else 1


def cmd_wire(args) -> int:
    util.require_root("watch-wire")
    seconds = args.seconds
    iface = args.iface
    print(f"  watching {iface} for {seconds}s -- looking for SOCKS/HTTP-proxy/TLS-SNI")
    try:
        with sniff.Sniffer(iface) as sn:
            events: list[sniff.Event] = []
            deadline = now() + seconds
            last_print = 0.0
            for ts, frame in sn.frames():
                if now() > deadline:
                    break
                for ev in sniff.analyze_frame(frame, ts, sn.my_ips):
                    events.append(ev)
                    if ev.severity >= 45 or ev.kind in ("socks5-greeting", "socks4-connect",
                                                        "http-connect"):
                        direction = "IN " if ev.inbound else "OUT"
                        print(f"  {util.iso(ts)} {direction} {ev.kind:<18} "
                              f"{ev.src}:{ev.sport} -> {ev.dst}:{ev.dport}  {ev.detail}")
                if events and now() - last_print > 5:
                    last_print = now()
    except PermissionError as exc:
        print(f"  {c('denied', RED)} {exc}")
        return 1
    summary = sniff.summarize(events)
    print()
    print(f"  {summary['total']} event(s); by kind: {util.canonical_json(summary['by_kind'])}")
    if summary["relay_proven"]:
        print(c(f"  RELAY PROVEN: inbound proxy use from {summary['inbound_proxy_clients']}",
                RED))
    return 0


def cmd_pcap(args) -> int:
    events = sniff.analyze_pcap(args.path, my_ips=args.my_ip or None)
    if args.json:
        print(util.canonical_json([e.to_dict() for e in events]))
        return 0
    for ev in events:
        direction = "IN " if ev.inbound else "OUT"
        print(f"  {util.iso(ev.ts)} {direction} {ev.kind:<18} "
              f"{ev.src}:{ev.sport} -> {ev.dst}:{ev.dport}  {ev.detail}")
    summary = sniff.summarize(events)
    print()
    print(f"  {summary['total']} event(s); {util.canonical_json(summary['by_kind'])}")
    if summary["relay_proven"]:
        print(c(f"  RELAY PROVEN: {summary['inbound_proxy_clients']}", RED))
    return 0


def cmd_report(args) -> int:
    config = _load(args)
    log = _log_for(config)
    limit = args.limit
    events = log.read(limit=limit)
    verdict = _verdict(config)
    state = _load_json(config.get("daemon.state", "/run/ward/state.json"))
    if isinstance(state.get("log_seq"), int):
        log.set_expected_records(state["log_seq"])
    chain = log.verify()
    print()
    print(c("  WARD incident report", BOLD))
    print(c(f"  generated {util.iso()}   config: {', '.join(config.sources)}", DIM))
    print(c("  " + "\u2500" * 66, DIM))
    print(f"  current risk   {verdict.score}/100 ({verdict.severity})")
    print(f"  event log      {log.path}  head={log.head[:16]}")
    print(f"  chain          {c('intact', GREEN) if chain['ok'] else c('BROKEN', RED)}"
          f" ({chain['records']} records)")
    print(f"  dropped        {log.dropped} (rate limit)")
    print()
    alerts = [e for e in events if e.get("kind") in ("alert", "response", "self-integrity")]
    if alerts:
        print(c(f"  {len(alerts)} alert/response event(s)", BOLD))
        for ev in alerts[-args.deep :]:
            print(f"    {ev.get('iso','')} [{ev.get('score','?'):>3}] {ev.get('title','')}")
            detail = ev.get("detail")
            if isinstance(detail, dict):
                for key in ("reasons", "rules", "mode", "snapshot", "changed"):
                    if key in detail:
                        print(f"        {key}: {util.truncate(str(detail[key]), 220)}")
        print()
    top = [f for f in verdict.findings if f.score >= 40]
    if top:
        print(c("  live findings >= 40", BOLD))
        for f in top:
            print(f"    {f.score:>3} {f.rule:<28} {f.title}")
        print()
    snaps_dir = config.get("respond.snapshot_dir", "/var/lib/ward/snapshots")
    if os.path.isdir(snaps_dir):
        snaps = sorted(os.listdir(snaps_dir))[-args.deep :]
        if snaps:
            print(c("  evidence snapshots", BOLD))
            for s in snaps:
                print(f"    {os.path.join(snaps_dir, s)}")
    print()
    return 0


def cmd_events(args) -> int:
    config = _load(args)
    log = _log_for(config)
    if args.verify:
        # Cross-check against the count the running daemon published. Without
        # this, emptying the log looks like a log that was never written.
        state = _load_json(config.get("daemon.state", "/run/ward/state.json"))
        declared = state.get("log_seq")
        if isinstance(declared, int):
            log.set_expected_records(declared)
        chain = log.verify()
        if isinstance(declared, int) and chain.get("ok") and chain["records"] < declared:
            chain = {
                "ok": False,
                "records": chain["records"],
                "reason": (
                    f"log holds {chain['records']} record(s) but the daemon "
                    f"state claims {declared} -- the log was truncated"
                ),
                "head": chain.get("head"),
            }
        print(util.canonical_json(chain))
        return 0 if chain["ok"] else 1
    for ev in log.read(limit=args.limit):
        print(f"{ev.get('iso','')} [{ev.get('seq',''):>6}] "
              f"[{ev.get('score',0):>3}] {ev.get('kind',''):<14} {ev.get('title','')}")
    return 0


def cmd_baseline(args) -> int:
    config = _load(args)
    from . import observe

    path = config.get("baseline.file")
    if args.reset:
        try:
            os.remove(path)
            print("  baseline cleared; it will be re-learned on the next scan")
        except OSError as exc:
            print(f"  {exc}")
            return 1
        return 0
    listeners, _ = observe.observe_sockets()
    procs = observe.observe_processes(include_content_scan=False)
    state = observe.baseline_state({}, procs, listeners)
    stored = _load_json(path)
    if stored:
        state["learned_at"] = stored.get("learned_at", "?")
        state["learned_by"] = stored.get("learned_by", "?")
    if args.json:
        print(util.canonical_json(state))
        return 0
    print()
    print(c("  baseline inventory", BOLD))
    print(f"  file       {path}")
    print(f"  learned    {state.get('learned_at', 'not yet')}  ({state.get('learned_by', '-')})")
    print(f"  processes  {len(state['processes'])}")
    print(f"  listeners  {len(state['listeners'])}")
    print(f"  modules    {len(state['modules'])}")
    world = [l for l in state["listeners"] if not util.is_loopback(l.split(":")[1])]
    if world:
        print(c(f"  world-reachable listeners ({len(world)}):", YELLOW))
        for entry in world:
            print(f"    {entry}")
    print()
    return 0


def cmd_tripwire(args) -> int:
    config = _load(args)
    action = respond.tripwire(
        config, config.get("daemon.heartbeat", HEARTBEAT), max_age=args.max_age
    )
    print(f"  {c('ok', GREEN) if action.ok else c('FAIL', RED)}  {action.detail}")
    return 0 if action.ok else 1


#: What each rule is for, split into fields. One long string per rule turned
#: `ward explain` into a wall of prose; the fields make it scannable and the
#: selftest asserts every rule has them.
EXPLAIN: dict[str, dict[str, str]] = {
    "R01": {
        "label": "relay software by name",
        "what": "a process whose executable or arguments are a known relay",
        "catches": "dante, gost, 3proxy, FRP, ngrok, and the residential-network "
                   "agents (Bright Data, IPRoyal, Smartproxy, Webshare, NetNut, "
                   "PacketStream, Pawnacle, Proxidize)",
        "limits": "a renamed binary slips past. R02 and R05 are the net for that.",
    },
    "R02": {
        "label": "proxy markers inside the binary",
        "what": "the executable's bytes contain proxy-protocol markers",
        "catches": "SOCKS handshakes, HTTP CONNECT request builders, Tor relay "
                   "directives, vendor strings",
        "limits": "discounted for browsers and interpreters, which legitimately "
                  "link proxy code. Two tiers: tier A counts alone, tier B needs "
                  "a second hit.",
    },
    "R03": {
        "label": "network-reachable listener",
        "what": "a TCP listener bound to a non-loopback address",
        "why it matters": "a proxy needs an inbound door, and a laptop has no "
                          "business having one",
        "scores": "30 for any world-bound port, 55 on a known relay port, "
                  "another 15 on 0.0.0.0 or ::. Allowlisted LAN ports are skipped, "
                  "in both their IPv4 and IPv6 form.",
    },
    "R04": {
        "label": "network-reachable UDP listener",
        "what": "a UDP listener reachable from the network",
        "why it matters": "covers DNS amplification relays and SOCKS over UDP, "
                          "which never appear as a TCP listener",
    },
    "R05": {
        "label": "connection fan-out",
        "what": "one process, many unrelated remote IPs",
        "why it matters": "this is the rule that catches a renamed proxy, "
                          "because renaming a binary does not change the shape of "
                          "its traffic",
        "thresholds": "25 distinct IPs and 8 distinct /16s. Browsers, toolchains "
                      "and P2P clients get a much larger budget.",
        "limits": "a legitimate peer-to-peer client with 25+ peers looks similar. "
                  "Those are allowlisted by name.",
    },
    "R06": {
        "label": "residential vendor reference",
        "what": "residential-proxy vendor names near a process",
        "why it matters": "catches enrolment before any traffic flows",
        "scoring": "70 in an executable path, cwd or environment, which is "
                   "structural evidence. 20 in the argument list of a shell or "
                   "editor, which is just text someone typed.",
    },
    "R07": {
        "label": "routing and NAT capability",
        "what": "routing and NAT capability",
        "why it matters": "on a laptop these have no legitimate use, and they are "
                          "how a neighbour's traffic gets carried over your uplink",
        "covers": "ip_forward, IPv6 forwarding, NAT masquerade, a forward chain "
                  "with policy accept, ICMP redirects",
    },
    "R08": {
        "label": "Tor as a relay",
        "what": "Tor configured as a relay or exit rather than a client",
        "why it matters": "a client is privacy. A relay is strangers' traffic.",
        "how": "parses /etc/tor/torrc and ignores commented directives, so a stock "
               "config does not read as a relay. Scored lower when tor is not "
               "running, since a config file is not traffic.",
    },
    "R09": {
        "label": "unexpected interfaces and tun modules",
        "what": "unexpected virtual interfaces and tunnel kernel modules",
        "why it matters": "no client means nothing is tunnelling",
        "why it is low": "deliberately. This is a hint, not evidence.",
    },
    "R10": {
        "label": "config and persistence drift",
        "what": "watched config files changed, or new files in persistence dirs",
        "why it matters": "a proxy that survives a reboot has to persist somewhere",
        "covers": "systemd units, cron, /usr/local/bin, ~/.ssh",
    },
    "R11": {
        "label": "diff against the baseline",
        "what": "a diff against the baseline learned on first run",
        "covers": "a new world-reachable listener, a new relay process, a new "
                  "tunnel kernel module",
    },
    "R12": {
        "label": "anti-forensics",
        "what": "anti-forensics and anti-analysis",
        "covers": "LD_PRELOAD from outside the application's own libraries, a "
                  "process running from a deleted binary while holding sockets",
        "limits": "a self-preload is normal. Firefox injects its own sandbox into "
                  "every child, so that case is ignored.",
    },
    "R13": {
        "label": "host firewall open port",
        "what": "the host firewall publicly opens a port",
        "why it matters": "an open port on the firewall is open to the world, "
                          "whatever the local process thinks about 127.0.0.1",
        "limits": "cached for five minutes. firewall-cmd is a slow subprocess and "
                  "a firewall zone does not change between scans.",
    },
    "R14": {
        "label": "egress asymmetry",
        "what": "interface-level egress asymmetry",
        "why it matters": "relaying other people's traffic produces far more "
                          "outbound than inbound; normal use is roughly balanced",
        "limits": "needs a large absolute volume before it counts at all",
    },
}

#: Rules that answer a question the operator asked, with the question first.
EXPLAIN_ORDER = ["what", "why it matters", "catches", "scores", "thresholds",
                 "scoring", "covers", "how", "why it is low", "limits"]


def cmd_explain(args) -> int:
    key = args.rule.upper()
    if not key.startswith("R"):
        key = "R" + key
    # Accept R3 as R03, and R3b as R03.
    if len(key) == 2 and key[1].isdigit():
        key = f"R0{key[1]}"
    for rid, fields in EXPLAIN.items():
        if not key.startswith(rid):
            continue
        print()
        print("  " + c(rid.ljust(5), BOLD) + c(fields["label"], CYAN))
        print()
        label_w = max(len(k) for k in EXPLAIN_ORDER if k in fields) + 2
        width = min(shutil.get_terminal_size((80, 24)).columns, 88) - 4 - label_w
        for field in EXPLAIN_ORDER:
            if field not in fields:
                continue
            text = " ".join(fields[field].split())
            lines = textwrap.wrap(text, width) if width > 20 else [text]
            print("  " + c(field.ljust(label_w), DIM) + lines[0])
            for extra in lines[1:]:
                print(" " * (4 + label_w) + extra)
            print()
        related = [f for f in ("watch-wire", "scan", "explain") if True]
        print(c("  see also: ward scan   ward selftest", DIM))
        print()
        return 0
    print(f"  no rule {args.rule}.")
    print(f"  known: {', '.join(sorted(EXPLAIN, key=lambda r: int(r[1:])))}")
    return 1


def cmd_selftest(args) -> int:
    from . import selftest

    return selftest.run(verbose=not args.quiet, quick=args.quick)


# ------------------------------------------------------------------ parser


#: How the commands are grouped on `ward -h`. Alphabetical order tells you
#: nothing about what to run first or what is safe, so the help is organised by
#: what you are trying to do. Order here is the order on screen.
COMMAND_GROUPS: list[tuple[str, str, list[str]]] = [
    ("Start here", "the three you will actually use", [
        ("status", "one-shot verdict, safe without sudo"),
        ("explain", "why a rule exists"),
        ("selftest", "prove the detector and the safety properties"),
    ]),
    ("Look around", "read-only, nothing is changed", [
        ("scan", "every finding, not just the summary"),
        ("report", "incident report, human-readable"),
        ("events", "read the hash-chained event log"),
        ("counters", "firewall packet counters"),
        ("baseline", "the known-good inventory WARD diffs against"),
        ("tripwire", "is the daemon still alive and honest"),
    ]),
    ("Check it works", "prove the claims rather than trust them", [
        ("watch", "scan on a loop in the foreground"),
        ("watch-wire", "live packet inspection for proxy protocols"),
        ("analyze-pcap", "decode a capture someone else took"),
    ]),
    ("Change the machine", "needs root, all of it reversible", [
        ("harden", "sysctl, LLMNR, sshd pinning, firewalld ports"),
        ("restore", "undo journalled hardening"),
        ("firewall", "render or install the nftables table"),
        ("seal", "record hashes of WARD's own files"),
    ]),
    ("Respond to an incident", "containment, and the undo for each", [
        ("lockdown", "maximum containment"),
        ("kill", "terminate a process, with evidence first"),
        ("unquarantine", "undo a containment port drop"),
        ("release", "unfreeze a process, restore its exec bit"),
    ]),
    ("Run in the background", "what systemd does for you", [
        ("daemon", "the supervised scan loop"),
    ]),
]

_GROUP_OF: dict[str, tuple[str, str]] = {
    cmd: (title, blurb) for title, blurb, cmds in COMMAND_GROUPS for cmd, _h in cmds
}


def format_grouped_help() -> str:
    """Render `ward -h` as groups instead of one alphabetical wall.

    argparse can give a set of subparsers only one title, so the grouping is
    rendered here. Every command still has its own `ward <cmd> -h`.
    """
    terminal = shutil.get_terminal_size((80, 24)).columns
    width = min(max(terminal, 64), 96)
    name_w = max(len(n) for _t, _b, cmds in COMMAND_GROUPS for n, _h in cmds)
    name_w = max(name_w, len("--config CONFIG"))
    title_w = max(len(title) for title, _b, _c in COMMAND_GROUPS) + 2
    title_w = max(title_w, name_w + 2)
    rule = "\u2500" * min(width - 2, 74)

    out: list[str] = [
        "",
        "  " + c("WARD", BOLD) + "  "
        + c("keep this machine from being sold as a residential proxy", DIM),
        c("  " + rule, DIM),
    ]
    for title, blurb, cmds in COMMAND_GROUPS:
        out.append("")
        out.append("  " + c(title.ljust(title_w), BOLD) + c(blurb, DIM))
        for name, summary in cmds:
            out.append("    " + c(name.ljust(name_w), CYAN) + "  " + summary)
    out += [
        "",
        "  " + c("Other", BOLD),
        "    " + c("--config CONFIG".ljust(name_w), CYAN) + "  use a different ward.toml",
        "    " + c("-h, --help".ljust(name_w), CYAN) + "  this screen",
        "",
        c("  Every command has its own help: ward scan -h", DIM),
        "",
    ]
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ward",
        description="WARD -- keep this machine from being sold as a residential proxy",
        add_help=False,
    )
    p.add_argument("--config", help="path to ward.toml")
    p.add_argument("-h", "--help", action="store_true", dest="want_help",
                   help="show this screen")
    sub = p.add_subparsers(dest="cmd", required=False)

    curated = {n: s for _t, _b, cmds in COMMAND_GROUPS for n, s in cmds}

    def add(name, func, help_):
        sp = sub.add_parser(name, help=help_,
                            description=curated.get(name, help_),
                            formatter_class=argparse.RawDescriptionHelpFormatter)
        sp.set_defaults(func=func)
        return sp

    sp = add("status", cmd_status, "one-shot verdict")
    sp.add_argument("--json", action="store_true")

    sp = add("scan", cmd_scan, "full finding list")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--fast", action="store_true", help="skip the integrity sweep")
    sp.add_argument("--no-log", action="store_true")

    sp = add("watch", cmd_watch, "live scan loop in the foreground")
    sp.add_argument("--once", action="store_true")
    sp.add_argument("--max-cycles", type=int)

    sp = add("daemon", cmd_daemon, "background scan loop")
    sp.add_argument("--foreground", action="store_true")

    sp = add("harden", cmd_harden, "apply host hardening")
    sp.add_argument("--dry-run", action="store_true")

    add("restore", cmd_restore, "undo journalled hardening").add_argument(
        "--dry-run", action="store_true"
    )

    sp = add("firewall", cmd_firewall, "render or install the nftables table")
    sp.add_argument("--apply", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--no-persist", action="store_true")
    sp.add_argument("--no-counters", action="store_true")

    add("counters", cmd_counters, "packet counters from the live table")

    add("seal", cmd_seal, "record hashes of WARD's own files (install step)")

    add("unquarantine", cmd_unquarantine,
        "clear the port-quarantine table (undo a containment drop)")

    sp = add("release", cmd_release, "unfreeze a contained process")
    sp.add_argument("pid", type=int)

    sp = add("lockdown", cmd_lockdown, "maximum containment")
    sp.add_argument("--yes", action="store_true")
    sp.add_argument("--dry-run", action="store_true")

    sp = add("kill", cmd_kill, "terminate a process, with evidence")
    sp.add_argument("pid", type=int)
    sp.add_argument("--grace", type=float, default=3.0)
    sp.add_argument("--no-evidence", dest="evidence", action="store_false")
    sp.add_argument("--dry-run", action="store_true")

    sp = add("watch-wire", cmd_wire, "live packet inspection for proxy protocols")
    sp.add_argument("seconds", type=float, nargs="?", default=30.0)
    sp.add_argument("--iface", default="any")

    sp = add("analyze-pcap", cmd_pcap, "decode a pcap file")
    sp.add_argument("path")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--my-ip", action="append",
                    help="treat this address as ours (repeatable); default: autodetect")

    sp = add("report", cmd_report, "human-readable incident report")
    sp.add_argument("--limit", type=int, default=5000)
    sp.add_argument("--deep", type=int, default=12)

    sp = add("events", cmd_events, "read the event log")
    sp.add_argument("--limit", type=int, default=40)
    sp.add_argument("--verify", action="store_true")

    sp = add("baseline", cmd_baseline, "learn or show the known-good inventory")
    sp.add_argument("--reset", action="store_true")
    sp.add_argument("--json", action="store_true")

    sp = add("tripwire", cmd_tripwire, "check the daemon heartbeat")
    sp.add_argument("--max-age", type=float, default=90.0)

    sp = add("explain", cmd_explain, "why a rule exists")
    sp.add_argument("rule")

    sp = add("selftest", cmd_selftest, "prove the detector fires")
    sp.add_argument("--quick", action="store_true")
    sp.add_argument("--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)

    # `ward` with nothing to do should teach, not scold.
    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(format_grouped_help())
        return 0

    # Check the command name before argparse does, so a typo gets a suggestion
    # instead of a 21-command usage dump.
    known = list(_GROUP_OF)
    word = next((a for a in argv if not a.startswith("-")), "")
    if word and word not in known:
        import difflib

        print()
        print(f"  {c('unknown command', RED)} {word!r}")
        for near in difflib.get_close_matches(word, known, n=3, cutoff=0.45):
            summary = dict(
                (n, s) for _t, _b, cmds in COMMAND_GROUPS for n, s in cmds
            )[near]
            print(f"    {c(near.ljust(14), CYAN)}{summary}")
        print(f"    {c('ward -h'.ljust(14), BOLD)}everything, grouped by what it does")
        print()
        return 2

    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        sys.stdout.write(format_grouped_help())
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n  interrupted")
        return 130
    except SystemExit:
        raise
    except Exception as exc:
        if os.environ.get("WARD_TRACEBACK"):
            raise
        print(f"  ward: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
