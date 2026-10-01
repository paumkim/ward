"""Response: forensics first, then contain, then (optionally) kill.

The order is not negotiable. Snapshot the binary, the sockets, the cgroup and a
packet capture *before* touching anything -- because a process that is killed
without evidence is a process you cannot prosecute, and a proxy operator who
sees evidence collection is a proxy operator who moves on to someone else's
machine. Both outcomes are good.

Response modes, from the config:
  observe   -- log and alert only. Default.
  contain   -- drop the relaying port in nft, stop the process from growing.
  kill      -- SIGTERM then SIGKILL the offending process.
  lockdown  -- kill + close all inbound except the allowlist.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from . import firewall, harden, signatures, util
from .detect import Finding, Verdict
from .util import now, run


@dataclass
class Action:
    kind: str
    ok: bool
    detail: str
    ts: float = field(default_factory=now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ok": self.ok,
            "detail": self.detail,
            "ts": self.ts,
            "iso": util.iso(self.ts),
        }


@dataclass
class Response:
    mode: str
    actions: list[Action] = field(default_factory=list)
    snapshot: str = ""

    @property
    def acted(self) -> bool:
        return bool(self.actions)


# ------------------------------------------------------------------ forensics


def _copy_binary(pid: int, dest_dir: str) -> str | None:
    exe = f"/proc/{pid}/exe"
    try:
        target = os.readlink(exe)
    except OSError:
        return None
    name = target.rsplit("/", 1)[-1] or str(pid)
    out = os.path.join(dest_dir, f"exe-{pid}-{name}")
    try:
        shutil.copyfile(exe, out, follow_symlinks=True)
        os.chmod(out, 0o600)
    except OSError:
        return None
    return out


def snapshot(config, verdict: Verdict, label: str = "scan") -> str:
    """Capture everything that would be lost if we started killing things."""
    base = config.get("respond.snapshot_dir", "/var/lib/ward/snapshots")
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime())
    dest = os.path.join(base, f"{stamp}-{label}-s{verdict.score}")
    util.ensure_dir(dest, 0o700)

    # --- text evidence
    commands = {
        "ss-listen.txt": ["ss", "-tulpn"],
        "ss-all.txt": ["ss", "-tapn"],
        "processes.txt": ["ps", "-eo", "pid,ppid,uid,user,etimes,pcpu,pmem,args",
                          "--sort=-pcpu"],
        "nft-ruleset.txt": ["nft", "list", "ruleset"],
        "iptables-save.txt": ["iptables-save"],
        "sysctl.txt": ["sysctl", "-a"],
        "network-interfaces.txt": ["ip", "-d", "addr"],
        "network-routes.txt": ["ip", "route", "show", "table", "all"],
        "arp-neighbours.txt": ["ip", "neigh", "show"],
        "firewalld-zones.txt": ["firewall-cmd", "--list-all-zones"],
        "systemd-units.txt": ["systemctl", "list-units", "--all", "--no-pager"],
        "user-units.txt": ["systemctl", "--user", "list-units", "--all", "--no-pager"],
        "kernel-modules.txt": ["cat", "/proc/modules"],
        "open-files.txt": ["ls", "-l", "/proc/*/fd"],
    }
    for name, argv in commands.items():
        try:
            rc, out, err = run(argv, timeout=25)
            with open(os.path.join(dest, name), "w") as fh:
                fh.write(f"$ {' '.join(argv)}\n{out}\n{err}\n")
        except OSError:
            continue

    # --- structured findings
    with open(os.path.join(dest, "verdict.json"), "w") as fh:
        fh.write(util.canonical_json(verdict.to_dict()))

    # --- per-subject deep dive on the worst findings
    pids = sorted(
        {
            s["pid"]
            for f in verdict.findings
            for s in f.subjects
            if isinstance(s, dict) and isinstance(s.get("pid"), int)
        }
    )[:12]
    for pid in pids:
        pdir = os.path.join(dest, f"pid-{pid}")
        util.ensure_dir(pdir, 0o700)
        for name, src in (
            ("cmdline", f"/proc/{pid}/cmdline"),
            ("status", f"/proc/{pid}/status"),
            ("stat", f"/proc/{pid}/stat"),
            ("maps", f"/proc/{pid}/maps"),
            ("limits", f"/proc/{pid}/limits"),
            ("cgroup", f"/proc/{pid}/cgroup"),
            ("environ", f"/proc/{pid}/environ"),
        ):
            data = util.read_bytes(src, 1 << 18)
            if data:
                with open(os.path.join(pdir, name), "wb") as fh:
                    fh.write(data)
        try:
            os.symlink(f"/proc/{pid}/exe", os.path.join(pdir, "exe.link"))
        except OSError:
            pass
        if config.get("respond.forensics", True):
            _copy_binary(pid, pdir)
        rc, out, _ = run(["ls", "-l", f"/proc/{pid}/fd"], timeout=10)
        with open(os.path.join(pdir, "fds.txt"), "w") as fh:
            fh.write(out)

    # --- live packet capture: the money shot for a relay argument
    if config.get("respond.forensics", True) and util.is_root():
        pcap = os.path.join(dest, "capture.pcap")
        if not _tcpdump(pcap, seconds=15):
            with open(os.path.join(dest, "capture-note.txt"), "w") as fh:
                fh.write("no packet capture: tcpdump not installed\n")

    # --- manifest so the snapshot itself is provably complete
    entries = []
    for root, _dirs, files in os.walk(dest):
        for name in sorted(files):
            full = os.path.join(root, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            entries.append(
                f"{util.sha256_file(full)} {st.st_size} {os.path.relpath(full, dest)}"
            )
    with open(os.path.join(dest, "MANIFEST.sha256"), "w") as fh:
        fh.write("\n".join(sorted(entries)) + "\n")
    return dest


def _tcpdump(path: str, seconds: int = 15) -> bool:
    """Capture a short pcap. Degrades gracefully when tcpdump is absent."""
    if not shutil.which("tcpdump"):
        return False
    try:
        p = subprocess.run(
            ["timeout", str(seconds), "tcpdump", "-i", "any", "-s", "0", "-w", path,
             "-Z", "root"],
            capture_output=True, timeout=seconds + 8,
        )
        return p.returncode in (0, 124) and os.path.exists(path)
    except (OSError, subprocess.TimeoutExpired):
        return False


# ------------------------------------------------------------------ quarantine


def quarantine_cgroup(pid: int) -> tuple[bool, str]:
    """Move a process into a frozen cgroup so it cannot do more damage.

    Freezing beats killing when the goal is evidence: the sockets stay open and
    visible in ss output, but the process stops moving.
    """
    if not util.is_root():
        return False, "requires root"
    base = "/sys/fs/cgroup/ward-quarantine"
    try:
        os.makedirs(base, exist_ok=True)
    except OSError as exc:
        return False, f"cgroup mkdir failed: {exc}"
    target = os.path.join(base, str(pid))
    try:
        os.makedirs(target, exist_ok=True)
        with open(f"{target}/cgroup.procs", "w") as fh:
            fh.write(str(pid))
    except OSError as exc:
        return False, f"cgroup move failed: {exc}"
    for fname, val in (("cgroup.freeze", "1"),):
        try:
            with open(f"{target}/{fname}", "w") as fh:
                fh.write(val)
            return True, f"pid {pid} frozen in {target}"
        except OSError:
            pass
    return True, f"pid {pid} moved to {target} (freeze unavailable)"


def unfreeze_cgroup(pid: int) -> tuple[bool, str]:
    target = f"/sys/fs/cgroup/ward-quarantine/{pid}/cgroup.freeze"
    try:
        with open(target, "w") as fh:
            fh.write("0")
    except OSError as exc:
        return False, str(exc)
    return True, f"pid {pid} unfrozen"


def move_binary_to_quarantine(config, pid: int) -> tuple[bool, str]:
    """Revoke the binary while the process is still running.

    chmod 000 on the file removes the ability to exec a second copy; the
    running process keeps its mapped pages, which is what we want for forensics.
    """
    if not util.is_root():
        return False, "requires root"
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False, "cannot read exe"
    qdir = config.get("respond.quarantine_dir", "/var/lib/ward/quarantine")
    util.ensure_dir(qdir, 0o700)
    copy = os.path.join(qdir, f"{time.strftime('%Y%m%dT%H%M%S')}-{os.path.basename(exe)}")
    try:
        shutil.copyfile(exe, copy, follow_symlinks=True)
        os.chmod(exe, 0o000)
    except OSError as exc:
        return False, str(exc)
    return True, f"copied to {copy}, chmod 000 on {exe}"


# ------------------------------------------------------------------ terminate


def kill_pid(pid: int, grace: float = 3.0, dry_run: bool = False) -> tuple[bool, str]:
    if dry_run:
        return True, f"would kill {pid}"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True, f"pid {pid} already gone"
    except PermissionError:
        return False, f"pid {pid}: permission denied"
    deadline = now() + grace
    while now() < deadline:
        if not _alive(pid):
            return True, f"pid {pid} terminated on SIGTERM"
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True, f"pid {pid} gone before SIGKILL"
    except PermissionError:
        return False, f"pid {pid}: permission denied on SIGKILL"
    time.sleep(0.3)
    return (not _alive(pid)), f"pid {pid} SIGKILLed"


def _alive(pid: int) -> bool:
    return os.path.isdir(f"/proc/{pid}")


def kill_process_tree(pid: int, grace: float = 3.0, dry_run: bool = False) -> list[tuple[int, bool, str]]:
    children: dict[int, list[int]] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        raw = util.read_text(f"/proc/{entry.name}/stat", 4096)
        idx = raw.rfind(")")
        if idx < 0:
            continue
        tail = raw[idx + 2 :].split()
        if len(tail) > 1 and tail[1].isdigit():
            children.setdefault(int(tail[1]), []).append(int(entry.name))
    order: list[int] = []
    stack = [pid]
    while stack:
        cur = stack.pop()
        order.append(cur)
        stack.extend(children.get(cur, []))
    results = []
    for target in reversed(order):  # children first
        results.append((target, *kill_pid(target, grace, dry_run)))
    return results


# ------------------------------------------------------------------ lockdown


def lockdown(config, journal: harden.Journal | None = None,
             dry_run: bool = False) -> Response:
    """Maximum containment: nothing inbound, no forwarding, relay ports dead."""
    res = Response(mode="lockdown")
    if dry_run:
        res.actions.append(Action("lockdown-dry-run", True,
                                  "would apply full lockdown"))
        return res
    util.require_root("lockdown")

    ok, msg = firewall.quarantine_ports(sorted(signatures.RELAY_PORTS))
    res.actions.append(Action("quarantine-relay-ports", ok, msg))

    fw = config.section("firewall")
    saved = {
        "lan_allowlist": fw.get("lan_allowlist", []),
        "lan_allowlist_udp": fw.get("lan_allowlist_udp", []),
    }
    import copy

    strict = copy.deepcopy(fw)
    strict["lan_allowlist"] = []
    strict["lan_allowlist_udp"] = []
    strict["allow_mdns"] = False
    from .config import Config

    strict_cfg = Config({"firewall": strict}, ["lockdown"])
    ok, msg = firewall.apply(strict_cfg, persist=False)
    res.actions.append(Action("firewall-strict", ok, msg))
    if journal:
        journal.record("lockdown-applied", "inet ward", saved,
                       {"lan_allowlist": [], "lan_allowlist_udp": []})

    for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
                "net.ipv4.conf.all.send_redirects"):
        rc, out, _ = run(["sysctl", "-n", key], timeout=5)
        before = out.strip()
        ok, msg = harden.apply_sysctl(key, "0")
        res.actions.append(Action(f"sysctl:{key}", ok, f"{before} -> 0 ({msg})"))
        if journal:
            journal.record("lockdown-sysctl", key, before, "0")
    return res


# ------------------------------------------------------------------ dispatch


def _target_pids(verdict: Verdict, config) -> list[int]:
    """Which processes are worth acting on?

    Never touch a protected binary, never touch WARD itself, and never touch a
    PID the finding does not actually implicate.
    """
    pids: list[int] = []
    for finding in verdict.findings:
        if finding.score < config.get("respond.contain_score", 70):
            continue
        rule = finding.rule
        if rule not in (
            "R01-relay-binary", "R02-binary-protocol-markers", "R05-connection-fanout",
            "R06-resi-vendor", "R12-ld-preload", "R12-deleted-exe",
            "R11-new-relay-process",
        ):
            continue
        for subject in finding.subjects:
            pid = subject.get("pid") if isinstance(subject, dict) else None
            if not isinstance(pid, int) or pid in pids:
                continue
            if not _alive(pid):
                continue
            base = ""
            try:
                base = os.path.basename(os.readlink(f"/proc/{pid}/exe"))
            except OSError:
                base = util.read_text(f"/proc/{pid}/comm", 64).strip()
            if signatures.is_protected(base) or pid in (os.getpid(), os.getppid()):
                continue
            pids.append(pid)
    return pids


def respond(config, verdict: Verdict, log=None, dry_run: bool = False) -> Response:
    """The decision point. Every action taken is returned, not hidden."""
    cfg = config.section("respond")
    mode = cfg.get("mode", "observe")
    res = Response(mode=mode)
    if mode == "observe" and not dry_run:
        return res

    snap_label = mode if mode != "observe" else "scan"
    if cfg.get("forensics", True):
        try:
            res.snapshot = snapshot(config, verdict, snap_label)
            res.actions.append(
                Action("snapshot", True, res.snapshot)
            )
        except OSError as exc:
            res.actions.append(Action("snapshot", False, str(exc)))

    pids = _target_pids(verdict, config)
    ports = sorted(
        {
            s["port"]
            for f in verdict.findings
            if f.rule in ("R03-world-listener", "R04-world-udp-listener", "R11-new-world-listener")
            for s in f.subjects
            if isinstance(s, dict) and isinstance(s.get("port"), int)
        }
    )

    if mode in ("contain", "kill", "lockdown") and ports:
        ok, msg = firewall.quarantine_ports(ports)
        res.actions.append(Action("port-quarantine", ok, msg))

    for pid in pids:
        if cfg.get("cgroup_quarantine", True) and mode in ("contain", "lockdown"):
            ok, msg = quarantine_cgroup(pid)
            res.actions.append(Action(f"freeze:{pid}", ok, msg))
        ok, msg = move_binary_to_quarantine(config, pid)
        res.actions.append(Action(f"revoke-exec:{pid}", ok, msg))

    if mode in ("kill", "lockdown"):
        auto = cfg.get("auto_kill", False)
        for pid in pids:
            if not auto and mode != "lockdown":
                res.actions.append(
                    Action(f"kill-skipped:{pid}", True,
                           "auto_kill is off; run 'ward kill' to confirm")
                )
                continue
            for target, ok, msg in kill_process_tree(pid, cfg.get("kill_grace_seconds", 3.0)):
                res.actions.append(Action(f"kill:{target}", ok, msg))

    if mode == "lockdown" or (cfg.get("auto_lockdown", False)
                              and verdict.score >= cfg.get("lockdown_score", 95)):
        lock = lockdown(config, dry_run=dry_run)
        res.actions.extend(lock.actions)

    if cfg.get("notify", True) and verdict.score >= cfg.get("notify_threshold", 60):
        _notify(verdict, res)
    if log is not None and res.actions:
        log.emit("response", {
            "mode": mode,
            "score": verdict.score,
            "snapshot": res.snapshot,
            "actions": [a.to_dict() for a in res.actions],
        }, score=verdict.score, rule="respond", title=f"response in {mode} mode")
    return res


def _notify(verdict: Verdict, res: Response) -> None:
    lines = [f"WARD: score {verdict.score} ({verdict.severity})"]
    lines += [f"  - {r}" for r in verdict.reasons[:5]]
    if res.snapshot:
        lines.append(f"  evidence: {res.snapshot}")
    body = "\n".join(lines)
    if shutil.which("notify-send"):
        run(["notify-send", "--urgency=critical", "WARD: possible relay detected", body],
            timeout=6)
    run(["logger", "-p", "authpriv.crit", "-t", "ward", "--", body], timeout=6)


# ------------------------------------------------------------------ tripwire


def tripwire(config, heartbeat_path: str, max_age: float = 90.0) -> Action:
    """If the daemon's heartbeat is stale, the machine may be unattended.

    Runs from a systemd timer so that killing the daemon does not silence the
    defender. In lockdown mode it re-applies the lockdown automatically.
    """
    try:
        st = os.stat(heartbeat_path)
        age = now() - st.st_mtime
    except OSError:
        age = 1e9
    if age <= max_age:
        return Action("tripwire", True, f"heartbeat {age:.0f}s old")
    if config.get("respond.mode") != "lockdown" or not config.get("respond.auto_lockdown"):
        return Action(
            "tripwire", True,
            f"heartbeat stale ({age:.0f}s) -- lockdown mode not armed, no action",
        )
    res = lockdown(config)
    return Action("tripwire", True, f"heartbeat stale ({age:.0f}s); " + "; ".join(
        a.detail for a in res.actions[:3]
    ))
