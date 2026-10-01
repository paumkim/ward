"""The WARD daemon: scan on an interval, act on the verdict, keep a heartbeat.

Two invariants that matter more than the code:
  * The heartbeat file is touched every cycle, and it is the input to the
    systemd tripwire. If an attacker kills the daemon, the tripwire notices.
  * Self-integrity: the daemon hashes its own code and its own config on start
    and every N cycles. Someone who edits WARD to make it quiet has to edit
    the hash check too, and the check lives in a different file.
"""

from __future__ import annotations

import os
import signal
import time
from dataclasses import dataclass, field
from typing import Any

from . import detect, firewall, harden, observe, respond, util
from .config import Config
from .events import EventLog
from .util import now

HEARTBEAT = "/run/ward/heartbeat"
STATE = "/run/ward/state.json"
SELF_HASHES = "/var/lib/ward/self-hashes.json"
INTEGRITY_STATE = "/var/lib/ward/integrity.json"


@dataclass
class Runtime:
    config: Config
    log: EventLog
    history: dict[int, dict[str, Any]] = field(default_factory=dict)
    last_verdict: dict[str, Any] = field(default_factory=dict)
    last_integrity: float = 0.0
    last_process_scan: float = 0.0
    last_prune: float = 0.0
    #: What the last cycle observed about the firewall and forwarding. The
    #: daemon runs as root and can read netlink; a user running `ward status`
    #: cannot, so this is published into the world-readable state file for it.
    last_host: dict[str, Any] = field(default_factory=dict)
    #: Consecutive cycles that raised. A defender that has stopped working must
    #: never present a clean verdict, so this is published and surfaced.
    cycle_errors: int = 0
    last_ok_ts: float = 0.0
    self_check_cycle: int = 0
    running: bool = True
    start_ts: float = field(default_factory=now)

    # ------------------------------------------------------------ persistence

    def _load_json(self, path: str, default: Any) -> Any:
        text = util.read_text(path, 8 << 20)
        if not text:
            return default
        try:
            import json

            return json.loads(text)
        except ValueError:
            return default

    def load_baseline(self) -> dict:
        data = self._load_json(self.config.get("baseline.file"), {}) or {}
        if data and data.get("schema") != observe.BASELINE_SCHEMA:
            self.log.emit(
                "baseline-reset",
                {"stored_schema": data.get("schema"),
                 "current_schema": observe.BASELINE_SCHEMA},
                title="baseline schema changed; re-learning instead of "
                      "reporting every listener as new",
            )
            return {}
        return data

    def save_baseline(self, data: dict) -> None:
        try:
            util.atomic_write(
                self.config.get("baseline.file"),
                util.canonical_json(data),
                0o600,
            )
        except OSError as exc:
            self.log.emit("error", {"what": "baseline write failed", "err": str(exc)})

    def load_integrity(self) -> dict:
        return self._load_json(self.integrity_path, {}) or {}

    def save_integrity(self, data: dict) -> None:
        try:
            util.atomic_write(
                self.integrity_path, util.canonical_json(data), 0o600
            )
        except OSError:
            pass

    @property
    def heartbeat_path(self) -> str:
        return self.config.get("daemon.heartbeat", HEARTBEAT)

    @property
    def state_path(self) -> str:
        return self.config.get("daemon.state", STATE)

    @property
    def self_hashes_path(self) -> str:
        return self.config.get("daemon.self_hashes", SELF_HASHES)

    @property
    def integrity_path(self) -> str:
        return self.config.get("daemon.integrity_state", INTEGRITY_STATE)

    def state(self) -> dict:
        return self._load_json(self.state_path, {})

    def write_state(self) -> None:
        try:
            util.atomic_write(
                self.state_path,
                util.canonical_json(
                    {
                        "pid": os.getpid(),
                        "start": self.start_ts,
                        "ts": now(),
                        "iso": util.iso(),
                        "score": self.last_verdict.get("score", 0),
                        "severity": self.last_verdict.get("severity", "info"),
                        "reasons": self.last_verdict.get("reasons", [])[:8],
                        "mode": self.config.get("respond.mode"),
                        "heartbeat": self.heartbeat_path,
                        "log": self.log.path,
                        "log_head": self.log.head,
                        "log_seq": self.log.seq,
                        "dropped_events": self.log.dropped,
                        "host": self.last_host,
                        "cycle_errors": self.cycle_errors,
                        "last_ok": self.last_ok_ts or None,
                    }
                ),
                0o644,
            )
        except OSError as exc:
            self.log.emit("error", {"what": "state write failed", "err": str(exc)})

    # ------------------------------------------------------------ heartbeat

    def beat(self) -> None:
        try:
            path = self.heartbeat_path
            util.ensure_dir(os.path.dirname(path) or ".", 0o755)
            with open(path, "w") as fh:
                fh.write(f"{now():.3f} {os.getpid()} {self.last_verdict.get('score', 0)}\n")
        except OSError:
            pass

    # ------------------------------------------------------------ self check

    def self_check(self) -> None:
        """Hash our own code. Alerts on any change after install."""
        import json

        paths: list[str] = []
        here = os.path.dirname(os.path.abspath(__file__))
        for name in sorted(os.listdir(here)):
            if name.endswith(".py"):
                paths.append(os.path.join(here, name))
        for extra in ("/usr/local/bin/ward", "/usr/local/lib/ward/config.py"):
            if os.path.isfile(extra):
                paths.append(extra)
        current = {p: util.sha256_file(p) for p in paths if os.path.isfile(p)}
        try:
            with open(self.self_hashes_path) as fh:
                stored = json.load(fh)
        except (OSError, ValueError):
            stored = None
        if stored:
            changed = [
                p for p, h in current.items()
                if stored.get(p) not in (None, h)
            ]
            missing = [p for p in stored if p not in current]
            if changed or missing:
                self.log.emit(
                    "self-integrity",
                    {"changed": changed, "missing": missing},
                    score=70,
                    rule="self-integrity",
                    title="WARD's own files changed on disk",
                )
        else:
            try:
                util.atomic_write(
                    self.self_hashes_path, json.dumps(current, indent=1), 0o600
                )
            except OSError:
                pass

    def record_self(self) -> int:
        """Record hashes of our own files. Returns the count, or -1 on failure."""
        import json

        here = os.path.dirname(os.path.abspath(__file__))
        current = {
            os.path.join(here, n): util.sha256_file(os.path.join(here, n))
            for n in sorted(os.listdir(here))
            if n.endswith(".py")
        }
        for extra in ("/usr/local/bin/ward",):
            if os.path.isfile(extra):
                current[extra] = util.sha256_file(extra)
        try:
            util.atomic_write(
                self.self_hashes_path, json.dumps(current, indent=1), 0o600
            )
            return len(current)
        except OSError as exc:
            self.log.emit(
                "error",
                {"what": "could not record self-hashes", "err": str(exc)},
                title="seal failed",
            )
            return -1

    # ------------------------------------------------------------ baseline

    def ensure_baseline(self) -> None:
        if not self.config.get("baseline.learn_on_first_run", True):
            return
        if self.load_baseline():
            return
        from . import observe

        listeners, _ = observe.observe_sockets()
        procs = observe.observe_processes(include_content_scan=False)
        state = observe.baseline_state({}, procs, listeners)
        state["learned_at"] = util.iso()
        state["learned_by"] = "ward daemon first run"
        self.save_baseline(state)
        files = observe.hash_manifest(
            list(self.config.get("detect.integrity_paths", []))
            + [str(p) for p in self.config.get("detect.integrity_user_paths", [])]
        )
        dirs = observe.listdir_snapshot(
            self.config.get("detect.watch_persistence_paths", [])
        )
        self.save_integrity({"files": files, "dirs": dirs, "at": util.iso()})
        self.log.emit(
            "baseline",
            {
                "processes": len(state["processes"]),
                "listeners": len(state["listeners"]),
                "files": len(files),
                "dirs": len(dirs),
            },
            title="baseline recorded",
        )

    # ------------------------------------------------------------ iface bytes

    def host_bytes(self) -> dict[str, int]:
        rx = tx = 0
        for path in ("/proc/net/dev",):
            for line in util.read_text(path, 1 << 16).splitlines()[2:]:
                if ":" not in line:
                    continue
                name, _, rest = line.partition(":")
                if name.strip() == "lo":
                    continue
                cols = rest.split()
                if len(cols) >= 9:
                    rx += int(cols[0])
                    tx += int(cols[8])
        return {"rx": rx, "tx": tx}

    # ------------------------------------------------------------ one cycle

    def cycle(self) -> dict[str, Any]:
        interval = float(self.config.get("detect.interval_seconds", 3.0))
        integrity_every = float(self.config.get("detect.integrity_interval_seconds", 900.0))
        do_integrity = (now() - self.last_integrity) >= integrity_every

        verdict = detect.scan(
            self.config,
            history=self.history,
            stored_baseline=self.load_baseline(),
            stored_integrity=self.load_integrity() if do_integrity else None,
            host_bytes=self.host_bytes(),
            do_integrity=do_integrity,
        )
        if do_integrity:
            self.last_integrity = now()
            self.save_integrity(
                {
                    "files": observe.hash_manifest(
                        list(self.config.get("detect.integrity_paths", []))
                        + [str(p) for p in self.config.get("detect.integrity_user_paths", [])]
                    ),
                    "dirs": observe.listdir_snapshot(
                        self.config.get("detect.watch_persistence_paths", [])
                    ),
                    "at": util.iso(),
                }
            )

        prev_score = self.last_verdict.get("score", 0)
        self.last_verdict = verdict.to_dict()
        host = observe.observe_host()
        self.last_host = {
            "checked": now(),
            "firewall_table": host.nft_table_present,
            "ip_forward": host.ip_forward,
            "ipv6_forwarding": host.ipv6_forwarding,
            "lan_iface": host.lan_iface,
        }

        escalate = verdict.score >= self.config.get("respond.contain_score", 70)
        if escalate and prev_score < self.config.get("respond.contain_score", 70):
            self.log.emit(
                "alert",
                {
                    "score": verdict.score,
                    "severity": verdict.severity,
                    "reasons": verdict.reasons,
                    "rules": sorted({f.rule for f in verdict.findings[:10]}),
                },
                score=verdict.score,
                rule="escalation",
                title=f"risk score {verdict.score} ({verdict.severity})",
            )
        elif verdict.score >= 60:
            # Log the top finding, rate-limited by the log itself.
            top = verdict.findings[0] if verdict.findings else None
            if top:
                self.log.emit(
                    "finding",
                    top.to_dict(),
                    score=top.score,
                    rule=top.rule,
                    title=top.title,
                )

        res = respond.respond(self.config, verdict, log=self.log)
        self.state_response = res
        self.cycle_errors = 0
        self.last_ok_ts = now()

        self.write_state()
        self.beat()

        # Periodic housekeeping
        if (now() - self.last_prune) > 3600:
            self.last_prune = now()
            self.log.prune(int(self.config.get("log.keep_days", 90)))
            self.self_check_cycle += 1
            if self.self_check_cycle % 12 == 1:
                self.self_check()
        return self.last_verdict

    # ------------------------------------------------------------ run loop

    def run(self, max_cycles: int | None = None) -> None:
        try:
            util.ensure_dir(self.config.get("detect.process_cwd", "/var/lib/ward"), 0o700)
        except OSError as exc:
            self.log.emit("error", {"what": "process_cwd unavailable", "err": str(exc)})
        self.ensure_baseline()
        self.beat()
        self.log.emit(
            "start",
            {
                "pid": os.getpid(),
                "config": self.config.sources,
                "mode": self.config.get("respond.mode"),
                "log_head": self.log.head,
            },
            title="WARD daemon started",
        )
        cycles = 0
        while self.running:
            started = now()
            try:
                self.cycle()
            except Exception as exc:  # never let one bad cycle kill the daemon
                self.cycle_errors += 1
                self.log.emit(
                    "error",
                    {"err": repr(exc), "type": type(exc).__name__,
                     "consecutive": self.cycle_errors},
                    title="scan cycle raised",
                )
                if self.cycle_errors in (1, 5, 60):
                    # Publishing state on the error path is what lets `ward
                    # status` say the defender is broken instead of showing the
                    # last good score as if it were current.
                    self.write_state()
                    self.beat()
            cycles += 1
            if max_cycles and cycles >= max_cycles:
                break
            # Sleep the remainder of the interval, waking early on a signal.
            interval = float(self.config.get("detect.interval_seconds", 3.0))
            remaining = interval - (now() - started)
            deadline = now() + max(0.1, remaining)
            while self.running and now() < deadline:
                time.sleep(min(0.25, max(0.05, deadline - now())))
        self.log.emit("stop", {"cycles": cycles}, title="WARD daemon stopped")


# ------------------------------------------------------------------ factory


def make_runtime(config: Config | None = None) -> Runtime:
    cfg = config or load_default_config()
    logcfg = cfg.section("log")
    log = EventLog(
        logcfg.get("file", "/var/lib/ward/events.jsonl"),
        mode=logcfg.get("mode", "hashchain"),
        rotate_bytes=int(logcfg.get("rotate_bytes", 32 << 20)),
        max_per_minute=int(logcfg.get("max_events_per_minute", 240)),
    )
    return Runtime(config=cfg, log=log)


def load_default_config() -> Config:
    from .config import load

    return load()


def install_signal_handlers(rt: Runtime) -> None:
    def handler(signum, _frame):
        rt.running = False
        rt.log.emit("signal", {"signal": signum}, title="shutdown signal")

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError):
            pass
