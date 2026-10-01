"""WARD configuration: layered defaults, optional TOML overlay, env overrides.

Layering (later wins):
    built-in defaults  ->  /etc/ward/ward.toml  ->  ~/.config/ward/ward.toml
                        ->  WARD_* env vars

The defaults are deliberately strict. Every knob exists so the operator can
loosen one specific thing without weakening the whole system.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:  # stdlib since 3.11, present on this host
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

ETC_CONFIG = "/etc/ward/ward.toml"
USER_CONFIG = str(Path.home() / ".config" / "ward" / "ward.toml")
ROOT = "/var/lib/ward"
RUN = "/run/ward"

DEFAULTS: dict[str, Any] = {
    "identity": {
        # Interfaces considered "the outside world". Anything listening on a
        # non-loopback address on these is reachable by third parties.
        "lan_ifaces": ["wlan0", "eth0", "enp0s31f6", "wlp2s0"],
        "trusted_lan_cidr": "192.168.0.0/16",
    },
    "firewall": {
        # WARD owns its own nft table. firewalld may keep running; we insert a
        # stricter table at a lower hook priority so we are evaluated first.
        "table": "ward",
        "family": "inet",
        "default_input": "drop",
        "default_forward": "drop",  # no transit, ever
        "default_output": "accept",
        # Established traffic always survives; ICMP is needed for PMTU and for
        # traceroute you may legitimately run.
        "allow_icmp": True,
        "allow_dhcp": True,
        "allow_loopback": True,
        "allow_mdns": True,
        # Ports that may accept inbound connections from the trusted LAN.
        # This is the single most important list in the whole file: an entry
        # here is a hole in the default-deny wall, so keep it tiny.
        "lan_allowlist": [1716],  # KDE Connect
        "lan_allowlist_udp": [1716],
        "drop_lanmr": [5355],  # LLMNR: spoofable, no legitimate need on wifi
        "drop_ssdp": [1900],  # UPnP: the other half of every port-forward attack
    },
    "harden": {
        "ip_forward": False,  # set net.ipv4.ip_forward=0, quarantine stale files
        # 99-tailscale.conf was found setting ip_forward=1 with tailscale not
        # installed. Quarantining it is safe; the operator can undo.
        "quarantine_sysctl_files": True,
        "llmnr": False,  # systemd-resolved LLMNR=no
    },
    "detect": {
        "interval_seconds": 3.0,
        # Subprocess-backed rules (firewall-cmd) and journal reads are cached
        # for this long. They answer "what is the machine configured like",
        # which changes on a human timescale, not a 3-second one.
        "external_interval_seconds": 300,
        "integrity_interval_seconds": 900.0,
        "process_cwd": "/var/lib/ward",
        # Per-process outbound fan-out, the strongest behavioural tell that a
        # process is relaying for strangers.
        # Listener rules
        # Relay-bandwidth heuristics
        "integrity_paths": [
            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/hosts", "/etc/resolv.conf",
            "/etc/tor/torrc", "/etc/pacman.conf", "/etc/pacman.d/mirrorlist",
            "/etc/nftables.conf", "/etc/firewalld/firewalld.conf",
        ],
        "integrity_user_paths": [
            "~/.ssh/authorized_keys", "~/.ssh/config",
            "~/.bashrc", "~/.zshrc", "~/.profile",
            "~/.config/ward/ward.toml",
        ],
        "watch_persistence": True,
        "watch_persistence_paths": [
            "~/.config/systemd/user", "~/.local/bin", "/etc/systemd/system",
            "/etc/cron.d", "/etc/crontab", "/var/spool/cron",
            "/usr/local/bin", "/usr/local/sbin", "/opt",
        ],
    },
    "respond": {
        "mode": "observe",  # observe | contain | kill | lockdown
        # Score at or above which we act. 0-100.
        "contain_score": 70,
        "auto_kill": False,  # deliberate opt-in; see README before enabling
        "auto_lockdown": False,
        "forensics": True,
        "quarantine_dir": "/var/lib/ward/quarantine/bin",
        "snapshot_dir": "/var/lib/ward/snapshots",
        "kill_grace_seconds": 3.0,
        "cgroup_quarantine": True,
        "notify": True,
        "notify_threshold": 60,
    },
    "baseline": {
        # First run records the current process/socket inventory as known-good.
        # Anything that appears later is a diff, not a guess.
        "learn_on_first_run": True,
        "file": "/var/lib/ward/baseline.json",
    },
    "daemon": {
        # The tripwire's only input. If this file goes stale, containment is
        # re-applied by a timer-driven unit the daemon cannot stop.
        "heartbeat": "/run/ward/heartbeat",
        "state": "/run/ward/state.json",
        "self_hashes": "/var/lib/ward/self-hashes.json",
        "integrity_state": "/var/lib/ward/integrity.json",
    },
    "log": {
        "file": "/var/lib/ward/events.jsonl",
        "mode": "hashchain",  # hashchain | plain
        "rotate_bytes": 32 * 1024 * 1024,
        "keep_days": 90,
        "max_events_per_minute": 240,
    },
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _coerce(value: str, like: Any) -> Any:
    if isinstance(like, bool):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(like, int) and not isinstance(like, bool):
        try:
            return int(value)
        except ValueError:
            return like
    if isinstance(like, float):
        try:
            return float(value)
        except ValueError:
            return like
    if isinstance(like, list):
        return [p.strip() for p in value.split(",") if p.strip()]
    return value


def _env_overlay(cfg: dict) -> None:
    """WARD_LOG_FILE, WARD_MODE, WARD_INTERVAL... -> nested config values.

    Path form uses '_' as the separator, list sections use '__'.
    """
    for key, raw in os.environ.items():
        if not key.startswith("WARD_"):
            continue
        path = key[5:].lower().split("__")
        node = cfg
        for part in path[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                return
        leaf = path[-1]
        if leaf in node:
            node[leaf] = _coerce(raw, node[leaf])


def _load_file(path: str) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    if tomllib is None:
        return {}
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (OSError, ValueError):
        return {}


VALID_MODES = ("observe", "contain", "kill", "lockdown")


def normalise_mode(raw: Any) -> str:
    """Coerce a response mode to a valid one, failing closed.

    This function exists because of a real incident: `respond()` gated its
    destructive actions on `mode == "observe"`, so any typo ("Observe",
    "observ", "Contian", a trailing space from a TOML edit) fell through to
    `chmod 000` on the target binary. A defence tool must never do more than
    asked because of a spelling mistake, so anything unrecognised becomes
    `observe`.
    """
    text = str(raw or "").strip().lower()
    if text in VALID_MODES:
        return text
    return "observe"


class Config:
    def __init__(self, data: dict[str, Any], sources: list[str]):
        self.data = data
        self.sources = sources

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> dict:
        val = self.get(name, {})
        return val if isinstance(val, dict) else {}

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Config {self.sources}>"


def load(path: str | None = None) -> Config:
    data = DEFAULTS
    sources = ["defaults"]
    for candidate in ([path] if path else [ETC_CONFIG, USER_CONFIG]):
        if not candidate:
            continue
        overlay = _load_file(candidate)
        if overlay:
            data = _deep_merge(data, overlay)
            sources.append(candidate)
    _env_overlay(data)
    return Config(data, sources)
