"""Detection rules and risk scoring.

Design rules, in priority order:
  1. A process that is provably relay software is bad on its own.
  2. A process that *behaves* like a relay is bad, even if it is renamed.
  3. A machine that is *configured* to relay (forwarding, NAT, ss listener,
     vendor config) is bad even with no traffic yet -- config is the tell.
  4. Unexpected change is suspicious; unexpected change plus any of the above
     is an incident.

Each rule returns Finding objects. `scan()` aggregates them into one verdict.
Scores are additive within a rule-group and capped, so ten weak signals cannot
out-vote one strong signal, but two strong signals do compound.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from . import observe, signatures, util
from .observe import Proc, Socket
from .util import now

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    title: str
    score: int
    severity: str
    detail: dict[str, Any] = field(default_factory=dict)
    subjects: list[dict] = field(default_factory=list)  # pids, ports, paths
    ts: float = field(default_factory=now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "title": self.title,
            "score": self.score,
            "severity": self.severity,
            "detail": self.detail,
            "subjects": self.subjects,
            "ts": self.ts,
            "iso": util.iso(self.ts),
        }


def _sev(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def finding(
    rule: str,
    title: str,
    score: int,
    detail: dict[str, Any] | None = None,
    subjects: list[dict] | None = None,
    severity: str | None = None,
) -> Finding:
    """Build a Finding, deriving severity from the score.

    Every rule used to hand-write severity alongside score, which is _sev()
    computed twice and a standing invitation to the two drifting apart. Pass
    `severity` only to override, and only when the score is not the whole story.
    """
    return Finding(
        rule=rule,
        title=title,
        score=score,
        severity=severity or _sev(score),
        detail=detail or {},
        subjects=subjects or [],
    )


# ------------------------------------------------------------------ R01 exe


def rule_relay_binary(procs: list[Proc]) -> list[Finding]:
    """R01: a known relay/proxy/residential-network binary is running."""
    out: list[Finding] = []
    for proc in procs:
        # A single signature at or above 80 is decisive. Below that, two
        # independent signatures on the same process corroborate each other.
        # A magic threshold alone made eight of the thirteen cmdline rules
        # permanently inert, which meant the cmdline layer contributed nothing
        # for exactly the dual-use tools it was written for.
        strong = [h for h in proc.sig_hits if h.get("score", 0) >= 80]
        independent = {h["name"] for h in proc.sig_hits if h.get("score", 0) >= 55}
        corroborated = len(independent) >= 2
        if not strong and not corroborated:
            continue
        listening_ext = [s for s in proc.listeners if s.world_reachable]
        best = max(h.get("score", 0) for h in proc.sig_hits)
        score = best + (10 if corroborated and best < 80 else 0)
        if listening_ext:
            score = min(100, score + 10)
        out.append(
            Finding(
                rule="R01-relay-binary",
                title=f"relay software running: {proc.exe_base} (pid {proc.pid})",
                score=score,
                severity=_sev(score),
                detail={
                    "exe": proc.exe,
                    "cmdline": util.truncate(proc.cmdline, 300),
                    "hits": proc.sig_hits,
                    "corroborated": corroborated,
                    "listening": [s.key for s in proc.listeners],
                    "world_reachable": [s.key for s in listening_ext],
                    "cwd": proc.cwd,
                    "uid": proc.uid,
                },
                subjects=[{"pid": proc.pid}, {"exe": proc.exe}],
            )
        )
    return out


# ------------------------------------------------------------------ R02 content


def rule_binary_content(procs: list[Proc]) -> list[Finding]:
    """R02: the executable itself contains SOCKS/HTTP-proxy/vendor markers."""
    out: list[Finding] = []
    for proc in procs:
        if not proc.content_hits:
            continue
        score = min(95, max(h[1] for h in proc.content_hits) + 10 * (len(proc.content_hits) - 1))
        hits = [{"name": n, "score": s, "why": w} for n, s, w in proc.content_hits]
        out.append(
            Finding(
                rule="R02-binary-protocol-markers",
                title=f"proxy protocol markers inside {proc.exe_base} (pid {proc.pid})",
                score=score,
                severity=_sev(score),
                detail={"exe": proc.exe, "hits": hits[:8]},
                subjects=[{"pid": proc.pid}, {"exe": proc.exe}],
            )
        )
    return out


# ------------------------------------------------------------------ R03 listeners


def rule_world_listeners(listeners: list[Socket], allow_lan: set[tuple[str, int]]) -> list[Finding]:
    """R03: something is reachable from the network that should not be.

    A world-bound SOCKS/HTTP port is the single strongest indicator that this
    machine is being sold as a proxy. A world-bound non-proxy port is still
    worth flagging -- it is either a mistake or the front door.
    """
    out: list[Finding] = []
    for sock in listeners:
        if not sock.world_reachable:
            continue
        if not sock.proto.startswith("tcp"):
            continue  # UDP listeners are covered by R04
        port = sock.local_port
        # tcp6 sockets are the same service as their tcp counterparts; a v4
        # allowlist entry has to cover [::]:port too or it protects nothing.
        if ("tcp", port) in allow_lan or ("tcp6", port) in allow_lan:
            continue
        is_relay = port in signatures.RELAY_PORTS
        # 5355/5353 are responders, not doors: they get their own lower score
        # because the fix is hardening, not suspicion.
        is_responder = port in (53, 5353, 5355)
        if is_responder:
            base = 25
        elif is_relay:
            base = 55
        else:
            base = 30
        if sock.wildcard_bound:
            base += 15  # 0.0.0.0 / :: is worse than LAN-IP-bound
        out.append(
            Finding(
                rule="R03-world-listener",
                title=(
                    f"network-reachable listener {sock.proto} {sock.local}:{port}"
                    + (" (known relay port)" if is_relay else "")
                    + (" (name responder)" if is_responder else "")
                ),
                score=min(95, base),
                severity=_sev(base),
                detail={
                    "proto": sock.proto,
                    "local": sock.local,
                    "port": port,
                    "wildcard": sock.wildcard_bound,
                    "relay_port": is_relay,
                    "responder_port": is_responder,
                    "exe": sock.exe,
                    "cmdline": util.truncate(sock.cmdline, 300),
                    "pid": sock.pid,
                },
                subjects=[{"port": port}, {"pid": sock.pid}],
            )
        )
    return out


# ------------------------------------------------------------------ R04 udp


def rule_udp_relay(listeners: list[Socket]) -> list[Finding]:
    """R04: UDP is how DNS amplification relays and SOCKS-over-UDP hide."""
    out: list[Finding] = []
    for sock in listeners:
        if sock.proto.startswith("udp") and sock.world_reachable:
            if sock.local_port in (53, 67, 68, 123, 546, 547, 1900, 5353, 5355):
                continue  # handled by hardening / normal infra
            score = 40 if sock.local_port in signatures.RELAY_PORTS else 25
            out.append(
                Finding(
                    rule="R04-world-udp-listener",
                    title=f"network-reachable UDP listener on {sock.local}:{sock.local_port}",
                    score=score,
                    severity=_sev(score),
                    detail={"proto": sock.proto, "port": sock.local_port, "exe": sock.exe},
                    subjects=[{"port": sock.local_port}, {"pid": sock.pid}],
                )
            )
    return out


# ------------------------------------------------------------------ R05 fan-out


def rule_connection_fanout(
    procs: list[Proc], history: dict[int, dict[str, Any]]
) -> list[Finding]:
    """R05: one process, many unrelated remote IPs.

    This is the behavioural signature of a proxy and is the rule that catches
    renamed binaries. Browsers and system services are excluded by a fan-out
    budget; a python3 or a no-name binary holding 60 sockets to 25 different
    /16s is not browsing.
    """
    out: list[Finding] = []
    for proc in procs:
        if proc.protected or not proc.conns:
            continue
        if len(procs) and proc.exe_base in _HIGH_FANOUT_OK:
            budget = 400
        else:
            budget = 60
        est = [s for s in proc.conns if s.state == "ESTABLISHED"]
        if len(est) < min(budget, 25):
            continue
        distinct = {s.remote for s in est}
        nets = {util.net16(s) for s in distinct}
        ports = {s.remote_port for s in est}
        if len(distinct) < 25 or len(nets) < 8:
            continue
        if proc.exe_base in _HIGH_FANOUT_OK and len(distinct) < 400:
            continue
        # Persist across scans: relay software keeps the shape, one sample may
        # just be a burst of downloads.
        prev = history.get(proc.pid, {})
        history[proc.pid] = {
            "distinct": len(distinct),
            "nets": len(nets),
            "seen": now(),
            "exe": proc.exe,
        }
        score = min(
            92,
            40
            + int(len(distinct) / 5)
            + int(len(nets))
            + (20 if prev else 0)
            + (10 if len(ports) > 20 else 0),
        )
        out.append(
            Finding(
                rule="R05-connection-fanout",
                title=(
                    f"{proc.exe_base} (pid {proc.pid}) holds {len(est)} connections "
                    f"to {len(distinct)} IPs across {len(nets)} /16s"
                ),
                score=score,
                severity=_sev(score),
                detail={
                    "established": len(est),
                    "distinct_remote_ips": len(distinct),
                    "distinct_net16s": sorted(nets)[:24],
                    "distinct_remote_ports": sorted(ports)[:24],
                    "exe": proc.exe,
                    "cmdline": util.truncate(proc.cmdline, 300),
                    "persisted": bool(prev),
                    "sample_peers": sorted(distinct)[:20],
                },
                subjects=[{"pid": proc.pid}, {"exe": proc.exe}],
            )
        )
    return out


_HIGH_FANOUT_OK = {
    "firefox", "librewolf", "chrome", "chromium", "brave", "opera", "vivaldi",
    "firefox-bin", "electron", "code", "opencode", "term", "brave-bin",
    "gnome-shell", "plasmashell", "kwin_wayland", "Xwayland", "updatedb",
    "plocate", "pip", "uv", "bun", "node", "deno", "cargo", "rustc", "go",
    "docker", "podman", "flatpak", "zypak", "steam", "lutris", "heroic",
    "curl", "wget", "rsync", "scp", "sftp", "git", "borg", "restic",
    # P2P file transfer: a seeder holding 25+ peers across many /16s is
    # ordinary use, not a relay. Freezing one of these would be a disaster.
    "qbittorrent-nox", "qbittorrent", "transmission-daemon", "transmission-cli",
    "transmission-remote", "deluge", "deluge-web", "deluged", "rtorrent",
    "aria2c", "syncthing", "rclone", "restic", "restic_1", "zsync",
    "nicotine", "nzbget", "sabnzbd", "hydra", "king Torrent", "ktorrent",
    # infra that legitimately talks to many hosts at once
    "docker", "podman", "containerd", "podman-healthcheck", "kubelet",
    "systemd-resolved", "resolved", "dhclient", "dhcpcd", "wpa_supplicant",
    "NetworkManager", "nm-openvpn", "nm-online", "keepalived",
}


# ------------------------------------------------------------------ R06 relay cfg


def rule_vendor_text(procs: list[Proc], host: observe.HostState) -> list[Finding]:
    """R06: residential-proxy vendor strings in env, cmdline or cwd."""
    out: list[Finding] = []
    for proc in procs:
        blob = " ".join(
            [proc.cmdline, proc.cwd, proc.exe, " ".join(f"{k}={v}" for k, v in proc.env.items())]
        )
        if not signatures.match_vendor_text(blob):
            continue
        found = sorted(
            {
                m.group(0).lower()
                for m in signatures.VENDOR_TEXT_RX.finditer(blob)
            }
        )[:8]
        out.append(
            Finding(
                rule="R06-resi-vendor",
                title=f"residential proxy vendor reference near {proc.exe_base} (pid {proc.pid})",
                score=80,
                severity="high",
                detail={"vendors": found, "cmdline": util.truncate(proc.cmdline, 300),
                        "cwd": proc.cwd},
                subjects=[{"pid": proc.pid}],
            )
        )
    return out


# ------------------------------------------------------------------ R07 forwarding


def rule_forwarding(host: observe.HostState) -> list[Finding]:
    """R07: routing and NAT capability.

    IP forwarding plus a listener is how a laptop gets turned into a relay for
    a neighbour. Forwarding on its own is already odd on a laptop.
    """
    out: list[Finding] = []
    if host.ip_forward == 1:
        out.append(finding(
            "R07-ip-forward",
            "net.ipv4.ip_forward=1 (this machine can route for others)",
            45,
            {"ip_forward": host.ip_forward,
             "sysctl_sources": host.sysctl_sources,
             "note": "laptops and desktops have no legitimate need to forward"},
            [{"sysctl": "net.ipv4.ip_forward"}],
        ))
    if host.ipv6_forwarding == 1:
        out.append(finding(
            "R07-ipv6-forward",
            "net.ipv6.conf.all.forwarding=1",
            35,
            {"sources": host.sysctl_sources},
            [{"sysctl": "net.ipv6.conf.all.forwarding"}],
        ))
    if host.masquerade_rules:
        # Low on purpose. Docker, Podman and libvirt all create masquerade
        # rules, so a high score here put every container host permanently in
        # the top band with nothing the operator could do about it.
        # Masquerade is evidence only next to forwarding.
        paired = host.ip_forward != 0
        out.append(finding(
            "R07-masquerade",
            f"{host.masquerade_rules} NAT masquerade rule(s) present",
            40 if paired else 20,
            {"count": host.masquerade_rules,
             "ip_forward": host.ip_forward,
             "why": "normal on a Docker/VM host; only meaningful together "
                    "with ip_forward=1",
             "note": "counted as a raw substring over the whole ruleset, so "
                     "this is a presence indicator, not an inventory"},
            [{"nft": "masquerade"}],
        ))
    if host.forward_chains:
        # Only the first base chain in priority order governs: it either drops
        # the packet or lets it through to the next one. Reporting firewalld's
        # policy-accept chain while our own table already dropped the packet is
        # true and useless.
        prio, policy, name = host.forward_chains[0]
        if policy == "accept":
            out.append(finding(
                "R07-forward-accept",
                f"forwarded traffic is permitted: the first forward chain in "
                f"priority order ({name}, priority {prio}) has policy accept",
                40,
                {"effective_policy": policy,
                 "governing_chain": name,
                 "governing_priority": prio,
                 "all_forward_chains": [
                     {"chain": n, "priority": p, "policy": pol}
                     for p, pol, n in host.forward_chains
                 ],
                 "why": "a machine that forwards is a relay for its neighbours"},
                [{"nft": "forward"}],
            ))
    elif host.forward_accept_rules:
        out.append(finding(
            "R07-forward-accept",
            "forwarded traffic is permitted by the host firewall",
            40,
            {"accept_chains": host.forward_accept_rules},
            [{"nft": "forward"}],
        ))
    if host.send_redirects == 1:
        out.append(finding(
            "R07-icmp-redirect",
            "ICMP send_redirects enabled (MITM lever on a LAN)",
            25,
            {"send_redirects": 1},
            [{"sysctl": "net.ipv4.conf.all.send_redirects"}],
        ))
    return out


# ------------------------------------------------------------------ R08 tor


def _torrc_active_directives(text: str) -> set[str]:
    """Parse torrc, honouring comments.

    The stock Arch torrc ships with *every* relay directive present but
    commented out, so a naive substring search reports a relay on a machine
    where tor has never run. Only uncommented directives count.
    """
    active: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        key = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""
        if not value:
            continue
        active.add(key)
        active.add(f"{key} {value}")
    return active


def rule_tor(listeners: list[Socket], host: observe.HostState) -> list[Finding]:
    """R08: Tor as a relay/exit rather than a client."""
    out: list[Finding] = []
    torrc = util.read_text("/etc/tor/torrc", 200000)
    active = _torrc_active_directives(torrc)
    running = _pid_alive("tor")
    for directive, label, score in (
        ("ORPort", "an ORPort", 70),
        ("ExitRelay 1", "ExitRelay 1", 80),
        ("DirPort", "a DirPort", 60),
        ("BridgeRelay 1", "BridgeRelay 1", 55),
    ):
        if directive not in active:
            continue
        effective = score if running else max(15, score - 45)
        out.append(
            Finding(
                rule="R08-tor-relay",
                title=f"torrc enables {label}" + ("" if running else " (tor not running)"),
                score=effective,
                severity=_sev(effective),
                detail={"directive": directive, "tor_running": running,
                        "note": "directive is uncommented in /etc/tor/torrc"},
                subjects=[{"file": "/etc/tor/torrc"}],
            )
        )
    for sock in listeners:
        if sock.local_port in (9001, 9030, 9050, 9051) and sock.world_reachable:
            out.append(
                Finding(
                    rule="R08-tor-relay",
                    title=f"Tor port {sock.local_port} reachable from the network",
                    score=60,
                    severity="high",
                    detail={"port": sock.local_port, "exe": sock.exe},
                    subjects=[{"port": sock.local_port}],
                )
            )
    return out


def _pid_alive(name: str) -> bool:
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        if os.path.basename(util.read_text(f"/proc/{entry.name}/comm", 64).strip()) == name:
            return True
    return False


# ------------------------------------------------------------------ R09 infra


def rule_relay_infra(host: observe.HostState) -> list[Finding]:
    """R09: extra interfaces, TUN devices, loaded modules.

    A tun/wg interface with no corresponding client is how a laptop ends up
    carrying other people's traffic. An unexpected virtual interface is a
    strong hint that something is tunnelling.
    """
    out: list[Finding] = []
    if host.extra_ifaces:
        out.append(
            Finding(
                rule="R09-extra-iface",
                title=f"unexpected network interface(s): {', '.join(host.extra_ifaces)}",
                score=35,
                severity="low",
                detail={"ifaces": host.extra_ifaces},
                subjects=[{"iface": i} for i in host.extra_ifaces],
            )
        )
    tun_like = [m for m in host.modules if m.startswith(("tun", "wireguard", "veth", "dummy", "tap"))]
    if tun_like:
        out.append(
            Finding(
                rule="R09-tun-module",
                title=f"tunnel-capable kernel module(s) loaded: {', '.join(tun_like)}",
                score=30,
                severity="low",
                detail={"modules": tun_like, "tun_device": host.tun_present},
                subjects=[{"module": m} for m in tun_like],
            )
        )
    return out


# ------------------------------------------------------------------ R10 integrity


def rule_integrity_diff(
    current_files: dict[str, str | None],
    current_dirs: dict[str, list[str]],
    stored: dict[str, Any],
) -> list[Finding]:
    """R10: watched config or persistence paths changed since the baseline."""
    out: list[Finding] = []
    prev_files = stored.get("files", {})
    for path, digest in current_files.items():
        old = prev_files.get(path)
        if old is None:
            continue
        if old != digest:
            out.append(
                Finding(
                    rule="R10-config-drift",
                    title=f"tracked file changed: {path}",
                    score=50,
                    severity="medium",
                    detail={"path": path, "was": old, "now": digest},
                    subjects=[{"path": path}],
                )
            )
    prev_dirs = stored.get("dirs", {})
    for path, rows in current_dirs.items():
        old_rows = set(prev_dirs.get(path, []))
        if not old_rows:
            continue
        new = [r for r in rows if r not in old_rows]
        # A new file in a persistence dir is how a proxy survives a reboot.
        interesting = [
            r for r in new
            if not re.search(r"(\.md$|\.log$|\.pyc$|~$|\.swp$|/core)", r)
        ]
        if not interesting:
            continue
        score = 55 if len(interesting) > 3 else 40
        out.append(
            Finding(
                rule="R10-persistence-drift",
                title=f"{len(interesting)} new file(s) in watched dir {path}",
                score=score,
                severity="medium",
                detail={"dir": path, "new_entries": interesting[:30]},
                subjects=[{"path": p} for p in [r.rsplit(":", 1)[0] for r in interesting[:20]]],
            )
        )
    return out


# ------------------------------------------------------------------ R11 baseline


def rule_baseline_diff(state: dict[str, Any], stored: dict[str, Any]) -> list[Finding]:
    """R11: processes/listeners/modules that were not in the approved baseline.

    On a laptop the process list is noisy, so we only report *relay-shaped*
    additions: a new world listener, or a new process holding sockets.
    """
    out: list[Finding] = []
    if not stored:
        return out
    old_listeners = set(stored.get("listeners", []))
    new_listeners = [l for l in state.get("listeners", []) if l not in old_listeners]
    for entry in new_listeners:
        parts = entry.split("|")
        port = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        # Splitting on ':' broke every IPv6 listener, because '::1' contains
        # colons: parts[1] was '' and is_loopback('') is False, so a loopback
        # IPv6 socket scored world-reachable.
        local = parts[1] if len(parts) > 1 else ""
        world = bool(local) and not util.is_loopback(local)
        if not world:
            continue
        out.append(
            Finding(
                rule="R11-new-world-listener",
                title=f"new network-reachable listener since baseline: {entry}",
                score=60 if port in signatures.RELAY_PORTS else 40,
                severity="medium",
                detail={"entry": entry, "relay_port": port in signatures.RELAY_PORTS},
                subjects=[{"port": port}],
            )
        )
    old_procs = set(stored.get("processes", []))
    new_procs = [p for p in state.get("processes", []) if p not in old_procs]
    relay_ish = [p for p in new_procs if signatures.match_exe(p.split("|")[0])]
    for entry in relay_ish:
        out.append(
            Finding(
                rule="R11-new-relay-process",
                title=f"new relay-software process since baseline: {entry}",
                score=70,
                severity="high",
                detail={"entry": entry},
                subjects=[{"exe": entry.rsplit(":", 1)[-1]}],
            )
        )
    old_mods = set(stored.get("modules", []))
    for mod in state.get("modules", []):
        name = mod.split()[0] if isinstance(mod, str) and mod else str(mod)
        if name in old_mods or mod in old_mods:
            continue
        if name.startswith(("tun", "wireguard", "kvm", "vbox", "tap", "veth")):
            out.append(
                Finding(
                    rule="R11-new-module",
                    title=f"new kernel module: {name}",
                    score=30,
                    severity="low",
                    detail={"module": name},
                    subjects=[{"module": name}],
                )
            )
    return out


# ------------------------------------------------------------------ R12 obf


def rule_obfuscation(procs: list[Proc]) -> list[Finding]:
    """R12: anti-analysis and anti-forensics behaviour."""
    out: list[Finding] = []
    for proc in procs:
        names = [h["name"] for h in proc.sig_hits]
        if "ld-preload" in names:
            hit = next(h for h in proc.sig_hits if h["name"] == "ld-preload")
            out.append(
                Finding(
                    rule="R12-ld-preload",
                    title=f"LD_PRELOAD injected into {proc.exe_base} (pid {proc.pid})",
                    score=hit.get("score", 30),
                    severity=_sev(hit.get("score", 30)),
                    detail={
                        "env": {"LD_PRELOAD": hit.get("why", "")},
                        "cmdline": util.truncate(proc.cmdline, 300),
                        "sockets": len(proc.listeners) + len(proc.conns),
                        "note": "a self-preload is normal (firefox sandbox, "
                                "sanitizers); this fires on preloads from "
                                "outside the app's own libraries",
                    },
                    subjects=[{"pid": proc.pid}],
                )
            )
        if "deleted-exe" in names and proc.listeners:
            out.append(
                Finding(
                    rule="R12-deleted-exe",
                    title=f"{proc.exe_base} (pid {proc.pid}) runs from a deleted binary and holds sockets",
                    score=80,
                    severity="high",
                    detail={"exe": proc.exe, "listeners": [s.key for s in proc.listeners]},
                    subjects=[{"pid": proc.pid}],
                )
            )
    return out


# ------------------------------------------------------------------ R13 exposure


def rule_port_exposure(config, cache: dict[str, Any] | None = None) -> list[Finding]:
    """R13: the host firewall leaves non-essential inbound ports open.

    `firewall-cmd` is a D-Bus round trip that took 8.02s per call on this
    host. Running it every 3s cycle made a scan take longer than its own
    interval, which is how the daemon ended up permanently behind and burning
    15% CPU. A firewall zone does not change between scans, so the answer is
    cached for `detect.external_interval_seconds`.
    """
    out: list[Finding] = []
    import shutil

    if not shutil.which("firewall-cmd"):
        return out
    ttl = float(config.get("detect.external_interval_seconds", 300))
    if cache is not None:
        cached = cache.get("port_exposure")
        if cached and now() - cached[0] < ttl:
            return cached[1]
    rc, out_txt, _ = util.run(
        ["firewall-cmd", "--zone=public", "--list-ports"], timeout=15
    )
    if rc == 0:
        for entry in out_txt.split():
            port_txt = entry.split("/")[0]
            try:
                port = int(port_txt)
            except ValueError:
                continue
            if port in signatures.RELAY_PORTS or port in (22, 23, 445, 3389, 5900):
                score = 50 if port in signatures.RELAY_PORTS else 35
                out.append(
                    Finding(
                        rule="R13-firewall-open-port",
                        title=f"firewalld publicly opens {entry}",
                        score=score,
                        severity="medium",
                        detail={"port": port, "entry": entry,
                                "zone": "public",
                                "note": "an open port on the firewall is open "
                                        "to the world"},
                        subjects=[{"port": port}],
                    )
                )
    if cache is not None:
        cache["port_exposure"] = (now(), out)
    return out


# ------------------------------------------------------------------ R14 egress


def rule_asymmetry(host_bytes: dict[str, int], procs: list[Proc]) -> list[Finding]:
    """R14: interface-level egress asymmetry.

    A proxy machine sends far more than it receives. Normal laptop use is
    bursty but roughly balanced over a window.
    """
    out: list[Finding] = []
    rx, tx = host_bytes.get("rx", 0), host_bytes.get("tx", 0)
    if rx + tx < 50 * 1024 * 1024:
        return out
    if tx <= rx * 4:
        return out
    ratio = tx / max(rx, 1)
    score = min(80, 30 + int(ratio))
    out.append(
        Finding(
            rule="R14-egress-asymmetry",
            title=f"egress is {ratio:.1f}x ingress ({util.human_bytes(tx)} out vs {util.human_bytes(rx)} in)",
            score=score,
            severity="medium",
            detail={"rx_bytes": rx, "tx_bytes": tx, "ratio": round(ratio, 2),
                    "why": "relaying traffic for others produces exactly this shape"},
            subjects=[{"iface": "all"}],
        )
    )
    return out


# ------------------------------------------------------------------ aggregate


@dataclass
class Verdict:
    score: int
    severity: str
    findings: list[Finding]
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            "findings": [f.to_dict() for f in self.findings],
            "ts": now(),
            "iso": util.iso(),
        }

    @property
    def clean(self) -> bool:
        return self.score < 20


def scan(
    config,
    *,
    history: dict[int, dict[str, Any]] | None = None,
    stored_baseline: dict[str, Any] | None = None,
    stored_integrity: dict[str, Any] | None = None,
    host_bytes: dict[str, int] | None = None,
    do_integrity: bool = True,
    cache: dict[str, Any] | None = None,
) -> Verdict:
    """Run every rule and reduce to one verdict."""
    history = history if history is not None else {}
    listeners, conns = observe.observe_sockets()
    procs = observe.observe_processes(
        include_content_scan=True, sockets=(listeners, conns)
    )
    host = observe.observe_host()

    allow_lan = {
        ("tcp", p) for p in config.get("firewall.lan_allowlist", [])
    } | {("tcp6", p) for p in config.get("firewall.lan_allowlist", [])} | {
        ("udp", p) for p in config.get("firewall.lan_allowlist_udp", [])
    } | {("udp6", p) for p in config.get("firewall.lan_allowlist_udp", [])}

    findings: list[Finding] = []
    findings += rule_relay_binary(procs)
    findings += rule_binary_content(procs)
    findings += rule_world_listeners(listeners, allow_lan)
    findings += rule_udp_relay(listeners)
    findings += rule_connection_fanout(procs, history)
    findings += rule_vendor_text(procs, host)
    findings += rule_forwarding(host)
    findings += rule_tor(listeners, host)
    findings += rule_relay_infra(host)
    findings += rule_obfuscation(procs)
    findings += rule_port_exposure(config, cache)
    if host_bytes:
        findings += rule_asymmetry(host_bytes, procs)

    state = observe.baseline_state(stored_baseline or {}, procs, listeners)
    if stored_baseline:
        findings += rule_baseline_diff(state, stored_baseline)

    if do_integrity and stored_integrity is not None:
        files = observe.hash_manifest(
            list(config.get("detect.integrity_paths", []))
            + [str(p) for p in config.get("detect.integrity_user_paths", [])]
        )
        dirs = (
            observe.listdir_snapshot(config.get("detect.watch_persistence_paths", []))
            if config.get("detect.watch_persistence", True)
            else {}
        )
        findings += rule_integrity_diff(files, dirs, stored_integrity)

    findings.sort(key=lambda f: -f.score)
    reasons = [f.title for f in findings[:8]]
    # Composite: worst signal plus a decayed contribution from the rest, so a
    # single lucky 95 does not mask a pile of 30s, but ten 30s do not add to 95.
    worst = findings[0].score if findings else 0
    rest = sorted((f.score for f in findings[1:]), reverse=True)[:6]
    composite = worst + int(sum(rest) * 0.35 / max(len(rest), 1))
    score = min(100, composite)
    if not findings:
        score = 0
    return Verdict(score=score, severity=_sev(score), findings=findings, reasons=reasons)
