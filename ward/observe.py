"""Read-only observation of the machine.

Everything here reads /proc, /sys and a handful of config files. No module in
this file is allowed to change machine state -- the responder owns all writes,
which keeps "what we saw" separate from "what we did about it".

Two hot paths:
  observe_sockets()      every detect interval  (cheap, /proc/net)
  observe_processes()    slower               (walks every /proc/PID)
"""

from __future__ import annotations

import os
import re
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import signatures, util
from .util import now, run

# ------------------------------------------------------------------ dataclasses


@dataclass
class Socket:
    proto: str  # tcp | udp | tcp6 | udp6
    local: str
    local_port: int
    remote: str
    remote_port: int
    state: str
    uid: int
    inode: int
    pid: int | None = None
    exe: str = ""
    cmdline: str = ""

    @property
    def listening(self) -> bool:
        return self.state == "LISTEN" and self.proto.startswith("tcp")

    @property
    def externally_bound(self) -> bool:
        return not util.is_loopback(self.local) and not util.is_wildcard(self.local)

    @property
    def wildcard_bound(self) -> bool:
        return util.is_wildcard(self.local)

    @property
    def world_reachable(self) -> bool:
        return not util.is_loopback(self.local)

    @property
    def key(self) -> str:
        return f"{self.proto}/{self.local}:{self.local_port}"


@dataclass
class Proc:
    pid: int
    ppid: int
    uid: int
    exe: str
    exe_base: str
    cmdline: str
    cwd: str = ""
    state: str = ""
    threads: int = 0
    rss: int = 0
    start_time: float = 0.0
    env: dict[str, str] = field(default_factory=dict)
    listeners: list[Socket] = field(default_factory=list)
    conns: list[Socket] = field(default_factory=list)
    content_hits: list[tuple[str, int, str]] = field(default_factory=list)
    sig_hits: list[dict] = field(default_factory=list)
    fds: int = 0

    @property
    def protected(self) -> bool:
        return signatures.is_protected(self.exe_base) or self.pid == os.getpid()

    @property
    def score(self) -> int:
        return sum(h[1] for h in self.content_hits) + sum(
            s.get("score", 0) for s in self.sig_hits
        )


TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}


# ------------------------------------------------------------------ sockets


def _inode_to_pid() -> dict[int, int]:
    """Map socket inode -> pid by walking /proc/*/fd once."""
    mapping: dict[int, int] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        fd_dir = f"/proc/{entry.name}/fd"
        try:
            with os.scandir(fd_dir) as fds:
                for fd in fds:
                    try:
                        target = os.readlink(fd.path)
                    except OSError:
                        continue
                    if target.startswith("socket:["):
                        try:
                            mapping[int(target[8:-1])] = int(entry.name)
                        except ValueError:
                            continue
        except (OSError, PermissionError):
            continue
    return mapping


def _parse_net_file(path: str, proto: str, want_state: bool) -> list[Socket]:
    out: list[Socket] = []
    try:
        with open(path, "r", errors="replace") as fh:
            next(fh, None)  # header
            for line in fh:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_raw = util.parse_hex_addr(parts[1])
                remote_raw = util.parse_hex_addr(parts[2])
                local, lport = util.split_addr(local_raw)
                remote, rport = util.split_addr(remote_raw)
                try:
                    inode = int(parts[9])
                    uid = int(parts[7])
                except ValueError:
                    continue
                st = TCP_STATES.get(parts[3], parts[3]) if want_state else "-"
                out.append(
                    Socket(
                        proto=proto,
                        local=local,
                        local_port=lport,
                        remote=remote,
                        remote_port=rport,
                        state=st,
                        uid=uid,
                        inode=inode,
                    )
                )
    except OSError:
        return out
    return out


def observe_sockets(
    attach_procs: bool = True, with_conns: bool = True
) -> tuple[list[Socket], list[Socket]]:
    """Return (listening_sockets, non_listening_sockets).

    Listeners are the crown jewels: anything bound to a non-loopback address is
    a door into this machine, and a SOCKS door is a paid-for residential proxy.
    """
    listeners: list[Socket] = []
    conns: list[Socket] = []
    for path, proto, stateful in (
        ("/proc/net/tcp", "tcp", True),
        ("/proc/net/tcp6", "tcp6", True),
        ("/proc/net/udp", "udp", False),
        ("/proc/net/udp6", "udp6", False),
    ):
        for sock in _parse_net_file(path, proto, stateful):
            if sock.state == "LISTEN":
                listeners.append(sock)
            else:
                conns.append(sock)
    if not attach_procs:
        return listeners, conns

    pid_by_inode = _inode_to_pid()
    by_pid: dict[int, list[Socket]] = {}
    for sock in listeners + (conns if with_conns else []):
        pid = pid_by_inode.get(sock.inode)
        if pid is None:
            continue
        sock.pid = pid
        by_pid.setdefault(pid, []).append(sock)
    for pid, socks in by_pid.items():
        head = util.truncate(util.read_text(f"/proc/{pid}/cmdline", 4096).replace("\x00", " "), 512)
        exe = ""
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = ""
        for sock in socks:
            sock.exe = exe
            sock.cmdline = head
    return listeners, conns


# ------------------------------------------------------------------ processes


def _read_env(pid: int) -> dict[str, str]:
    env: dict[str, str] = {}
    raw = util.read_text(f"/proc/{pid}/environ", 16384)
    for item in raw.split("\x00"):
        if "=" in item:
            k, _, v = item.partition("=")
            if len(k) <= 96:
                env[k] = v[:512]
    return env


def _start_time(pid: int, btime: float, hz: float) -> float:
    raw = util.read_text(f"/proc/{pid}/stat", 8192)
    # comm can contain spaces and parentheses; fields start after the last ')'
    idx = raw.rfind(")")
    if idx < 0:
        return 0.0
    tail = raw[idx + 2 :].split()
    if len(tail) < 20:
        return 0.0
    try:
        ticks = int(tail[19])
    except ValueError:
        return 0.0
    return btime + ticks / hz if hz else 0.0


def _boot_time() -> tuple[float, float]:
    try:
        with open("/proc/stat") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return float(line.split()[1]), os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        pass
    return 0.0, 100.0


def observe_processes(
    include_content_scan: bool = True, content_limit: int = 6 << 20
) -> list[Proc]:
    btime, hz = _boot_time()
    listeners, conns = observe_sockets()
    list_by_pid: dict[int, list[Socket]] = {}
    conn_by_pid: dict[int, list[Socket]] = {}
    for sock in listeners:
        if sock.pid:
            list_by_pid.setdefault(sock.pid, []).append(sock)
    for sock in conns:
        if sock.pid:
            conn_by_pid.setdefault(sock.pid, []).append(sock)

    uid_map = _uid_map()
    procs: list[Proc] = []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        raw = util.read_text(f"/proc/{pid}/stat", 8192)
        if not raw:
            continue
        idx = raw.rfind(")")
        comm = raw[raw.find("(") + 1 : idx] if idx > 0 else ""
        tail = raw[idx + 2 :].split() if idx > 0 else []
        state = tail[0] if tail else "?"
        ppid = int(tail[1]) if len(tail) > 1 and tail[1].isdigit() else 0
        try:
            rss_pages = int(tail[21]) if len(tail) > 21 else 0
            threads = int(tail[17]) if len(tail) > 17 else 0
        except ValueError:
            rss_pages, threads = 0, 0
        try:
            uid = os.stat(f"/proc/{pid}").st_uid
        except OSError:
            uid = uid_map.get(os.stat("/proc/self").st_uid, 1000)
        cmdline = util.truncate(
            util.read_text(f"/proc/{pid}/cmdline", 8192).replace("\x00", " ").strip(), 1024
        )
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = ""
        # A deleted binary with a live socket is a classic anti-forensics move.
        deleted = exe.endswith(" (deleted)")
        if deleted:
            exe = exe[: -len(" (deleted)")]
        exe_base = exe.rsplit("/", 1)[-1] if exe else (comm or cmdline.split(" ")[0])
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            cwd = ""
        try:
            fds = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            fds = 0

        proc = Proc(
            pid=pid,
            ppid=ppid,
            uid=uid,
            exe=exe,
            exe_base=exe_base,
            cmdline=cmdline or comm,
            cwd=cwd,
            state=state,
            threads=threads,
            rss=rss_pages * 4096,
            start_time=_start_time(pid, btime, hz),
            env=_read_env(pid),
            listeners=list_by_pid.get(pid, []),
            conns=conn_by_pid.get(pid, []),
            fds=fds,
        )
        _attach_signatures(proc, deleted)
        if include_content_scan and exe and not signatures.is_protected(exe_base):
            _content_scan(proc, content_limit)
        procs.append(proc)
    procs.sort(key=lambda p: p.pid)
    return procs


def _attach_signatures(proc: Proc, deleted: bool) -> None:
    hits = proc.sig_hits
    if deleted:
        hits.append(
            {
                "name": "deleted-exe",
                "score": 45,
                "why": "running from a deleted binary (anti-forensics)",
            }
        )
    sig = signatures.match_exe(proc.exe_base)
    if sig:
        hits.append({"name": sig.name, "score": sig.score, "why": sig.why})
    sig = signatures.match_cmdline(proc.cmdline)
    if sig:
        hits.append({"name": sig.name, "score": sig.score, "why": sig.why})
    if proc.cwd and proc.cwd.startswith(("/tmp", "/var/tmp", "/dev/shm", "/run/user")):
        hits.append(
            {
                "name": "volatile-cwd",
                "score": 25,
                "why": f"cwd is {proc.cwd} (typical of dropped payloads)",
            }
        )
    if proc.env.get("LD_PRELOAD"):
        target = proc.env["LD_PRELOAD"]
        base = target.rsplit("/", 1)[-1].strip()
        # Firefox preloads its own sandbox into every child; flagging that is
        # how an operator learns to ignore the rule. The interesting cases are
        # a library the app does not ship, and anything loaded from a volatile
        # directory.
        volatile = target.lstrip().startswith(("/tmp", "/var/tmp", "/dev/shm",
                                              "/run/user", "/run/shm"))
        if base not in signatures.BENIGN_PRELOAD:
            why = f"LD_PRELOAD={util.truncate(target, 80)} (not an app-shipped library)"
            if volatile:
                why = f"LD_PRELOAD from a volatile path: {util.truncate(target, 80)}"
            hits.append(
                {
                    "name": "ld-preload",
                    "score": 55 if (proc.listeners or proc.conns) else 35,
                    "why": why,
                }
            )
        elif volatile:
            # A known-benign library name loaded from /tmp is still wrong.
            hits.append(
                {
                    "name": "ld-preload",
                    "score": 60,
                    "why": f"known library name loaded from a volatile path: "
                           f"{util.truncate(target, 80)}",
                }
            )
    for key in ("http_proxy", "https_proxy", "all_proxy", "ALL_PROXY"):
        if proc.env.get(key):
            hits.append(
                {
                    "name": "proxy-env",
                    "score": 20,
                    "why": f"{key} set in environment",
                }
            )
    for sock in proc.listeners:
        if sock.proto.startswith("tcp") and signatures.RELAY_PORTS & {sock.local_port}:
            hits.append(
                {
                    "name": "relay-port",
                    "score": signatures.score_for_port(sock.local_port),
                    "why": f"listening on relay port {sock.local_port}",
                }
            )


def _content_scan(proc: Proc, limit: int) -> None:
    if not proc.exe or not os.path.isfile(proc.exe):
        return
    data = util.read_bytes(proc.exe, limit)
    if not data:
        return
    proc.content_hits = signatures.scan_bytes(data, proc.exe_base)


_UID_CACHE: dict[int, str] = {}


def _uid_map() -> dict[int, str]:
    global _UID_CACHE
    if not _UID_CACHE:
        try:
            with open("/etc/passwd") as fh:
                for line in fh:
                    parts = line.split(":")
                    if len(parts) > 2 and parts[2].isdigit():
                        _UID_CACHE[int(parts[2])] = parts[0]
        except OSError:
            pass
    return _UID_CACHE


def uid_name(uid: int) -> str:
    return _uid_map().get(uid, str(uid))


# ------------------------------------------------------------------ host state


@dataclass
class HostState:
    ip_forward: int
    ipv6_forwarding: int
    send_redirects: int
    accept_redirects: int
    rp_filter: int
    martians: int
    tun_present: bool
    extra_ifaces: list[str]
    lan_iface: str | None
    lan_addr: str
    modules: list[str]
    sysctl_sources: list[str]
    #: True/False when netlink could be read, None when it could not.
    nft_table_present: bool | None
    nft_readable: bool
    masquerade_rules: int
    forward_accept_rules: int
    martian_log_lines: int
    #: (priority, policy) for every base chain hooked into forward, sorted by
    #: effective order. The first entry is the policy that actually applies.
    forward_chains: list[tuple[int, str, str]]


_FWD_CHAIN_RX = re.compile(
    r"chain\s+(\S+)\s*\{\s*type\s+filter\s+hook\s+forward\s+priority\s+"
    r"([-\w\s+.]*?)\s*;\s*policy\s+(accept|drop)\s*;",
    re.IGNORECASE,
)


def _priority_value(raw: str) -> int:
    """Convert an nft priority expression to a comparable integer.

    nft allows 'filter', 'filter - 5', 'raw', numeric values and combinations.
    Named anchors map onto the same scale nft uses internally. The operator is
    applied, not just consumed: getting that wrong would rank WARD's own
    priority-filter-5 chain behind firewalld's filter+10 and make us report the
    wrong effective forward policy.
    """
    anchors = {
        "raw": -300, "mangle": -150, "dstnat": -100, "filter": 0,
        "security": 50, "srcnat": 100,
    }
    raw = raw.strip()
    if not raw:
        return 0
    total = 0
    sign = 1
    for token in re.split(r"([+-])", raw):
        token = token.strip()
        if not token:
            continue
        if token == "+":
            sign = 1
            continue
        if token == "-":
            sign = -1
            continue
        if token in anchors:
            total += sign * anchors[token]
        else:
            try:
                total += sign * int(token)
            except ValueError:
                return total
        sign = 1
    return total


def _parse_forward_chains(nft_out: str) -> list[tuple[int, str, str]]:
    chains: list[tuple[int, str, str]] = []
    for m in _FWD_CHAIN_RX.finditer(nft_out):
        prio = _priority_value(m.group(2))
        chains.append((prio, m.group(3).lower(), m.group(1)))
    chains.sort(key=lambda t: t[0])
    return chains


def _effective_forward_policy(chains: list[tuple[int, str, str]]) -> str:
    """The policy that actually governs forwarded traffic.

    Only the first base chain in priority order matters: it either drops the
    packet or lets it through to the next chain. Reporting "firewalld's
    FORWARD accepts" while our own table already dropped it is technically true
    and practically useless.
    """
    if not chains:
        return "none"
    return chains[0][1]


def _sysctl(name: str) -> int:
    rc, out, _ = run(["sysctl", "-n", name], timeout=3)
    try:
        return int(out.strip())
    except ValueError:
        return -1


def observe_host() -> HostState:
    rc, out, _ = run(["ip", "-o", "link", "show"], timeout=5)
    extra: list[str] = []
    lan_iface, lan_addr = None, ""
    for line in out.splitlines():
        m = re.match(r"\d+:\s+([^:@]+)(?:@\S+)?:\s+<[^>]*>", line)
        if not m:
            continue
        name = m.group(1)
        if name in ("lo", "wlan0", "eth0", "enp0s31f6", "wlp2s0", "docker0",
                    "br0", "veth0", "virbr0"):
            continue
        extra.append(name)
    rc, out, _ = run(["ip", "-o", "-4", "addr", "show"], timeout=5)
    for line in out.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m and m.group(1) != "lo":
            lan_iface, lan_addr = m.group(1), m.group(2)
            break
    modules: list[str] = []
    try:
        with open("/proc/modules") as fh:
            for line in fh:
                parts = line.split()
                if parts:
                    modules.append(parts[0])
    except OSError:
        pass
    sources: list[str] = []
    for base in ("/etc/sysctl.conf", "/etc/sysctl.d"):
        if os.path.isfile(base):
            sources.append(base)
        elif os.path.isdir(base):
            for name in sorted(os.listdir(base)):
                if name.endswith(".conf"):
                    sources.append(os.path.join(base, name))
    rc, nft_out, nft_err = run(["nft", "list", "ruleset"], timeout=10)
    nft_readable = rc == 0
    if nft_readable:
        table_present = "table inet ward" in nft_out or "table ip ward" in nft_out
        masq = nft_out.count("masquerade") + nft_out.count("snat")
        fwd_chains = _parse_forward_chains(nft_out)
        fwd_accept = sum(1 for _p, pol, _n in fwd_chains if pol == "accept")
    else:
        # Reporting "no table" when we simply could not read netlink would tell
        # the operator their firewall is gone. Unknown is the honest answer.
        table_present = None
        masq = 0
        fwd_chains = []
        fwd_accept = 0
    rc, j, _ = run(["journalctl", "-k", "--since", "-1h", "--no-pager"], timeout=15)
    martians = len(re.findall(r"martian source", j)) if j else 0
    return HostState(
        ip_forward=_sysctl("net.ipv4.ip_forward"),
        ipv6_forwarding=_sysctl("net.ipv6.conf.all.forwarding"),
        send_redirects=_sysctl("net.ipv4.conf.all.send_redirects"),
        accept_redirects=_sysctl("net.ipv4.conf.all.accept_redirects"),
        rp_filter=_sysctl("net.ipv4.conf.all.rp_filter"),
        martians=martians,
        tun_present=os.path.exists("/dev/net/tun"),
        extra_ifaces=extra,
        lan_iface=lan_iface,
        lan_addr=lan_addr,
        modules=modules,
        sysctl_sources=sources,
        nft_table_present=table_present,
        nft_readable=nft_readable,
        masquerade_rules=masq,
        forward_accept_rules=fwd_accept,
        martian_log_lines=martians,
        forward_chains=fwd_chains,
    )


# ------------------------------------------------------------------ integrity


def hash_manifest(paths: Iterable[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for raw in paths:
        path = os.path.expanduser(raw)
        if os.path.isfile(path):
            try:
                st = os.stat(path)
                out[path] = f"{util.sha256_file(path)}:{st.st_size}:{int(st.st_mtime)}"
            except OSError:
                out[path] = None
    return out


def listdir_snapshot(paths: Iterable[str]) -> dict[str, list[str]]:
    """name+size+mtime for files in watched directories (persistence hunting)."""
    out: dict[str, list[str]] = {}
    for raw in paths:
        path = os.path.expanduser(raw)
        if not os.path.isdir(path):
            continue
        rows: list[str] = []
        for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.stat(full, follow_symlinks=False)
                except OSError:
                    continue
                rows.append(f"{full}:{st.st_size}:{int(st.st_mtime)}")
                if len(rows) > 4000:
                    break
            if len(rows) > 4000:
                break
        out[path] = sorted(rows)
    return out


def setuid_inventory() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"suid": [], "sgid": [], "world_writable": []}
    for base in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
                 "/usr/local/sbin", "/opt", "/home"):
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
            dirs[:] = [
                d
                for d in dirs
                if d not in (".git", "node_modules", "__pycache__", "snap", "flatpak")
            ]
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                mode = st.st_mode
                if mode & 0o4000:
                    found["suid"].append(full)
                if mode & 0o2000:
                    found["sgid"].append(full)
                if base != "/home" and mode & 0o002 and st.st_uid == 0:
                    found["world_writable"].append(full)
            if len(found["suid"]) > 500:
                break
    return found


# ------------------------------------------------------------------ baseline


#: Bump when the shape of baseline_state changes. A stored baseline from an
#: older schema is not comparable to a fresh one, and diffing them produces a
#: finding per listener rather than a re-learn. Found the hard way: changing
#: the listener key format made every listener on the box look new.
BASELINE_SCHEMA = 2


def baseline_state(baseline: dict[str, Any], procs: list[Proc], listeners: list[Socket]) -> dict[str, Any]:
    """Reduce current state to a comparable, JSON-safe fingerprint set.

    Module entries are stored as *names*, not /proc/modules lines. Storing the
    whole line means a module's refcount or size change reads as a new module,
    which turns R11 into noise on the first scan.
    """
    modules: list[str] = []
    for line in util.read_text("/proc/modules", 1 << 20).splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] in ("nf_conntrack", "nf_tables", "nft_chain_nat"):
            continue  # bookkeeping we do not care about
        modules.append(parts[0])
    return {
        "schema": BASELINE_SCHEMA,
        "ts": now(),
        "processes": sorted(
            f"{p.exe_base}:{p.exe}" for p in procs if not p.protected
        ),
        # Keyed on port and executable, not on the bound address. A DHCP lease
        # renewal that changes 192.168.1.x to 192.168.1.y used to make every
        # listener on the box look new, which produced a finding per listener
        # and pushed the composite over the action threshold for good.
        "listeners": sorted(
            f"{s.proto}|{s.local_port}|{s.exe.rsplit('/', 1)[-1]}"
            for s in listeners
        ),
        "modules": sorted(set(modules)),
    }
