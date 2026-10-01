"""nftables control for WARD.

Design: WARD owns one table, `inet ward`, with base chains at a *lower* hook
priority than firewalld's (`filter - 5`), so our drop is evaluated first. This
means WARD's default-deny holds even if firewalld is misconfigured, and
firewalld keeps managing its own zones without a fight.

The ruleset is generated from config and rendered with explicit handles so that
reload is idempotent. `apply()` is atomic: it flushes only our table, never the
whole ruleset.

The three properties that matter for this job:
  1. input  policy drop  -- a proxy needs an inbound door; we remove the doors
  2. forward policy drop  -- a relay needs to route; we forbid transit
  3. no masquerade       -- we never make traffic look like it came from here
"""

from __future__ import annotations

import os
import re
from typing import Iterable

from . import util
from .util import run

TABLE = "ward"
PRIORITY_FILTER = "filter - 5"
PRIORITY_NAT = "srcnat + 5"


def _chain(name: str) -> str:
    return f"{TABLE}_{name}"


def render(config) -> str:
    """Build the full nft script for the WARD table."""
    fw = config.section("firewall")
    family = fw.get("family", "inet")
    table = fw.get("table", TABLE)
    allow_lan: list[int] = fw.get("lan_allowlist", [])
    allow_udp: list[int] = fw.get("lan_allowlist_udp", [])
    drop_lanmr: list[int] = fw.get("drop_lanmr", [])
    drop_ssdp: list[int] = fw.get("drop_ssdp", [])
    ifaces: list[str] = config.get("identity.lan_ifaces", [])
    cidr = config.get("identity.trusted_lan_cidr", "192.168.0.0/16")
    pol_in = fw.get("default_input", "drop")
    pol_fwd = fw.get("default_forward", "drop")
    pol_out = fw.get("default_output", "accept")

    L: list[str] = []
    add = L.append
    add("#!/usr/sbin/nft -f")
    add("# WARD generated ruleset -- do not edit by hand.")
    add("# Regenerate with: ward firewall --apply")
    add(f"table {family} {table} {{")
    add("")

    # ---- input ------------------------------------------------------------
    add(f"    chain {_chain('input')} {{")
    add(f"        type filter hook input priority {PRIORITY_FILTER}; policy {pol_in};")
    add("        ct state invalid counter drop comment \"ward:invalid\"")
    add("        ct state established,related counter accept comment \"ward:est\"")
    if fw.get("allow_loopback", True):
        add("        iifname \"lo\" counter accept comment \"ward:lo\"")
    if fw.get("allow_dhcp", True):
        add("        udp sport 67 udp dport 68 counter accept comment \"ward:dhcp4\"")
        add("        udp sport 547 udp dport 546 counter accept comment \"ward:dhcp6\"")
    if fw.get("allow_icmp", True):
        add("        ip protocol icmp counter accept comment \"ward:icmp4\"")
        add("        ip6 nexthdr icmpv6 counter accept comment \"ward:icmp6\"")
        add("        ip6 nexthdr ipv6-icmp counter accept comment \"ward:icmp6-alt\"")
    if fw.get("allow_mdns", True):
        for iface in ifaces:
            add(
                f'        iifname "{iface}" ip daddr 224.0.0.251 udp dport 5353 '
                'counter accept comment "ward:mdns"'
            )
        # IPv6 mDNS uses ff02::fb. Without this, device discovery silently
        # breaks on the IPv6 path while still working on IPv4, which is the
        # kind of half-broken that nobody notices for a month.
        add(
            '        ip6 daddr ff02::fb udp dport 5353 counter accept '
            'comment "ward:mdns6"'
        )
    # LLMNR and SSDP: legitimate on nothing we run, and both are standard
    # building blocks for redirecting other people's traffic.
    for port in drop_lanmr:
        add(
            f"        udp dport {port} counter drop comment \"ward:drop-llmnr\""
        )
    for port in drop_ssdp:
        add(
            f"        udp dport {port} ct state new counter drop comment \"ward:drop-upnp\""
        )
    # Explicitly refuse the classic relay ports even from the LAN. If you truly
    # need one, remove it here -- and know what you are doing.
    from . import signatures

    for port in sorted(signatures.RELAY_PORTS):
        add(
            f"        tcp dport {port} counter drop comment \"ward:no-relay-port\""
        )
    for port in allow_lan:
        add(
            f"        ip saddr {cidr} tcp dport {port} counter accept "
            f'comment "ward:lan-allow"'
        )
    for port in allow_udp:
        add(
            f"        ip saddr {cidr} udp dport {port} counter accept "
            f'comment "ward:lan-allow-udp"'
        )
    add(f"        counter comment \"ward:final-drop\"")
    add("    }")
    add("")

    # ---- forward ----------------------------------------------------------
    # Policy drop with no accept rules at all: this machine is an endpoint,
    # never a router. This is the rule that makes relay-by-forwarding
    # impossible rather than merely unlikely.
    add(f"    chain {_chain('forward')} {{")
    add(f"        type filter hook forward priority {PRIORITY_FILTER}; policy {pol_fwd};")
    add('        counter comment "ward:no-transit"')
    add("    }")
    add("")

    # ---- output -----------------------------------------------------------
    add(f"    chain {_chain('output')} {{")
    add(f"        type filter hook output priority {PRIORITY_FILTER}; policy {pol_out};")
    add('        ct state established,related counter accept comment "ward:out-est"')
    if fw.get("allow_loopback", True):
        add('        oifname "lo" counter accept comment "ward:out-lo"')
    add('        counter comment "ward:out-final"')
    add("    }")
    add("")

    # ---- prerouting -------------------------------------------------------
    # The input chain drops these ports anyway. This chain exists to leave a
    # record in the kernel log of *who* tried, because "someone on the internet
    # knocked on 1080" is exactly the evidence a residential-proxy accusation
    # needs. Sampled at 1-in-16 so a scan cannot flood the journal.
    add(f"    chain {_chain('prerouting')} {{")
    add(f"        type filter hook prerouting priority {PRIORITY_FILTER}; policy accept;")
    probe = ", ".join(
        str(p) for p in sorted(
            {1080, 1081, 1082, 3128, 3333, 4444, 5555, 6666, 6667, 6697,
             7777, 8000, 8008, 8080, 8081, 8118, 8888, 8880, 9050, 9051,
             9090, 10808, 10809, 31337}
        )
    )
    add(f"        tcp flags & (fin | syn) == syn tcp dport {{ {probe} }} "
        "numgen random mod 16 < 1 "
        'counter log prefix "ward-relay-probe " level warn')
    add("    }")
    add("}")
    return "\n".join(L) + "\n"


def render_quarantine(ports: Iterable[int], table: str = "ward_quarantine",
                      allow: Iterable[int] = (), lan_cidr: str = "192.168.0.0/16") -> str:
    """A standalone table that drops traffic to specific ports outright.

    Used by the responder to make a relaying port dead immediately, even before
    the process is gone. Separate table so it survives a table flush.
    """
    ports = sorted({int(p) for p in ports if p})
    L = [f"table inet {table} {{", f"    chain {table}_input {{",
         f"        type filter hook input priority filter - 10; policy accept;",
         "        ct state established,related counter accept",
         # Loopback and the operator's allowlist survive. Quarantining a port
         # must stop the relay, not break the machine's own services or the
         # one thing the operator deliberately opened.
         '        iifname "lo" counter accept comment "ward:quarantine-lo"']
    for port in allow:
        L.append(
            f"        ip saddr {lan_cidr} tcp dport {port} counter accept "
            f'comment "ward:quarantine-lan-allow"'
        )
    for port in ports:
        L.append(f"        tcp dport {port} counter drop comment \"ward:quarantine\"")
        L.append(f"        udp dport {port} counter drop comment \"ward:quarantine\"")
    L += ["    }", "}"]
    return "\n".join(L) + "\n"


def render_unquarantine(table: str = "ward_quarantine") -> str:
    return f"delete table inet {table}\n"


# ------------------------------------------------------------------ apply


def _nft(script: str, timeout: float = 15.0) -> tuple[int, str, str]:
    """Feed a script to nft via a file.

    Uses /run/ward when we can write it, and a private temp file otherwise, so
    that a read-only caller (a plain `ward status`) can still render and check.
    """
    import tempfile

    fd, tmp = tempfile.mkstemp(prefix="ward-nft-", suffix=".nft", dir=_scratch_dir())
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(script)
        return run(["nft", "-f", tmp], timeout=timeout)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def _scratch_dir() -> str | None:
    if os.access("/run/ward", os.W_OK):
        return "/run/ward"
    return None


def check(config) -> tuple[bool, str]:
    """Validate the rendered ruleset without touching the live ruleset."""
    import tempfile

    fd, tmp = tempfile.mkstemp(prefix="ward-nft-", suffix=".nft")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(render(config))
        rc, out, err = run(["nft", "-c", "-f", tmp], timeout=15)
        return rc == 0, (err or out).strip()
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def apply(config, persist: bool = True) -> tuple[bool, str]:
    """Install the WARD table. Only touches our own table."""
    if not util.is_root():
        return False, "nftables apply requires root"
    ok, msg = check(config)
    if not ok:
        return False, f"ruleset failed validation: {msg}"
    rc, out, err = run(["nft", "list", "ruleset"], timeout=10)
    family = config.get("firewall.family", "inet")
    table = config.get("firewall.table", TABLE)
    pre = f"delete table {family} {table}\n" if f"table {family} {table}" in out else ""
    rc, out, err = _nft(pre + render(config))
    if rc != 0:
        return False, f"nft -f failed: {err.strip() or out.strip()}"
    if persist:
        path = "/etc/ward/nftables-ward.conf"
        try:
            util.atomic_write(path, render(config), 0o600)
        except OSError as exc:
            return True, f"applied (persist failed: {exc})"
    return True, f"applied table {family} {table}"


def remove(table: str = TABLE, family: str = "inet") -> tuple[bool, str]:
    if not util.is_root():
        return False, "requires root"
    rc, _, err = _nft(f"delete table {family} {table}\n")
    if rc != 0 and "No such file" not in err:
        return False, err.strip()
    return True, f"removed table {family} {table}"


def quarantine_ports(ports: Iterable[int], table: str = "ward_quarantine",
                     config=None) -> tuple[bool, str]:
    if not util.is_root():
        return False, "requires root"
    ports = list(ports)
    if not ports:
        return True, "nothing to quarantine"
    allow: list[int] = []
    cidr = "192.168.0.0/16"
    if config is not None:
        allow = [int(p) for p in config.get("firewall.lan_allowlist", [])]
        cidr = config.get("identity.trusted_lan_cidr", cidr)
    _nft(render_unquarantine(table))
    rc, _, err = _nft(render_quarantine(ports, table, allow, cidr))
    if rc != 0:
        return False, err.strip()
    return True, f"quarantined ports {sorted(set(ports))} in table inet {table}"


def unquarantine(table: str = "ward_quarantine") -> tuple[bool, str]:
    _nft(render_unquarantine(table))
    return True, f"cleared quarantine table inet {table}"


def counters(config) -> dict[str, int]:
    """Read packet counters out of the live table, for `ward status`.

    Reading a base chain's counters needs CAP_NET_ADMIN, so an unprivileged
    caller gets an empty result and a clear message rather than a table that
    looks absent.
    """
    table = config.get("firewall.table", TABLE)
    rc, out, err = run(["nft", "list", "table", "inet", table], timeout=10)
    if rc != 0:
        if not util.is_root():
            raise PermissionError(
                "reading nftables counters needs root (CAP_NET_ADMIN): "
                f"{err.strip() or 'permission denied'}"
            )
        return {}
    counts: dict[str, int] = {}
    for m in re.finditer(
        r"counter packets (\d+) bytes \d+ comment \"ward:([\w-]+)\"", out
    ):
        counts[m.group(2)] = int(m.group(1))
    return counts
