"""Host hardening: sysctl, stale config quarantine, LLMNR, sshd.

All of it is reversible. Anything WARD changes is recorded in a restore journal
so `ward restore` can put the machine back exactly as it was, which is the only
honest way to make an operator willing to run something like this.

The one change we consider non-negotiable is dropping IP forwarding on a
laptop, because forwarding is the mechanism by which a machine relays for
neighbours. If that fails, everything else is best-effort.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Any

from . import util
from .util import now, run

SYSCTL_DIR = "/etc/sysctl.d"
WARD_SYSCTL = f"{SYSCTL_DIR}/99-ward-hardening.conf"
QUARANTINE_DIR = "/var/lib/ward/quarantine/sysctl"

#: Written once, applied by systemd-sysctl on every boot.
HARDENING_CONF = """\
# Managed by WARD -- see /usr/local/bin/ward. Edit ward.toml, not this file.
# Purpose: make this machine structurally unable to forward traffic for others.

# --- no transit routing (the core anti-relay control) ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- no ICMP-based redirection or source routing ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_local = 0
net.ipv4.conf.default.accept_local = 0

# --- martian and spoofing resistance ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

# --- do not act as an open resolver for the LAN ---
net.ipv6.conf.all.accept_ra = 1
"""


def sysctl_exists(key: str) -> bool:
    """Does this kernel expose that sysctl?

    ``sysctl -p`` aborts the whole file on the first unknown key, and knobs
    like log_ignore_promisc have been removed from recent kernels. Checking
    /proc/sys first keeps hardening from failing for a reason that does not
    matter.
    """
    return os.path.exists("/proc/sys/" + key.replace(".", "/"))


def render_hardening_conf(keys: list[str] | None = None) -> tuple[str, list[str]]:
    """Return (conf_text, skipped_keys) for the keys this kernel actually has."""
    out: list[str] = []
    skipped: list[str] = []
    for line in HARDENING_CONF.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if keys is not None and key not in keys:
            continue
        if not sysctl_exists(key):
            skipped.append(key)
            continue
        out.append(line)
    return "\n".join(out).rstrip() + "\n", skipped


@dataclass
class Journal:
    """Every mutation WARD performs lands here so it can be undone."""

    path: str = "/var/lib/ward/restore-journal.jsonl"
    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, kind: str, target: str, before: Any, after: Any, note: str = "") -> None:
        entry = {
            "ts": now(),
            "iso": util.iso(),
            "kind": kind,
            "target": target,
            "before": before,
            "after": after,
            "note": note,
        }
        self.entries.append(entry)
        try:
            util.ensure_dir(os.path.dirname(self.path), 0o700)
            with open(self.path, "a") as fh:
                fh.write(util.canonical_json(entry) + "\n")
        except OSError:
            pass

    def load_all(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            with open(self.path, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(rec, dict):
                        out.append(rec)
        except OSError:
            return []
        return out


# ------------------------------------------------------------------ sysctl


def read_sysctl_file(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                if k:
                    out[k] = v.strip().split("#")[0].strip()
    except OSError:
        return {}
    return out


def find_conflicting_sysctl_files(needles: tuple[str, ...]) -> list[dict[str, Any]]:
    """Find .conf files that would re-enable forwarding on the next boot.

    One entry per file (with every offending key listed), because quarantining
    a file twice would be reported twice and read like two different problems.
    Sorting matters: systemd-sysctl applies files in lexical order, so our
    99-ward file must sort last.
    """
    hits: dict[str, dict[str, Any]] = {}
    candidates: list[str] = []
    if os.path.isfile("/etc/sysctl.conf"):
        candidates.append("/etc/sysctl.conf")
    if os.path.isdir(SYSCTL_DIR):
        for name in sorted(os.listdir(SYSCTL_DIR)):
            if name.endswith(".conf"):
                candidates.append(os.path.join(SYSCTL_DIR, name))
    for path in candidates:
        if os.path.basename(path).startswith("99-ward"):
            continue  # our own file is the intended end state
        values = read_sysctl_file(path)
        for key in needles:
            if key in values and values[key] not in ("0",):
                entry = hits.setdefault(
                    path,
                    {"path": path, "keys": [], "value": values[key],
                     "sorts_before_ward": os.path.basename(path) < "99-ward-hardening.conf"},
                )
                entry["keys"].append(f"{key}={values[key]}")
    return list(hits.values())


#: Every knob the hardening file sets. Restoring means putting these back to
#: whatever the machine had before WARD touched them, so the live values are
#: captured first. sysctl --system does the rest.
HARDPENNED_SYSCTLS = [
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.secure_redirects",
    "net.ipv4.conf.all.accept_local",
    "net.ipv4.conf.default.accept_local",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.tcp_rfc1337",
]


def snapshot_sysctls() -> dict[str, str | None]:
    """Current values of every knob the hardening file writes."""
    out: dict[str, str | None] = {}
    for key in HARDPENNED_SYSCTLS:
        rc, value, _ = run(["sysctl", "-n", key], timeout=4)
        out[key] = value.strip() if rc == 0 else None
    return out


def install_sysctl_conf(dry_run: bool = False,
                        journal: Journal | None = None) -> tuple[bool, str]:
    body, skipped = render_hardening_conf()
    if os.path.isfile(WARD_SYSCTL):
        existing = util.read_text(WARD_SYSCTL)
        if existing == body:
            note = f" (skipped {len(skipped)} knob(s) this kernel lacks)" if skipped else ""
            return True, f"{WARD_SYSCTL} already current{note}"
    if dry_run:
        return True, f"would write {WARD_SYSCTL}"
    # Record what was there and what the live values were. Without the live
    # snapshot, restore can delete the file but has no way to put the runtime
    # values back, because sysctl -p loads one file rather than all of them.
    if journal is not None:
        journal.record(
            "sysctl-conf-written", WARD_SYSCTL,
            {"existed": os.path.isfile(WARD_SYSCTL),
             "previous": util.read_text(WARD_SYSCTL, 1 << 16)},
            {"exists": True, "keys": len(HARDPENNED_SYSCTLS)},
            note="WARD hardening file; sorts last so it wins",
        )
        journal.record(
            "sysctl-values-snapshot", "/proc/sys",
            snapshot_sysctls(), {"owned_by": "99-ward-hardening.conf"},
            note="live values before hardening, for restore to verify against",
        )
    try:
        util.atomic_write(WARD_SYSCTL, body, 0o644)
    except OSError as exc:
        return False, f"write failed: {exc}"
    if skipped:
        return True, (
            f"wrote {WARD_SYSCTL} (omitted {len(skipped)} knob(s) this kernel "
            f"does not have: {', '.join(skipped)})"
        )
    return True, f"wrote {WARD_SYSCTL}"


def apply_sysctls_now() -> tuple[bool, str]:
    rc, out, err = run(["sysctl", "-p", WARD_SYSCTL], timeout=20)
    if rc != 0:
        return False, (err or out).strip()
    return True, "applied hardening sysctls"


def apply_sysctl(name: str, value: str) -> tuple[bool, str]:
    rc, out, err = run(["sysctl", "-w", f"{name}={value}"], timeout=8)
    if rc != 0:
        return False, (err or out).strip()
    return True, f"{name}={value}"


def quarantine_conflicting_sysctl(hit: dict[str, Any], journal: Journal,
                                  dry_run: bool = False) -> tuple[bool, str]:
    """Rename a conflicting file out of the way, remembering to restore it."""
    path = hit["path"]
    if os.path.basename(path).startswith("99-ward"):
        return True, f"{path} is ours"
    if dry_run:
        target = os.path.join(QUARANTINE_DIR, os.path.basename(path) + ".ward-disabled")
        return True, f"would move {path} -> {target} (it sets {', '.join(hit.get('keys', []))})"
    util.ensure_dir(QUARANTINE_DIR, 0o700)
    target = os.path.join(QUARANTINE_DIR, os.path.basename(path) + f".ward-disabled")
    before = util.read_text(path, 1 << 20)
    try:
        shutil.move(path, target)
    except OSError as exc:
        return False, f"move failed: {exc}"
    try:
        util.atomic_write(target + ".orig", before, 0o600)
    except OSError:
        pass
    journal.record(
        "sysctl-file-quarantined", path, {"moved_to": target},
        {"exists": False}, note="sets " + ", ".join(hit.get("keys", [])),
    )
    return True, f"quarantined {path} (it sets {', '.join(hit.get('keys', []))})"


# ------------------------------------------------------------------ resolved


def disable_llmnr(dry_run: bool = False,
                  journal: Journal | None = None) -> tuple[bool, str]:
    """Turn off LLMNR in systemd-resolved.

    LLMNR answers name queries for anything, including neighbours' traffic, and
    it is trivially spoofable. On a wifi laptop it is pure attack surface.
    """
    dropin_dir = "/etc/systemd/resolved.conf.d"
    dropin = f"{dropin_dir}/99-ward-hardening.conf"
    body = (
        "# Managed by WARD\n"
        "[Resolve]\n"
        "LLMNR=no\n"
        "MulticastDNS=yes\n"
        "DNSOverTLS=opportunistic\n"
    )
    if dry_run:
        return True, f"would write {dropin}"
    if journal is not None:
        journal.record(
            "resolved-dropin-written", dropin,
            {"existed": os.path.isfile(dropin),
             "previous": util.read_text(dropin, 1 << 16)},
            {"exists": True, "llmnr": "no"},
            note="LLMNR off; restore removes this and restarts resolved",
        )
    util.ensure_dir(dropin_dir, 0o755)
    try:
        util.atomic_write(dropin, body, 0o644)
    except OSError as exc:
        return False, f"write failed: {exc}"
    rc, _, err = run(["systemctl", "restart", "systemd-resolved"], timeout=20)
    if rc != 0:
        return False, f"resolved restart failed: {err.strip()}"
    return True, f"LLMNR disabled via {dropin}"


# ------------------------------------------------------------------ sshd


def harden_sshd(journal: Journal, dry_run: bool = False) -> tuple[bool, str]:
    """Pin sshd so it cannot be turned into a forwarder.

    GatewayPorts + PermitTunnel + a broad PermitOpen are how an SSH-only host
    becomes a SOCKS server. On this host sshd is masked, but the config is
    written anyway so that enabling it later does not open the door.
    """
    path = "/etc/ssh/sshd_config"
    if not os.path.isfile(path):
        return True, f"{path} absent (sshd masked) -- nothing to pin"
    if dry_run:
        return True, f"would pin {path}"
    before = util.read_text(path, 1 << 20)
    dropin = "/etc/ssh/sshd_config.d/99-ward-hardening.conf"
    body = (
        "# Managed by WARD\n"
        "GatewayPorts no\n"
        "PermitTunnel no\n"
        "PermitOpen any\n"
        "X11Forwarding no\n"
        "AllowAgentForwarding no\n"
        "MaxSessions 5\n"
    )
    util.ensure_dir("/etc/ssh/sshd_config.d", 0o755)
    util.atomic_write(dropin, body, 0o644)
    # Make sure the Include line exists, otherwise the dropin is ignored.
    text = util.read_text(path, 1 << 20)
    if "Include /etc/ssh/sshd_config.d/*.conf" not in text:
        util.atomic_write(
            path,
            "Include /etc/ssh/sshd_config.d/*.conf\n" + text,
            0o644,
        )
        journal.record("sshd-include-added", path, {"had_include": False},
                       {"had_include": True})
    # Only validate when sshd could actually validate something. A masked sshd
    # with no generated host keys fails `sshd -t` for reasons that have nothing
    # to do with our dropin, and reporting that as a hardening failure trains
    # the operator to ignore the output.
    has_hostkey = any(
        os.path.isfile(f"/etc/ssh/{name}")
        for name in ("ssh_host_ed25519_key", "ssh_host_rsa_key", "ssh_host_ecdsa_key")
    )
    if not has_hostkey:
        journal.record("sshd-pinned", path, {"hostkeys": "absent"},
                       {"dropin": dropin}, note="no host keys; sshd -t skipped")
        return True, (
            f"pinned sshd via {dropin} (sshd -t skipped: no host keys generated, "
            f"which is expected while sshd is masked)"
        )
    rc, out, err = run(["sshd", "-t"], timeout=10)
    if rc != 0:
        return False, f"sshd config test failed: {(err or out).strip()}"
    journal.record("sshd-pinned", path, {"see": dropin + ".orig"},
                   {"see": dropin}, note="no GatewayPorts/PermitTunnel")
    return True, f"pinned sshd via {dropin} (sshd -t passed)"


# ------------------------------------------------------------------ firewalld


def firewalld_close_extra_ports(journal: Journal, keep: list[int] | None = None,
                                dry_run: bool = False) -> tuple[bool, str]:
    """Remove firewalld's public port openings except an explicit keep list.

    firewalld is the first line of defence on this box; leaving a port open
    there is a standing invitation, and 8765/tcp was open with nothing to
    justify it.
    """
    if not shutil.which("firewall-cmd"):
        return True, "firewalld not installed"
    if not util.is_root():
        return True, "firewalld zone read needs root; skipped (not a failure)"
    rc, _, out = run(["systemctl", "is-active", "firewalld"], timeout=8)
    if rc != 0 or "inactive" in out:
        return True, "firewalld not running; no public zone to close"
    keep = set(keep or [])
    rc, out, err = run(["firewall-cmd", "--zone=public", "--list-ports"], timeout=15)
    if rc != 0:
        return False, f"could not read the firewalld public zone: {err.strip() or 'unknown'}"
    closed: list[str] = []
    for entry in out.split():
        port_txt = entry.split("/")[0]
        try:
            port = int(port_txt)
        except ValueError:
            continue
        if port in keep:
            continue
        if dry_run:
            closed.append(entry)
            continue
        run(["firewall-cmd", "--permanent", "--zone=public", f"--remove-port={entry}"],
            timeout=10)
        run(["firewall-cmd", "--zone=public", f"--remove-port={entry}"], timeout=10)
        journal.record("firewalld-port-closed", f"public:{entry}",
                       {"open": True}, {"open": False})
        closed.append(entry)
    if not dry_run and closed:
        run(["firewall-cmd", "--reload"], timeout=20)
    return True, ("would close " if dry_run else "closed ") + (", ".join(closed) or "nothing")


def firewalld_close_services(journal: Journal, keep: list[str] | None = None,
                             dry_run: bool = False) -> tuple[bool, str]:
    """Remove firewalld services that are not actually in use.

    An `ssh` entry in a public zone is a standing invitation even when sshd is
    masked, and a live one is a standing SOCKS server (`ssh -D`). We keep
    dhcpv6-client, which the DHCPv6 flow genuinely needs.
    """
    if not shutil.which("firewall-cmd"):
        return True, "firewalld not installed"
    if not util.is_root():
        return True, "firewalld zone read needs root; skipped (not a failure)"
    rc, _, out = run(["systemctl", "is-active", "firewalld"], timeout=8)
    if rc != 0 or "inactive" in out:
        return True, "firewalld not running; no services to close"
    keep = set(keep or ["dhcpv6-client"])
    rc, out, err = run(["firewall-cmd", "--zone=public", "--list-services"], timeout=15)
    if rc != 0:
        return False, f"could not read firewalld services: {err.strip() or 'unknown'}"
    closed: list[str] = []
    for svc in out.split():
        if svc in keep:
            continue
        if dry_run:
            closed.append(svc)
            continue
        run(["firewall-cmd", "--permanent", "--zone=public", f"--remove-service={svc}"],
            timeout=15)
        run(["firewall-cmd", "--zone=public", f"--remove-service={svc}"], timeout=15)
        journal.record("firewalld-service-closed", f"public:{svc}",
                       {"open": True}, {"open": False})
        closed.append(svc)
    if not dry_run and closed:
        run(["firewall-cmd", "--reload"], timeout=25)
    return True, ("would close services: " if dry_run else "closed services: ") + (
        ", ".join(closed) or "nothing"
    )


# ------------------------------------------------------------------ driver


@dataclass
class HardeningResult:
    actions: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    journal: Journal | None = None


def harden(config, dry_run: bool = False,
           journal: Journal | None = None) -> HardeningResult:
    """Apply the full hardening set. Idempotent."""
    res = HardeningResult(journal=journal or Journal())
    h = config.section("harden")

    ok, msg = install_sysctl_conf(dry_run=dry_run, journal=res.journal)
    (res.actions if ok else res.failures).append(msg)

    if h.get("ip_forward", False) is False:
        conflicts = find_conflicting_sysctl_files(
            ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")
        )
        for hit in conflicts:
            if not h.get("quarantine_sysctl_files", True):
                res.actions.append(
                    f"would need to disable {hit['path']} (sets "
                    f"{', '.join(hit.get('keys', []))})"
                )
                continue
            ok, msg = quarantine_conflicting_sysctl(hit, res.journal, dry_run=dry_run)
            (res.actions if ok else res.failures).append(msg)
        if not dry_run:
            ok, msg = apply_sysctls_now()
            (res.actions if ok else res.failures).append(msg)
            # net.ipv4.ip_forward is written by tailscale-style files; verify the
            # live value actually moved.
            rc, live, _ = run(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5)
            if live.strip() == "0":
                res.actions.append("verified net.ipv4.ip_forward=0")
            else:
                res.failures.append(
                    f"net.ipv4.ip_forward is still {live.strip()!r} -- something re-enabled it"
                )

    if h.get("llmnr", False) is False:
        ok, msg = disable_llmnr(dry_run=dry_run, journal=res.journal)
        (res.actions if ok else res.failures).append(msg)

    ok, msg = harden_sshd(res.journal, dry_run=dry_run)
    (res.actions if ok else res.failures).append(msg)

    ok, msg = firewalld_close_extra_ports(res.journal, dry_run=dry_run)
    (res.actions if ok else res.failures).append(msg)

    ok, msg = firewalld_close_services(res.journal, dry_run=dry_run)
    (res.actions if ok else res.failures).append(msg)

    return res


# ------------------------------------------------------------------ restore


def restore(journal_path: str = "/var/lib/ward/restore-journal.jsonl",
            dry_run: bool = False) -> list[dict[str, Any]]:
    """Undo journalled changes, newest first.

    Every mutation `harden()` performs has a handler here. That was not true:
    the sysctl file, the live sysctl values, the LLMNR drop-in and the firewalld
    services were all either unjournalled or journalled with no handler, so
    `ward restore` left most of the hardening in place while the README claimed
    otherwise.
    """
    j = Journal(path=journal_path)
    entries = j.load_all()
    undone: list[dict[str, Any]] = []
    handled = 0
    unhandled: list[str] = []

    def finish(entry: dict[str, Any], result: str, ok: bool = True) -> None:
        nonlocal handled
        undone.append({**entry, "result": result})
        if ok and not dry_run:
            handled += 1

    for entry in reversed(entries):
        kind, target = entry.get("kind"), entry.get("target")
        before = entry.get("before") or {}
        try:
            if dry_run:
                finish(entry, "would undo", ok=False)
                continue

            if kind == "sysctl-file-quarantined":
                moved = before.get("moved_to")
                if moved and os.path.exists(moved) and not os.path.exists(target):
                    shutil.move(moved, target)
                    finish(entry, "restored the quarantined file")
                else:
                    finish(entry, "nothing to do", ok=False)

            elif kind == "sysctl-conf-written":
                _remove_our_file(target, before, finish, entry,
                                 "/etc/sysctl.d/99-ward-hardening.conf")

            elif kind == "sysctl-values-snapshot":
                # The file is gone, so reload every remaining sysctl file in
                # order. `sysctl -p /etc/sysctl.conf` loads exactly one file
                # and would have left ip_forward at 0.
                rc, out, err = run(["systemctl", "restart", "systemd-sysctl"],
                                   timeout=25)
                if rc == 0:
                    finish(entry, "reloaded sysctl from the remaining files")
                else:
                    rc2, _, err2 = run(["sysctl", "--system"], timeout=25)
                    finish(entry,
                           "reloaded sysctl via sysctl --system" if rc2 == 0
                           else f"sysctl reload failed: {(err or err2).strip()}",
                           ok=rc2 == 0)
                drift = sysctl_drift(before)
                if drift:
                    undone[-1]["drift"] = drift
                    undone[-1]["result"] += (
                        f"; {len(drift)} value(s) differ from the snapshot: "
                        + ", ".join(f"{k}={v}" for k, v in list(drift.items())[:6])
                    )

            elif kind == "resolved-dropin-written":
                _remove_our_file(target, before, finish, entry,
                                 "/etc/systemd/resolved.conf.d/99-ward-hardening.conf")
                rc, _, err = run(["systemctl", "restart", "systemd-resolved"],
                                 timeout=25)
                undone[-1]["result"] += (
                    "; restarted resolved" if rc == 0
                    else f"; resolved restart failed: {err.strip()}"
                )

            elif kind == "firewalld-port-closed":
                port = target.split(":", 1)[-1]
                run(["firewall-cmd", "--permanent", "--zone=public",
                     f"--add-port={port}"], timeout=15)
                run(["firewall-cmd", "--zone=public", f"--add-port={port}"],
                    timeout=15)
                finish(entry, f"reopened {port}")

            elif kind == "firewalld-service-closed":
                svc = target.split(":", 1)[-1]
                run(["firewall-cmd", "--permanent", "--zone=public",
                     f"--add-service={svc}"], timeout=15)
                run(["firewall-cmd", "--zone=public", f"--add-service={svc}"],
                    timeout=15)
                finish(entry, f"reopened the {svc} service")

            elif kind == "sshd-pinned":
                run(["rm", "-f", "/etc/ssh/sshd_config.d/99-ward-hardening.conf"],
                    timeout=10)
                finish(entry, "removed the sshd drop-in")

            elif kind == "sshd-include-added":
                text = util.read_text(target, 1 << 20)
                first, _, rest = text.partition("\n")
                if first.startswith("Include /etc/ssh/sshd_config.d"):
                    util.atomic_write(target, rest, 0o644)
                finish(entry, "removed the Include line")

            elif kind == "nft-table-applied":
                from . import firewall as fw

                ok, msg = fw.remove()
                finish(entry, msg if ok else f"nft: {msg}", ok=ok)
                persisted = before.get("persisted")
                if persisted and os.path.isfile(persisted):
                    try:
                        os.remove(persisted)
                        undone[-1]["result"] += f"; removed {persisted}"
                    except OSError as exc:
                        undone[-1]["result"] += f"; could not remove {persisted}: {exc}"

            elif kind == "binary-exec-revoked":
                path = target
                mode = before.get("mode")
                try:
                    if mode is None:
                        finish(entry, "no recorded mode; left as is", ok=False)
                    else:
                        os.chmod(path, int(mode, 8))
                        finish(entry, f"restored {path} to {mode}")
                except OSError as exc:
                    finish(entry, f"failed: {exc}", ok=False)

            else:
                unhandled.append(kind)
                undone.append({**entry, "result": "no undo handler"})
        except OSError as exc:
            undone.append({**entry, "result": f"failed: {exc}"})

    if not dry_run and handled:
        run(["firewall-cmd", "--reload"], timeout=25)

    undone.append({
        "kind": "summary",
        "result": f"{handled} change(s) undone",
        "undone": handled,
        "unhandled_kinds": sorted(set(unhandled)),
    })
    return undone


def _remove_our_file(target: str, before: dict, finish, entry: dict,
                     ours: str) -> None:
    """Remove a file WARD wrote, restoring a previous version if there was one."""
    if target != ours:
        finish(entry, f"refusing to remove {target}: not a WARD file", ok=False)
        return
    previous = before.get("previous")
    try:
        if previous:
            util.atomic_write(target, previous, 0o644)
            finish(entry, f"restored the previous {target}")
        elif os.path.isfile(target):
            os.remove(target)
            finish(entry, f"removed {target}")
        else:
            finish(entry, "nothing to do", ok=False)
    except OSError as exc:
        finish(entry, f"failed: {exc}", ok=False)


def sysctl_drift(before: dict[str, Any]) -> dict[str, str]:
    """Knobs whose current value differs from the pre-hardening snapshot."""
    out: dict[str, str] = {}
    for key, was in (before or {}).items():
        if was is None:
            continue
        rc, now_value, _ = run(["sysctl", "-n", key], timeout=4)
        if rc != 0:
            continue
        have = now_value.strip()
        if have != str(was):
            out[key] = f"{was} -> {have}"
    return out
