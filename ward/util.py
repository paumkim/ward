"""Small shared helpers: subprocess, hashing, atomic writes, time, formatting.

No third-party dependencies on purpose. WARD has to keep working on a machine
that is being actively attacked, so its own dependency surface stays at zero.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import time
from typing import Any, Iterable, Sequence

# ---------------------------------------------------------------- time


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    ts = now() if ts is None else ts
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
    return f"{base}{int((ts % 1) * 1000):03d}{_offset()}"


def _offset() -> str:
    off = -time.timezone
    if time.daylight and time.localtime().tm_isdst:
        off = -time.altzone
    sign = "+" if off >= 0 else "-"
    off = abs(off)
    return f"{sign}{off // 3600:02d}:{(off % 3600) // 60:02d}"


def ago(ts: float, ref: float | None = None) -> str:
    ref = now() if ref is None else ref
    d = max(0.0, ref - ts)
    if d < 1:
        return "just now"
    if d < 60:
        return f"{int(d)}s ago"
    if d < 3600:
        return f"{int(d // 60)}m ago"
    if d < 86400:
        return f"{int(d // 3600)}h ago"
    return f"{int(d // 86400)}d ago"


# ---------------------------------------------------------------- hashing


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def sha256_file(path: str, limit: int | None = None) -> str | None:
    """Hash a file. Returns None when it cannot be read (races, permissions)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            if limit is None:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            else:
                h.update(fh.read(limit))
    except (OSError, ValueError):
        return None
    return h.hexdigest()


def canonical_json(obj: Any) -> str:
    """Stable serialization used for hashing. Key order must never drift."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


# ---------------------------------------------------------------- fs


def atomic_write(path: str, data: str, mode: int = 0o600) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def ensure_dir(path: str, mode: int = 0o700) -> str:
    os.makedirs(path, mode=mode, exist_ok=True)
    return path


def read_text(path: str, limit: int = 1 << 20) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def read_bytes(path: str, limit: int = 1 << 24) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


# ---------------------------------------------------------------- proc


def run(
    argv: Sequence[str],
    timeout: float = 10.0,
    check: bool = False,
    env: dict | None = None,
) -> tuple[int, str, str]:
    """Run a command, never raise on failure, never block forever."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        p = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=full_env,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except (OSError, ValueError) as exc:
        return 127, "", str(exc)
    if check and p.returncode != 0:
        raise RuntimeError(f"{shlex.join(argv)} -> {p.returncode}: {p.stderr.strip()}")
    return p.returncode, p.stdout, p.stderr


def is_root() -> bool:
    return os.geteuid() == 0


def require_root(what: str) -> None:
    if not is_root():
        raise SystemExit(f"ward: {what} requires root (try: sudo ward {what})")


# ---------------------------------------------------------------- net


_HEX32 = re.compile(r"^[0-9A-Fa-f]{8}$")
_HEX4W = re.compile(r"^[0-9A-Fa-f]{32}$")


def parse_hex_addr(field: str) -> str:
    """Decode /proc/net/{tcp,udp} address fields into dotted-quad / ipv6."""
    if ":" not in field:
        return field
    addr, _, port = field.partition(":")
    try:
        port_i = int(port, 16)
    except ValueError:
        return field
    if _HEX32.match(addr):
        b = bytes.fromhex(addr)[::-1]
        return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}:{port_i}"
    if _HEX4W.match(addr):
        b = bytes.fromhex(addr)
        b = b"".join(b[i : i + 4][::-1] for i in range(0, 16, 4))
        # compress the longest run of zero 16-bit groups, like inet_ntop
        groups = [b[i : i + 2].hex() for i in range(0, 16, 2)]
        best_start, best_len, cur_start, cur_len = -1, 0, -1, 0
        for i, g in enumerate(groups + ["x"]):
            if g == "0000" and i < len(groups):
                if cur_len == 0:
                    cur_start = i
                cur_len += 1
            else:
                if cur_len > best_len:
                    best_start, best_len = cur_start, cur_len
                cur_len = 0
        if best_len > 1:
            head = ":".join(groups[:best_start])
            tail = ":".join(groups[best_start + best_len :])
            v6 = f"{head}::{tail}" if head and tail else f"{head}::{tail}" or "::"
        else:
            v6 = ":".join(groups)
        return f"[{v6}]:{port_i}"
    return field


def split_addr(field: str) -> tuple[str, int]:
    if field.startswith("["):
        host, _, rest = field.partition("]")
        return host[1:], int(rest.lstrip(":") or 0)
    host, _, port = field.rpartition(":")
    return host, int(port or 0)


def is_loopback(host: str) -> bool:
    if host in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1"):
        return True
    return host.startswith("127.")


def is_wildcard(host: str) -> bool:
    return host in ("0.0.0.0", "::", "*", "")


def is_linklocal(host: str) -> bool:
    return host.startswith(("169.254.", "fe80:", "fe80::"))


def is_multicast(host: str) -> bool:
    return (
        host.startswith("224.")
        or host.startswith("ff")
        or host in ("ff00::",)
    )


def net16(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[:2]) if len(parts) == 4 else host


# ---------------------------------------------------------------- fmt


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def human_int(n: int) -> str:
    return f"{n:,}"


def truncate(s: str, n: int) -> str:
    s = s.replace("\x00", "")
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def first(iterable: Iterable[Any], default: Any = None) -> Any:
    for item in iterable:
        return item
    return default
