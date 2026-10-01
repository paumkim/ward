"""Hash-chained append-only event log.

Why a chain: if the machine is being sold as a proxy, the attacker will want to
erase the evidence. A plain log can be truncated or rewritten silently. Each
record carries the hash of the previous one, so any edit, deletion or reordering
is detectable with `ward verify-log`.

Also rate-limits, so a runaway loop cannot turn the log into a disk-filler, and
keeps the per-minute budget configurable.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Iterator

from . import util
from .util import canonical_json, now, sha256_text

GENESIS = "0" * 64

#: Fields that participate in the chain hash. Anything outside this set is
#: metadata that a future schema bump may add without invalidating old chains.
_CHAINED = ("ts", "seq", "kind", "score", "rule", "title", "detail", "prev")


class EventLog:
    def __init__(
        self,
        path: str,
        mode: str = "hashchain",
        rotate_bytes: int = 32 * 1024 * 1024,
        max_per_minute: int = 240,
    ):
        self.path = path
        self.mode = mode
        self.rotate_bytes = rotate_bytes
        self.max_per_minute = max_per_minute
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS
        self._minute = 0.0
        self._minute_count = 0
        self._dropped = 0
        self._declared_records = 0
        self._load_head()
        self._declared_records = self._seq
        try:
            util.ensure_dir(os.path.dirname(path) or ".", 0o700)
        except OSError:
            # A read-only or unwritable log location must not stop the detector
            # from running; emit() will report the failure instead.
            pass

    # ------------------------------------------------------------ head

    def _load_head(self) -> None:
        last = self._last_record()
        if last:
            self._seq = int(last.get("seq", 0))
            self._prev = last.get("hash", GENESIS)

    def _last_record(self) -> dict | None:
        if not os.path.isfile(self.path):
            return None
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                block = min(size, 262144)
                fh.seek(size - block)
                tail = fh.read(block).decode("utf-8", "replace")
        except OSError:
            return None
        for line in reversed(tail.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                return rec
        return None

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def head(self) -> str:
        return self._prev

    @property
    def seq(self) -> int:
        """How many records this writer believes exist."""
        return self._declared_records

    # ------------------------------------------------------------ write

    def _rate_ok(self) -> bool:
        t = now()
        if t - self._minute >= 60:
            self._minute, self._minute_count = t, 0
        if self._minute_count >= self.max_per_minute:
            self._dropped += 1
            return False
        self._minute_count += 1
        return True

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self.path) < self.rotate_bytes:
                return
        except OSError:
            return
        stamp = time_stamp()
        try:
            os.replace(self.path, f"{self.path}.{stamp}")
        except OSError:
            return
        self._prev, self._seq = GENESIS, 0

    def emit(
        self,
        kind: str,
        detail: Any = None,
        *,
        title: str = "",
        score: int = 0,
        rule: str = "",
        **extra: Any,
    ) -> dict | None:
        with self._lock:
            if not self._rate_ok():
                return None
            self._seq += 1
            rec: dict[str, Any] = {
                "ts": now(),
                "iso": util.iso(),
                "seq": self._seq,
                "kind": kind,
                "score": int(score),
                "rule": rule,
                "title": title or kind,
                "detail": detail,
                "prev": self._prev if self.mode == "hashchain" else GENESIS,
            }
            rec.update(extra)
            rec["hash"] = self._hash(rec)
            self._prev = rec["hash"]
            self._declared_records = self._seq
            try:
                self._rotate_if_needed()
                with open(self.path, "a") as fh:
                    fh.write(canonical_json(rec) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                return None
            return rec

    def _hash(self, rec: dict) -> str:
        if self.mode != "hashchain":
            return sha256_text(canonical_json(rec))
        payload = {k: rec.get(k) for k in _CHAINED}
        return sha256_text(canonical_json(payload))

    # ------------------------------------------------------------ read

    def read(self, limit: int = 200, kinds: set[str] | None = None) -> list[dict]:
        out: list[dict] = []
        if not os.path.isfile(self.path):
            return out
        with open(self.path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if kinds and rec.get("kind") not in kinds:
                    continue
                out.append(rec)
        out.sort(key=lambda r: r.get("seq", 0))
        return out[-limit:] if limit else out

    def iter_all(self) -> Iterator[dict]:
        if not os.path.isfile(self.path):
            return
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
                    yield rec

    def verify(self) -> dict:
        """Walk the chain. Returns a verdict dict with the first break found.

        "I could not read the log" and "the log is empty" are different states,
        and neither of them is "chain intact". A tamper-evident log that
        reports all-clear to anyone who cannot open it is worse than no log.
        """
        dirpath = os.path.dirname(self.path) or "."
        try:
            dir_readable = os.access(dirpath, os.R_OK | os.X_OK)
            os.listdir(dirpath)
        except OSError:
            dir_readable = False
        if not dir_readable:
            return {
                "ok": False,
                "records": 0,
                "reason": f"cannot read {dirpath} (permission denied); "
                          f"verify as root: sudo ward events --verify",
                "head": None,
            }
        if not os.path.exists(self.path):
            if self._declared_records:
                return {
                    "ok": False,
                    "records": 0,
                    "reason": (
                        f"{self.path} does not exist but the daemon state claims "
                        f"{self._declared_records} record(s) -- the log was deleted"
                    ),
                    "head": None,
                }
            return {
                "ok": True,
                "records": 0,
                "reason": "no log file yet; nothing has been recorded",
                "head": GENESIS,
            }
        if not os.access(self.path, os.R_OK):
            return {
                "ok": False,
                "records": 0,
                "reason": f"cannot read {self.path} (permission denied); "
                          f"verify as root: sudo ward events --verify",
                "head": None,
            }
        prev = GENESIS
        count = 0
        bad_seq = False
        last_seq = 0
        for rec in self.iter_all():
            count += 1
            if rec.get("seq") != last_seq + 1:
                bad_seq = True
            last_seq = rec.get("seq", last_seq)
            if self.mode != "hashchain":
                continue
            if rec.get("prev") != prev:
                return {
                    "ok": False,
                    "records": count,
                    "reason": "chain break: prev hash mismatch",
                    "at_seq": rec.get("seq"),
                    "head": prev,
                }
            expect = self._hash({**rec, "hash": None})
            if rec.get("hash") != expect:
                return {
                    "ok": False,
                    "records": count,
                    "reason": "record tampered: content hash mismatch",
                    "at_seq": rec.get("seq"),
                    "head": prev,
                }
            prev = rec["hash"]
        if count < self._declared_records:
            return {
                "ok": False,
                "records": count,
                "reason": (
                    f"log holds {count} record(s) but the writer claims "
                    f"{self._declared_records} -- {self._declared_records - count} "
                    f"record(s) were deleted"
                ),
                "head": prev,
            }
        return {
            "ok": True,
            "records": count,
            "reason": "chain intact",
            "head": prev,
            "seq_gap": bad_seq,
        }

    def set_expected_records(self, n: int) -> None:
        """Record how many records the writer believes it has written.

        The tripwire uses this: an attacker who empties the log cannot also
        rewrite the daemon's state file without leaving a mismatch.
        """
        self._declared_records = max(0, int(n))

    def note_write(self) -> None:
        self._declared_records = self._seq

    def prune(self, keep_days: int) -> int:
        """Delete rotated files older than keep_days. Never touches the live log."""
        removed = 0
        base = os.path.dirname(self.path) or "."
        prefix = os.path.basename(self.path) + "."
        cutoff = now() - keep_days * 86400
        try:
            names = os.listdir(base)
        except OSError:
            return 0
        for name in names:
            if not name.startswith(prefix):
                continue
            p = os.path.join(base, name)
            try:
                if os.path.getmtime(p) < cutoff:
                    os.remove(p)
                    removed += 1
            except OSError:
                continue
        return removed


def time_stamp() -> str:
    import time

    return time.strftime("%Y%m%dT%H%M%S", time.localtime())
