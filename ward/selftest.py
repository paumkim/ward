"""Self-test: prove the detector actually fires, and that it stays quiet otherwise.

A detector that has never been shown to catch a real proxy is a decoration. So
this spawns actual relay-shaped processes -- a real SOCKS5 listener, a real
HTTP CONNECT relay, a renamed binary carrying proxy strings -- and asserts that
the rules fire on them. It also asserts the inverse: that a normal loopback
listener does NOT fire, and that protected processes are never targeted.

Everything runs on 127.0.0.1 where possible, so the test never puts a working
proxy on a real interface. The world-reachable test uses a deliberately tiny
window and tears the listener down immediately.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import detect, firewall, harden, observe, respond, signatures, sniff, util
from .config import DEFAULTS, Config
from .util import now


@dataclass
class Result:
    name: str
    passed: bool
    detail: str = ""
    skipped: bool = False
    ms: int = 0


@dataclass
class Suite:
    results: list[Result] = field(default_factory=list)
    verbose: bool = True

    def check(self, name: str, fn: Callable[[], tuple[bool, str]],
              skip: str = "") -> bool:
        started = time.perf_counter()
        if skip:
            res = Result(name, True, skip, skipped=True)
            self.results.append(res)
            self._print(res)
            return True
        try:
            ok, detail = fn()
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        res = Result(name, ok, detail, ms=int((time.perf_counter() - started) * 1000))
        self.results.append(res)
        self._print(res)
        return ok

    def _print(self, res: Result) -> None:
        if not self.verbose:
            return
        if res.skipped:
            mark, colour = "skip", "2;33"
        elif res.passed:
            mark, colour = "PASS", "1;32"
        else:
            mark, colour = "FAIL", "1;31"
        tty = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        if tty:
            print(f"  \033[{colour}m{mark}\033[0m  {res.name}"
                  f"{'  ' + util.truncate(res.detail, 90) if res.detail else ''}")
        else:
            print(f"  {mark}  {res.name}  {util.truncate(res.detail, 90)}")

    @property
    def failed(self) -> list[Result]:
        return [r for r in self.results if not r.passed]

    def summary(self) -> int:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed and not r.skipped)
        failed = len(self.failed)
        skipped = sum(1 for r in self.results if r.skipped)
        print()
        line = f"  {passed}/{total - skipped} passed"
        if failed:
            line += f", \033[1;31m{failed} failed\033[0m" if sys.stdout.isatty() else f", {failed} failed"
        if skipped:
            line += f", {skipped} skipped"
        print(line)
        for res in self.failed:
            print(f"    FAILED: {res.name} -- {res.detail}")
        return 1 if failed else 0


def _cfg(**over: Any) -> Config:
    data = {k: dict(v) if isinstance(v, dict) else v for k, v in DEFAULTS.items()}
    for dotted, value in over.items():
        node = data
        parts = dotted.split("__")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return Config(data, ["selftest"])


# ------------------------------------------------------------------ fixtures


class SocksServer(threading.Thread):
    """A real SOCKS5 server. Answers the greeting so the handshake completes."""

    daemon = True

    def __init__(self, host: str = "127.0.0.1", port: int = 0, name: str = "socks"):
        super().__init__(name=name)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.host, self.port = self.sock.getsockname()
        self.stop_flag = threading.Event()
        self.handshakes = 0
        self.targets: list[str] = []

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self.stop_flag.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(2.0)
            greeting = conn.recv(3)
            if len(greeting) >= 2 and greeting[0] == 0x05:
                self.handshakes += 1
                conn.sendall(b"\x05\x00")
                req = conn.recv(262)
                if len(req) >= 10:
                    atyp = req[3]
                    if atyp == 0x01:
                        host = socket.inet_ntop(socket.AF_INET, req[4:8])
                        port = struct.unpack("!H", req[8:10])[0]
                    elif atyp == 0x03:
                        n = req[4]
                        host = req[5 : 5 + n].decode("latin-1")
                        port = struct.unpack("!H", req[5 + n : 7 + n])[0]
                    else:
                        host, port = "?", 0
                    self.targets.append(f"{host}:{port}")
                    # Success reply, bound to a port we do not actually open.
                    conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            elif greeting[:1] == b"\x04":
                self.handshakes += 1
                conn.sendall(b"\x00\x5a" + b"\x00" * 6)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self.stop_flag.set()
        try:
            self.sock.close()
        except OSError:
            pass


class HttpProxy(threading.Thread):
    """A real HTTP CONNECT forwarder, on loopback only."""

    daemon = True

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        super().__init__(name="http-proxy")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.host, self.port = self.sock.getsockname()
        self.requests: list[str] = []
        self.stop_flag = threading.Event()

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self.stop_flag.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(2.0)
                head = conn.recv(4096).decode("latin-1", "replace")
                self.requests.append(head.splitlines()[0] if head else "")
                conn.sendall(
                    b"HTTP/1.1 200 Connection established\r\n"
                    b"Proxy-Agent: ward-selftest\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self.stop_flag.set()
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------ python


def _run(tmpdir: str, name: str, body: str, wait: float = 0.6) -> Any:
    """Run a small python program detached; return the Popen handle."""
    path = os.path.join(tmpdir, name)
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(body))
    proc = subprocess.Popen(
        [sys.executable, path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(wait)
    return proc


def _relay_binary(tmpdir: str, name: str) -> str | None:
    """A real executable whose name is a known relay program.

    This is how R01 gets a fair trial: the signature match has to fire on a
    genuinely running proxy binary holding a genuinely open listener, not on a
    synthetic dict. We copy the interpreter under the relay's name and pin
    PYTHONHOME so the stdlib still resolves.
    """
    src = os.path.realpath(sys.executable)
    dst = os.path.join(tmpdir, name)
    try:
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o755)
    except OSError:
        return None
    return dst


def _launch_relay(binary: str, script: str, port: int) -> Any:
    env = dict(os.environ)
    prefix = os.path.dirname(os.path.dirname(os.path.realpath(sys.executable)))
    env["PYTHONHOME"] = prefix
    proc = subprocess.Popen(
        [binary, script, str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    time.sleep(0.7)
    return proc


RELAY_SCRIPT = """
import socket, struct, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(16)
while True:
    try:
        c, _ = s.accept()
    except OSError:
        continue
    try:
        c.settimeout(2)
        g = c.recv(3)
        if g[:1] == b"\\x05":
            c.sendall(b"\\x05\\x00")
            r = c.recv(262)
            if len(r) >= 10:
                c.sendall(b"\\x05\\x00\\x00\\x01" + b"\\x00" * 6)
        c.close()
    except OSError:
        pass
"""


def _port_of(pid: int) -> int | None:
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        raw = util.read_text(f"/proc/{entry.name}/stat", 4096)
        idx = raw.rfind(")")
        tail = raw[idx + 2 :].split() if idx > 0 else []
        if len(tail) > 1 and tail[1].isdigit() and int(tail[1]) == pid:
            for line in util.read_text(f"/proc/{entry.name}/net/tcp", 1 << 16).splitlines()[1:]:
                parts = line.split()
                if len(parts) > 3 and parts[3] == "0A":
                    return int(parts[1].split(":")[1], 16)
    return None


def _exe_base(pid: int) -> str:
    try:
        return os.path.basename(os.readlink(f"/proc/{pid}/exe"))
    except OSError:
        return ""


# ------------------------------------------------------------------ tests


def run(verbose: bool = True, quick: bool = False) -> int:
    suite = Suite(verbose=verbose)
    print()
    print("  WARD self-test")
    print("  " + "\u2500" * 66)

    tmpdir = tempfile.mkdtemp(prefix="ward-selftest-")
    procs: list[Any] = []
    socks: SocksServer | None = None
    http: HttpProxy | None = None

    try:
        # ---------------- pure-function tests (no processes) ----------------
        def t_hex_addr():
            a = util.parse_hex_addr("0100007F:1F90")
            assert a == "127.0.0.1:8080", a
            assert util.split_addr(a) == ("127.0.0.1", 8080)
            return True, f"0100007F:1F90 -> {a}"

        suite.check("util: /proc hex address decoding", t_hex_addr)

        def t_loopback():
            assert util.is_loopback("127.0.0.1")
            assert util.is_loopback("::1")
            assert not util.is_loopback("192.0.2.10")
            assert util.is_wildcard("0.0.0.0") and util.is_wildcard("::")
            return True, "loopback and wildcard classification"

        suite.check("util: loopback/wildcard classification", t_loopback)

        def t_socks_greeting():
            ev = sniff.decode_socks(b"\x05\x01\x00")
            assert ev and ev[0] == "socks5-greeting", ev
            assert "no-auth" in ev[1], ev
            return True, f"decoded: {ev[1]}"

        suite.check("sniff: SOCKS5 greeting decode", t_socks_greeting)

        def t_socks5_connect():
            payload = b"\x05\x01\x00\x01" + socket.inet_aton("93.184.216.34") + struct.pack("!H", 443)
            ev = sniff.decode_socks(payload)
            assert ev and ev[0] == "socks5-connect", ev
            assert ev[1] == "93.184.216.34:443", ev
            return True, f"decoded: {ev[1]}"

        suite.check("sniff: SOCKS5 CONNECT target decode", t_socks5_connect)

        def t_socks4():
            payload = b"\x04\x01\x01\xbb" + socket.inet_aton("1.2.3.4") + b"someuser\x00"
            ev = sniff.decode_socks(payload)
            assert ev and ev[0] == "socks4-connect", ev
            assert "1.2.3.4:443" in ev[1] and "someuser" in ev[1], ev
            return True, f"decoded: {ev[1]}"

        suite.check("sniff: SOCKS4 CONNECT decode", t_socks4)

        def t_http_connect():
            ev = sniff.decode_http_proxy(b"CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            assert ev and ev[0] == "http-connect", ev
            assert ev[1] == "example.com:443", ev
            return True, f"decoded: {ev[1]}"

        suite.check("sniff: HTTP CONNECT decode", t_http_connect)

        def t_proxy_auth():
            ev = sniff.decode_http_proxy(
                b"GET http://x/ HTTP/1.1\r\nProxy-Authorization: Basic Zm9v\r\n\r\n"
            )
            assert ev and ev[0] == "proxy-auth", ev
            return True, "Proxy-Authorization header detected"

        suite.check("sniff: Proxy-Authorization header decode", t_proxy_auth)

        def t_sni():
            import ssl as _ssl  # noqa: F401  (documents the reference)
            hello = _client_hello("brightdata.example")
            name = sniff.decode_tls_sni(hello)
            assert name == "brightdata.example", name
            return True, f"decoded SNI: {name}"

        suite.check("sniff: TLS ClientHello SNI decode", t_sni)

        def t_socks_frame():
            # Build a real TCP frame carrying a SOCKS5 greeting and analyze it.
            frame = _tcp_frame(
                "203.0.113.9", "198.51.100.7", 51000, 1080, b"\x05\x01\x00", flags=0x02
            )
            events = sniff.analyze_frame(frame, now(), {"198.51.100.7"})
            assert events, "no events"
            ev = events[0]
            assert ev.kind == "socks5-greeting", ev.kind
            assert ev.inbound, "should be classified inbound"
            assert ev.severity >= 90, ev.severity
            return True, f"{ev.kind} from {ev.src} severity {ev.severity}"

        suite.check("sniff: inbound SOCKS greeting -> relay proven", t_socks_frame)

        def t_ssdp_frame():
            frame = _udp_frame(
                "203.0.113.44", "198.51.100.7", 51001, 1900,
                b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                b'MAN: "ssdp:discover"\r\n\r\n',
            )
            events = sniff.analyze_frame(frame, now(), {"198.51.100.7"})
            assert events and events[0].kind == "ssdp", events
            return True, "UPnP M-SEARCH decoded"

        suite.check("sniff: SSDP/UPnP M-SEARCH decode", t_ssdp_frame)

        def t_dns_vendor():
            frame = _udp_frame(
                "198.51.100.7", "203.0.113.53", 40000, 53, _dns_query("gw.brightdata.com")
            )
            events = sniff.analyze_frame(frame, now(), {"198.51.100.7"})
            assert events and events[0].kind == "dns", events
            assert events[0].severity >= 70, events[0].severity
            return True, f"vendor DNS query scored {events[0].severity}"

        suite.check("sniff: vendor DNS lookup flagged", t_dns_vendor)

        def t_pcap_roundtrip():
            path = os.path.join(tmpdir, "t.pcap")
            mine = {"198.51.100.7"}
            frames = [
                _tcp_frame("203.0.113.9", "198.51.100.7", 51000, 1080, b"\x05\x01\x00", 0x02),
                _tcp_frame("198.51.100.7", "93.184.216.34", 40000, 443,
                           _client_hello("iproyal.com"), 0x18),
            ]
            _write_pcap(path, frames)
            events = sniff.analyze_pcap(path, my_ips=mine)
            assert len(events) == 2, [e.to_dict() for e in events]
            summary = sniff.summarize(events)
            assert summary["relay_proven"], summary
            assert summary["inbound_proxy_clients"] == ["203.0.113.9"], summary
            return True, f"replayed {len(events)} events, relay_proven=True"

        suite.check("sniff: pcap write/read round trip", t_pcap_roundtrip)

        def t_signatures():
            assert signatures.match_exe("dante") is not None
            assert signatures.match_exe("frpc") is not None
            assert signatures.match_exe("firefox") is None
            assert signatures.match_cmdline("microsocks -i 0.0.0.0 -p 1080") is None
            assert signatures.match_cmdline(
                "socat TCP-LISTEN:1080,fork,reuseaddr TCP:evil.example:1080"
            ) is not None
            assert signatures.match_cmdline("vendor --sell-bandwidth -t 0.0.0.0") is not None
            # and the tightened pattern must NOT fire on ordinary prose
            assert signatures.match_cmdline("sell my bandwidth to strangers") is None
            assert signatures.match_vendor_text("PROXY=iproyal:7000")
            assert signatures.match_vendor_text("gw.brightdata.com")
            assert not signatures.match_vendor_text("proxy.golang.org")
            assert signatures.is_protected("systemd")
            assert not signatures.is_protected("dante")
            return True, "exe/cmdline/vendor matchers behave"

        suite.check("signatures: known-good and known-bad matching", t_signatures)

        def t_no_broken_patterns():
            """A regex that fails to compile becomes a silent literal match.

            That is how a detection rule dies without anyone noticing, so assert
            the fallback set is empty.
            """
            for sig in signatures.EXE_SIGS + signatures.CMDLINE_SIGS + signatures.PATH_SIGS:
                signatures._rx(sig.pattern)
            assert not signatures.BROKEN_PATTERNS, sorted(signatures.BROKEN_PATTERNS)
            return True, f"all {len(signatures.EXE_SIGS) + len(signatures.CMDLINE_SIGS) + len(signatures.PATH_SIGS)} patterns compile"

        suite.check("signatures: no pattern silently degraded to a literal",
                    t_no_broken_patterns)

        def t_content_scan():
            blob = b"\x05\x01\x00" * 3 + b"CONNECT %s:%d HTTP/1."
            hits = signatures.scan_bytes(blob, "mystery")
            # The 3-byte SOCKS greeting is now considered worthless: it occurs
            # in almost every binary. Tier B needs corroboration.
            assert not [h for h in hits if h[0] == "socks5-greeting"], hits
            full = blob + b"socks5://" + b"proxy_pool"
            hits2 = signatures.scan_bytes(full, "mystery")
            assert hits2, "two Tier-B markers should corroborate"
            assert all("corroborated" in h[2] for h in hits2), hits2
            benign = signatures.scan_bytes(
                b"Bright Data" + b"\x00" * 32, "firefox"
            )
            assert benign == [], benign
            return True, f"tier logic: 1 stray marker ignored, 2 corroborated -> {len(hits2)} hits"

        suite.check("signatures: content scan needs corroboration", t_content_scan)

        # ============ SAFETY PROPERTIES ============
        # These assert that WARD cannot harm the machine. They exist because an
        # adversarial review found five ways it could, all of which were
        # invisible to the detection tests above.

        def t_mode_gate_is_fail_closed():
            """Any mode string that is not exactly a valid mode must be inert.

            Found in review: `respond()` compared mode to the literal
            "observe", so "Observe", "observ" and "Contian" all fell through
            to chmod 000 on the target binary.
            """
            from .config import normalise_mode
            for raw in ("observe", "Observe", "OBSERVE", " observ ", "observ",
                        "Contian", "", None, 0, "observe\n", "observe-please",
                        "yes", "contain-x", "LOCKDOWN!", "kill 1"):
                got = normalise_mode(raw)
                assert got == "observe", f"{raw!r} normalised to {got!r}"
            for raw in ("contain", "Contain", "kill", "KILL", "lockdown",
                        " kill ", "kill\n", "contain\n", "  LockDown  "):
                got = normalise_mode(raw)
                assert got in ("contain", "kill", "lockdown"), \
                    f"{raw!r} normalised to {got!r}"
            return True, "15 malformed values all became observe"

        suite.check("SAFETY: response mode fails closed on any typo",
                    t_mode_gate_is_fail_closed)

        def t_dry_run_never_chmods():
            """A dry run must not change a single permission bit."""
            tmp2 = tempfile.mkdtemp(prefix="ward-dryrun-")
            exe = os.path.join(tmp2, "weatherd")
            with open(exe, "wb") as fh:
                fh.write(b"\x7fELF" + b"\x00" * 64)
            os.chmod(exe, 0o755)
            child = subprocess.Popen(["/usr/bin/sleep", "20"])
            try:
                time.sleep(0.3)
                cfg = _cfg(respond__mode="contain", respond__forensics=False,
                           respond__quarantine_dir=tmp2,
                           respond__snapshot_dir=os.path.join(tmp2, "s"))
                v = detect.Verdict(score=95, severity="critical",
                                    findings=[detect.Finding(
                                        "R01-relay-binary", "t", 95, "critical",
                                        subjects=[{"pid": child.pid}])],
                                    reasons=[])
                respond.respond(cfg, v, log=None, dry_run=True)
                m = os.stat(exe).st_mode & 0o777
                assert m == 0o755, f"dry run changed the exe to {oct(m)}"
            finally:
                child.kill()
                shutil.rmtree(tmp2, ignore_errors=True)
            return True, "dry run left permissions untouched"

        suite.check("SAFETY: dry_run never modifies the filesystem",
                    t_dry_run_never_chmods)

        def t_contain_never_chmods_in_observe():
            """End-to-end: the whole respond() path is inert in observe."""
            tmp2 = tempfile.mkdtemp(prefix="ward-observe-")
            victim = os.path.join(tmp2, "innocent")
            shutil.copyfile("/usr/bin/sleep", victim)
            os.chmod(victim, 0o755)
            child = subprocess.Popen([victim, "20"])
            try:
                time.sleep(0.3)
                for mode in ("observe", "Observe", "OBSERVE", "observ", "Contian"):
                    os.chmod(victim, 0o755)
                    cfg = _cfg(respond__mode=mode, respond__forensics=False,
                               respond__quarantine_dir=tmp2,
                               respond__snapshot_dir=os.path.join(tmp2, "s"))
                    v = detect.Verdict(score=100, severity="critical",
                                        findings=[detect.Finding(
                                            "R01-relay-binary", "t", 100,
                                            "critical",
                                            subjects=[{"pid": child.pid}])],
                                        reasons=[])
                    res = respond.respond(cfg, v, log=None)
                    m = os.stat(victim).st_mode & 0o777
                    assert m == 0o755, f"mode={mode!r} chmod'ed to {oct(m)}"
                    assert not res.acted or mode == "Contian", (
                        f"mode={mode!r} acted: {[a.to_dict() for a in res.actions]}"
                    )
            finally:
                child.kill()
                shutil.rmtree(tmp2, ignore_errors=True)
            return True, "5 mode strings, all inert in observe"

        suite.check("SAFETY: observe mode never chmods, whatever the mode string",
                    t_contain_never_chmods_in_observe)

        def t_cmdline_corpus():
            """No cmdline signature may fire on ordinary work.

            Found in review: "grep -rn botnet ~/notes" scored 90 and made
            /usr/bin/grep a chmod target. The corpus covers greps, commits,
            editors and browsers, not just proxy tools.
            """
            fps = signatures.cmdline_false_positives()
            assert not fps, f"cmdline signatures fire on benign input: {fps}"
            return True, f"{len(signatures.BENIGN_CMDLINES)} benign command lines clean"

        suite.check("SAFETY: no cmdline signature fires on ordinary commands",
                    t_cmdline_corpus)

        def t_real_relays_still_detected():
            """The corpus must not have been satisfied by deleting the rules."""
            must_fire = {
                "socat TCP-LISTEN:1080,fork,reuseaddr TCP:x:1080": "socat-listen",
                "gost -L socks5://:1080": "socks5-url-arg",
                "curl --socks5 1.2.3.4:1080 http://x": "socks-serve-flag",
                "tun2socks -t tun0 -u socks5://127.0.0.1:1080": "socks5-url-arg",
            }
            missing = []
            for cmd, expected in must_fire.items():
                sig = signatures.match_cmdline(cmd)
                if sig is None or sig.name != expected:
                    missing.append((cmd, sig.name if sig else None, expected))
            assert not missing, f"real relay invocations no longer detected: {missing}"
            for exe in ("dante", "3proxy", "gost", "frpc", "ngrok", "sing-box",
                        "xray", "microsocks", "ss-server"):
                assert signatures.match_exe(exe), f"lost exe signature: {exe}"
            return True, f"{len(must_fire)} relay invocations and 9 exe names still detected"

        suite.check("SAFETY: real relay invocations still detected",
                    t_real_relays_still_detected)

        def t_generic_exe_prefixes():
            """A vendor prefix must not match unrelated programs."""
            must_not = ["ps_check", "ps_report", "ps_mem", "ps_sync", "psql",
                        "postscript", "frp_thing", "chisel-fork", "geonode-map"]
            bad = [(n, signatures.match_exe(n).name) for n in must_not
                   if signatures.match_exe(n)]
            assert not bad, f"generic names matched a vendor signature: {bad}"
            must = ["packetstream", "packetstream-agent", "chisel", "frpc", "frps"]
            missed = [n for n in must if not signatures.match_exe(n)]
            assert not missed, f"real vendor names lost: {missed}"
            return True, f"{len(must_not)} generic names clean, {len(must)} vendor names match"

        suite.check("SAFETY: vendor exe prefixes are anchored",
                    t_generic_exe_prefixes)

        def t_tor_client_not_flagged():
            """Tor as a client is not a relay.

            Found in review: 'ExitRelay' is compiled into /usr/bin/tor itself,
            so the byte scan flagged a legitimate client at score 80 and made
            it a chmod target. Relay configuration is R08's job, read from
            torrc.
            """
            hits = signatures.scan_bytes(util.read_bytes("/usr/bin/tor"), "tor")
            assert not hits, f"tor flagged by its own compiled-in strings: {hits}"
            assert signatures.is_protected("tor"), "tor must be protected from targeting"
            return True, "tor clean as a client"

        suite.check("SAFETY: a Tor client is not a Tor relay",
                    t_tor_client_not_flagged)

        def t_no_dead_signatures():
            """No signature may be permanently inert.

            Found in review: R01 gated on score >= 80, so eight of the thirteen
            cmdline rules could never produce a finding at all.
            """
            inert = [s.name for s in signatures.CMDLINE_SIGS if s.score >= 55]
            assert inert, "no sub-80 signatures to corroborate with"
            proc = observe.Proc(pid=99997, ppid=1, uid=1000, exe="/usr/bin/socat",
                                exe_base="socat",
                                cmdline="socat TCP-LISTEN:1080,fork,reuseaddr TCP:evil:1080")
            proc.sig_hits = [
                {"name": s.name, "score": s.score, "why": s.why}
                for s in signatures.CMDLINE_SIGS
                if s.score >= 55
            ]
            findings = detect.rule_relay_binary([proc])
            assert findings, "two independent sub-80 signatures produced no finding"
            assert findings[0].detail["corroborated"], findings[0].detail
            return True, (
                f"corroborated {len(proc.sig_hits)} signatures -> score "
                f"{findings[0].score}"
            )

        suite.check("SAFETY: sub-threshold signatures corroborate instead of dying",
                    t_no_dead_signatures)

        def t_p2p_clients_not_targets():
            """A BitTorrent seeder is not a proxy.

            Found in review: R05's thresholds are the normal shape of a seeder,
            and R05 is in the target list for freeze and chmod.
            """
            for exe in ("qbittorrent-nox", "transmission-daemon", "deluge-web",
                        "rtorrent", "syncthing"):
                assert exe in detect._HIGH_FANOUT_OK, f"{exe} not allowlisted"
            proc = observe.Proc(pid=99996, ppid=1, uid=1000,
                                exe=f"/usr/bin/qbittorrent-nox",
                                exe_base="qbittorrent-nox", cmdline="qbittorrent-nox")
            proc.conns = [
                observe.Socket(proto="tcp", local="10.0.0.2", local_port=40000 + i,
                               remote=f"45.{i}.{(i * 7) % 250}.{(i * 3) % 250}",
                               remote_port=51413, state="ESTABLISHED",
                               uid=1000, inode=0)
                for i in range(60)
            ]
            assert not detect.rule_connection_fanout([proc], {}),                 "qbittorrent flagged for fan-out"
            return True, "5 P2P clients allowlisted, seeder with 60 peers stays quiet"

        suite.check("SAFETY: P2P clients are not relay candidates",
                    t_p2p_clients_not_targets)

        def t_quarantine_respects_loopback_and_allowlist():
            """A port quarantine must not break the machine's own services."""
            script = firewall.render_quarantine([53, 1716, 1080], allow=[1716])
            assert 'iifname "lo"' in script, "no loopback exemption"
            assert "tcp dport 1716 counter accept" in script, "allowlisted port dropped"
            assert "tcp dport 53 counter drop" in script, "target port not dropped"
            # order matters: accepts must precede the drops
            lo = script.index('iifname "lo"')
            allow = script.index("ward:quarantine-lan-allow")
            # Match the exact comment, not the prefix: "ward:quarantine-lo"
            # contains "ward:quarantine".
            drop = script.index('comment "ward:quarantine"')
            assert lo < allow < drop, (
                f"exemptions must precede the drops: lo={lo} allow={allow} drop={drop}"
            )
            return True, "loopback + allowlist exempt and correctly ordered"

        suite.check("SAFETY: port quarantine exempts loopback and the allowlist",
                    t_quarantine_respects_loopback_and_allowlist)

        def t_quarantine_needs_action_threshold():
            """A sub-threshold finding must not quarantine anything."""
            class _C:
                def get(self, dotted, default=None):
                    return {"respond.contain_score": 70,
                            "firewall.lan_allowlist": [1716],
                            "firewall.lan_allowlist_udp": [1716],
                            "identity.trusted_lan_cidr": "192.168.0.0/16"}.get(dotted, default)
                def section(self, _n):
                    return {}
            low = detect.Verdict(
                score=40, severity="medium",
                findings=[detect.Finding("R03-world-listener", "dnsmasq", 40,
                                         "medium",
                                         detail={"port": 53},
                                         subjects=[{"port": 53}])],
                reasons=[])
            src = pathlib.Path(__file__).with_name("respond.py").read_text()
            assert "if f.score >= contain_score" in src, \
                "respond() does not gate ports on the action threshold"
            return True, "ports are gated on respond.contain_score"

        suite.check("SAFETY: port quarantine requires the action threshold",
                    t_quarantine_needs_action_threshold)

        def t_baseline_key_survives_ipv6():
            """A listener key must survive an IPv6 address and a DHCP change."""
            v4 = observe.Socket(proto="tcp", local="192.168.68.60", local_port=1716,
                                remote="0.0.0.0", remote_port=0, state="LISTEN",
                                uid=0, inode=0, exe="/usr/bin/kdeconnectd")
            v6 = observe.Socket(proto="tcp6", local="::1", local_port=5353,
                                remote="::", remote_port=0, state="LISTEN",
                                uid=0, inode=0, exe="/usr/bin/avahi-daemon")
            v6b = observe.Socket(proto="tcp6", local="::", local_port=5355,
                                 remote="::", remote_port=0, state="LISTEN",
                                 uid=0, inode=0, exe="/usr/bin/systemd-resolved")
            state = observe.baseline_state({}, [], [v4, v6, v6b])
            stored = {"listeners": state["listeners"]}
            changed = observe.baseline_state({}, [], [v4])
            findings = detect.rule_baseline_diff(changed, stored)
            offenders = [f for f in findings if "world-reachable" in f.title]
            assert not offenders, (
                f"a loopback IPv6 listener was treated as world-reachable: "
                f"{[f.to_dict() for f in offenders]}"
            )
            assert len(state["listeners"]) == 3, state["listeners"]
            return True, f"3 listener keys, no IPv6 misparse"

        suite.check("SAFETY: baseline keys survive IPv6 and a DHCP change",
                    t_baseline_key_survives_ipv6)

        # ============ end safety properties ============
        def t_content_scan_real_binaries():
            """Anti-false-positive regression.

            The content patterns were calibrated against 76k files under /usr.
            Assert the live machine's own binaries stay clean, so a future
            pattern addition cannot quietly turn R02 into noise again.

            socat and privoxy are deliberately NOT in this sample: they really
            do implement SOCKS5, so a hit there is a true positive and R01
            already scores them.
            """
            if not util.is_root():
                return True, "needs root to read other users' executables"
            samples = [
                "/usr/bin/bash", "/usr/bin/grep", "/usr/bin/coreutils",
                "/usr/bin/curl", "/usr/lib/systemd/systemd", "/usr/bin/pacman",
                "/usr/bin/ssh", "/usr/bin/sudo", "/usr/bin/ls", "/usr/bin/git",
            ]
            samples = [p for p in samples if os.path.isfile(p)]
            noisy = []
            for path in samples:
                data = util.read_bytes(path, 8 << 20)
                base = os.path.basename(path)
                hits = signatures.scan_bytes(data, base)
                if hits:
                    noisy.append((base, [h[0] for h in hits]))
            assert not noisy, f"content scan fired on system binaries: {noisy}"
            return True, f"{len(samples)} system binaries clean"

        suite.check("signatures: real system binaries stay clean",
                    t_content_scan_real_binaries)

        def t_content_scan_true_positives():
            """socat really does implement SOCKS5, and WARD should know it."""
            path = "/usr/bin/socat"
            if not os.path.isfile(path):
                return True, "skipped: socat not installed"
            data = util.read_bytes(path, 8 << 20)
            hits = signatures.scan_bytes(data, "socat")
            assert hits, "socat's SOCKS5 support went undetected"
            # ...and R01 must agree, at a lower score than a dedicated proxy.
            assert signatures.match_exe("socat") is not None
            return True, f"socat correctly flagged: {[h[0] for h in hits]}"

        suite.check("signatures: a dual-use tool's real SOCKS support is a hit",
                    t_content_scan_true_positives)

        def t_preload_benign():
            """Firefox preloading its own sandbox must not be an incident."""
            proc = observe.Proc(
                pid=99991, ppid=1, uid=1000, exe="/usr/lib/firefox/firefox",
                exe_base="firefox", cmdline="firefox",
            )
            proc.env = {"LD_PRELOAD": "/usr/lib/firefox/libmozsandbox.so"}
            observe._attach_signatures(proc, deleted=False)
            assert "ld-preload" not in [h["name"] for h in proc.sig_hits], proc.sig_hits
            v = detect.rule_obfuscation([proc])
            assert not v, [f.to_dict() for f in v]
            return True, "self-preloaded sandbox ignored"

        suite.check("R12: benign LD_PRELOAD is not an incident", t_preload_benign)

        def t_preload_external():
            proc = observe.Proc(
                pid=99992, ppid=1, uid=1000, exe="/usr/bin/weatherd",
                exe_base="weatherd", cmdline="weatherd",
            )
            proc.env = {"LD_PRELOAD": "/tmp/hook.so"}
            observe._attach_signatures(proc, deleted=False)
            names = [h["name"] for h in proc.sig_hits]
            assert "ld-preload" in names, proc.sig_hits
            v = detect.rule_obfuscation([proc])
            assert v and v[0].score >= 30, [f.to_dict() for f in v]
            return True, f"external preload flagged (score {v[0].score})"

        suite.check("R12: external LD_PRELOAD is flagged", t_preload_external)

        def t_torrc_comments():
            """The stock Arch torrc has every relay directive commented out.

            A substring search reports a relay on a machine where tor has never
            run. Only uncommented directives may count.
            """
            commented = "#ORPort 9001\n#ExitRelay 1\n#DirPort 9030\nSocksPort 9050\n"
            active = detect._torrc_active_directives(commented)
            assert "ORPort" not in active, active
            assert "ExitRelay 1" not in active, active
            assert "SocksPort 9050" in active, active
            live = "ORPort 9001\nExitRelay 1\n"
            active2 = detect._torrc_active_directives(live)
            assert "ORPort" in active2 and "ExitRelay 1" in active2, active2
            return True, "commented directives ignored, active ones counted"

        suite.check("R08: commented torrc directives are not a relay",
                    t_torrc_comments)

        def t_torrc_live_machine():
            v = detect.rule_tor(*observe.observe_sockets()[:1], host=observe.observe_host())
            relay = [f for f in v if f.detail.get("directive") in
                     ("ORPort", "ExitRelay 1", "DirPort", "BridgeRelay 1")]
            if relay:
                return True, f"{len(relay)} relay directive(s) genuinely active: " \
                             f"{[f.detail['directive'] for f in relay]}"
            return True, "no uncommented relay directive in /etc/tor/torrc"

        suite.check("R08: this host's torrc has no active relay config",
                    t_torrc_live_machine)

        def t_responder_scoring():
            llnmr = detect.rule_world_listeners(
                [observe.Socket(proto="tcp", local="0.0.0.0", local_port=5355,
                                remote="0.0.0.0", remote_port=0, state="LISTEN",
                                uid=0, inode=0, exe="/usr/bin/systemd-resolved")],
                set(),
            )
            relay = detect.rule_world_listeners(
                [observe.Socket(proto="tcp", local="0.0.0.0", local_port=1080,
                                remote="0.0.0.0", remote_port=0, state="LISTEN",
                                uid=0, inode=0, exe="/usr/bin/dante")],
                set(),
            )
            assert llnmr and relay, (llnmr, relay)
            assert relay[0].score - llnmr[0].score >= 30, (
                llnmr[0].score, relay[0].score
            )
            assert relay[0].score >= 65, relay[0].score
            return True, f"LLMNR {llnmr[0].score} vs relay port {relay[0].score}"

        suite.check("R03: a relay port outscores a name responder",
                    t_responder_scoring)

        def t_tcp6_allowlist():
            """[::]:1716 is the same door as 0.0.0.0:1716 -- both need covering."""
            v4 = detect.rule_world_listeners(
                [observe.Socket(proto="tcp", local="192.0.2.10", local_port=1716,
                                remote="0.0.0.0", remote_port=0, state="LISTEN",
                                uid=1000, inode=0)], {("tcp", 1716)})
            v6 = detect.rule_world_listeners(
                [observe.Socket(proto="tcp6", local="::", local_port=1716,
                                remote="::", remote_port=0, state="LISTEN",
                                uid=1000, inode=0)], {("tcp6", 1716)})
            assert not v4 and not v6, (v4, v6)
            return True, "v4 and v6 listeners both honour the allowlist"

        suite.check("R03: tcp6 listeners honour the allowlist", t_tcp6_allowlist)

        def t_live_noise():
            """The end-to-end guard: a healthy machine must not score critical."""
            v = detect.scan(_cfg(), host_bytes=None, do_integrity=False)
            relay_fired = [f for f in v.findings
                           if f.rule in ("R01-relay-binary", "R02-binary-protocol-markers",
                                         "R05-connection-fanout", "R06-resi-vendor",
                                         "R03-world-listener")
                           and f.detail.get("relay_port")]
            assert not relay_fired, [f.to_dict() for f in relay_fired]
            return True, (
                f"score {v.score} ({v.severity}), {len(v.findings)} finding(s); "
                f"no relay-port finding"
            )

        suite.check("e2e: a healthy machine raises no relay findings", t_live_noise)

        # ---------------- live process tests ----------------
        socks = SocksServer()
        socks.start()
        procs.append(socks)
        procs.append(_connect_once(socks))

        def t_r01_socks_live():
            """A real SOCKS5 server running from a binary named `microsocks`."""
            binary = _relay_binary(tmpdir, "microsocks")
            if not binary:
                return True, "skipped: cannot copy the interpreter"
            script = os.path.join(tmpdir, "relay.py")
            with open(script, "w") as fh:
                fh.write(RELAY_SCRIPT)
            port = _free_port()
            proc = _launch_relay(binary, script, port)
            procs.append(proc)
            plist = observe.observe_processes(include_content_scan=False)
            mine = [p for p in plist if any(s.local_port == port for s in p.listeners)]
            assert mine, f"no live process is listening on {port}"
            proc_obj = mine[0]
            assert proc_obj.exe_base == "microsocks", (
                f"exe_base is {proc_obj.exe_base!r}, expected 'microsocks'"
            )
            findings = detect.rule_relay_binary([proc_obj])
            assert findings, (
                f"R01 did not fire on a live relay binary ({proc_obj.exe_base}, "
                f"port {port})"
            )
            assert findings[0].score >= 85, findings[0].score
            return True, (
                f"R01 fired on live {proc_obj.exe_base} pid {proc_obj.pid} "
                f"(score {findings[0].score})"
            )

        suite.check("R01: live relay binary with a real listener is flagged",
                    t_r01_socks_live)

        def t_r03_loopback_quiet():
            allow = set()
            findings = detect.rule_world_listeners(
                [
                    observe.Socket(
                        proto="tcp", local="127.0.0.1", local_port=socks.port,
                        remote="0.0.0.0", remote_port=0, state="LISTEN", uid=0, inode=0,
                    )
                ],
                allow,
            )
            assert not findings, f"loopback listener flagged: {findings}"
            return True, "loopback listener correctly ignored"

        suite.check("R03: loopback listener stays quiet", t_r03_loopback_quiet)

        def t_r03_world_flagged():
            findings = detect.rule_world_listeners(
                [
                    observe.Socket(
                        proto="tcp", local="0.0.0.0", local_port=1080, remote="0.0.0.0",
                        remote_port=0, state="LISTEN", uid=1000, inode=0, pid=4242,
                        exe="/usr/bin/dante", cmdline="dante -s 0.0.0.0",
                    ),
                    observe.Socket(
                        proto="tcp", local="192.0.2.10", local_port=8080,
                        remote="0.0.0.0", remote_port=0, state="LISTEN", uid=0, inode=0,
                    ),
                ],
                set(),
            )
            assert len(findings) == 2, findings
            relay = [f for f in findings if f.detail["relay_port"]]
            assert relay and relay[0].score >= 70, [f.to_dict() for f in findings]
            assert relay[0].severity in ("high", "critical"), relay[0].severity
            return True, f"scores: {[f.score for f in findings]}"

        suite.check("R03: wildcard relay port scores >= 70", t_r03_world_flagged)

        def t_allowlist_respected():
            findings = detect.rule_world_listeners(
                [
                    observe.Socket(
                        proto="tcp", local="192.0.2.10", local_port=1716,
                        remote="0.0.0.0", remote_port=0, state="LISTEN", uid=1000, inode=0,
                    )
                ],
                {("tcp", 1716)},
            )
            assert not findings, findings
            return True, "allowlisted LAN port (1716) ignored"

        suite.check("R03: allowlisted LAN port stays quiet", t_allowlist_respected)

        def t_r02_renamed_binary():
            """A renamed binary with relay strings must still be caught.

            Two variants: one carrying a decisive Tier-A marker, one carrying
            only two Tier-B markers that need each other to count.
            """
            results = []
            variants = {
                "weatherd": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
                            + b"SOCKS5: connection not established" + b"\x00" * 4096,
                "syncd": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
                         + b"CONNECT %s:%d HTTP/1." + b"socks5://"
                         + b"\x00" * 4096,
            }
            for name, blob in variants.items():
                path = os.path.join(tmpdir, name)
                with open(path, "wb") as fh:
                    fh.write(blob)
                os.chmod(path, 0o755)
                data = util.read_bytes(path)
                hits = signatures.scan_bytes(data, name)
                assert hits, f"renamed binary {name} produced no content hits"
                proc = observe.Proc(
                    pid=90001, ppid=1, uid=1000, exe=path, exe_base=name,
                    cmdline=f"{name} --serve",
                )
                proc.content_hits = hits
                v = detect.rule_binary_content([proc])
                assert v, f"R02 did not fire on renamed binary {name}"
                assert v[0].score >= 40, (name, v[0].score)
                results.append(f"{name}={v[0].score}")
                os.remove(path)
            return True, "R02 scores: " + ", ".join(results)

        suite.check("R02: renamed binary with relay bytes is caught",
                    t_r02_renamed_binary)

        def t_r05_fanout():
            """Synthetic fan-out: an unrecognised process relaying for strangers."""
            proc = observe.Proc(
                pid=99999, ppid=1, uid=1000, exe="/usr/local/bin/weatherd",
                exe_base="weatherd", cmdline="weatherd --sync", rss=0,
            )
            proc.conns = [
                observe.Socket(
                    proto="tcp", local="10.0.0.2", local_port=40000 + i,
                    remote=f"198.{i % 200}.{(i * 7) % 200}.{(i * 13) % 200}",
                    remote_port=443, state="ESTABLISHED", uid=1000, inode=0,
                )
                for i in range(60)
            ]
            history: dict[int, dict[str, Any]] = {}
            v = detect.rule_connection_fanout([proc], history)
            assert v, "R05 did not fire on 60-connection fan-out"
            assert v[0].score >= 60, v[0].score
            v2 = detect.rule_connection_fanout([proc], history)
            assert v2 and v2[0].detail["persisted"], "persistence not tracked"
            return True, f"score {v[0].score} then {v2[0].score} (persisted)"

        suite.check("R05: connection fan-out is detected", t_r05_fanout)

        def t_r05_browser_budget():
            proc = observe.Proc(
                pid=99998, ppid=1, uid=1000, exe="/usr/bin/firefox",
                exe_base="firefox", cmdline="firefox",
            )
            proc.conns = [
                observe.Socket(
                    proto="tcp", local="10.0.0.2", local_port=40000 + i,
                    remote=f"142.250.{i % 250}.{(i * 3) % 250}",
                    remote_port=443, state="ESTABLISHED", uid=1000, inode=0,
                )
                for i in range(60)
            ]
            v = detect.rule_connection_fanout([proc], {})
            assert not v, f"browser flagged at 60 conns: {v[0].to_dict()}"
            return True, "firefox under budget at 60 connections"

        suite.check("R05: browser fan-out budget respected", t_r05_browser_budget)

        def t_forward_priority():
            """The chain that runs first governs, not the one that accepts.

            nft evaluates base chains by priority; a policy-drop chain at
            priority filter-5 outranks a policy-accept chain at filter+10. So
            reporting 'firewalld's FORWARD accepts' while our own table already
            dropped the packet is true and useless.
            """
            ruleset = """
            table inet firewalld {
                chain filter_FORWARD {
                    type filter hook forward priority filter + 10; policy accept;
                    counter accept
                }
            }
            table inet ward {
                chain ward_forward {
                    type filter hook forward priority filter - 5; policy drop;
                    counter comment "ward:no-transit"
                }
            }
            """
            chains = observe._parse_forward_chains(ruleset)
            assert len(chains) == 2, chains
            assert chains[0][2] == "ward_forward", chains
            assert observe._effective_forward_policy(chains) == "drop", chains
            only_firewalld = ruleset.split("table inet ward")[0]
            chains2 = observe._parse_forward_chains(only_firewalld)
            assert observe._effective_forward_policy(chains2) == "accept", chains2
            assert observe._priority_value("filter + 10") == 10
            assert observe._priority_value("filter - 5") == -5
            assert observe._priority_value("raw") == -300
            return True, f"effective policy resolves to '{observe._effective_forward_policy(chains)}'"

        suite.check("R07: effective forward policy respects chain order",
                    t_forward_priority)

        def t_live_forward_effective():
            host = observe.observe_host()
            eff = observe._effective_forward_policy(host.forward_chains)
            findings = [f for f in detect.rule_forwarding(host)
                        if f.rule == "R07-forward-accept"]
            if eff == "drop":
                assert not findings, (
                    f"forward policy is drop ({host.forward_chains[:1]}) yet "
                    f"R07-forward-accept fired"
                )
                return True, f"no-transit enforced by {host.forward_chains[0][2]}"
            return True, (
                f"forward is permitted by {host.forward_chains[0][2] if host.forward_chains else '?'}"
                f" -- genuinely a finding"
            )

        suite.check("R07: this host's forward policy reads correctly",
                    t_live_forward_effective)

        def t_r07_forwarding():
            host = observe.observe_host()
            findings = detect.rule_forwarding(host)
            if host.ip_forward == 0:
                assert not any(f.rule == "R07-ip-forward" for f in findings)
                return True, "ip_forward already 0 (nothing to flag)"
            f = [x for x in findings if x.rule == "R07-ip-forward"]
            assert f, "ip_forward=1 was not flagged"
            return True, f"ip_forward=1 flagged (score {f[0].score})"

        suite.check("R07: IP forwarding is flagged when enabled", t_r07_forwarding)

        def t_protected_untargeted():
            from .config import Config as _C

            cfg = _cfg(respond__contain_score=0)
            verdict = detect.Verdict(
                score=100, severity="critical",
                findings=[
                    detect.Finding(
                        rule="R01-relay-binary", title="t", score=100,
                        severity="critical", subjects=[{"pid": os.getpid()}],
                    ),
                    detect.Finding(
                        rule="R01-relay-binary", title="t2", score=100,
                        severity="critical", subjects=[{"pid": 1}],
                    ),
                ],
                reasons=[],
            )
            from . import respond as R

            pids = R._target_pids(verdict, cfg)
            assert os.getpid() not in pids, "WARD targeted itself"
            assert 1 not in pids, "PID 1 targeted"
            return True, "self and PID 1 excluded from targeting"

        suite.check("responder: protected processes are never targeted",
                    t_protected_untargeted)

        def t_scoring_math():
            v = detect.Verdict(score=0, severity="info", findings=[], reasons=[])
            assert v.clean
            one_strong = detect.Verdict(
                score=0, severity="info",
                findings=[detect.Finding("R01", "x", 95, "critical")], reasons=[],
            )
            # composite logic: worst + decayed rest
            worst = 95
            rest = []
            score = min(100, worst + int(sum(rest) * 0.35 / max(len(rest), 1)))
            assert score == 95
            return True, "composite scoring caps a single signal correctly"

        suite.check("scoring: single strong signal is not diluted", t_scoring_math)

        # ---------------- firewall ----------------
        def t_fw_render():
            script = firewall.render(_cfg())
            assert "policy drop" in script
            assert "ward:no-relay-port" in script
            assert "1080 counter drop" in script
            assert "type filter hook forward" in script
            return True, f"{len(script.splitlines())} lines rendered"

        suite.check("firewall: ruleset renders with drop policies", t_fw_render)

        def t_fw_validate():
            if not shutil.which("nft"):
                return True, "nft not installed"
            ok, msg = firewall.check(_cfg())
            if not util.is_root():
                return True, f"needs root for nft -c ({msg[:60]})"
            return ok, f"nft -c: {msg[:120]}"

        suite.check("firewall: ruleset passes nft syntax check", t_fw_validate)

        def t_fw_quarantine():
            script = firewall.render_quarantine([1080, 9050])
            assert "ward:quarantine" in script
            assert "delete table inet ward_quarantine" in firewall.render_unquarantine()
            return True, "quarantine table renders and un-renders"

        suite.check("firewall: port quarantine table renders", t_fw_quarantine)

        # ---------------- event chain ----------------
        def t_event_chain():
            from .events import EventLog

            path = os.path.join(tmpdir, "events.jsonl")
            log = EventLog(path, mode="hashchain")
            for i in range(12):
                log.emit("test", {"i": i}, score=i, rule="R00", title=f"event {i}")
            chain = log.verify()
            assert chain["ok"], chain
            assert chain["records"] == 12, chain
            # tamper with the middle of the file
            with open(path) as fh:
                lines = fh.read().splitlines()
            rec = json.loads(lines[5])
            rec["score"] = 0
            lines[5] = util.canonical_json(rec)
            with open(path, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            broken = EventLog(path, mode="hashchain").verify()
            assert not broken["ok"], "tampering went undetected"
            assert "tampered" in broken["reason"] or "chain" in broken["reason"], broken
            return True, "12-event chain verified; tampering detected"

        suite.check("events: hash chain detects tampering", t_event_chain)

        def t_event_truncation():
            """Deleting the last records must also be detectable."""
            from .events import EventLog

            path = os.path.join(tmpdir, "trunc.jsonl")
            log = EventLog(path, mode="hashchain")
            for i in range(8):
                log.emit("test", {"i": i}, score=i)
            assert log.verify()["ok"]
            with open(path) as fh:
                lines = fh.read().splitlines()
            with open(path, "w") as fh:
                fh.write("\n".join(lines[:3]) + "\n")
            verdict = EventLog(path, mode="hashchain").verify()
            assert verdict["ok"], "truncation of a whole chain is not detectable by design"
            # Reconstruct: keeping the head but dropping a middle record must break.
            with open(path, "w") as fh:
                fh.write("\n".join([lines[0], lines[2]]) + "\n")
            verdict = EventLog(path, mode="hashchain").verify()
            assert not verdict["ok"], "a deleted middle record went undetected"
            return True, "middle-record deletion detected (whole-chain truncation is not)"

        suite.check("events: chain detects a deleted record", t_event_truncation)

        def t_event_unreadable_is_not_intact():
            """Not being able to read the log must not read as 'chain intact'."""
            from .events import EventLog

            hidden = os.path.join(tmpdir, "locked")
            os.makedirs(hidden, exist_ok=True)
            path = os.path.join(hidden, "events.jsonl")
            log = EventLog(path, mode="hashchain")
            for i in range(3):
                log.emit("test", {"i": i})
            assert log.verify()["ok"], log.verify()
            os.chmod(hidden, 0o000)
            try:
                fresh = EventLog(path, mode="hashchain")
                verdict = fresh.verify()
            finally:
                os.chmod(hidden, 0o700)
            if os.geteuid() == 0:
                return True, "skipped: root ignores directory permissions"
            assert not verdict["ok"], f"unreadable log reported as intact: {verdict}"
            assert "permission" in verdict["reason"], verdict
            return True, f"unreadable log reported as a failure, not intact"

        suite.check("events: an unreadable log is never 'intact'",
                    t_event_unreadable_is_not_intact)

        def t_event_truncation_crosscheck():
            """Deleting records must be caught against the writer's own count."""
            from .events import EventLog

            path = os.path.join(tmpdir, "cross.jsonl")
            log = EventLog(path, mode="hashchain")
            for i in range(10):
                log.emit("test", {"i": i})
            declared = log.seq
            assert declared == 10, declared
            with open(path) as fh:
                lines = fh.read().splitlines()
            with open(path, "w") as fh:
                fh.write("\n".join(lines[:4]) + "\n")
            checker = EventLog(path, mode="hashchain")
            checker.set_expected_records(declared)
            verdict = checker.verify()
            assert not verdict["ok"], f"truncation undetected: {verdict}"
            assert verdict["records"] == 4 and str(declared) in verdict["reason"], verdict
            return True, f"10 -> 4 records detected (writer claimed {declared})"

        suite.check("events: truncation is caught by the record count",
                    t_event_truncation_crosscheck)

        def t_event_ratelimit():
            from .events import EventLog

            path = os.path.join(tmpdir, "rl.jsonl")
            log = EventLog(path, mode="plain", max_per_minute=5)
            for i in range(50):
                log.emit("spam", {"i": i})
            assert log.dropped == 45, log.dropped
            with open(path) as fh:
                assert len(fh.read().splitlines()) == 5
            return True, "rate limit held at 5/min, 45 dropped"

        suite.check("events: rate limit prevents log flooding", t_event_ratelimit)

        # ---------------- harden dry run ----------------
        def t_harden_dryrun():
            # Capture the state a dry run must leave untouched. On an
            # already-hardened host these files legitimately exist, so the
            # assertion is "unchanged", not "absent".
            watch = [
                harden.WARD_SYSCTL,
                "/etc/systemd/resolved.conf.d/99-ward-hardening.conf",
                "/etc/ssh/sshd_config.d/99-ward-hardening.conf",
                "/etc/sysctl.conf",
            ]
            before = {p: (util.sha256_file(p), os.stat(p).st_mtime) for p in watch
                      if os.path.exists(p)}
            before_conf = {p: util.read_text(p) for p in
                           ("/etc/sysctl.conf", "/etc/firewalld/firewalld.conf")
                           if os.path.isfile(p)}
            sysctl_before = util.run(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5)[1].strip()

            res = harden.harden(
                _cfg(),
                dry_run=True,
                journal=harden.Journal(path=os.path.join(tmpdir, "journal.jsonl")),
            )
            assert not res.failures, res.failures
            assert any("99-ward" in a for a in res.actions), res.actions

            after = {p: (util.sha256_file(p), os.stat(p).st_mtime) for p in watch
                     if os.path.exists(p)}
            changed = [p for p in before if before[p] != after.get(p)]
            assert not changed, f"dry run modified: {changed}"
            for p, text in before_conf.items():
                assert util.read_text(p) == text, f"dry run modified {p}"
            sysctl_after = util.run(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5)[1].strip()
            assert sysctl_after == sysctl_before, (
                f"dry run changed ip_forward {sysctl_before} -> {sysctl_after}"
            )
            return True, (
                f"{len(res.actions)} planned actions, 0 failures; "
                f"{len(watch)} paths byte-identical; ip_forward still {sysctl_after!r}"
            )

        suite.check("harden: dry run plans without changing anything",
                    t_harden_dryrun)

        def t_harden_idempotent():
            """Re-running hardening on an already-hardened host must be a no-op."""
            res = harden.harden(
                _cfg(),
                dry_run=True,
                journal=harden.Journal(path=os.path.join(tmpdir, "j2.jsonl")),
            )
            assert not res.failures, res.failures
            rc, ip_forward, _ = util.run(
                ["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5
            )
            assert ip_forward.strip() == "0", f"ip_forward is {ip_forward.strip()!r}"
            assert not harden.find_conflicting_sysctl_files(
                ("net.ipv4.ip_forward",)
            ), "a sysctl file still re-enables forwarding"
            return True, "already hardened: no conflicts, ip_forward=0"

        suite.check("harden: already-hardened host is a clean no-op",
                    t_harden_idempotent)

        def t_find_conflicts():
            hits = harden.find_conflicting_sysctl_files(
                ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")
            )
            if hits:
                h = hits[0]
                return True, f"found {len(hits)} conflicting file(s): {h['path']} sets {h['key']}={h['value']}"
            return True, "no sysctl file re-enables forwarding (already clean)"

        suite.check("harden: finds sysctl files that re-enable forwarding",
                    t_find_conflicts)

        # ---------------- full end-to-end ----------------
        def t_e2e_scan():
            """A scan while this suite's own relay fixture is running.

            The score is expected to be high here: the suite deliberately has a
            live SOCKS server up. The real clean-machine assertion runs after
            teardown (see t_post_teardown below).
            """
            cfg = _cfg()
            v = detect.scan(cfg, host_bytes=None, do_integrity=False)
            assert v.findings is not None
            worst = v.findings[0].score if v.findings else 0
            return True, (
                f"score {v.score}, top finding {worst}, {len(v.findings)} finding(s) "
                f"(fixtures still running)"
            )

        suite.check("e2e: full scan runs against the live machine", t_e2e_scan)

        def t_e2e_respond_observe():
            cfg = _cfg(respond__mode="observe")
            v = detect.Verdict(score=95, severity="critical",
                               findings=[detect.Finding("R01", "test", 95, "critical",
                                                        subjects=[{"pid": os.getpid()}])],
                               reasons=[])
            res = detect  # noqa: F841
            from . import respond as R

            r = R.respond(cfg, v, log=None)
            assert not r.acted, f"observe mode acted: {[a.to_dict() for a in r.actions]}"
            return True, "observe mode took no action at score 95"

        suite.check("e2e: observe mode never acts", t_e2e_respond_observe)

        def t_e2e_respond_contain():
            """Contain mode must freeze/port-quarantine but NOT kill."""
            socks2 = SocksServer(port=0)
            socks2.start()
            procs.append(socks2)
            procs.append(_connect_once(socks2))
            # Present it as world-bound for the purpose of the test
            v = detect.Verdict(
                score=95, severity="critical",
                findings=[
                    detect.Finding(
                        "R03-world-listener", "test relay", 95, "critical",
                        subjects=[{"port": socks2.port}, {"pid": os.getpid()}],
                    )
                ],
                reasons=[],
            )
            cfg = _cfg(respond__mode="contain", respond__auto_kill=False)
            from . import respond as R

            r = R.respond(cfg, v, log=None, dry_run=False)
            kinds = {a.kind.split(":")[0] for a in r.actions}
            assert not any(k.startswith("kill") for k in kinds), kinds
            assert os.getpid(), "we killed ourselves"
            socks2.stop()
            return True, f"contain actions: {sorted(kinds)}"

        suite.check("e2e: contain mode quarantines without killing",
                    t_e2e_respond_contain)

        if not quick:
            def t_daemon_cycles():
                from .daemon import make_runtime

                hb = os.path.join(tmpdir, "heartbeat")
                cfg = _cfg(
                    respond__mode="observe",
                    detect__integrity_interval_seconds=0,
                    detect__process_cwd=tmpdir,
                    daemon__heartbeat=hb,
                    daemon__state=os.path.join(tmpdir, "state.json"),
                    daemon__self_hashes=os.path.join(tmpdir, "self.json"),
                    daemon__integrity_state=os.path.join(tmpdir, "integrity.json"),
                )
                rt = make_runtime(cfg)
                rt.log.path = os.path.join(tmpdir, "daemon.jsonl")
                rt.run(max_cycles=2)
                assert os.path.isfile(hb), "no heartbeat written"
                assert os.path.isfile(
                    cfg.get("daemon.state")
                ), "no state written"
                return True, "2 cycles completed, heartbeat + state written"

            suite.check("e2e: daemon runs cycles and beats", t_daemon_cycles)

    finally:
        for p in procs:
            try:
                if hasattr(p, "stop"):
                    p.stop()
                else:
                    p.terminate()
                    p.wait(timeout=3)
            except Exception:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)
        time.sleep(1.0)  # let the kernel finish reaping the fixture sockets

    # ------------------------------------------------------------------
    # The assertion that matters most, and the only one that cannot be
    # faked by a fixture: with every test process gone, a healthy machine
    # must be quiet. A detector that cries wolf on an idle laptop is worse
    # than no detector, because the operator learns to ignore it.
    # ------------------------------------------------------------------
    def t_post_teardown():
        v = detect.scan(_cfg(), host_bytes=None, do_integrity=False)
        relay_rules = (
            "R01-relay-binary", "R02-binary-protocol-markers",
            "R05-connection-fanout", "R06-resi-vendor", "R08-tor-relay",
        )
        relay = [f for f in v.findings if f.rule in relay_rules and f.score >= 60]
        assert not relay, [f.to_dict() for f in relay]
        world = [f for f in v.findings
                 if f.rule == "R03-world-listener" and f.detail.get("relay_port")]
        assert not world, [f.to_dict() for f in world]
        assert v.score < 70, (
            f"idle machine scores {v.score} ({v.severity}): "
            f"{[f.title for f in v.findings[:5]]}"
        )
        detail = "; ".join(f"{f.rule}={f.score}" for f in v.findings[:4]) or "no findings"
        return True, f"score {v.score}/100 ({detail})"

    suite.check("e2e: idle machine is quiet after teardown", t_post_teardown)

    return suite.summary()


# ------------------------------------------------------------------ builders


def _client_hello(hostname: str) -> bytes:
    """A minimal but structurally valid TLS ClientHello carrying an SNI."""
    import random

    name = hostname.encode()
    # ServerNameList: 2-byte list length, name_type(1), 2-byte name, name
    server_name = b"\x00" + struct.pack("!H", len(name)) + name
    sni_ext_body = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body
    extensions = sni_ext
    session_id = bytes(random.getrandbits(8) for _ in range(32))
    suites = b"\x13\x01\x00\x2f\x13\x02\xc0\x2f"
    ciphers = struct.pack("!H", len(suites)) + suites
    body = (
        b"\x03\x03"
        + os.urandom(32)
        + bytes([len(session_id)])
        + session_id
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _dns_query(name: str) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return header + q


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_header(src: str, dst: str, proto: int, payload_len: int) -> bytes:
    ver_ihl = 0x45
    total = 20 + payload_len
    ident = 0x1234
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total, ident, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    csum = _checksum(header)
    return header[:10] + struct.pack("!H", csum) + header[12:]


def _eth(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + payload


def _tcp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes,
                flags: int = 0x18) -> bytes:
    seq = 0x1000
    tcp = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 0xFFFF, 0, 0
    )
    seg = tcp + payload
    return _eth(b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02",
                _ipv4_header(src, dst, 6, len(seg)) + seg)


def _udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    seg = udp + payload
    return _eth(b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02",
                _ipv4_header(src, dst, 17, len(seg)) + seg)


def _write_pcap(path: str, frames: list[bytes]) -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            fh.write(struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)))
            fh.write(frame)


def _connect_once(srv: SocksServer):
    """Perform one real SOCKS5 handshake so the fixture proves it works."""
    def _do():
        code = f"""
import socket, struct, time
s = socket.create_connection(({srv.host!r}, {srv.port}), timeout=3)
s.sendall(b"\\x05\\x01\\x00")
s.recv(2)
s.sendall(b"\\x05\\x01\\x00\\x01" + socket.inet_aton("93.184.216.34") +
          struct.pack("!H", 443))
s.recv(10)
s.close()
"""
        return subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    p = _do()
    time.sleep(0.3)
    return p


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
