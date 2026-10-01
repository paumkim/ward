"""Packet inspection: the proof layer.

A signature match says "this looks like a proxy". A packet capture says "a
stranger on the internet sent a SOCKS5 CONNECT to this machine and we answered".
Only the second one is undeniable, and it is the one an ISP, a hosting provider
or a lawyer will accept.

We decode, in pure stdlib:
  * TLS ClientHello SNI   -- "who is this stranger asking for?"
  * HTTP CONNECT / proxy auth headers
  * SOCKS4 / SOCKS5 request bytes
  * SSDP (UPnP) M-SEARCH and NOTIFY
  * DNS-over-UDP query names, so we can see a vendor lookup

Runs on AF_PACKET (needs root) or, for non-root, replays a pcap we already
captured. No third-party dependency either way.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field
from typing import Iterator

from . import signatures, util
from .util import now

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD

# TLS content types
CT_HANDSHAKE = 0x16

# SOCKS
SOCKS4_VER = 0x04
SOCKS5_VER = 0x05


@dataclass
class Event:
    ts: float
    kind: str  # sni | socks5 | socks4 | http-connect | ssdp | dns | proxy-auth
    detail: str
    src: str
    dst: str
    sport: int
    dport: int
    inbound: bool
    severity: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "iso": util.iso(self.ts),
            "kind": self.kind,
            "detail": self.detail,
            "src": self.src,
            "dst": self.dst,
            "sport": self.sport,
            "dport": self.dport,
            "inbound": self.inbound,
            "severity": self.severity,
            **({"extra": self.extra} if self.extra else {}),
        }


# ------------------------------------------------------------------ parsing


def _parse_ethernet(frame: bytes) -> tuple[int, bytes] | None:
    if len(frame) < 14:
        return None
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    # VLAN tags
    while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:
        etype = struct.unpack("!H", frame[off + 2 : off + 4])[0]
        off += 4
    return etype, frame[off:]


def _parse_ipv4(pkt: bytes) -> tuple[str, str, int, int, bytes] | None:
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        return None
    proto = pkt[9]
    src = socket.inet_ntop(socket.AF_INET, pkt[12:16])
    dst = socket.inet_ntop(socket.AF_INET, pkt[16:20])
    frag = struct.unpack("!H", pkt[6:8])[0]
    if frag & 0x1FFF:
        return None  # non-first fragment: no ports available
    return src, dst, proto, ihl, pkt[ihl:]


def _parse_ipv6(pkt: bytes) -> tuple[str, str, int, int, bytes] | None:
    if len(pkt) < 40 or (pkt[0] >> 4) != 6:
        return None
    plen = struct.unpack("!H", pkt[4:6])[0]
    nxt = pkt[6]
    src = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, pkt[24:40])
    off = 40
    # Walk the extension chain we care about; bail on anything we cannot size.
    hops = 0
    while nxt in (0, 43, 60) and hops < 4:
        if len(pkt) < off + 8:
            return None
        ext_len = (pkt[off + 1] + 1) * 8
        nxt = pkt[off]
        off += ext_len
        hops += 1
    return src, dst, nxt, off, pkt[off:]


def _parse_ports(seg: bytes) -> tuple[int, int] | None:
    if len(seg) < 4:
        return None
    return struct.unpack("!H", seg[0:2])[0], struct.unpack("!H", seg[2:4])[0]


# ------------------------------------------------------------------ decoders


def decode_tls_sni(payload: bytes) -> str | None:
    """Pull the SNI out of a TLS ClientHello without a TLS stack."""
    if len(payload) < 6 or payload[0] != CT_HANDSHAKE:
        return None
    # Record header is 5 bytes (type, version[2], length[2]); the handshake
    # type lives at offset 5, not 1.
    if payload[5] != 0x01:
        return None
    p = 5 + 4  # past handshake header (type + 3-byte length)
    if len(payload) < p + 2 + 32:
        return None
    p += 2  # client version
    p += 32  # random
    sid_len = payload[p]
    p += 1 + sid_len
    if len(payload) < p + 2:
        return None
    cs_len = struct.unpack("!H", payload[p : p + 2])[0]
    p += 2 + cs_len
    if len(payload) < p + 1:
        return None
    comp_len = payload[p]
    p += 1 + comp_len
    if len(payload) < p + 2:
        return None
    ext_total = struct.unpack("!H", payload[p : p + 2])[0]
    p += 2
    end = min(len(payload), p + ext_total)
    while p + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", payload[p : p + 4])
        body = payload[p + 4 : p + 4 + ext_len]
        p += 4 + ext_len
        if ext_type != 0x0000 or len(body) < 5:
            continue
        # ServerNameList: 2-byte list length, then (1-byte name_type, 2-byte
        # name length, name) entries.
        list_len = struct.unpack("!H", body[0:2])[0]
        q = 2
        end_list = min(len(body), 2 + list_len)
        while q + 3 <= end_list:
            name_type = body[q]
            name_len = struct.unpack("!H", body[q + 1 : q + 3])[0]
            start = q + 3
            stop = start + name_len
            if stop > len(body):
                break
            if name_type == 0x00:
                try:
                    return body[start:stop].decode("ascii", "replace")
                except Exception:
                    return None
            q = stop
    return None


def decode_http_proxy(payload: bytes) -> tuple[str, str] | None:
    """Return (kind, detail) for HTTP requests that mean 'proxy for me'."""
    if not payload.startswith((b"CONNECT ", b"GET ", b"POST ", b"HEAD ", b"PUT ")):
        return None
    try:
        head = payload[:4096].decode("latin-1")
    except Exception:
        return None
    lowered = head.lower()
    if lowered.startswith("connect "):
        target = head[8:].split(" ")[0]
        return ("http-connect", target)
    if "proxy-authorization:" in lowered:
        line = next(
            (l for l in head.splitlines() if l.lower().startswith("proxy-authorization")),
            "proxy-authorization",
        )
        return ("proxy-auth", line[:80])
    return None


def decode_socks(payload: bytes) -> tuple[str, str] | None:
    """Identify a SOCKS greeting/request and its target."""
    if len(payload) < 2:
        return None
    ver = payload[0]
    if ver == SOCKS5_VER:
        if payload[1] <= 0x08 and len(payload) >= 2 + payload[1]:
            methods = payload[2 : 2 + payload[1]]
            # VER NMETHODS METHODS...
            if len(payload) == 2 + payload[1]:
                names = {0x00: "no-auth", 0x01: "gssapi", 0x02: "userpass", 0xFF: "none"}
                return (
                    "socks5-greeting",
                    f"auth methods: {','.join(names.get(m, hex(m)) for m in methods)}",
                )
            if len(payload) >= 4 and payload[1] == 0x01:
                return ("socks5-connect", _socks5_target(payload))
        return ("socks5", f"nmethods={payload[1]}")
    if ver == SOCKS4_VER and len(payload) >= 9:
        # SOCKS4: VN CD DSTPORT[2] DSTIP[4] USERID NUL
        cmd = payload[1]
        if cmd == 0x01:  # CONNECT
            port = struct.unpack("!H", payload[2:4])[0]
            ip = socket.inet_ntop(socket.AF_INET, payload[4:8])
            user = payload[8:].split(b"\x00")[0].decode("latin-1", "replace")
            return ("socks4-connect", f"{ip}:{port} user={user or '(none)'}")
    return None


def _socks5_target(payload: bytes) -> str:
    # VER CMD RSV ATYP DST.ADDR DST.PORT
    if len(payload) < 5:
        return "truncated"
    atyp = payload[3]
    try:
        if atyp == 0x01 and len(payload) >= 10:
            host = socket.inet_ntop(socket.AF_INET, payload[4:8])
            port = struct.unpack("!H", payload[8:10])[0]
        elif atyp == 0x03 and len(payload) >= 7:
            n = payload[4]
            host = payload[5 : 5 + n].decode("latin-1", "replace")
            port = struct.unpack("!H", payload[5 + n : 7 + n])[0]
        elif atyp == 0x04 and len(payload) >= 24:
            host = socket.inet_ntop(socket.AF_INET6, payload[4:20])
            port = struct.unpack("!H", payload[20:22])[0]
        else:
            return f"atyp={atyp}"
        return f"{host}:{port}"
    except (struct.error, OSError, ValueError):
        return "unparseable"


def decode_dns(payload: bytes) -> str | None:
    """First question name from a DNS query."""
    if len(payload) < 12:
        return None
    qd = struct.unpack("!H", payload[4:6])[0]
    if qd < 1:
        return None
    p = 12
    labels: list[str] = []
    while p < len(payload) and len(labels) < 24:
        ln = payload[p]
        if ln == 0:
            break
        if ln & 0xC0:
            break
        p += 1
        labels.append(payload[p : p + ln].decode("latin-1", "replace"))
        p += ln
    return ".".join(labels) if labels else None


def decode_ssdp(payload: bytes) -> str | None:
    head = payload[:512].decode("latin-1", "replace")
    if head.upper().startswith(("M-SEARCH", "NOTIFY")):
        line = head.splitlines()[0]
        host = next(
            (l.split(":", 1)[1].strip() for l in head.splitlines()
             if l.lower().startswith("host:")), "")
        return f"SSDP {line} host={host}"
    if "SOAPACTION" in head.upper() or "upnp" in head.lower():
        return "SSDP/UPnP control traffic"
    return None


# ------------------------------------------------------------------ per packet


def analyze_frame(frame: bytes, ts: float, my_ips: set[str]) -> list[Event]:
    """Turn one Ethernet frame into zero or more Events."""
    parsed = _parse_ethernet(frame)
    if not parsed:
        return []
    etype, rest = parsed
    if etype == ETH_P_IP:
        ip = _parse_ipv4(rest)
        if not ip:
            return []
        src, dst, proto, off, seg = ip
    elif etype == ETH_P_IPV6:
        ip6 = _parse_ipv6(rest)
        if not ip6:
            return []
        src, dst, proto, off, seg = ip6
    else:
        return []

    events: list[Event] = []
    inbound = dst in my_ips and src not in my_ips

    if proto == 6:  # TCP
        ports = _parse_ports(seg)
        if not ports:
            return []
        sport, dport = ports
        doff = (seg[12] >> 4) * 4 if len(seg) >= 13 else 20
        payload = seg[doff:] if len(seg) > doff else b""
        if not payload:
            return []
        sni = decode_tls_sni(payload)
        if sni:
            sev = 0
            if signatures.match_vendor_text(sni):
                sev = 80
            events.append(
                Event(ts, "sni", sni, src, dst, sport, dport, inbound, sev,
                      {"vendor": bool(sev)})
            )
            return events
        http = decode_http_proxy(payload)
        if http:
            kind, detail = http
            sev = 75 if kind == "http-connect" else 60
            return [
                Event(ts, kind, detail, src, dst, sport, dport, inbound, sev,
                      {"target": detail} if kind == "http-connect" else {})
            ]
        sk = decode_socks(payload)
        if sk:
            kind, detail = sk
            # An inbound SOCKS greeting from off-machine is the whole ballgame.
            sev = 95 if inbound else 40
            return [Event(ts, kind, detail, src, dst, sport, dport, inbound, sev)]
        return events

    if proto == 17:  # UDP
        ports = _parse_ports(seg)
        if not ports:
            return []
        sport, dport = ports
        payload = seg[8:]  # UDP header is 8 bytes: ports, length, checksum
        if not payload:
            return []
        if dport in (1900, 1900 + 1):
            info = decode_ssdp(payload)
            if info:
                return [Event(ts, "ssdp", info, src, dst, sport, dport, inbound, 45)]
        if sport in (53, 5353) or dport in (53, 5353):
            name = decode_dns(payload)
            if name:
                sev = 70 if signatures.match_vendor_text(name) else 0
                return [Event(ts, "dns", name, src, dst, sport, dport, inbound, sev,
                              {"vendor": bool(sev)})]
        info = decode_ssdp(payload)
        if info:
            return [Event(ts, "ssdp", info, src, dst, sport, dport, inbound, 45)]
        return events
    return events


# ------------------------------------------------------------------ capture


def my_addresses() -> set[str]:
    out: set[str] = set()
    try:
        for fam, _t, _p, _c, _s in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_UNSPEC, socket.SOCK_STREAM
        ):
            out.add(fam[4][0] if isinstance(fam, tuple) else str(fam))
    except OSError:
        pass
    # /proc is the truth; getaddrinfo is a nicety.
    for path in ("/proc/net/fib_trie",):
        text = util.read_text(path, 1 << 20)
        import re as _re

        for m in _re.finditer(r"\|--\s+(\d+\.\d+\.\d+\.\d+)", text):
            out.add(m.group(1))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        out.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    out.add("127.0.0.1")
    return out


class Sniffer:
    def __init__(self, iface: str = "any", snaplen: int = 2048):
        self.iface = iface
        self.snaplen = snaplen
        self.sock: socket.socket | None = None
        self.my_ips = my_addresses()

    def __enter__(self) -> "Sniffer":
        if not util.is_root():
            raise PermissionError("packet capture requires root")
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )
        self.sock.bind((self.iface, 0))
        self.sock.settimeout(0.5)
        return self

    def __exit__(self, *exc) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def frames(self) -> Iterator[tuple[float, bytes]]:
        assert self.sock is not None
        while True:
            try:
                data = self.sock.recv(self.snaplen)
            except TimeoutError:
                continue
            except OSError:
                return
            yield now(), data

    def scan(self, seconds: float = 30.0, stop: object | None = None) -> list[Event]:
        """Capture for `seconds` and return every interesting event."""
        events: list[Event] = []
        deadline = now() + seconds
        with self:
            for ts, frame in self.frames():
                if now() > deadline or (stop is not None and stop()):
                    break
                events.extend(analyze_frame(frame, ts, self.my_ips))
        return events


# ------------------------------------------------------------------ pcap replay


def read_pcap(path: str) -> Iterator[tuple[float, bytes]]:
    """Yield (ts, ethernet_frame) from a classic pcap file.

    Supports LINKTYPE_ETHERNET and LINKTYPE_LINUX_SLL/SLL2 so captures from
    `tcpdump -i any` replay correctly.
    """
    with open(path, "rb") as fh:
        magic = fh.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, nano = "<", False
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, nano = ">", False
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, nano = "<", True
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, nano = ">", True
        else:
            raise ValueError(f"not a pcap file: {path}")
        hdr = fh.read(20)
        if len(hdr) < 20:
            return
        linktype = struct.unpack(endian + "I", hdr[16:20])[0]
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec, _usec, caplen, _orig = struct.unpack(endian + "IIII", rec)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            ts = sec + (1e-9 if nano else 1e-6) * _usec
            if linktype == 1:  # Ethernet
                yield ts, data
            elif linktype == 113:  # LINUX_SLL
                if len(data) >= 16:
                    yield ts, b"\x00" * 12 + b"\x08\x00" + data[16:]
            elif linktype == 276:  # LINUX_SLL2
                if len(data) >= 20:
                    yield ts, b"\x00" * 12 + data[12:14] + data[20:]
            else:
                yield ts, data


def analyze_pcap(path: str, my_ips: set[str] | None = None) -> list[Event]:
    ips = my_ips if my_ips is not None else my_addresses()
    events: list[Event] = []
    for ts, frame in read_pcap(path):
        try:
            events.extend(analyze_frame(frame, ts, ips))
        except Exception:
            continue
    return events


# ------------------------------------------------------------------ summary


def summarize(events: list[Event]) -> dict:
    """Condense an event list into the counts that matter for a decision."""
    by_kind: dict[str, int] = {}
    inbound_socks: set[str] = set()
    vendors: set[str] = set()
    for ev in events:
        by_kind[ev.kind] = by_kind.get(ev.kind, 0) + 1
        if ev.inbound and ev.kind.startswith(("socks", "http-connect", "proxy-auth")):
            inbound_socks.add(ev.src)
        if ev.kind in ("sni", "dns") and ev.extra.get("vendor"):
            vendors.add(ev.detail)
    return {
        "total": len(events),
        "by_kind": by_kind,
        "inbound_proxy_clients": sorted(inbound_socks),
        "vendor_domains": sorted(vendors),
        "relay_proven": bool(inbound_socks),
        "worst": max((e.severity for e in events), default=0),
    }
