"""Known-bad signatures for proxy / relay / residential-network software.

Two kinds of match:
  * exe name / cmdline / path regexes -> "this process is relay software"
  * byte patterns in the binary        -> "this binary speaks SOCKS/HTTP-proxy"

The pattern list is intentionally conservative. A false positive on a Firefox
launch is a bad day; a false negative on a renamed SOCKS server is the whole
problem we are here to solve, so we lean on behaviour scoring as well.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class Sig(NamedTuple):
    name: str
    kind: str  # exe | cmdline | path
    pattern: str
    score: int
    why: str


_rx_cache: dict[str, re.Pattern] = {}

#: Patterns that failed to compile and fell back to a literal match. A broken
#: regex silently becoming a literal is how a detection rule dies quietly, so
#: the set is exposed and the self-test asserts it stays empty.
BROKEN_PATTERNS: set[str] = set()


def _rx(pattern: str) -> re.Pattern:
    rx = _rx_cache.get(pattern)
    if rx is None:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            BROKEN_PATTERNS.add(pattern)
            rx = re.compile(re.escape(pattern), re.IGNORECASE)
        _rx_cache[pattern] = rx
    return rx


# ------------------------------------------------------------------ exe names
# Binaries whose entire purpose is to forward traffic for someone else.
EXE_SIGS: list[Sig] = [
    Sig("dante", "exe", r"^dante$", 90, "SOCKS4/5 server"),
    Sig("microsocks", "exe", r"^microsocks$", 90, "SOCKS5 server"),
    Sig("sockd", "exe", r"^sockd$", 90, "sockd proxy daemon"),
    Sig("3proxy", "exe", r"^3proxy$", 85, "multi-protocol proxy suite"),
    Sig("tinyproxy", "exe", r"^tinyproxy$", 80, "lightweight HTTP proxy"),
    Sig("privoxy", "exe", r"^privoxy$", 70, "HTTP(S) filtering proxy"),
    Sig("squid", "exe", r"^squid$", 80, "caching proxy"),
    Sig("gost", "exe", r"^gost$|^gost\.?v?\d*$", 90, "GOST relay/proxy"),
    Sig("frp", "exe", r"^frpc$|^frps$|^frpc?_\w+$", 90, "FRP tunnel client/server"),
    Sig("ngrok", "exe", r"^ngrok$", 90, "ngrok tunnel agent"),
    Sig("cloudflared", "exe", r"^cloudflared$", 75, "Cloudflare tunnel connector"),
    Sig("chisel", "exe", r"^chisel", 85, "chisel TCP/UDP tunnel over HTTP"),
    Sig("ncat-nc", "exe", r"^ncat$|^netcat$|^nc\.openbsd$|^nc$", 60, "netcat (relay-capable)"),
    Sig("socat", "exe", r"^socat$", 55, "socat (relay-capable)"),
    Sig("rinetd", "exe", r"^rinetd$", 90, "port forwarder"),
    Sig("haproxy", "exe", r"^haproxy$", 60, "haproxy (can be a forward proxy)"),
    Sig("xray", "exe", r"^xray$", 85, "Xray proxy core"),
    Sig("v2ray", "exe", r"^v2ray$", 85, "V2Ray proxy core"),
    Sig("singbox", "exe", r"^sing-box$", 80, "sing-box proxy core"),
    Sig("shadowsocks", "exe", r"^ss-server$|^ss-local$|^shadowsocks", 85, "shadowsocks"),
    Sig("wireguard", "exe", r"^wg-quick$", 40, "WireGuard up (may be exit node)"),
    Sig("openvpn-server", "exe", r"^openvpn$", 50, "openvpn (server mode relays)"),
    Sig("iodine", "exe", r"^iodine$", 70, "iodine DNS tunnel"),
    Sig("dnscat", "exe", r"^dnscat2?$", 85, "dnscat DNS tunnel"),
    Sig("iodine-proxy", "exe", r"^iodine-proxy$", 85, "iodine proxy"),
    Sig("stunnel", "exe", r"^stunnel4?$", 45, "stunnel TLS wrapper"),
    Sig("redsocks", "exe", r"^redsocks$", 60, "redirector into a SOCKS proxy"),
    Sig("ss-local-tor", "exe", r"^ss-local$", 80, "socks client into a tunnel"),
    Sig("proxychains", "exe", r"^proxychains4?$", 30, "proxychains client (local only)"),
    Sig("resiproxy", "exe", r"^resiproxy$|^resi.*proxy$", 95, "residential proxy agent"),
    Sig("brightdata", "exe", r"^brightdata|bright-data|brightdata_", 95, "Bright Data agent"),
    Sig("oxylabs", "exe", r"^oxylabs|oxy-?proxy", 95, "Oxylabs agent"),
    Sig("iproyal", "exe", r"^iproyal", 95, "IPRoyal agent"),
    Sig("smartproxy", "exe", r"^smartproxy$|^smart_?proxy_?agent", 95, "Smartproxy agent"),
    Sig("webshare", "exe", r"^webshare", 95, "Webshare agent"),
    Sig("netnut", "exe", r"^netnut", 95, "NetNut agent"),
    Sig("geonode", "exe", r"^geonode", 90, "Geonode agent"),
    Sig("packetstream", "exe", r"^packetstream|^ps_\w+", 95, "PacketStream proxy"),
    Sig("pawnacle", "exe", r"^pawnacle", 95, "Pawnacle agent"),
    Sig("tensortrader", "exe", r"^tensor.?trader", 90, "residential proxy trader"),
    Sig("proxidize", "exe", r"^proxidize", 95, "Proxidize proxy stack"),
    Sig("gostcoin", "exe", r"^gost_?miner|^xmrig$", 90, "cryptomining relay/proxy"),
    Sig("xmrig", "exe", r"^xmrig", 85, "miner (shares the same abuse pattern)"),
]

# ------------------------------------------------------------------ cmdline
# A process that is *invoked* as a proxy, whatever the binary is called.
CMDLINE_SIGS: list[Sig] = [
    Sig("socks-serve-flag", "cmdline", r"(--socks-port|--socks5|-l\s*\d+\s*--socks)", 85,
        "SOCKS server flag"),
    Sig("botnet-word", "cmdline", r"\b(botnet|botnet_?node|bot[-_ ]?master|slave[-_ ]?node)\b", 90,
        "cmdline mentions botnet roles"),
    Sig("http-proxy-flag", "cmdline", r"(--http-port|http_proxy_port|--proxy-port)", 60,
        "HTTP proxy port flag"),
    Sig("redir-flag", "cmdline", r"(--redir\s+|--redirect\s+http)", 55, "redirection flag"),
    Sig("tun-flag", "cmdline", r"(--tun\s+--|\-interface\s+tun|setup_tun)", 55, "TUN device setup"),
    Sig("tun2socks", "cmdline", r"tun2socks|hev-socks5-tunnel", 70, "tun-to-socks bridge"),
    Sig("socat-listen", "cmdline", r"TCP-LISTEN|UDP4-LISTEN|UNIX-LISTEN|LISTEN:", 60,
        "socat-style listener in the command line"),
    Sig("fork-relay", "cmdline", r",fork[,)]|reuseaddr", 35, "forking listener flags"),
    Sig("relay-word", "cmdline", r"\b(socks5?[-_ ]?server|proxy[-_ ]?server|residential[-_ ]?proxy)\b",
        70, "cmdline advertises a proxy server"),
    Sig("sell-word", "cmdline", r"\b(sell|monetize|share)[\s_-]+(my[\s_-]+)?(bandwidth|traffic|internet)\b",
        80, "cmdline mentions selling bandwidth"),
    Sig("botnet-word", "cmdline", r"\b(botnet|botnet_?node|bot[-_ ]?master|slave[-_ ]?node)\b", 90,
        "cmdline mentions botnet roles"),
    Sig("peer2peer-share", "cmdline", r"--(share|lease)[-_ ]bandwidth|bandwidth[-_ ]share", 80,
        "bandwidth sharing flag"),
    Sig("wg-quick-up", "cmdline", r"wg-quick\s+up", 20, "WireGuard interface up"),
]

# ------------------------------------------------------------------ paths
# Files that should not exist on a machine that is not a relay.
PATH_SIGS: list[Sig] = [
    Sig("resi-config", "path", r"/(etc|opt|var/lib)/[\w./-]*(resi|residential)[-_]?proxy", 80,
        "residential proxy config path"),
    Sig("proxy-cred", "path", r"/\.(config|ward)/[\w./-]*proxy.*\.(json|yaml|yml|conf|txt)$", 45,
        "proxy credentials/config in dotfiles"),
]

# ------------------------------------------------------------------ binary content
# Byte patterns that indicate a proxy/tunnel binary.
#
# These were chosen empirically, not from memory: every candidate needle was
# counted across 76k files under /usr/bin, /usr/sbin, /usr/lib and /usr/local
# on the target machine. Anything that also occurs in glib, curl, git-lfs, Qt,
# inxi or javap was rejected or demoted. A three-byte sequence like
# "\x05\x01\x00" matched nearly everything, which is exactly how a content
# scanner becomes a noise generator -- so it is gone.
#
# TIER A ("decisive") was measured to appear only in relay software. One hit
# is enough.
TIER_A: list[tuple[str, bytes, int, str]] = [
    ("residential-proxy-client", b"residential_proxy", 90, "residential proxy client strings"),
    ("brightdata-client", b"Bright Data", 85, "Bright Data client strings"),
    ("iproyal-client", b"iproyal", 85, "IPRoyal client strings"),
    ("webshare-client", b"webshare", 75, "Webshare client strings"),
    ("socks-server-error", b"SOCKS5: connection not established", 85,
     "SOCKS5 server error strings"),
    ("socks-server-flag", b"--socks-port", 85, "SOCKS server command-line flag"),
    ("microsocks", b"microsocks", 90, "microsocks SOCKS5 server"),
    ("dante", b"SOCKS4/5", 85, "dante SOCKS server"),
    ("gost-relay", b"gost -L", 85, "GOST relay listener flags"),
    ("shadowsocks", b"shadowsocks", 80, "shadowsocks strings"),
    ("sing-box", b"sing-box", 75, "sing-box proxy core"),
    ("tor-exit-relay", b"ExitRelay", 80, "Tor ExitRelay directive"),
    ("socks5-auth-protocol", b"SOCKS5 authentication", 80, "SOCKS5 auth negotiation"),
    ("socks-proxy-service", b"SOCKS proxy", 60, "SOCKS proxy service handling"),
]

# TIER B ("supporting") is clean on a healthy system but not unique. Two
# independent Tier-B hits are required before this contributes anything, so a
# program that merely mentions socks4:// in a URL parser stays quiet.
TIER_B: list[tuple[str, bytes, int, str]] = [
    ("rotate-ips", b"rotate_ip", 70, "IP rotation logic"),
    ("proxy-pool", b"proxy_pool", 70, "proxy pool logic"),
    ("bandwidth-share", b"bandwidth_share", 70, "bandwidth sharing logic"),
    ("socks5-url", b"socks5://", 30, "SOCKS5 URL handling"),
    ("socks4-url", b"socks4://", 25, "SOCKS4 URL handling"),
    ("connect-builder", b"CONNECT %s:%d HTTP/1.", 45, "HTTP CONNECT request builder"),
    ("connect-established", b"HTTP/1.1 200 Connection established", 45,
     "HTTP CONNECT success response"),
    ("proxy-auth-header", b"Proxy-Authorization", 40, "Proxy-Authorization header"),
    ("privoxy", b"Privoxy", 60, "Privoxy filtering proxy"),
    ("tor-orport", b"ORPort", 20, "Tor ORPort directive"),
]

#: Kept as a flat list for callers that only want the names.
BYTE_SIGS: list[tuple[str, bytes, int, str]] = TIER_A + TIER_B

#: Tier B needs a second, independent hit before it counts.
TIER_B_MIN_HITS = 2

#: Content matches are weak on interpreters and on anything that merely imports a
#: proxy library, so they are discounted for these names.
BENIGN_CONTENT = {
    # interpreters and runtimes that link proxy-capable libraries by design
    "firefox", "librewolf", "chromium", "chrome", "brave", "opera", "vivaldi",
    "python3", "python", "node", "bun", "deno", "ruby", "perl", "java",
    "opencode", "term", "code", "electron", "gnome-shell", "plasmashell",
    "ssh", "curl", "wget", "git", "pacman", "systemd", "resolved", "nm",
    # mail / editors / tools that legitimately understand SOCKS URLs
    "thunar", "dolphin", "nautilus", "gwenview", "okular", "kmail", "mutt",
    "neomutt", "ranger", "yazi", "rsync", "curl", "aria2c", "wget2",
    # desktop plumbing: dbus, portals, kded, powerdevil, gvfs
    "dbus-broker", "dbus-broker-launch", "kded6", "kded5", "kactivitymanagerd",
    "kaccess", "ksystemstats", "ksecretd", "ksmserver", "xembedsniproxy",
    "gmenudbusmenuproxy", "xdg-desktop-portal", "xdg-desktop-portal-kde",
    "xdg-desktop-portal-gtk", "xdg-document-portal", "xdg-permission-store",
    "gvfsd", "gvfsd-fuse", "gvfsd-trash", "gvfs-udisks2-volume-monitor",
    "gvfs-mtp-volume-monitor", "gvfs-gphoto2-volume-monitor",
    "gvfs-afc-volume-monitor", "discover-notifier", "discover", "powerdevil",
    "kwin_wayland", "kwin_wayland_wrapper", "kwin_x11", "startplasma-wayland",
    "at-spi2-registryd", "at-spi-bus-launcher", "polkitd", "polkit-kde",
    "kscreenlocker", "kded", "pulseaudio", "pipewire", "wireplumber",
    "nvidia-smi", "grep", "sed", "awk", "sleep", "timeout", "tee", "tr",
    "cat", "head", "tail", "sort", "uniq", "journalctl", "coredumpctl",
    "crashhandler", "crashhelper", "xdg-open", "xdg-settings", "flatpak",
    "zypak", "bwrap", "zypak-helper", "fwupd", "upower", "accounts-daemon",
    "colord", "packagekitd", "packagekit", "plocate", "updatedb", "locate",
    "bash", "zsh", "fish", "sh", "dash", "systemd-journald", "pipewire-pulse",
    "xscreensaver", "ksmserver", "wmfw", "kscreen-doctor",
}

#: LD_PRELOAD targets that a program legitimately preloads on itself. Firefox
#: ships libmozsandbox.so and injects it into every child; flagging that at
#: "high" is how a detector teaches its operator to ignore it.
BENIGN_PRELOAD = {
    "libmozsandbox.so", "libxul.so", "libgmalloc.so", "libmozglue.so",
    "libnss3.so", "libjemalloc.so", "libtsan.so", "libasan.so",
}

#: Executables we never flag regardless of evidence, because breaking them
#: breaks the machine. Anything here is also protected from auto-kill.
PROTECTED_EXES = {
    "systemd", "systemd-journald", "systemd-resolved", "systemd-logind",
    "systemd-udevd", "systemd-networkd", "NetworkManager", "nmcli",
    "firewalld", "nft", "iptables", "ip", "sshd", "ssh", "sudo", "su",
    "sudoers", "polkitd", "packagekitd", "pacman", "bash", "zsh", "fish",
    "kdeconnectd", "rtkit-daemon", "pipewire", "wireplumber", "pulseaudio",
    "dbus-daemon", "Xorg", "Xwayland", "kwin_wayland", "kwin_x11",
    "gnome-keyring-daemon", "kscreenlocker", "fprintd", "upowerd",
    "ward", "python3.14", "python3.13", "python3.12",
}

#: Ports that are inherently "someone else's traffic" when listening.
RELAY_PORTS = {
    1080, 1081, 1082, 1086, 2080, 3128, 3333, 4444, 5555, 6666, 6667, 6697,
    7777, 8000, 8008, 8080, 8081, 8118, 8888, 8880, 9000, 9050, 9051, 9090,
    9150, 10000, 10808, 10809, 12345, 31337, 33333, 4711, 50000,
}

#: Domains that only ever appear when a machine is enrolled in a proxy network.
#: Matched on DNS queries we can observe, and on config/cmdline text.
VENDOR_DOMAINS = [
    "brightdata.com", "bright-data.net", "oxylabs.io", "iproyal.com",
    "smartproxy.com", "decodo.com", "webshare.io", "netnut.io", "geonode.com",
    "packetstream.io", "pawnacle.com", "tensortrader.com", "brightdata.pro",
    "proxy6.net", "proxyscrape.com", "scraperapi.com", "zyte.com",
    "residential-proxy", "proxidize", "traffmonetizer", "pactproxies",
]

#: Bare vendor tokens, so "iproyal:7000" in an env var matches as well as
#: "gw.iproyal.com" in a DNS query.
VENDOR_TOKENS = [
    "brightdata", "bright-data", "bright_data", "oxylabs", "iproyal",
    "smartproxy", "smart-proxy", "decodo", "webshare", "netnut", "geonode",
    "packetstream", "pawnacle", "tensortrader", "proxy6", "proxyscrape",
    "scraperapi", "proxidize", "traffmonetizer", "residential_proxy",
    "residential-proxy", "resi_proxy",
]

VENDOR_DNS_RX = re.compile(
    "|".join(re.escape(d) for d in VENDOR_DOMAINS), re.IGNORECASE
)
VENDOR_TEXT_RX = re.compile(
    "|".join(re.escape(d) for d in VENDOR_DOMAINS + VENDOR_TOKENS), re.IGNORECASE
)

EXE_RX = [(s, _rx(s.pattern)) for s in EXE_SIGS]
CMDLINE_RX = [(s, _rx(s.pattern)) for s in CMDLINE_SIGS]
PATH_RX = [(s, _rx(s.pattern)) for s in PATH_SIGS]


def match_exe(name: str) -> Sig | None:
    base = name.rsplit("/", 1)[-1]
    for sig, rx in EXE_RX:
        if rx.match(base):
            return sig
    return None


def match_cmdline(cmd: str) -> Sig | None:
    for sig, rx in CMDLINE_RX:
        if rx.search(cmd):
            return sig
    return None


def match_path(path: str) -> Sig | None:
    for sig, rx in PATH_RX:
        if rx.search(path):
            return sig
    return None


def match_vendor_text(text: str) -> bool:
    return bool(VENDOR_TEXT_RX.search(text))


def scan_bytes(data: bytes, exe_base: str) -> list[tuple[str, int, str]]:
    """Return [(name, score, why)] for proxy-protocol markers found in a binary.

    Two tiers: a Tier-A hit is decisive on its own, Tier B needs corroboration.
    """
    if exe_base in BENIGN_CONTENT:
        return []
    hits: list[tuple[str, int, str]] = []
    for name, needle, score, why in TIER_A:
        if needle in data:
            hits.append((name, score, why))
    tier_b = [(n, s, w) for n, needle, s, w in TIER_B if needle in data]
    if len(tier_b) >= TIER_B_MIN_HITS:
        # Corroborated: keep the strongest two and discount, so a program with
        # four incidental mentions does not outrank a real relay binary.
        tier_b.sort(key=lambda t: -t[1])
        for name, score, why in tier_b[:2]:
            hits.append((name, max(20, score - 15), f"{why} (corroborated)"))
    return hits


def is_protected(exe_base: str) -> bool:
    return exe_base in PROTECTED_EXES


def score_for_port(port: int) -> int:
    if port in RELAY_PORTS:
        return 55
    if 1024 <= port <= 65535 and port in (1080, 8080, 8888):
        return 55
    return 0
