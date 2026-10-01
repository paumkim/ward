# WARD

**Make this machine impossible to quietly sell as a residential proxy.**

A residential proxy network pays for your home connection. The moment your IP
address is on someone's proxy pool, strangers' traffic leaves through your
uplink: scraping, ad fraud, credential stuffing, whatever the buyer paid for.
You get a few dollars a month, you carry the traffic, you carry the complaints,
and if anyone traces it, it is your address on a warrant.

WARD defends against that in four layers: **prevent** the machine from being
capable of it, **detect** it if it happens anyway, **prove** it at packet level,
and **contain** it without destroying the evidence.

Pure Python standard library. No dependencies, because a defender that needs a
package index to start is a defender that will not start.

---

## Quick start

```bash
sudo ./install.sh

sudo ward harden             # sysctl, LLMNR, sshd pinning, firewalld ports
sudo ward firewall --apply   # default-deny input, no transit forwarding
sudo ward selftest           # prove the detector actually fires
ward status                  # your current verdict
```

Arm the daemon once you trust the output:

```bash
sudo systemctl enable --now ward.service ward-harden.service
systemctl enable --now ward-tripwire.timer
```

---

## What is actually being defended

A machine becomes a residential proxy through one of four doors. WARD closes
all four, and watches all four.

| Door | What it looks like | WARD's answer |
|---|---|---|
| **A listener** | `dante`, `3proxy`, `socat TCP-LISTEN`, a renamed binary | R01, R02, R03 — signature, byte scan, and port classification |
| **A relay** | No new binary, just a process relaying for strangers | R05 — connection fan-out: many sockets, many unrelated IPs, many /16s |
| **Forwarding** | `ip_forward=1` + NAT so a neighbour's traffic rides your uplink | R07 + the `inet ward` forward chain with `policy drop` |
| **Persistence** | A systemd unit or cron job that restarts the relay | R10, R11 — watched directories and a learned baseline |

Two of these are the ones people miss. R05 catches a proxy that has been renamed
to `weatherd`, because renaming a binary does not change the shape of its
traffic. R07 catches the case where nothing is running at all right now, but
the machine is *primed* — forwarding on, a stale `99-tailscale.conf` waiting to
re-enable it at next boot.

---

## Layer 1 — Prevention

**`ward firewall`** installs one nftables table, `inet ward`:

- `input` policy **drop**, with an explicit allowlist
- `forward` policy **drop**, with no accept rules at all — this machine is an
  endpoint, never a router
- `output` policy accept
- every known relay port (1080, 3128, 8080, 8888, 9050, …) dropped on input,
  **including from the LAN**, so a compromised neighbour cannot use you either

The table is installed at hook priority `filter - 5`, *before* firewalld's
`filter + 10`. firewalld keeps managing its zones; WARD's drop is simply
evaluated first, so a firewalld misconfiguration cannot open a hole.

**`ward harden`** writes `/etc/sysctl.d/99-ward-hardening.conf` (sorted last, so
it wins) and:

- forces `net.ipv4.ip_forward=0` and IPv6 forwarding off
- **quarantines any sysctl file that would re-enable them** — on this host that
  means `99-tailscale.conf`, left behind by a tailscale install that is no
  longer present
- drops ICMP redirects, source routing, and `accept_local`
- turns on `rp_filter`, `log_martians`, `syn_cookies`
- disables LLMNR in systemd-resolved (spoofable, and it answers for your
  neighbours)
- pins `sshd` against `GatewayPorts`/`PermitTunnel`/`AllowAgentForwarding`
- closes firewalld's open public ports

Every change is journalled to `/var/lib/ward/restore-journal.jsonl`.
`sudo ward restore` puts it all back.

---

## Layer 2 — Detection

Fourteen rules, each explainable:

```bash
ward explain R05
```

Scoring is additive within reason, but a single 95 outranks a pile of 30s:
composite = worst + a decayed contribution from the rest. Ten weak signals
cannot manufacture a critical verdict, and one strong signal is not diluted.

The rules that carry the most weight:

**R03 — world-reachable listener.** A proxy needs an inbound door. A TCP
listener on a non-loopback address is 30; on a known relay port 55; on
`0.0.0.0`/`::` another 15 on top. This is the highest-precision rule there is:
a laptop has no business having one.

**R05 — connection fan-out.** One process holding many established connections
to many unrelated remote IPs across many /16s. Browsers and dev toolchains get
a 400-connection budget; everything else gets 25 distinct IPs. A firefox with
60 connections is a firefox. A `python3` with 60 connections to 40 different
`/16`s is a proxy.

**R01/R02 — relay software, by name and by content.** 60+ executable names
(`dante`, `gost`, `frpc`, `ngrok`, plus the residential agents: Bright Data,
IPRoyal, Smartproxy, Webshare, NetNut, PacketStream, Pawnacle, Proxidize…), and
a byte-pattern scan for SOCKS handshakes, `CONNECT %s:%d HTTP/1.`, Tor relay
directives, and vendor strings. R02 is what catches the renamed binary; it is
discounted for browsers and interpreters, which legitimately link proxy code.

**R06 — vendor strings** in any process's command line, cwd, or environment.
Catches enrolment before traffic flows.

---

## Layer 3 — Proof

```bash
sudo ward watch-wire 60
sudo ward analyze-pcap capture.pcap
```

Raw AF_PACKET capture, decoded in stdlib: TLS ClientHello SNI, HTTP `CONNECT`,
`Proxy-Authorization`, SOCKS4/SOCKS5 requests with their target host and port,
SSDP/UPnP, and DNS query names. Replays pcap files, so you can hand a capture
to someone else and they can re-derive the same conclusion.

An inbound SOCKS greeting from an off-machine address is scored 95 and reported
as `RELAY PROVEN` with the source addresses listed. That is the evidence an ISP
or a provider will actually accept — a signature match is an opinion, a packet
capture is a fact.

---

## Layer 4 — Containment

Response modes, in escalating order:

| Mode | Does |
|---|---|
| `observe` | Logs and alerts. **Default.** Never acts. |
| `contain` | Drops the relaying port in nft, freezes the process in a cgroup, revokes exec permission on its binary |
| `kill` | Contain, then SIGTERM → SIGKILL |
| `lockdown` | Kill, close all inbound except the allowlist, drop every relay port, force forwarding off |

**Forensics come first, always.** Before anything is touched:

- a full snapshot: `ss`, `ps`, nft ruleset, sysctl, routes, ARP, systemd units,
  `/proc/*/fd`, `MANIFEST.sha256`
- per-PID deep dive: cmdline, maps, environ, cgroup, a **copy of the binary**
- a 15-second pcap where tcpdump is available

Then containment, then a copy of the binary in `quarantine/` and `chmod 000` on
the original. The running process keeps its mapped pages, which is what you
want — the process stays visible in `ss` output while it stops moving.

Auto-kill is **off** by default and `auto_lockdown` is off. Move to `contain`
after your baseline is clean, then to `kill` once you have watched a few days
of output and believe the false-positive rate.

**The tripwire.** `ward-tripwire.timer` runs every minute from a separate unit
the daemon cannot stop. If the heartbeat goes stale while lockdown is armed,
containment is re-applied. Killing the daemon does not silence the defender.

---

## The event log is tamper-evident

Each record carries the SHA-256 of the previous one:

```
ward events --verify
ward report
```

Truncation, reordering, or editing any record breaks the chain and is reported
with the sequence number. If someone empties the log to hide that your machine
was relaying, the break is the evidence. Rate-limited to 240 events/minute so
a runaway loop cannot fill your disk.

---

## Self-test

```bash
sudo ward selftest
```

This is the part that makes the rest credible. It spawns **real** fixtures — an
actual SOCKS5 server, an actual HTTP CONNECT relay, a binary with SOCKS bytes
under a fake name — and asserts that the rules fire, and that they stay quiet on
a normal loopback listener. It also asserts the inverse properties that matter
most: that WARD never targets itself, never targets PID 1, and that
`observe` mode takes no action at score 95.

Everything runs on `127.0.0.1`, so the test never puts a working proxy on a
real interface.

---

## Commands

```
ward status              one-shot verdict
ward scan --json         full finding list
ward watch               live loop, foreground
ward daemon              supervised background loop
ward harden [--dry-run]  apply host hardening
ward restore             undo journalled hardening
ward firewall [--apply]  render or install the nftables table
ward counters            packet counters from the live table
ward lockdown            maximum containment
ward kill PID            terminate a process, with evidence
ward watch-wire [SECS]   live packet inspection
ward analyze-pcap FILE   decode a capture
ward report              incident report
ward events [--verify]   read / verify the log
ward baseline [--reset]  learn or show the known-good inventory
ward tripwire            check the daemon heartbeat
ward explain R05         why a rule exists
ward selftest            prove the detector fires
```

Exit code is 0 below score 70, 1 at or above — so `ward status` works as a
monitoring check.

---

## Configuration

`/etc/ward/ward.toml`, or `~/.config/ward/ward.toml` for user overrides.
Env overrides use `WARD_` with `__` for nesting: `WARD_RESPOND__MODE=contain`.

Built-in defaults are strict. Every knob exists so you can loosen one specific
thing without weakening the system — and the one knob you should look at
carefully is `firewall.lan_allowlist`, because every entry is a hole in the
default-deny wall. Prefer binding a service to `127.0.0.1` over opening a port.

---

## What WARD will not do

- It will not kill processes while in `observe` mode, and it will not touch
  anything in `signatures.PROTECTED_EXES` (systemd, NetworkManager, firewalld,
  the shell, WARD itself) regardless of evidence.
- It will not modify your firewalld zones beyond closing open public ports, and
  it will not disable the NetworkManager.
- It is not an IDS replacement, a sandbox, or a VPN client. It is one specific
  job, done thoroughly: this machine does not become someone else's proxy.
- Nothing here needs a cloud account, a phone-home, or a subscription.
