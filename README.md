# WARD

Keep this machine from being sold as a residential proxy.

A residential proxy network pays for your home connection. Once your IP is on
someone's proxy pool, strangers' traffic leaves over your uplink and your
address is what ends up on the complaint. You get a few dollars a month. You
carry the traffic and the liability.

WARD closes the four doors through which that happens, and collects proof when
you need to show anyone.

Pure Python standard library. No dependencies. A defender that needs a package
index to start on an attacked machine will not start.

## Quick start

```bash
sudo ./install.sh

sudo ward harden             # sysctl, LLMNR, sshd pinning, firewalld ports
sudo ward firewall --apply   # default-deny inbound, no transit forwarding
sudo ward selftest           # 68 checks: detection, safety, performance, hygiene
ward status                  # current verdict
```

Arm the daemon once you trust the output:

```bash
sudo systemctl enable --now ward.service ward-harden.service
systemctl enable --now ward-tripwire.timer
```

Undo everything:

```bash
sudo ward restore
```

## How a machine becomes a proxy

Four doors. WARD closes all four and watches all four.

| Door | What it looks like | WARD's answer |
|------|--------------------|---------------|
| A listener | `dante`, `3proxy`, `socat TCP-LISTEN`, a renamed binary | R01, R02, R03 |
| A relay | No new binary, just a process forwarding for strangers | R05 |
| Forwarding | `ip_forward=1` plus NAT so a neighbour's traffic rides your uplink | R07 and a `forward` chain with `policy drop` |
| Persistence | A systemd unit or cron job that restarts the relay | R10, R11 |

Two of these get missed most often.

R05 catches a proxy renamed to `weatherd`. Renaming a binary does not change
the shape of its traffic.

R07 catches the case where nothing is running right now but the machine is
primed. A stale `99-tailscale.conf` waiting to re-enable forwarding at next
boot is the whole attack surface, and there is no process to find.

## Prevention

`ward firewall` installs one nftables table, `inet ward`:

- `input` policy `drop`, behind an explicit allowlist
- `forward` policy `drop`, with no accept rules at all
- `output` policy `accept`
- every known relay port (1080, 3128, 8080, 8888, 9050, ...) refused inbound,
  including from the LAN, so a compromised neighbour cannot use you either

The table loads at hook priority `filter - 5`, ahead of firewalld's
`filter + 10`. firewalld keeps managing its zones. WARD's drop is evaluated
first, so a firewalld misconfiguration cannot open a hole.

`ward harden` writes `/etc/sysctl.d/99-ward-hardening.conf`. It sorts last, so it wins:

- `net.ipv4.ip_forward=0` and IPv6 forwarding off
- any sysctl file that would re-enable them gets quarantined
- ICMP redirects, source routing and `accept_local` off
- `rp_filter`, `log_martians` and `syn_cookies` on
- LLMNR disabled in systemd-resolved
- `sshd` pinned against `GatewayPorts`, `PermitTunnel` and
  `AllowAgentForwarding`
- firewalld's open public ports and unused services closed

Every change is journalled to `/var/lib/ward/restore-journal.jsonl`.

## Detection

Fourteen rules, each explainable:

```bash
ward explain R05
```

Scoring is additive but damped: the worst signal plus a decayed contribution
from the rest. One 95 is not diluted by six 30s, and six 30s do not add up to
95.

Two independent signatures corroborate each other below the 80-point threshold,
which is why a renamed `socat TCP-LISTEN:1080,fork,reuseaddr` still scores 85.
A single signature below the threshold is not enough.

**R03, network-reachable listener.** A proxy needs an inbound door, and a
laptop has no business having one. A TCP listener on a non-loopback address
scores 30. On a known relay port, 55. On `0.0.0.0` or `::`, another 15.

**R05, connection fan-out.** One process holding many established connections
to many unrelated remote IPs across many /16s. Browsers and dev toolchains get
a 400-connection budget. Everything else gets 25 distinct IPs. A firefox with 60
connections is a firefox. A `python3` with 60 connections to 40 different /16s
is a proxy.

**R01 and R02, relay software by name and by content.** Sixty-plus executable
names, including the residential agents (Bright Data, IPRoyal, Smartproxy,
Webshare, NetNut, PacketStream, Pawnacle, Proxidize). Then a byte-pattern scan
for SOCKS handshakes, `CONNECT %s:%d HTTP/1.`, Tor relay directives and vendor
strings. R02 is what catches the renamed binary. It is discounted for browsers
and interpreters, which link proxy code legitimately.

**R06, vendor strings** in any process's command line, cwd or environment.
Catches enrolment before traffic flows.

## Proof

```bash
sudo ward watch-wire 60
sudo ward analyze-pcap capture.pcap
```

Raw AF_PACKET capture, decoded in stdlib: TLS ClientHello SNI, HTTP `CONNECT`,
`Proxy-Authorization`, SOCKS4 and SOCKS5 requests with target host and port,
SSDP/UPnP, and DNS query names. Replays pcap files, so someone else can
re-derive the same conclusion from the same evidence.

An inbound SOCKS greeting from an off-machine address scores 95 and is reported
as `RELAY PROVEN` with the source addresses listed. A signature match is an
opinion. A packet capture is a fact.

## Containment

Every mode name is validated. A typo in `respond.mode` falls back to
`observe`, and `ward status` says so. WARD never does more than it was asked to
do because of a spelling mistake.

| Mode | Does |
|------|------|
| `observe` | Logs and alerts. Default. Never acts. |
| `contain` | Drops the relaying port in nft, freezes the process in a cgroup, revokes exec permission on its binary |
| `kill` | Contain, then SIGTERM and SIGKILL |
| `lockdown` | Kill, close all inbound except the allowlist, drop every relay port, force forwarding off |

Forensics come first, always. Before anything is touched:

- a full snapshot: `ss`, `ps`, nft ruleset, sysctl, routes, ARP, systemd units,
  `/proc/*/fd`, `MANIFEST.sha256`
- per-PID deep dive: cmdline, maps, environ, cgroup, a copy of the binary
- a 15-second pcap where tcpdump is available

Then containment. Then a copy of the binary in `quarantine/` and `chmod 000` on
the original. The running process keeps its mapped pages, so it stays visible in
`ss` output while it stops moving.

`auto_kill` and `auto_lockdown` ship disabled. Move to `contain` after your
baseline is clean, then to `kill` once you have watched a few days of output.

**Undo paths.** Every containment action has a command that reverses it, because
a false positive must be recoverable by a human without a reboot:

```
ward unquarantine          clear the port-quarantine table
ward release PID           unfreeze a process and restore its exec bit
ward kill PID --no-evidence   skip the snapshot, just kill
```

`ward status` lists every binary whose exec bit has been revoked and whether the
original is executable again.

**The tripwire.** `ward-tripwire.timer` runs every minute from a unit the
daemon cannot stop. If the heartbeat goes stale while lockdown is armed,
containment is re-applied. Killing the daemon does not silence the defender.

## The event log is tamper-evident

Each record carries the SHA-256 of the previous one.

```
ward events --verify
ward report
```

Editing, reordering or deleting a record breaks the chain and is reported with
the sequence number. Emptying the log to hide that your machine was relaying
leaves the break as the evidence. Rate-limited to 240 events per minute so a
runaway loop cannot fill your disk.

Two cases report failure rather than a clean result: an unreadable log, and a
log holding fewer records than the running daemon claims to have written. A
tamper-evident log that reports all-clear to anyone who cannot open it is worse
than no log.

## Self-test

```bash
sudo ward selftest
```

This is what makes the rest of the README believable. It spawns real fixtures: a
working SOCKS5 server, a working HTTP CONNECT relay, and a binary carrying relay
bytes under a fake name. Then it asserts the rules fire on them.

It also asserts the inverse properties:

- a loopback listener stays quiet
- a healthy idle machine scores under 70, with no relay findings
- WARD never targets itself or PID 1
- `observe` mode takes no action at score 95

Everything runs on `127.0.0.1`, so the test never puts a working proxy on a real
interface.

```
68/68 passed
```

Roughly a quarter of the codebase is tests. Two of those checks are worth
naming: one runs a full scan after every fixture is torn down and requires an
idle machine to score zero, and one walks the source for functions and config
keys that nothing references. The second exists because 14 dead functions and
21 unread config knobs had accumulated. A knob nothing reads is worse than no
knob, because an operator reads `relay_mbps_threshold` and believes it does
something.

## A note on detection patterns

The byte patterns in `signatures.py` were measured, not guessed. Every candidate
was counted across 76,279 files under `/usr/bin`, `/usr/sbin`, `/usr/lib` and
`/usr/local` before being kept.

That process removed more patterns than it added. The obvious three-byte SOCKS5
greeting `\x05\x01\x00` appears in almost every binary and was deleted.
`socks4://` appears in glib. `ngrok` appears in git-lfs and Qt. `Xray` appears
in inxi. Patterns that only occur in relay software are tier A and count on
their own. Everything else is tier B and needs two corroborating hits.

A regex that fails to compile silently degrades to a literal string match under
`re.escape`, which is how a detection rule dies without anyone noticing. The
self-test asserts the fallback set stays empty.

## Commands

```
ward status              one-shot verdict
ward scan [--json]       full finding list
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
ward events [--verify]   read or verify the log
ward baseline [--reset]  learn or show the known-good inventory
ward tripwire            check the daemon heartbeat
ward explain R05         why a rule exists
ward selftest            prove the detector fires
ward unquarantine        undo a containment port drop
ward release PID         unfreeze a process, restore its exec bit
ward seal                record hashes of WARD's own files
```

Exit code is 0 below score 70 and 1 at or above, so `ward status` works as a
monitoring check.

## Configuration

`/etc/ward/ward.toml`, then `~/.config/ward/ward.toml` for user overrides. Env
overrides use `WARD_` with `__` for nesting, such as
`WARD_RESPOND__MODE=contain`.

Defaults are strict. Every knob exists so you can loosen one specific thing
without weakening the rest. A knob that nothing reads is deleted rather than
documented, and the self-test fails if one comes back.

One knob needs care: `firewall.lan_allowlist`. Every entry is a hole in the
default-deny wall. Prefer binding a service to `127.0.0.1` over opening a port.

## Limits

- It will not kill anything in `observe` mode, and it will not touch anything
  in `signatures.PROTECTED_EXES` regardless of evidence.
- It cannot stop a remote host using this machine as a plain internet gateway
  with no local listener. Nothing listening means nothing to observe. The
  forwarding rules close the kernel-level routes. Software-level, that case is
  undetectable, and this README will not pretend otherwise.
- It reads `/proc` and talks to netlink. A kernel-level rootkit defeats it.
- It watches a fixed list of paths for integrity. It is not a whole-system
  integrity checker.
- Nothing here needs a cloud account, a phone-home, or a subscription.

## Cost

Measured on this host, not estimated:

| | before | after |
|---|---|---|
| warm scan | 6.22s | 0.26s |
| steady-state CPU | 15.4% of a core | under 1% |
| scan interval | 3s | 10s |

Three things got it there. `firewall-cmd` was being run every cycle, and its
D-Bus round trip took 8.02s on its own, longer than the whole interval. Rules
that answer "how is this machine configured" are now cached for
`detect.external_interval_seconds`. And the default interval went from 3s to
10s, which is where most of the CPU saving came from: a scan costs 0.26s, so
running it every 3s is 8.5% of a core forever.

The interval change costs almost nothing in detection latency. The tripwire runs
every 60s regardless, and R05 needs two consecutive samples before it
corroborates, so it was never going to fire inside three seconds. Set
`detect.interval_seconds` back to 3.0 if you want the tighter loop and can pay
for it.

## Licence

MIT. See [LICENSE](LICENSE). Security policy and threat model in
[SECURITY.md](SECURITY.md).