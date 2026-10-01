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
sudo ward selftest           # 74 checks: detection, safety, performance, hygiene
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

Every change is journalled to `/var/lib/ward/restore-journal.jsonl`, including
the live sysctl values captured before they were changed.

`sudo ward restore` reverses all of it: removes the two config files, reloads
sysctl from whatever files remain, restarts resolved, reopens the firewalld
ports and services, removes the nft table, and restores any exec bit it revoked.
It prints the count and names anything it could not reverse. A self-test walks
the source and fails if `harden()` records a change that `restore()` has no
handler for, so the two cannot drift apart again.

The round trip was verified on this host: with WARD fully removed the public
zone held `dhcpv6-client ssh` and `8765/tcp`; after `ward harden` it held
`dhcpv6-client` and nothing; after `ward restore` it was back to `dhcpv6-client
ssh` and `8765/tcp`.

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

**R01 and R02, relay software by name and by content.**

R01 matches executable names. Sixty-plus of them, including the residential
agents: Bright Data, IPRoyal, Smartproxy, Webshare, NetNut, PacketStream,
Pawnacle, Proxidize.

R02 looks inside the executable for SOCKS handshakes, `CONNECT %s:%d HTTP/1.`,
Tor relay directives and vendor strings. This is what catches a renamed binary.
It is discounted for browsers and interpreters, which link proxy code
legitimately.

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

Every mode name is validated. A typo in `respond.mode` falls back to `observe`,
and `ward status` says so. WARD never does more than it was asked to do because
of a spelling mistake.

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
containment is re-applied.

The timer uses `Wants=ward.service`, not `Requires=`. With `Requires`, stopping
the daemon also stops the timer, so the tripwire could never notice the daemon
being dead, which is the only thing it exists to do. It sat inactive for 33
minutes for exactly that reason.

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
74/74 passed
```

Roughly a quarter of the codebase is tests. Two of the checks are worth knowing
about:

- one runs a full scan after every fixture is torn down and requires an idle
  machine to score zero
- one walks the source for functions and config keys that nothing references

The second one exists because 14 dead functions and 21 unread config knobs had
accumulated. A knob nothing reads is worse than no knob, because an operator
reads `relay_mbps_threshold` and believes it does something.

## A note on detection patterns

The byte patterns in `signatures.py` were measured, not guessed. Every candidate
was counted across 76,279 files under `/usr/bin`, `/usr/sbin`, `/usr/lib` and
`/usr/local` before being kept.

That process removed more patterns than it added. Four that had to go:

| needle | why |
|---|---|
| `\x05\x01\x00` | three bytes, and it is in almost every binary |
| `socks4://` | appears in glib, which handles proxy URLs properly |
| `ngrok` | appears in git-lfs and Qt |
| `Xray` | appears in inxi |

What survived splits into two tiers. Tier A occurs only in relay software and
counts on its own. Tier B needs two corroborating hits.

A regex that fails to compile silently degrades to a literal string match under
`re.escape`, which is how a detection rule dies without anyone noticing. The
self-test asserts the fallback set stays empty.

## Commands

`ward -h` groups these the same way, by what you are trying to do.

**Start here**

```
ward status       one-shot verdict, safe without sudo
ward explain R05  why a rule exists
ward selftest     prove the detector and the safety properties
```

**Look around** (read-only)

```
ward scan         the full finding list, not a summary
ward report       incident report, human-readable
ward events       read the hash-chained log
ward counters     firewall packet counters
ward baseline     the known-good inventory WARD diffs against
ward tripwire     is the daemon still alive and honest
```

**Check it works**

```
ward watch           scan on a loop in the foreground
ward watch-wire      live packet inspection for proxy protocols
ward analyze-pcap    decode a capture someone else took
```

**Change the machine** (needs root, all of it reversible)

```
ward harden      sysctl, LLMNR, sshd pinning, firewalld ports
ward restore     undo journalled hardening
ward firewall    render or install the nftables table
ward seal        record hashes of WARD's own files
```

**Respond to an incident**

```
ward lockdown       maximum containment
ward kill PID       terminate a process, with evidence first
ward unquarantine   undo a containment port drop
ward release PID    unfreeze a process, restore its exec bit
```

Every command has its own help, and an unknown command suggests the closest
match rather than printing all of them.

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
- If the daemon stops working, `ward status` says so instead of showing the last
  good score. A broken defender that reports "no findings" is worse than no
  defender, so the daemon publishes its own health and status refuses to render
  a clean verdict when the heartbeat is stale or a cycle is failing.
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

Three changes got it there:

1. `firewall-cmd` ran every cycle. Its D-Bus round trip took 8.02s on its own,
   longer than the whole interval. Rules that answer "how is this machine
   configured" are cached for `detect.external_interval_seconds` instead.
2. `observe_processes()` called `observe_sockets()` internally while `scan()`
   had already called it, so every `/proc/*/fd` was walked twice per cycle.
3. The default interval went from 3s to 10s. This is where most of the saving
   came from: a scan costs 0.26s, so running one every 3s is 8.5% of a core
   forever.

The interval change costs almost nothing in detection latency. The tripwire runs
every 60s regardless, and R05 needs two consecutive samples before it
corroborates, so it was never going to fire inside three seconds. Set
`detect.interval_seconds` back to 3.0 if you want the tighter loop and can pay
for it.

## Licence

MIT. See [LICENSE](LICENSE). Security policy and threat model in
[SECURITY.md](SECURITY.md).