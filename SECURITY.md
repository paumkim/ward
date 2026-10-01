# Security policy

## Reporting a vulnerability

Open a private security advisory on
[GitHub](https://github.com/paumkim/ward/security/advisories/new), or email
`paumkim@gmail.com`. Please do not open a public issue for anything that would
let someone bypass detection on someone else's machine.

Include: what you found, the WARD version, the rule or code path involved, and
a reproduction if you have one. Findings that produce a false all-clear (a
tampered or unreadable log reported as intact, an unfiltered process skipped by
a signature rule) are the ones I most want to hear about.

## Threat model

WARD defends **this host** against becoming a residential proxy: a relay that
carries strangers' traffic out over your residential IP.

### In scope

- A proxy, SOCKS, HTTP CONNECT or tunnel relay running or being installed here
- This host being used as a NAT gateway, transit router or VPN exit node
- Rootkits or root processes hiding relay sockets from `ss`/`lsof`
- Attempts to disable, blind or tamper with WARD itself
- Tor configured as a relay or exit rather than a client
- Local privilege escalation to root followed by any of the above

### Out of scope

- **A remote host using this machine as a plain internet gateway.** Nothing is
  listening locally, so there is nothing to observe. WARD closes the kernel-level
  routes (`ip_forward=0`, `forward` policy drop, no masquerade). Software-level
  abuse of a machine behaving like an ordinary endpoint is out of reach, and this
  document will not pretend otherwise.
- Detecting general malware, ransomware, or a compromised browser
- Web filtering, application allowlisting or antivirus
- Tracking you, or anything requiring a cloud account or a phone-home

## Trust assumptions

WARD runs as root, because reading other users' `exe` links and talking to
nftables requires it. It therefore trusts:

- The kernel and the `/proc` interface. A kernel-level rootkit defeats WARD.
- The host filesystem outside its own integrity manifest. WARD watches a fixed
  list of paths; it is not a whole-system integrity checker.
- Its own configuration files. `ward selftest` and `ward events --verify` are
  the checks for "has someone edited me".

`auto_kill` and `auto_lockdown` ship **disabled**. WARD will freeze and
quarantine a process before it kills one, and it will never target anything in
`signatures.PROTECTED_EXES`. Turn those on only after reading
`ward explain R05` and watching a few days of `ward watch` output.