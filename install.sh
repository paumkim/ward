#!/usr/bin/env bash
# WARD installer. Idempotent: safe to run twice.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB=/usr/local/lib/ward
BIN=/usr/local/bin/ward
ETC=/etc/ward
VAR=/var/lib/ward
RUN=/run/ward
UNITS="$SRC/systemd"

log()  { printf '  \033[1;32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[1;33mwarn\033[0m  %s\n' "$*"; }
die()  { printf '  \033[1;31mfail\033[0m  %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root: sudo $0"

log "checking python"
python3 - <<'EOF' || die "python3.11+ with tomllib is required"
import sys, tomllib, socket, struct
assert sys.version_info >= (3, 11), sys.version
EOF

log "installing package -> $LIB"
install -d -m 0755 "$LIB"
for f in "$SRC"/ward/*.py; do
    install -m 0644 "$f" "$LIB/$(basename "$f")"
done
install -m 0755 "$SRC/ward-bin" "$BIN"

log "installing config"
install -d -m 0755 "$ETC"
if [ -f "$ETC/ward.toml" ]; then
    cp -a "$ETC/ward.toml" "$ETC/ward.toml.bak.$(date +%Y%m%dT%H%M%S)"
    log "backed up existing $ETC/ward.toml"
fi
install -m 0644 "$SRC/config/ward.toml" "$ETC/ward.toml"

log "creating state dirs"
install -d -m 0700 "$VAR" "$VAR/snapshots" "$VAR/quarantine" "$ETC"
install -d -m 0755 "$RUN"

log "installing systemd units"
for u in ward.service ward-harden.service ward-tripwire.service ward-tripwire.timer; do
    install -m 0644 "$UNITS/$u" /etc/systemd/system/"$u"
done
systemctl daemon-reload

log "sealing WARD's own files"
"$BIN" seal >/dev/null 2>&1 && log "self-hashes recorded (self-tamper baseline)"

log "validating the nftables ruleset"
if "$BIN" firewall >/dev/null 2>&1; then
    log "ruleset validates"
else
    warn "ruleset did not validate (needs root for nft -c); continuing"
fi

cat <<'EOF'

  WARD installed. Next:

    sudo ward harden            # sysctl, LLMNR, sshd pinning, firewalld ports
    sudo ward firewall --apply  # default-deny input, no transit forwarding
    sudo ward selftest          # prove the detector actually fires
    ward status                 # current verdict
    ward explain R05            # why each rule exists

  Then arm the daemon when you are happy with the output:

    sudo systemctl enable --now ward.service ward-harden.service
    systemctl enable --now ward-tripwire.timer

EOF
