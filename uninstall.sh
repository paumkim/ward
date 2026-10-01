#!/usr/bin/env bash
# WARD uninstaller. Undoes what it can, and says plainly what it cannot.
set -uo pipefail

LOG="  "
log()  { printf '  \033[1;32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[1;33mwarn\033[0m  %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 1; }

echo
echo "  WARD uninstall"
echo

if systemctl is-active --quiet ward.service; then
    systemctl stop ward.service
    log "stopped ward.service"
fi
if systemctl is-enabled --quiet ward-tripwire.timer 2>/dev/null; then
    systemctl disable --now ward-tripwire.timer 2>/dev/null
    log "disabled ward-tripwire.timer"
fi
for u in ward.service ward-harden.service ward-tripwire.service ward-tripwire.timer; do
    systemctl disable --now "$u" >/dev/null 2>&1
    rm -f "/etc/systemd/system/$u"
done
systemctl daemon-reload
log "removed systemd units"

if command -v nft >/dev/null; then
    nft delete table inet ward 2>/dev/null && log "removed nft table inet ward"
    nft delete table inet ward_quarantine 2>/dev/null && log "removed quarantine table"
fi

if [ -f /var/lib/ward/restore-journal.jsonl ]; then
    echo
    echo "  Reverting the host hardening that WARD applied:"
    /usr/local/bin/ward restore 2>/dev/null || warn "restore failed; run 'ward restore' by hand"
fi

rm -f /usr/local/bin/ward
rm -rf /usr/local/lib/ward
log "removed the package"

cat <<'EOF'

  Kept on purpose (they are evidence, not code):
    /var/lib/ward/events.jsonl       hash-chained log
    /var/lib/ward/snapshots/         forensic snapshots
    /var/lib/ward/quarantine/        revoked binaries
    /var/lib/ward/restore-journal.jsonl
    /etc/ward/                       config and rendered ruleset
    /etc/sysctl.d/99-ward-hardening.conf

  Delete those by hand when you no longer need the record.

EOF
