#!/usr/bin/env bash
# Shared by the reviewed firewall helpers. Never source backup data as shell code.
validate_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)) || {
    echo "Invalid port: $1" >&2; return 2;
  }
}
validate_interface() {
  [[ "$1" =~ ^[a-zA-Z0-9_.:-]+$ ]] || { echo "Invalid interface: $1" >&2; return 2; }
}
require_root_ufw() {
  [[ "$EUID" == 0 ]] || { echo "Applying or restoring firewall rules requires root." >&2; return 2; }
  command -v ufw >/dev/null || { echo "ufw is not installed." >&2; return 2; }
}
backup_firewall() {
  umask 077
  mkdir -p /var/backups/cyber-posture || return "$?"
  FIREWALL_BACKUP="$(mktemp -d /var/backups/cyber-posture/ufw.XXXXXXXX)" || return "$?"
  cp -a -- /etc/ufw "$FIREWALL_BACKUP/ufw" || return "$?"
  cp -a -- /etc/default/ufw "$FIREWALL_BACKUP/default-ufw" || return "$?"
  LC_ALL=C ufw status verbose > "$FIREWALL_BACKUP/status.txt" || return "$?"
  echo "Firewall backup: $FIREWALL_BACKUP"
}
restore_firewall() {
  local backup="$1"
  # Rollback calls this function in an || list, which disables Bash errexit
  # inside the whole function. Propagate every failure explicitly.
  require_root_ufw || return "$?"
  [[ -d "$backup/ufw" && -f "$backup/default-ufw" && -f "$backup/status.txt" ]] || {
    echo "Not a firewall backup: $backup" >&2; return 2;
  }
  [[ "$(stat -c %u -- "$backup")" == 0 ]] || { echo "Backup must be owned by root." >&2; return 2; }
  local was_active
  if grep -qx 'Status: active' "$backup/status.txt"; then
    was_active=1
  elif grep -qx 'Status: inactive' "$backup/status.txt"; then
    was_active=0
  else
    echo "Backup firewall status is invalid: $backup/status.txt" >&2; return 2
  fi
  cp -a -- "$backup/ufw/." /etc/ufw/ || return "$?"
  cp -a -- "$backup/default-ufw" /etc/default/ufw || return "$?"
  if [[ "$was_active" == 1 ]]; then
    ufw --force enable || return "$?"
    ufw reload || return "$?"
  else
    ufw --force disable || return "$?"
  fi
  echo "Restored firewall from $backup"
}
rollback_on_error() {
  local rc="$1"
  trap - ERR INT TERM
  echo "Firewall update failed; restoring $FIREWALL_BACKUP" >&2
  restore_firewall "$FIREWALL_BACKUP" || echo "Automatic restore failed. Console recovery is required." >&2
  exit "$rc"
}
