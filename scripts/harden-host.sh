#!/usr/bin/env bash
# Preview a scoped UFW baseline; --apply preserves existing rules and creates a backup.
set -eEuo pipefail
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/firewall-common.sh"
APPLY=0
SSH_PORT=22
TRUSTED_INTERFACE=tailscale0
SSH_SOURCE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --ssh-port) SSH_PORT="${2:?Missing SSH port}"; shift 2 ;;
    --interface) TRUSTED_INTERFACE="${2:?Missing interface}"; shift 2 ;;
    --ssh-from) SSH_SOURCE="${2:?Missing source CIDR}"; shift 2 ;;
    --rollback) restore_firewall "${2:?Missing backup directory}"; exit ;;
    --help|-h)
      echo "Usage: $0 [--interface tailscale0] [--ssh-port 22] [--ssh-from CIDR] [--apply]"
      echo "       $0 --rollback BACKUP_DIRECTORY"
      exit ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
validate_port "$SSH_PORT"
validate_interface "$TRUSTED_INTERFACE"
if [[ -n "$SSH_SOURCE" ]]; then
  python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$SSH_SOURCE"
fi
RULE=(allow in on "$TRUSTED_INTERFACE")
if [[ -n "$SSH_SOURCE" ]]; then RULE+=(from "$SSH_SOURCE"); fi
RULE+=(to any port "$SSH_PORT" proto tcp comment cyber-posture-ssh)
echo "Proposed: preserve existing rules; deny incoming by default; allow outgoing."
printf 'Proposed: ufw'; printf ' %q' "${RULE[@]}"; printf '\n'
echo "Existing broad allow rules require separate review. Verify access from a second device."
if [[ "$APPLY" != 1 ]]; then
  echo "Preview only. Use --apply to back up and apply these rules."
  exit 0
fi
require_root_ufw
ip link show dev "$TRUSTED_INTERFACE" >/dev/null
backup_firewall
trap 'rollback_on_error "$?"' ERR
trap 'rollback_on_error 130' INT
trap 'rollback_on_error 143' TERM
ufw "${RULE[@]}"
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose
trap - ERR INT TERM
printf 'Rollback: sudo %q --rollback %q\n' "$0" "$FIREWALL_BACKUP"
