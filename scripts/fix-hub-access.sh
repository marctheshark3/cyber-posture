#!/usr/bin/env bash
# Preview/add access to a hub only on an explicitly selected interface and source.
set -eEuo pipefail
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/firewall-common.sh"
APPLY=0
HUB_PORT="${HUB_PORT:-9093}"
HUB_INTERFACE=tailscale0
HUB_SOURCE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --port) HUB_PORT="${2:?Missing port}"; shift 2 ;;
    --interface) HUB_INTERFACE="${2:?Missing interface}"; shift 2 ;;
    --from) HUB_SOURCE="${2:?Missing source CIDR}"; shift 2 ;;
    --rollback) restore_firewall "${2:?Missing backup directory}"; exit ;;
    --help|-h)
      echo "Usage: $0 [--port 9093] [--interface tailscale0] [--from CIDR] [--apply]"
      echo "       $0 --rollback BACKUP_DIRECTORY"
      exit ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
validate_port "$HUB_PORT"
validate_interface "$HUB_INTERFACE"
if [[ -n "$HUB_SOURCE" ]]; then
  python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$HUB_SOURCE"
elif [[ "$HUB_INTERFACE" != tailscale* ]]; then
  echo "A LAN interface requires an explicit --from source CIDR." >&2
  exit 2
fi
RULE=(allow in on "$HUB_INTERFACE")
if [[ -n "$HUB_SOURCE" ]]; then RULE+=(from "$HUB_SOURCE"); fi
RULE+=(to any port "$HUB_PORT" proto tcp comment cyber-posture-hub)
printf 'Proposed: ufw'; printf ' %q' "${RULE[@]}"; printf '\n'
if [[ "$APPLY" != 1 ]]; then
  echo "Preview only. Use --apply to back up and apply this rule."
  exit 0
fi
require_root_ufw
ip link show dev "$HUB_INTERFACE" >/dev/null
backup_firewall
trap 'rollback_on_error "$?"' ERR
trap 'rollback_on_error 130' INT
trap 'rollback_on_error 143' TERM
ufw "${RULE[@]}"
ufw reload
ufw status verbose
trap - ERR INT TERM
printf 'Rollback: sudo %q --rollback %q\n' "$0" "$FIREWALL_BACKUP"
