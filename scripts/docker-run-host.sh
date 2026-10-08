#!/usr/bin/env bash
# Limited, read-only host evidence collection. Full persistence checks run natively.
set -euo pipefail
umask 077
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
VERSION="$(tr -d '[:space:]' < "$SCRIPT_DIR/../VERSION")"
IMAGE="${CYBER_IMAGE:-ghcr.io/marctheshark3/cyber-posture:$VERSION}"
STATE_DIR="${CYBER_STATE_DIR:-$HOME/.local/state/cyber-posture-docker}"
CONFIG_DIR="${CYBER_CONFIG_DIR:-$HOME/.config/cyber-posture}"
mkdir -p "$STATE_DIR/reports" "$STATE_DIR/host-integrity" "$CONFIG_DIR"
if [[ $# -eq 0 ]]; then set -- scan; fi
exec docker run --rm \
  --network host --pid host \
  --user "${CYBER_DOCKER_USER:-$(id -u):$(id -g)}" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  --tmpfs /run:rw,noexec,nosuid,nodev,mode=755 \
  -e CYBER_STATE_DIR=/var/lib/cyber-posture \
  -e CYBER_REPORT_DIR=/var/lib/cyber-posture/reports \
  -e CYBER_CONFIG_DIR=/etc/cyber-posture \
  -e "CYBER_PROFILE=${CYBER_PROFILE:-default}" \
  -e "CYBER_HUB_URL=${CYBER_HUB_URL:-}" \
  -e "CYBER_TZ=${CYBER_TZ:-UTC}" \
  -e HOST_ROOT=/host \
  --mount "type=bind,source=$STATE_DIR,target=/var/lib/cyber-posture" \
  --mount "type=bind,source=$CONFIG_DIR,target=/etc/cyber-posture,readonly" \
  --mount type=bind,source=/etc,target=/host/etc,readonly \
  --mount type=bind,source=/tmp,target=/host/tmp,readonly \
  --mount type=bind,source=/var/tmp,target=/host/var/tmp,readonly \
  --mount type=bind,source=/dev/shm,target=/host/dev/shm,readonly \
  "$IMAGE" "$@"
