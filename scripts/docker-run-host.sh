#!/usr/bin/env bash
# Run cyber-posture against the Docker *host* (not only the container).
set -euo pipefail

IMAGE="${CYBER_IMAGE:-ghcr.io/marctheshark3/cyber-posture:latest}"
PROFILE="${CYBER_PROFILE:-default}"
STATE_DIR="${CYBER_STATE_DIR:-$HOME/.local/state/cyber-posture-docker}"
CONFIG_DIR="${CYBER_CONFIG_DIR:-$HOME/.config/cyber-posture}"
HUB_URL="${CYBER_HUB_URL:-}"

mkdir -p "$STATE_DIR/reports" "$STATE_DIR/host-integrity" "$CONFIG_DIR"

# Prefer local build if present
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  :
elif docker image inspect cyber-posture:local >/dev/null 2>&1; then
  IMAGE=cyber-posture:local
fi

ARGS=("$@")
if [[ ${#ARGS[@]} -eq 0 ]]; then
  ARGS=(scan)
fi

DOCKER_USER="${CYBER_DOCKER_USER:-0:0}"  # root inside for ss/proc completeness on host

exec docker run --rm -i \
  --net=host \
  --pid=host \
  --user "$DOCKER_USER" \
  -e CYBER_STATE_DIR=/var/lib/cyber-posture \
  -e CYBER_REPORT_DIR=/var/lib/cyber-posture/reports \
  -e CYBER_CONFIG_DIR=/etc/cyber-posture \
  -e CYBER_PROFILE="$PROFILE" \
  -e CYBER_HUB_URL="$HUB_URL" \
  -e CYBER_TZ="${CYBER_TZ:-America/New_York}" \
  -e HOST_ROOT=/host \
  -v "$STATE_DIR:/var/lib/cyber-posture" \
  -v "$CONFIG_DIR:/etc/cyber-posture" \
  -v /etc:/host/etc:ro \
  -v /tmp:/tmp \
  -v /var/tmp:/var/tmp \
  -v /dev/shm:/dev/shm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  "$IMAGE" \
  "${ARGS[@]}"
