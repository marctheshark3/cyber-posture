#!/usr/bin/env bash
# Install cyber-posture CLI for the current user.
set -euo pipefail
umask 077
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
  echo "PyYAML is required for the bundled profiles. Install python3-yaml, then rerun." >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${CYBER_BIN_DIR:-$HOME/bin}"
mkdir -p "$BIN_DIR"

ln -sfn "$ROOT/bin/cyber-posture" "$BIN_DIR/cyber-posture"
chmod +x "$ROOT/bin/cyber-posture" "$ROOT/scripts"/*.sh "$ROOT/lib/cyber_posture"/scan_*.py

if ! command -v cyber-posture >/dev/null 2>&1; then
  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "Add to shell rc:  export PATH=\"$BIN_DIR:\$PATH\""
  fi
fi

PROFILE="${CYBER_PROFILE:-default}"
if [[ "${1:-}" == "--link-scripts" ]]; then
  # Optional: drop copies/symlinks into a local scripts dir (set CYBER_LINK_DIR)
  LINK_DIR="${CYBER_LINK_DIR:-$HOME/.local/share/cyber-posture/scripts}"
  mkdir -p "$LINK_DIR"
  ln -sfn "$ROOT/lib/cyber_posture/scan_exposure.py" "$LINK_DIR/cyber-posture-scan.py"
  ln -sfn "$ROOT/lib/cyber_posture/scan_integrity.py" "$LINK_DIR/cyber-host-integrity-scan.py"
  ln -sfn "$ROOT/scripts/install-malware-tools.sh" "$LINK_DIR/cyber-malware-tools-install.sh"
  ln -sfn "$ROOT/scripts/harden-host.sh" "$LINK_DIR/cyber-harden-host.sh"
  ln -sfn "$ROOT/scripts/fix-hub-access.sh" "$LINK_DIR/cyber-fix-hub-access.sh"
  ln -sfn "$ROOT/scripts/identify-port.sh" "$LINK_DIR/cyber-identify-port.sh"
  echo "Scripts linked → $LINK_DIR"
fi

"$BIN_DIR/cyber-posture" init-config --profile "$PROFILE"
echo
echo "OK. Try:"
echo "  cyber-posture paths"
echo "  cyber-posture scan"
echo "  cyber-posture integrity --update-baseline"
