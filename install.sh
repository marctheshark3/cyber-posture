#!/usr/bin/env bash
# Install cyber-posture CLI for the current user.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${CYBER_BIN_DIR:-$HOME/bin}"
mkdir -p "$BIN_DIR"

ln -sfn "$ROOT/bin/cyber-posture" "$BIN_DIR/cyber-posture"
chmod +x "$ROOT/bin/cyber-posture" "$ROOT/scripts"/*.sh "$ROOT/lib/cyber_posture"/scan_*.py

# ensure ~/bin on PATH hint
if ! command -v cyber-posture >/dev/null 2>&1; then
  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo "Add to shell rc:  export PATH=\"$BIN_DIR:\$PATH\""
  fi
fi

PROFILE="${CYBER_PROFILE:-default}"
if [[ "${1:-}" == "--hermes-tron" ]]; then
  H="$HOME/.hermes/profiles/tron/scripts"
  mkdir -p "$H"
  ln -sfn "$ROOT/lib/cyber_posture/scan_exposure.py" "$H/cyber-posture-scan.py"
  ln -sfn "$ROOT/lib/cyber_posture/scan_integrity.py" "$H/cyber-host-integrity-scan.py"
  ln -sfn "$ROOT/scripts/install-malware-tools.sh" "$H/cyber-malware-tools-install.sh"
  ln -sfn "$ROOT/scripts/harden-host.sh" "$H/cyber-harden-host.sh"
  ln -sfn "$ROOT/scripts/fix-hub-access.sh" "$H/cyber-fix-hub-access.sh"
  ln -sfn "$ROOT/scripts/identify-port.sh" "$H/cyber-identify-port.sh"
  # wrappers
  cat >"$H/cyber-posture-scan-quiet.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$BIN_DIR/cyber-posture" scan --quiet "\$@"
EOF
  cat >"$H/cyber-host-integrity-quiet.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$BIN_DIR/cyber-posture" integrity --quiet "\$@"
EOF
  cat >"$H/cyber-host-integrity-deep.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec "$BIN_DIR/cyber-posture" integrity --deep --quiet "\$@"
EOF
  chmod +x "$H"/cyber-posture-scan-quiet.sh "$H"/cyber-host-integrity-*.sh
  echo "Hermes tron scripts linked → $H"
  PROFILE=spark-adb4
fi

"$BIN_DIR/cyber-posture" init-config --profile "$PROFILE" || true
echo
echo "OK. Try:"
echo "  cyber-posture paths"
echo "  cyber-posture scan"
echo "  cyber-posture integrity --update-baseline"
