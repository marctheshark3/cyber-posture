#!/usr/bin/env bash
# Optional host hardening helpers (needs root). Review before running.
# Keeps SSH; prefers Tailscale NIC; binds Ollama to loopback if installed.
set -euo pipefail

echo "== Ollama loopback (if installed) =="
if systemctl list-unit-files 2>/dev/null | grep -q '^ollama.service'; then
  mkdir -p /etc/systemd/system/ollama.service.d
  cat >/etc/systemd/system/ollama.service.d/override.conf <<'UNIT'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
UNIT
  systemctl daemon-reload
  systemctl restart ollama.service || true
  sleep 1
  ss -tlnp | grep 11434 || true
else
  echo "ollama.service not found — skip"
fi

echo "== code-server (restart any code-server@ instances if present) =="
if systemctl list-unit-files 2>/dev/null | grep -q 'code-server@'; then
  systemctl restart 'code-server@*.service' 2>/dev/null || true
fi

echo "== ufw baseline (allow SSH + tailscale0) =="
if command -v ufw >/dev/null 2>&1; then
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw allow in on tailscale0 2>/dev/null || true
  ufw allow in on docker0 2>/dev/null || true
  ufw --force enable
  ufw status verbose
else
  echo "ufw not installed — skip"
fi

echo "== done =="
