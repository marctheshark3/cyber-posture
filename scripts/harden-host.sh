#!/usr/bin/env bash
# Host-level cyber hardening (needs root once).
# Safe: keeps SSH + Tailscale; binds Ollama loopback; restarts code-server.
set -euo pipefail

echo "== Ollama loopback =="
mkdir -p /etc/systemd/system/ollama.service.d
cat >/etc/systemd/system/ollama.service.d/override.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
EOF
systemctl daemon-reload
systemctl restart ollama.service
sleep 1
ss -tlnp | grep 11434 || true

echo "== code-server bind (user config already 127.0.0.1) =="
if systemctl list-unit-files | grep -q 'code-server@'; then
  systemctl restart "code-server@marctheshark.service" || systemctl restart 'code-server@*.service' || true
fi
ss -tlnp | grep 13337 || true

echo "== ufw baseline (allow SSH + tailscale0 + loopback semantics) =="
# Do not lock out: allow OpenSSH before enable
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
# Tailscale interface — full allow on tailnet NIC
ufw allow in on tailscale0
# Docker bridges often need established related; allow docker0 for container→host if needed
ufw allow in on docker0
# Comment: LAN (wl*) gets default deny — good
ufw --force enable
ufw status verbose

echo "== done =="
