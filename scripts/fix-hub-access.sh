#!/usr/bin/env bash
# Restore hub/Tailscale access after cyber harden (ufw default-deny).
# Env: HUB_PORT (default 9093), LAN_TEST_URL, TS_TEST_URL optional echo only.
set -euo pipefail
HUB_PORT="${HUB_PORT:-9093}"

echo "== before =="
ufw status verbose || true

ufw allow OpenSSH comment 'ssh' || true
ufw allow in on lo comment 'loopback' || true
ufw allow in on tailscale0 comment 'tailscale iface' || true
ufw allow 41641/udp comment 'tailscale wireguard' || true
ufw allow "${HUB_PORT}/tcp" comment 'wiki-hub' || true
ufw allow from 100.64.0.0/10 comment 'tailscale CGNAT' || true

ufw reload
echo "== after =="
ufw status verbose

echo
echo "Set LAN_TEST_URL / TS_TEST_URL to print your phone test links."
[[ -n "${LAN_TEST_URL:-}" ]] && echo "LAN: $LAN_TEST_URL"
[[ -n "${TS_TEST_URL:-}" ]] && echo "Tailscale: $TS_TEST_URL"
