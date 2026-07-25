#!/usr/bin/env bash
# Usage: sudo bash cyber-identify-port.sh [port]
set -euo pipefail
PORT="${1:-37807}"
echo "== ss =="
ss -ltnp "sport = :$PORT" || true
echo "== lsof =="
lsof -nP -iTCP:"$PORT" -sTCP:LISTEN || true
echo "== fuser =="
fuser -v "${PORT}/tcp" 2>&1 || true
echo "== ufw =="
ufw status verbose | head -40 || true
