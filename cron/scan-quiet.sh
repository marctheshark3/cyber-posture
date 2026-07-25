#!/usr/bin/env bash
set -euo pipefail
exec cyber-posture scan --quiet "$@"
