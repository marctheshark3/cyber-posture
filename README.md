# cyber-posture

Portable **Linux host cyber posture** toolkit: network exposure scanning + host integrity / malware IoCs.

Built for multi-machine use (workstation, DGX, home lab). Originally developed for Rage Industries / House OS on `spark-adb4`, now profile-driven.

## What you get

| Command | Purpose |
|---------|---------|
| `cyber-posture scan` | Listeners, docker publishes, ufw, auth HTTP probes, LAN reachability + **quick integrity** merge |
| `cyber-posture integrity` | IoCs (ld.so.preload, fake kernel procs, tmp ELF, SSH/cron/systemd drift) |
| `cyber-posture integrity --deep` | + chkrootkit, rkhunter, debsums, ClamAV (if installed) |
| `cyber-posture integrity --clam` | Scoped signature scan (Downloads/tmp/shm) |
| `cyber-posture digest` | Short daily summary (stdout → cron/Discord) |
| `cyber-posture scan --quiet` | Cron: silent unless CRITICAL/HIGH fingerprint **changes** |
| `cyber-posture init-config` | Seed `~/.config/cyber-posture/config.yaml` |

**No root required** for core scans. Optional: `sudo scripts/install-malware-tools.sh`.

## Quick start (any Linux)

```bash
git clone git@github.com:marctheshark3/cyber-posture.git
cd cyber-posture
./install.sh                  # PATH symlink + default config
cyber-posture paths
cyber-posture scan
cyber-posture integrity --update-baseline
```

Optional AV/rootkit packages:

```bash
sudo ./scripts/install-malware-tools.sh
cyber-posture integrity --deep --update-baseline
```


## Docker

Image: `ghcr.io/marctheshark3/cyber-posture` (multi-arch `amd64`/`arm64`).

```bash
# pull release
docker pull ghcr.io/marctheshark3/cyber-posture:v1.0.0
docker pull ghcr.io/marctheshark3/cyber-posture:latest

# scan the *host* (not only the container)
./scripts/docker-run-host.sh scan
./scripts/docker-run-host.sh integrity --deep

# compose
docker compose run --rm cyber-posture scan
```

CI publishes:

| Tag | When |
|-----|------|
| `edge` | every push to `main` |
| `vX.Y.Z`, `latest` | git tag `v*` release workflow |
| `sha-<short>` | every image build |

Private GHCR: `echo $GH_TOKEN | docker login ghcr.io -u USER --password-stdin`

## License

- **Code:** MIT — [`LICENSE`](LICENSE)
- **Third-party / image aggregate:** [`NOTICE.md`](NOTICE.md), [`docs/LICENSING.md`](docs/LICENSING.md)

## Multi-host profiles

```bash
# generic laptop/server
./install.sh
cyber-posture init-config --profile default

# DGX / House OS stack
export CYBER_PROFILE=spark-adb4
cyber-posture init-config --profile spark-adb4 --force
# or copy:
cp config/profiles/spark-adb4.yaml ~/.config/cyber-posture/config.yaml
```

Per-host overrides via env:

| Env | Default |
|-----|---------|
| `CYBER_STATE_DIR` | `~/.local/state/cyber-posture` |
| `CYBER_REPORT_DIR` | `$STATE/reports` (or Hermes wiki outputs if present) |
| `CYBER_CONFIG_DIR` | `~/.config/cyber-posture` |
| `CYBER_PROFILE` | `default` |
| `CYBER_HUB_URL` | shown in Discord digests |
| `CYBER_TZ` | `America/New_York` |

On a machine that already has Hermes Tron + wiki, scanners auto-detect:

- state → `~/.hermes/profiles/tron/state/cyber-posture`
- reports → `~/Documents/wiki/wiki/outputs/cyber-posture`

so existing `/security/cyber` hub wiring keeps working.

## Cron examples

```bash
# every 6h — alert only on delta
0 */6 * * *  $HOME/bin/cyber-posture scan --quiet

# daily digest always
20 7 * * *   $HOME/bin/cyber-posture digest

# weekly deep integrity
30 10 * * 0  $HOME/bin/cyber-posture integrity --deep --quiet
```

See `cron/` for ready wrappers.

## Layout

```
bin/cyber-posture           CLI
lib/cyber_posture/          scanners + path helpers
config/default.yaml
config/profiles/*.yaml      host profiles (known ports, probes)
scripts/install-malware-tools.sh
scripts/harden-host.sh      optional ufw/ollama loopback (sudo, review first!)
scripts/fix-hub-access.sh
scripts/identify-port.sh
docs/                       hardening + integrity notes
```

## Security notes

- LAN is **not** a trust boundary — prefer loopback binds + Tailscale.
- ClamAV defaults to **on-demand** (no clamd) so GPU/LLM hosts keep RAM.
- debsums “missing NVIDIA files” on DGX images are vendor debt → INFO, not malware.
- Rootkits can lie to a live kernel — CRITICAL IoC ⇒ offline/live-USB inspect.
- Never commit real `authorized_keys`, `.env`, or scan JSON with secrets.

## Hermes bridge (optional)

```bash
./install.sh --hermes-tron
# symlinks scanners into ~/.hermes/profiles/tron/scripts/
```

## License

MIT — Marc / Rage Industries. Private forks OK.
