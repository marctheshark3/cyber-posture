# cyber-posture

Portable **Linux host cyber posture** toolkit: network exposure scanning + host integrity / malware IoCs.

Profile-driven. No cloud account required. Works on workstations, labs, and GPU boxes.

## Features

| Command | Purpose |
|---------|---------|
| `cyber-posture scan` | Listeners, docker publishes, ufw, auth HTTP probes, LAN reachability + **quick integrity** |
| `cyber-posture integrity` | IoCs (ld.so.preload, fake kernel procs, tmp ELF, SSH/cron/systemd drift) |
| `cyber-posture integrity --deep` | + chkrootkit, rkhunter, debsums, ClamAV (if installed) |
| `cyber-posture integrity --clam` | Scoped signature scan (Downloads/tmp/shm) |
| `cyber-posture digest` | Short daily summary (stdout → cron) |
| `cyber-posture scan --quiet` | Cron: silent unless CRITICAL/HIGH fingerprint **changes** |
| `cyber-posture init-config` | Seed `~/.config/cyber-posture/config.yaml` |

**No root required** for core scans. Optional: `sudo ./scripts/install-malware-tools.sh`.

## Quick start

```bash
git clone https://github.com/marctheshark3/cyber-posture.git
cd cyber-posture
./install.sh
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

Image: `ghcr.io/marctheshark3/cyber-posture` (`linux/amd64`, `linux/arm64`).

```bash
docker pull ghcr.io/marctheshark3/cyber-posture:latest

# scan the *host* (not only the container)
./scripts/docker-run-host.sh scan
./scripts/docker-run-host.sh integrity --deep
```

| Image tag | When |
|-----------|------|
| `edge` | every push to `main` |
| `X.Y.Z`, `latest` | git tag `vX.Y.Z` release |
| `sha-<short>` | every image build |

Private-by-default packages may need:  
`echo $GH_TOKEN | docker login ghcr.io -u USER --password-stdin`

## Profiles

```bash
# minimal
cyber-posture init-config --profile default --force

# sample lab (LLM + camera ports) — edit to match your machine
cp config/profiles/example-lab.yaml ~/.config/cyber-posture/config.yaml
```

Env overrides: `CYBER_STATE_DIR`, `CYBER_REPORT_DIR`, `CYBER_CONFIG_DIR`, `CYBER_PROFILE`, `CYBER_HUB_URL`, `CYBER_TZ`.

## Cron

```bash
0 */6 * * *  $HOME/bin/cyber-posture scan --quiet
20 7 * * *   $HOME/bin/cyber-posture digest
30 10 * * 0  $HOME/bin/cyber-posture integrity --deep --quiet
```

## Security notes

- LAN is **not** a trust boundary — prefer loopback binds + overlay VPN.
- ClamAV defaults to **on-demand** (no clamd) to save RAM on GPU hosts.
- Rootkits can lie to a live kernel — CRITICAL IoC ⇒ offline/live-USB inspect.
- Never commit real `authorized_keys`, `.env`, or scan JSON with secrets.

## License

- **Code:** MIT — [`LICENSE`](LICENSE)
- **Third-party / image aggregate:** [`NOTICE.md`](NOTICE.md), [`docs/LICENSING.md`](docs/LICENSING.md)
