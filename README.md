# cyber-posture

Portable **Linux host cyber posture** toolkit: network exposure scanning + host integrity / malware IoCs.

Profile-driven. No cloud account required. Works on workstations, labs, and GPU boxes.

## Features

| Command | Purpose |
|---------|---------|
| `cyber-posture scan` | Listeners, docker publishes, ufw, endpoint HTTP/TLS probes, IPv4/IPv6 TCP/UDP exposure + **quick integrity** |
| `cyber-posture integrity` | IoCs (ld.so.preload, fake kernel procs, tmp ELF, SSH/cron/systemd drift) |
| `cyber-posture integrity --deep` | + chkrootkit, rkhunter, debsums, ClamAV (if installed) |
| `cyber-posture integrity --clam` | Scoped signature scan (Downloads/tmp/shm) |
| `cyber-posture digest` | Short daily summary (stdout → cron) |
| `cyber-posture scan --quiet` | Cron: HIGH/CRITICAL changes, recovery and daily reminders |
| `cyber-posture init-config` | Seed `~/.config/cyber-posture/config.yaml` |

**Linux + Python 3.10+ + PyYAML** (`python3-yaml` on Debian/Ubuntu). Core checks run as your user; unreadable or unavailable checks are reported as incomplete. Optional: `sudo ./scripts/install-malware-tools.sh`.

## Quick start

```bash
git clone https://github.com/marctheshark3/cyber-posture.git
cd cyber-posture
./install.sh
cyber-posture paths
cyber-posture scan
# Review findings and current persistence before approving a baseline:
cyber-posture integrity --update-baseline
```

Optional AV/rootkit packages:

```bash
sudo ./scripts/install-malware-tools.sh
cyber-posture integrity --deep
```

## Docker

Build and test the current checkout:

```bash
make docker
CYBER_IMAGE=cyber-posture:local ./scripts/docker-run-host.sh scan
```

Released image: `ghcr.io/marctheshark3/cyber-posture` (`linux/amd64`, `linux/arm64`).
The helper defaults to the version in `VERSION`; set `CYBER_IMAGE` to a verified image digest
for repeatable deployment. It runs as your UID with dropped capabilities, read-only host
mounts and no Docker socket. Compose also supports a local build: `docker compose up --build`.

**Container host collection is partial and returns exit 2.** Host user persistence,
package integrity, Docker inventory and firewall runtime require native checks. Container
results never imply that these unobserved host surfaces passed. See [coverage details](docs/HOST-INTEGRITY.md).

## Profiles

```bash
# minimal
cyber-posture init-config --profile default --force

# sample lab (LLM + camera ports) — edit to match your machine
cp config/profiles/example-lab.yaml ~/.config/cyber-posture/config.yaml
```

YAML profiles require PyYAML; malformed profiles or missing named profiles fail explicitly. JSON profiles are also supported. Empty allowlists are honored. `expect_bind` and HTTP `auth: required` policies are checked for known services; non-HTTP authentication needs separate verification. Mark public health endpoints explicitly, for example `{path: /health, auth: public}`.

Env overrides: `CYBER_STATE_DIR`, `CYBER_REPORT_DIR`, `CYBER_CONFIG_DIR`, `CYBER_PROFILE`, `CYBER_HUB_URL`, `CYBER_TZ`.

## Cron

```bash
0 */6 * * *  $HOME/bin/cyber-posture scan --quiet
20 7 * * *   $HOME/bin/cyber-posture digest
30 10 * * 0  $HOME/bin/cyber-posture integrity --deep --quiet
```

## Scan status and validation

- Exit **0**: declared checks completed; review finding severities separately.
- Exit **2**: incomplete coverage or a scan/configuration error.
- `--no-write`: no report, baseline or alert state is written; cannot be combined with `--update-baseline`.
- Notifications are stdout/stderr only. Test delivery and monitor missed/failed cron jobs.
- `make test`: isolated regression tests and Python/shell syntax checks.

See [host integrity and baseline behavior](docs/HOST-INTEGRITY.md) and the
[workstation/home-lab hardening playbook](docs/HARDENING-PLAYBOOK.md).

## Multiple machines

Install and run the scanner on each Linux host with that host's own policy and
user persistence baseline. Source cloning, scan scheduling and alert delivery
are separate steps. Keep your inventory, real host profiles and fleet automation
in private operations configuration; this public tool works independently of it.
Start with one read-only pilot, then roll out a reviewed version. Follow the
[multi-host deployment guide](docs/MULTI-HOST.md).

## Security notes

- LAN is **not** a trust boundary — prefer loopback binds + overlay VPN.
- ClamAV defaults to **on-demand** (no clamd) to save RAM on GPU hosts.
- Rootkits can lie to a live kernel — CRITICAL IoC ⇒ offline/live-USB inspect.
- Never commit real `authorized_keys`, `.env`, or scan JSON with secrets.

## License

- **Code:** MIT — [`LICENSE`](LICENSE)
- **Third-party / image aggregate:** [`NOTICE.md`](NOTICE.md), [`docs/LICENSING.md`](docs/LICENSING.md)
