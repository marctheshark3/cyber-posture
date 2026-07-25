# Multi-host deployment

## Pattern

1. Clone once per machine (or shared NFS home).
2. `./install.sh` → `~/bin/cyber-posture`.
3. Per-host profile in `~/.config/cyber-posture/config.yaml`.
4. Separate state dirs (default XDG) so baselines don’t cross-contaminate.

## Suggested host profiles

| Host | Profile | Notes |
|------|---------|-------|
| spark-adb4 (DGX) | `spark-adb4` | LLM/cam/hub known ports |
| Mac / laptop Linux | `default` | SSH + generic |
| Pi / edge | `default` + slim known_services | add camera ports you run |

Create a new profile:

```bash
cp config/default.yaml config/profiles/my-nas.yaml
# edit known_services + probes
cp config/profiles/my-nas.yaml ~/.config/cyber-posture/config.yaml
```

## Sync options

- **git pull** on each host (recommended)
- **private GitHub** + deploy key
- Do **not** rsync `~/.local/state/cyber-posture` across machines

## Hermes / OPS integration

Only needed on the machine that runs wiki-hub:

```bash
./install.sh --hermes-tron
# keeps /security/cyber + OPS ingest paths
```

Other machines: CLI + cron only; optional ship digests via Discord webhook / email.

## Windows

Not supported (relies on `ss`, `/proc`, systemd --user). Use WSL2 Ubuntu and run there.
