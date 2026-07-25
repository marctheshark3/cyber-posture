# Multi-host deployment

## Pattern

1. Clone once per machine.
2. `./install.sh` → `~/bin/cyber-posture`.
3. Per-host profile in `~/.config/cyber-posture/config.yaml`.
4. Separate state dirs (default XDG) so baselines do not cross-contaminate.

## Profiles

| Profile | Use |
|---------|-----|
| `default` | Minimal (SSH + common system ports) |
| `example-lab` | Sample LLM + camera stack ports — **edit to match your hosts** |

```bash
cp config/profiles/example-lab.yaml ~/.config/cyber-posture/config.yaml
# edit known_services + probes
```

## Sync

- **git pull** on each host
- Do **not** rsync `~/.local/state/cyber-posture` across machines

## Windows

Not supported natively (needs `ss`, `/proc`). Use WSL2 Ubuntu.
