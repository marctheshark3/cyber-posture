# Hardening playbook (generic Linux)

**LAN is not a trust boundary.** Prefer loopback binds + Tailscale (or similar) over opening services on `0.0.0.0`.

## Target state

| Surface | Preferred bind |
|---------|----------------|
| LLM APIs (vLLM, Ollama, OpenAI-compat proxies) | `127.0.0.1` + auth |
| Private dashboards / workbenches | `127.0.0.1` or tailnet only |
| Camera / streaming (go2rtc, YOLO UIs) | `127.0.0.1`; proxy behind auth |
| SSH | intentional (`any` or tailnet-only) |
| Vendor admin UIs (e.g. NVIDIA DGX dashboard-admin) | **not** `*:PORT` on LAN — ufw deny or disable unit |
| ufw | default deny in; allow OpenSSH + tailnet NIC |

## Compose / config patterns

- Put inference engines on `127.0.0.1`.
- If a reverse proxy container must reach loopback engines, use `network_mode: host` or a shared net carefully — bridge + `host.docker.internal` will **not** hit host loopback the way you expect.
- Prefer Tailscale Serve over WAN port-forwards.

## Identifying root listeners (`ss` shows no process)

1. Port in `/proc/net/tcp6` with **uid 0** and state `0A` (LISTEN).
2. Compare LAN vs loopback: `connect_ex((lan_ip, port))` vs `127.0.0.1`.
3. `systemctl list-units | rg -i dgx|nvidia` for vendor dashboards.
4. Optional: `sudo bash scripts/identify-port.sh PORT`.

## NVIDIA DGX note

`dgx-dashboard-admin` often binds a **random high port** on `*`. Scanner flags this as `VENDOR_SURFACE` when the unit is active.

```bash
sudo ufw deny <PORT>/tcp comment 'dgx-dashboard-admin'
# or
sudo systemctl disable --now dgx-dashboard-admin.service
```

## Post-change verify

```bash
cyber-posture scan --update-baseline
# LAN should be minimal (often SSH only unless you accept more in profile)
```

## Policy

- Bind fixes first; ufw is belt after suspenders.
- Re-baseline after intentional SSH key / systemd unit changes.
