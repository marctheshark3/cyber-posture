# Hardening playbook (spark-adb4)

Target: House OS / Vigil / LLM / hub. **LAN is not a trust boundary.**

## Target state (post 2026-07-24)

| Surface | Bind |
|---------|------|
| YOLO UIs 8766–8768 | `127.0.0.1` (hub proxies) |
| go2rtc 1984 / 8554 / 8555 | `127.0.0.1` |
| vLLM 8093 | `127.0.0.1` (host net container) |
| LiteLLM 4000 | `127.0.0.1` + API key; **host network** |
| Ornith 8082 | `127.0.0.1:8082:8080` |
| wiki-hub 9093 | dual: `127.0.0.1` + Tailscale `100.x` (`WIKI_HUB_HOST=auto`) |
| Private Docker UIs | `127.0.0.1:host:container` |
| code-server 13337 | `127.0.0.1` (`~/.config/code-server/config.yaml`; kill+systemd restart picks up) |
| Closet shop 8787 | `127.0.0.1` |
| Ollama 11434 | `127.0.0.1` via `/etc/systemd/system/ollama.service.d/override.conf` (**sudo**) |
| dgx-dashboard-service | `127.0.0.1:11000` (OK) |
| dgx-dashboard-admin | must **not** be `*:PORT` on LAN — ufw deny or disable unit |
| ufw | default deny in; allow OpenSSH + `tailscale0` (+ docker0) (**sudo**) |

## Compose / config touch points

- `~/docker-compose.llm-pair.yml` — vLLM `--host 127.0.0.1`; LiteLLM `network_mode: host` + `--host 127.0.0.1`
- `~/litellm_config.yaml` — `api_base: http://127.0.0.1:8093/v1` and `:8082` (not docker DNS / host.docker.internal after loopback engines)
- Cam: `~/Documents/agent-video-monitor/security_video_monitor/config*.yaml` → `stream.host: 127.0.0.1`
- go2rtc: `~/Documents/rage-industries/local-camera-kit/go2rtc/go2rtc.yaml`
- wiki-hub: `~/.config/systemd/user/wiki-hub.service` `WIKI_HUB_HOST=auto`; `app.py` dual-bind
- Host sudo bundle: `~/.hermes/profiles/tron/scripts/cyber-harden-host.sh`

## Critical coupling: vLLM loopback ↔ LiteLLM

If vLLM binds **only** `127.0.0.1`, a **bridge-network** LiteLLM cannot reach it via `host.docker.internal` (hits docker0, not loopback).

**Fix used:** LiteLLM `network_mode: host` + `api_base: http://127.0.0.1:8093/v1`.

## Identifying root listeners (`ss` shows no process)

1. Port in `/proc/net/tcp6` with **uid 0** and state `0A` (LISTEN).
2. Compare LAN vs loopback connect: `connect_ex(('192.168.x.x', port))` — if open, real LAN exposure (not just self-probe).
3. Compare known loopback service (e.g. `:11000` refused on LAN, open on 127.0.0.1).
4. `systemctl list-units | rg -i dgx|nvidia` → check `dgx-dashboard-admin.service` (PID often early boot).
5. Confirm: `/proc/<admin-pid>/net/tcp6` contains the port hex (37807 = `0x93AF`).
6. Optional: `sudo bash …/cyber-identify-port.sh PORT` (`ss`/`lsof`/`fuser`).

**Known vendor:** NVIDIA DGX Dashboard Admin listens on a **random high port** `*` while Dashboard Service stays on `127.0.0.1:11000`. Scanner code `VENDOR_SURFACE` / KNOWN 37807+11000.

```bash
sudo ufw deny 37807/tcp comment 'dgx-dashboard-admin'
# or
sudo systemctl disable --now dgx-dashboard-admin.service
```

## Post-change verify

```bash
python3 - <<'PY'
import socket
ports=[22,4000,8093,11434,13337,8766,1984,9093,11000,37807]
for host in ['127.0.0.1','192.168.1.63','100.110.151.120']:
    openp=[]
    for p in ports:
        s=socket.socket(); s.settimeout(0.25)
        if s.connect_ex((host,p))==0: openp.append(p)
        s.close()
    print(host, openp)
PY
# LiteLLM want 401; hub want 200 on lo + ts IP; LAN 9093 refuse
python3 ~/.hermes/profiles/tron/scripts/cyber-posture-scan.py --update-baseline
```

Healthy LAN sample after full harden: **`[22]`** only (plus any intentional).  
Healthy TS IP: hub **9093** (+ SSH if allowed).

## Sudo / gateway (Marc host shell)

```bash
sudo bash ~/.hermes/profiles/tron/scripts/cyber-harden-host.sh
# Discord session cannot restart gateway — host SSH:
systemctl --user restart hermes-gateway-tron.service
```

## Policy notes

- After harden, **LiteLLM is localhost-only** unless you add Tailscale bind/`tailscale serve`.
- SSH on LAN remains expected.
- Prefer bind fixes over relying on ufw alone; ufw is belt after suspenders.
