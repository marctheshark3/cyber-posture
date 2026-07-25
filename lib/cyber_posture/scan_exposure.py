#!/usr/bin/env python3
"""Continuous cyber posture scan for spark-adb4 / Rage stack.

Modes:
  --quiet     silent exit if no HIGH/CRITICAL delta vs baseline and no P0 open
  --json PATH write machine JSON
  --md PATH   write markdown report
  --html PATH write hub-friendly HTML
  --update-baseline  rewrite baseline snapshot after successful scan
  --full      include MEDIUM noise in Discord/stdout (default: HIGH+)

Silent contract for cron (no_agent): print nothing + exit 0 when clean;
print Discord-ready markdown when attention needed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

def _init_paths():
    """Portable paths: env CYBER_* or XDG; Hermes wiki layout only if present."""
    home = Path.home()
    state = Path(os.environ.get("CYBER_STATE_DIR") or (home / ".local/state/cyber-posture")).expanduser()
    report = Path(os.environ.get("CYBER_REPORT_DIR") or (state / "reports")).expanduser()
    # Prefer existing Hermes wiki outputs when present (spark continuity)
    hermes_out = home / "Documents/wiki/wiki/outputs/cyber-posture"
    if hermes_out.is_dir() and not os.environ.get("CYBER_REPORT_DIR"):
        report = hermes_out
    hermes_state = home / ".hermes/profiles/tron/state/cyber-posture"
    if hermes_state.is_dir() and not os.environ.get("CYBER_STATE_DIR"):
        state = hermes_state
    state.mkdir(parents=True, exist_ok=True)
    report.mkdir(parents=True, exist_ok=True)
    tz_name = os.environ.get("CYBER_TZ", "America/New_York")
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")
    return state, report, tz

HOME = Path.home()
STATE_DIR, _REPORT_DIR, TZ = _init_paths()
BASELINE_PATH = STATE_DIR / "baseline.json"
LAST_PATH = STATE_DIR / "last-scan.json"
DEFAULT_MD = _REPORT_DIR / "latest.md"
DEFAULT_HTML = _REPORT_DIR / "index.html"
DEFAULT_JSON = STATE_DIR / "last-scan.json"

# Services we expect. bind: loopback | lan | tailnet | any
# auth: required | none | unknown
KNOWN: dict[int, dict[str, str]] = {
    22: {"name": "ssh", "owner": "system", "expect_bind": "any", "auth": "keyish", "tier": "control"},
    4000: {"name": "litellm", "owner": "llm", "expect_bind": "lan", "auth": "required", "tier": "llm"},
    8093: {"name": "vllm-qwen36", "owner": "llm", "expect_bind": "loopback_or_lan", "auth": "required", "tier": "llm"},
    8082: {"name": "ornith-optional", "owner": "llm", "expect_bind": "loopback_or_lan", "auth": "required", "tier": "llm"},
    11434: {"name": "ollama", "owner": "llm", "expect_bind": "loopback", "auth": "required", "tier": "llm"},
    9093: {"name": "wiki-hub", "owner": "hub", "expect_bind": "lan", "auth": "required", "tier": "private-ui"},
    9091: {"name": "quartz-wiki-ui", "owner": "hub", "expect_bind": "lan", "auth": "required", "tier": "private-ui"},
    9092: {"name": "neuralyogi-static", "owner": "publicish", "expect_bind": "lan", "auth": "none-ok", "tier": "static"},
    9090: {"name": "llm-benchmark-dash", "owner": "dev", "expect_bind": "loopback", "auth": "required", "tier": "dev"},
    3333: {"name": "fine-tuning-workbench", "owner": "dev", "expect_bind": "loopback", "auth": "required", "tier": "dev"},
    8766: {"name": "cam0-yolo-ui", "owner": "vigil", "expect_bind": "loopback", "auth": "required", "tier": "camera"},
    8767: {"name": "cam1-yolo-ui", "owner": "vigil", "expect_bind": "loopback", "auth": "required", "tier": "camera"},
    8768: {"name": "cam-pilot-yolo-ui", "owner": "vigil", "expect_bind": "loopback", "auth": "required", "tier": "camera"},
    1984: {"name": "go2rtc-api", "owner": "vigil", "expect_bind": "loopback", "auth": "required", "tier": "camera"},
    8554: {"name": "go2rtc-rtsp", "owner": "vigil", "expect_bind": "loopback", "auth": "required", "tier": "camera"},
    8555: {"name": "go2rtc-webrtc", "owner": "vigil", "expect_bind": "loopback", "auth": "required", "tier": "camera"},
    9500: {"name": "nerv-dashboard", "owner": "nerv", "expect_bind": "loopback", "auth": "required", "tier": "dev"},
    9510: {"name": "nerv-backend", "owner": "nerv", "expect_bind": "loopback", "auth": "required", "tier": "dev"},
    8792: {"name": "loopie-photo-gallery", "owner": "media", "expect_bind": "loopback", "auth": "required", "tier": "private-ui"},
    8793: {"name": "mosaic-generator", "owner": "media", "expect_bind": "loopback", "auth": "required", "tier": "dev"},
    8787: {"name": "python-ui-8787", "owner": "unknown", "expect_bind": "loopback", "auth": "required", "tier": "unknown"},
    13337: {"name": "code-server-or-node", "owner": "dev", "expect_bind": "loopback", "auth": "required", "tier": "dev"},
    11000: {
        "name": "dgx-dashboard-service",
        "owner": "nvidia-dgx",
        "expect_bind": "loopback",
        "auth": "unknown",
        "tier": "vendor",
    },
    # Random high port from NVIDIA DGX Dashboard Admin (confirmed via /proc/1575 net + unit)
    37807: {
        "name": "dgx-dashboard-admin",
        "owner": "nvidia-dgx",
        "expect_bind": "loopback",
        "auth": "unknown",
        "tier": "vendor",
    },
    53: {"name": "dns-local", "owner": "system", "expect_bind": "loopback", "auth": "n/a", "tier": "system"},
    631: {"name": "cups", "owner": "system", "expect_bind": "loopback", "auth": "n/a", "tier": "system"},
}

# Probe paths — unauthenticated GET. 401/403 = auth present.
PROBES: dict[int, list[str]] = {
    4000: ["/v1/models", "/health/liveliness"],
    8093: ["/v1/models", "/health"],
    8082: ["/v1/models", "/health"],
    11434: ["/api/tags"],
    9093: ["/"],
    9091: ["/"],
    9092: ["/"],
    9090: ["/"],
    3333: ["/"],
    8766: ["/", "/stream.mjpg"],
    8767: ["/", "/stream.mjpg"],
    8768: ["/", "/stream.mjpg"],
    1984: ["/", "/api/streams"],
    9500: ["/"],
    9510: ["/", "/docs"],
    8792: ["/"],
    8793: ["/"],
    8787: ["/"],
    13337: ["/"],
    8554: ["/"],
}


@dataclass
class Listener:
    proto: str
    addr: str
    port: int
    bind_class: str  # loopback | lan_all | specific | tailnet | other
    process: str = ""


@dataclass
class Finding:
    severity: str  # CRITICAL HIGH MEDIUM LOW INFO
    code: str
    title: str
    detail: str
    port: int | None = None
    remediation: str = ""


@dataclass
class ScanResult:
    ts: str
    host: str
    lan_ips: list[str] = field(default_factory=list)
    tailscale_ips: list[str] = field(default_factory=list)
    listeners: list[dict[str, Any]] = field(default_factory=list)
    probes: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    docker: list[dict[str, str]] = field(default_factory=list)
    ufw: str = "unknown"
    summary: dict[str, int] = field(default_factory=dict)
    fingerprint: str = ""
    host_integrity: dict[str, Any] = field(default_factory=dict)


def run(cmd: list[str], timeout: int = 20) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return f"ERR:{e}"


def classify_bind(addr: str) -> str:
    if addr in ("127.0.0.1", "::1", "127.0.0.53", "127.0.0.54"):
        return "loopback"
    if addr in ("0.0.0.0", "*", "::", "[::]"):
        return "lan_all"
    if addr.startswith("100."):
        return "tailnet"
    if addr.startswith("172.") or addr.startswith("192.168.") or addr.startswith("10."):
        return "specific"
    return "other"


def parse_ss() -> list[Listener]:
    out = run(["ss", "-tulpn"])
    listeners: list[Listener] = []
    # tcp   LISTEN 0 4096 0.0.0.0:4000 0.0.0.0:* users:(("docker-proxy",pid=...))
    for line in out.splitlines():
        if "LISTEN" not in line and "UNCONN" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        if proto not in ("tcp", "udp"):
            continue
        local = parts[4]
        proc = ""
        m = re.search(r'users:\(\("([^"]+)"', line)
        if m:
            proc = m.group(1)
        # handle [fe80::...]:546 and *:11434 and 127.0.0.53%lo:53
        if local.count(":") >= 2 and local.startswith("["):
            # [addr]:port
            rm = re.match(r"\[([^\]]+)\]:(\d+)$", local)
            if not rm:
                continue
            addr, port_s = rm.group(1), rm.group(2)
        else:
            # strip interface zone %lo
            local_clean = local.split("%")[0] if "%" in local and "]" not in local else local
            if local_clean.startswith("["):
                rm = re.match(r"\[([^\]]+)\]:(\d+)$", local_clean)
                if not rm:
                    continue
                addr, port_s = rm.group(1), rm.group(2)
            else:
                # 0.0.0.0:4000 or *:11434
                if ":" not in local_clean:
                    continue
                addr, port_s = local_clean.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            continue
        listeners.append(
            Listener(
                proto=proto,
                addr=addr,
                port=port,
                bind_class=classify_bind(addr),
                process=proc,
            )
        )
    return listeners


def lan_and_tail_ips() -> tuple[list[str], list[str]]:
    out = run(["ip", "-4", "-o", "addr", "show"])
    lan, ts = [], []
    for line in out.splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", line)
        if not m:
            continue
        ip = m.group(1)
        # iface is field 1 in `ip -o` output: "2: wlP9s9    inet ..."
        parts = line.split()
        iface = parts[1].rstrip(":") if len(parts) > 1 else ""
        if ip.startswith("127."):
            continue
        if iface.startswith("br-") or iface in ("docker0", "virbr0"):
            continue
        if ip.startswith("100."):
            ts.append(ip)
        elif iface.startswith("tailscale"):
            ts.append(ip)
        else:
            lan.append(ip)
    return sorted(set(lan)), sorted(set(ts))


def docker_ps() -> list[dict[str, str]]:
    out = run(
        [
            "docker",
            "ps",
            "--format",
            "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}",
        ]
    )
    rows = []
    for line in out.splitlines():
        if not line.strip() or line.startswith("NAMES"):
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            parts = (parts + [""] * 4)[:4]
        rows.append(
            {
                "name": parts[0],
                "image": parts[1],
                "ports": parts[2],
                "status": parts[3],
            }
        )
    return rows


def ufw_status() -> str:
    # non-root usually fails — try and classify
    out = run(["ufw", "status", "verbose"])
    if "Status: active" in out:
        return "active"
    if "Status: inactive" in out:
        return "inactive"
    if "need to be root" in out.lower() or "ERROR" in out:
        # read conf
        conf = Path("/etc/ufw/ufw.conf")
        if conf.is_file():
            txt = conf.read_text(errors="ignore")
            if re.search(r"(?m)^ENABLED=yes", txt):
                return "enabled-conf-unknown-runtime"
            if re.search(r"(?m)^ENABLED=no", txt):
                return "inactive"
        return "unknown-needs-root"
    return "unknown"


def http_probe(port: int, path: str, timeout: float = 2.5) -> dict[str, Any]:
    url = f"http://127.0.0.1:{port}{path}"
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "cyber-posture-scan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200)
            return {
                "port": port,
                "path": path,
                "url": url,
                "status": getattr(resp, "status", 200),
                "auth": "none",
                "bytes": len(body),
                "snippet": body[:80].decode("utf-8", "replace"),
            }
    except urllib.error.HTTPError as e:
        auth = "required" if e.code in (401, 403) else "none"
        if e.code in (401, 403):
            auth = "required"
        elif e.code == 404:
            auth = "unknown"
        else:
            auth = "none"
        return {
            "port": port,
            "path": path,
            "url": url,
            "status": e.code,
            "auth": auth,
            "bytes": 0,
            "snippet": str(e),
        }
    except Exception as e:
        return {
            "port": port,
            "path": path,
            "url": url,
            "status": 0,
            "auth": "down",
            "bytes": 0,
            "snippet": str(e)[:120],
        }


def port_open_on(host: str, port: int, timeout: float = 0.35) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def analyze(
    listeners: list[Listener],
    probes: list[dict[str, Any]],
    docker_rows: list[dict[str, str]],
    ufw: str,
    lan_ips: list[str],
) -> list[Finding]:
    findings: list[Finding] = []
    tcp_all = [l for l in listeners if l.proto == "tcp"]
    by_port: dict[int, list[Listener]] = {}
    for l in tcp_all:
        by_port.setdefault(l.port, []).append(l)

    # UFW
    if ufw == "inactive":
        findings.append(
            Finding(
                "HIGH",
                "HOST_FW_OFF",
                "Host firewall (ufw) inactive",
                "ufw is installed but inactive. Every 0.0.0.0 bind is reachable to the entire LAN (and any compromised IoT/guest device).",
                remediation="Enable ufw with allow OpenSSH + Tailscale + explicit allowlist; default deny incoming. Do this carefully from console/Tailscale session.",
            )
        )

    # Camera / go2rtc unauth on non-loopback
    for port in (1984, 8554, 8555, 8766, 8767, 8768):
        ls = by_port.get(port, [])
        exposed = [l for l in ls if l.bind_class in ("lan_all", "specific", "tailnet", "other")]
        if not exposed:
            continue
        auth = next((p["auth"] for p in probes if p["port"] == port and p["auth"] in ("none", "required")), "unknown")
        sev = "CRITICAL" if auth == "none" else "HIGH"
        findings.append(
            Finding(
                sev,
                "CAMERA_SURFACE",
                f"Camera-related port {port} exposed beyond loopback",
                f"bind={[l.addr for l in exposed]} auth_probe={auth}. Home-cam / MJPEG / go2rtc must not be world-readable on LAN without auth.",
                port=port,
                remediation="Bind go2rtc + YOLO UIs to 127.0.0.1; front with wiki-hub auth or Tailscale Serve/Funnel only if intentional. Add go2rtc api username/password.",
            )
        )

    # LLM unauth
    for port, name in ((8093, "vLLM"), (11434, "Ollama"), (8082, "Ornith")):
        ls = by_port.get(port, [])
        if not ls:
            continue
        exposed = [l for l in ls if l.bind_class != "loopback"]
        auth = next((p["auth"] for p in probes if p["port"] == port and p.get("status")), "unknown")
        # prefer any probe saying required
        auths = [p["auth"] for p in probes if p["port"] == port]
        if "required" in auths:
            auth = "required"
        elif "none" in auths:
            auth = "none"
        if exposed and auth == "none":
            findings.append(
                Finding(
                    "CRITICAL",
                    "LLM_UNAUTH",
                    f"{name} :{port} unauthenticated and non-loopback",
                    f"Anyone on LAN can burn GPU / pull models / abuse local inference. bind={[l.addr for l in exposed]}",
                    port=port,
                    remediation="Require API key at proxy (LiteLLM only public entry), bind engines to 127.0.0.1, or firewall drop from LAN except Tailscale.",
                )
            )
        elif exposed and auth == "required":
            findings.append(
                Finding(
                    "MEDIUM",
                    "LLM_BOUND_WIDE",
                    f"{name} :{port} authenticated but wide bind",
                    f"Auth OK; still prefer loopback + single proxy. bind={[l.addr for l in exposed]}",
                    port=port,
                    remediation="Bind to 127.0.0.1; leave only LiteLLM on LAN/tailnet with key.",
                )
            )

    # LiteLLM should require auth
    litellm_auth = [p for p in probes if p["port"] == 4000]
    if litellm_auth:
        if any(p["auth"] == "required" for p in litellm_auth):
            findings.append(
                Finding(
                    "INFO",
                    "LITELLM_AUTH_OK",
                    "LiteLLM requires API key",
                    "Unauthenticated /v1/models → 401. Good.",
                    port=4000,
                )
            )
        elif any(p["auth"] == "none" for p in litellm_auth):
            findings.append(
                Finding(
                    "CRITICAL",
                    "LITELLM_OPEN",
                    "LiteLLM accepts unauthenticated requests",
                    "Proxy is the front door — must enforce keys.",
                    port=4000,
                    remediation="Set master key / require virtual keys; reject missing Authorization.",
                )
            )

    # Policy: intentional LAN hub (family phones without TS) — file or env
    # ~/.hermes/profiles/tron/state/cyber-posture/accepted-policy.json
    # {"lan_hub_ok": true, "lan_allow_ports": [22, 9093]}
    policy_path = STATE_DIR / "accepted-policy.json"
    policy: dict[str, Any] = {}
    if policy_path.is_file():
        try:
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
        except Exception:
            policy = {}
    lan_hub_ok = bool(policy.get("lan_hub_ok", True))  # default True after 2026-07 hub access restore
    lan_allow = set(int(x) for x in policy.get("lan_allow_ports", [22, 9093]))

    # Private UIs with no auth on lan_all
    private_ports = (9093, 9091, 8792, 9500, 9510, 3333, 9090, 13337, 8787, 8793)
    for port in private_ports:
        ls = by_port.get(port, [])
        exposed = [l for l in ls if l.bind_class == "lan_all"]
        if not exposed:
            continue
        if port == 9093 and lan_hub_ok:
            findings.append(
                Finding(
                    "INFO",
                    "HUB_LAN_ACCEPTED",
                    "wiki-hub on 0.0.0.0 (accepted family LAN access)",
                    "Intentional: phones on Wi-Fi hit :9093. Mitigations: ufw allow 9093 only + no WAN forward. Prefer Tailscale long-term.",
                    port=9093,
                    remediation="When ready: dual-bind lo+TS only + fix ufw tailscale0; enable tailscale serve.",
                )
            )
            continue
        auths = [p["auth"] for p in probes if p["port"] == port]
        if "required" in auths:
            continue
        if "none" in auths or not auths:
            meta = KNOWN.get(port, {})
            sev = "HIGH" if meta.get("tier") in ("private-ui", "camera", "dev", "unknown") else "MEDIUM"
            findings.append(
                Finding(
                    sev,
                    "PRIVATE_UI_OPEN",
                    f"Private/dev UI :{port} ({meta.get('name','?')}) open on 0.0.0.0 without auth",
                    f"LAN clients get HTTP 200 with no credentials. process={[l.process for l in exposed]}",
                    port=port,
                    remediation="Bind 127.0.0.1 or Tailscale IP only; add reverse-proxy auth; or ufw allow from tailnet only.",
                )
            )

    # NVIDIA DGX dashboard-admin binds a *random* high port on * (uid 0). Detect any lan_all high port while unit active.
    dgx_admin_active = False
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "dgx-dashboard-admin.service"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        dgx_admin_active = (r.stdout or "").strip() == "active"
    except Exception:
        pass
    vendor_lan_ports = []
    for port, ls in by_port.items():
        if port in (22, 9093) or port in KNOWN:
            # still flag known 37807 via loop below if present
            if port not in (37807,):
                continue
        for l in ls:
            if l.bind_class == "lan_all" and l.proto == "tcp" and port >= 1024:
                vendor_lan_ports.append(port)
    # Fixed known + random
    for port in (37807, 11000):
        meta = KNOWN.get(port, {})
        ls = by_port.get(port, [])
        exposed = [l for l in ls if l.bind_class == "lan_all"]
        if not exposed:
            continue
        findings.append(
            Finding(
                "HIGH",
                "VENDOR_SURFACE",
                f"NVIDIA {meta.get('name', port)} :{port} listening beyond loopback",
                f"Owner={meta.get('owner')}. bind={[l.addr for l in exposed]}.",
                port=port,
                remediation=(
                    f"sudo ufw deny {port}/tcp comment 'dgx-dashboard-admin' "
                    "OR sudo systemctl disable --now dgx-dashboard-admin.service"
                ),
            )
        )
    if dgx_admin_active:
        random_admin = [
            p
            for p, ls in by_port.items()
            if p not in KNOWN
            and p > 1024
            and any(l.bind_class == "lan_all" and l.proto == "tcp" for l in ls)
        ]
        for port in sorted(set(random_admin))[:5]:
            findings.append(
                Finding(
                    "HIGH",
                    "VENDOR_SURFACE",
                    f"Likely NVIDIA dgx-dashboard-admin random port :{port}",
                    "dgx-dashboard-admin.service is active; random high port on * is its usual pattern.",
                    port=port,
                    remediation=(
                        f"sudo ufw deny {port}/tcp comment 'dgx-dashboard-admin' "
                        "OR sudo systemctl disable --now dgx-dashboard-admin.service"
                    ),
                )
            )

    # Unexpected high ports lan_all (skip already-flagged vendor)
    flagged = {f.port for f in findings if f.port}
    known_ports = set(KNOWN) | {53, 631, 5353, 41641} | lan_allow
    for port, ls in by_port.items():
        if port in known_ports or port in flagged:
            continue
        if port >= 49152:
            if all(l.bind_class == "loopback" or l.addr.startswith("100.") for l in ls):
                continue
        for l in ls:
            if l.bind_class == "lan_all" and l.proto == "tcp":
                findings.append(
                    Finding(
                        "MEDIUM",
                        "UNKNOWN_LISTENER",
                        f"Unexpected TCP listener :{port} on {l.addr}",
                        f"process={l.process or '?'} — not in cyber allowlist.",
                        port=port,
                        remediation="Identify process; bind loopback or add to known inventory with owner.",
                    )
                )

    # Docker publishes to 0.0.0.0
    wide_docker = []
    for row in docker_rows:
        ports = row.get("ports") or ""
        if "0.0.0.0:" in ports or "[::]:" in ports:
            wide_docker.append(row["name"])
    if wide_docker:
        findings.append(
            Finding(
                "MEDIUM",
                "DOCKER_PUBLISH_ALL",
                f"Docker published to 0.0.0.0 ({len(wide_docker)} containers)",
                "containers: " + ", ".join(wide_docker[:20]),
                remediation="Prefer 127.0.0.1:HOST:CONTAINER publishes; use tailscale serve for remote access.",
            )
        )

    # Policy drift vs house-os access model
    findings.append(
        Finding(
            "INFO",
            "POLICY_NOTE",
            "Access model vs runtime",
            "Target: engines/cams loopback; hub may be LAN-open (accepted) behind ufw+router NAT. Prefer Tailscale for phones long-term.",
            remediation="Track backlog in #cyber-ops weekly review. No WAN port-forwards.",
        )
    )

    # LAN reachability confirmation
    if lan_ips:
        sample = lan_ips[0]
        probe_ports = (1984, 8766, 8767, 8768, 8093, 9093, 11434, 4000, 13337, 22)
        open_lan = [p for p in probe_ports if port_open_on(sample, p)]
        unexpected = [p for p in open_lan if p not in lan_allow]
        if unexpected:
            findings.append(
                Finding(
                    "HIGH",
                    "LAN_REACHABLE",
                    f"Unexpected ports reachable on LAN IP {sample}",
                    f"open={open_lan} unexpected={unexpected} allow={sorted(lan_allow)}",
                    remediation="Host firewall + bind address fixes.",
                )
            )
        elif open_lan:
            findings.append(
                Finding(
                    "INFO",
                    "LAN_EXPECTED",
                    f"LAN open ports within allowlist on {sample}",
                    f"open={open_lan}",
                )
            )

    return findings


def fingerprint(findings: list[Finding]) -> str:
    crit = sorted(
        f"{f.severity}:{f.code}:{f.port}:{f.title}"
        for f in findings
        if f.severity in ("CRITICAL", "HIGH")
    )
    blob = "\n".join(crit).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def to_markdown(result: ScanResult) -> str:
    lines = [
        f"# Cyber posture — {result.host}",
        "",
        f"_Scanned {result.ts}_",
        "",
        "## Summary",
        "",
        f"- CRITICAL: **{result.summary.get('CRITICAL', 0)}**",
        f"- HIGH: **{result.summary.get('HIGH', 0)}**",
        f"- MEDIUM: {result.summary.get('MEDIUM', 0)}",
        f"- LOW: {result.summary.get('LOW', 0)}",
        f"- INFO: {result.summary.get('INFO', 0)}",
        f"- Firewall: `{result.ufw}`",
        f"- LAN: {', '.join(result.lan_ips) or '—'}",
        f"- Tailscale: {', '.join(result.tailscale_ips) or '—'}",
        f"- Fingerprint: `{result.fingerprint}`",
        "",
    ]
    hi = result.host_integrity or {}
    if hi:
        hs = hi.get("summary") or {}
        lines += [
            "## Host integrity",
            "",
            f"- ok: {hi.get('ok')} · mode: `{hi.get('mode')}` · fp `{hi.get('fingerprint')}`",
            f"- C{hs.get('CRITICAL', 0)} / H{hs.get('HIGH', 0)} / M{hs.get('MEDIUM', 0)}",
            f"- duration: {hi.get('duration_s')}s",
            f"- detail MD: `wiki/outputs/cyber-posture/host-integrity.md`",
            "",
        ]
    lines += [
        "## Findings",
        "",
    ]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = sorted(result.findings, key=lambda f: (order.get(f["severity"], 9), f["code"]))
    for f in findings:
        port = f" :{f['port']}" if f.get("port") else ""
        lines.append(f"### [{f['severity']}] {f['title']}{port}")
        lines.append("")
        lines.append(f"- code: `{f['code']}`")
        lines.append(f"- {f['detail']}")
        if f.get("remediation"):
            lines.append(f"- **fix:** {f['remediation']}")
        lines.append("")
    lines.append("## Listeners (tcp)")
    lines.append("")
    lines.append("| Port | Addr | Class | Process | Known |")
    lines.append("|------|------|-------|---------|-------|")
    tcp = [l for l in result.listeners if l.get("proto") == "tcp"]
    tcp = sorted(tcp, key=lambda x: (x.get("port") or 0, x.get("addr") or ""))
    for l in tcp:
        meta = KNOWN.get(l["port"], {})
        lines.append(
            f"| {l['port']} | `{l['addr']}` | {l['bind_class']} | {l.get('process') or '—'} | {meta.get('name', '—')} |"
        )
    lines.append("")
    lines.append("## Docker")
    lines.append("")
    for d in result.docker:
        lines.append(f"- `{d['name']}` — {d.get('ports') or 'no published ports'} — {d.get('status')}")
    lines.append("")
    lines.append("## Auth probes")
    lines.append("")
    for p in result.probes:
        lines.append(
            f"- :{p['port']}{p['path']} → {p['status']} auth={p['auth']}"
        )
    lines.append("")
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    colors = {
        "CRITICAL": "#ff5c5c",
        "HIGH": "#ffc857",
        "MEDIUM": "#5ec8ff",
        "LOW": "#7d8da8",
        "INFO": "#a78bfa",
    }
    cards = []
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in sorted(result.findings, key=lambda x: (order.get(x["severity"], 9), x["code"])):
        c = colors.get(f["severity"], "#ccc")
        port = f" :{f['port']}" if f.get("port") else ""
        cards.append(
            f"""<article class="finding" style="border-left-color:{c}">
            <div class="sev" style="color:{c}">{esc(f['severity'])}</div>
            <h3>{esc(f['title'])}{esc(port)}</h3>
            <p class="code"><code>{esc(f['code'])}</code></p>
            <p>{esc(f['detail'])}</p>
            <p class="fix"><strong>Fix:</strong> {esc(f.get('remediation') or '—')}</p>
            </article>"""
        )
    rows = []
    for l in sorted(
        [x for x in result.listeners if x.get("proto") == "tcp"],
        key=lambda x: (x.get("port") or 0, x.get("addr") or ""),
    ):
        meta = KNOWN.get(l["port"], {})
        cls = l.get("bind_class")
        mark = " wide" if cls == "lan_all" else ""
        rows.append(
            f"<tr class='{mark}'><td class='mono'>{l['port']}</td><td><code>{esc(l['addr'])}</code></td>"
            f"<td>{esc(cls)}</td><td>{esc(l.get('process') or '—')}</td>"
            f"<td>{esc(meta.get('name', '—'))}</td></tr>"
        )
    summary = result.summary
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Cyber · Mission Posture — {esc(result.host)}</title>
<style>
:root {{
  --bg:#05070c; --panel:#0a0f18; --panel2:#0d1420; --line:rgba(120,160,220,.14);
  --text:#dce6f5; --muted:#7d8da8; --dim:#5a6a84; --cyan:#5ec8ff; --amber:#ffc857;
  --red:#ff5c5c; --green:#3dd68c; --violet:#a78bfa;
  --mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;
  --sans:"IBM Plex Sans","Segoe UI",system-ui,sans-serif;
}}
* {{ box-sizing:border-box; }}
html,body {{ margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); }}
body {{
  min-height:100vh;
  background:
    radial-gradient(900px 400px at 0% 0%, rgba(255,92,92,.06), transparent 50%),
    radial-gradient(700px 360px at 100% 0%, rgba(94,200,255,.06), transparent 45%),
    linear-gradient(180deg,#070b12 0%, var(--bg) 40%);
}}
a {{ color:var(--cyan); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.mono {{ font-family:var(--mono); }}
.topbar {{ border-bottom:1px solid var(--line); background:rgba(5,7,12,.92); backdrop-filter:blur(8px); position:sticky; top:0; z-index:40; }}
.top-inner {{ max-width:1200px; margin:0 auto; padding:10px 14px 0; }}
.brand {{ font-family:var(--mono); font-size:.68rem; letter-spacing:.2em; text-transform:uppercase; color:var(--amber); font-weight:700; }}
h1 {{ margin:2px 0 0; font-size:clamp(1.15rem,2.2vw,1.45rem); font-weight:700; letter-spacing:.04em; text-transform:uppercase; }}
.hsub {{ color:var(--muted); font-size:.8rem; margin-top:2px; }}
.asof {{ font-family:var(--mono); font-size:.72rem; color:var(--dim); border:1px solid var(--line); padding:6px 10px; border-radius:4px; background:rgba(0,0,0,.35); }}
.brand-row {{ display:flex; flex-wrap:wrap; justify-content:space-between; gap:10px; align-items:flex-end; padding-bottom:8px; }}
.nav {{ display:flex; flex-wrap:wrap; gap:2px; border-top:1px solid var(--line); margin-top:6px; }}
.nav a {{ font-family:var(--mono); font-size:.68rem; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); padding:8px 10px; border-bottom:2px solid transparent; }}
.nav a:hover,.nav a.on {{ color:var(--cyan); border-bottom-color:var(--cyan); text-decoration:none; }}
main {{ max-width:1200px; margin:0 auto; padding:14px 14px 60px; }}
.kpis {{ display:grid; grid-template-columns:repeat(6,1fr); gap:8px; margin:12px 0; }}
@media (max-width:900px) {{ .kpis {{ grid-template-columns:repeat(3,1fr); }} }}
@media (max-width:520px) {{ .kpis {{ grid-template-columns:repeat(2,1fr); }} }}
.kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:10px 12px; position:relative; overflow:hidden; }}
.kpi::before {{ content:""; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--cyan); }}
.kpi.red::before {{ background:var(--red); }}
.kpi.amber::before {{ background:var(--amber); }}
.kpi .lab {{ font-family:var(--mono); font-size:.58rem; letter-spacing:.12em; text-transform:uppercase; color:var(--dim); }}
.kpi .val {{ font-family:var(--mono); font-size:1.25rem; font-weight:700; margin-top:2px; }}
.kpi .sub {{ font-size:.68rem; color:var(--muted); margin-top:2px; word-break:break-all; }}
.panel {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; margin-top:12px; }}
.phd {{ display:flex; justify-content:space-between; align-items:center; padding:8px 12px; border-bottom:1px solid var(--line); background:linear-gradient(180deg,rgba(94,200,255,.04),transparent); }}
.phd h2 {{ margin:0; font-family:var(--mono); font-size:.72rem; letter-spacing:.14em; text-transform:uppercase; color:var(--cyan); }}
.pbd {{ padding:12px; }}
.finding {{ background:var(--panel2); border:1px solid var(--line); border-left:3px solid var(--dim); border-radius:6px; padding:12px 14px; margin:0 0 10px; }}
.finding h3 {{ margin:4px 0 8px; font-size:1rem; }}
.sev {{ font-family:var(--mono); font-size:.62rem; font-weight:700; letter-spacing:.1em; }}
.code {{ color:var(--dim); margin:0 0 8px; font-family:var(--mono); font-size:.78rem; }}
.fix {{ color:#cde7ff; font-size:.85rem; }}
table {{ width:100%; border-collapse:collapse; font-size:.8rem; }}
th {{ text-align:left; font-family:var(--mono); font-size:.62rem; letter-spacing:.1em; text-transform:uppercase; color:var(--dim); padding:4px 6px; border-bottom:1px solid var(--line); }}
td {{ padding:7px 6px; border-bottom:1px solid rgba(120,160,220,.08); vertical-align:top; }}
tr.wide td {{ background:rgba(255,92,92,.06); }}
.note {{ color:var(--muted); font-size:.8rem; margin:8px 0 0; }}
.foot {{ margin-top:16px; color:var(--dim); font-size:.72rem; font-family:var(--mono); border-top:1px solid var(--line); padding-top:10px; }}
</style>
</head>
<body>
<header class="topbar">
  <div class="top-inner">
    <div class="brand-row">
      <div>
        <div class="brand">Rage Industries · Exposure surface</div>
        <h1>Cyber posture</h1>
        <div class="hsub">Listeners · auth probes · firewall · host integrity / malware IoCs — blade (Vigil stays separate)</div>
      </div>
      <div class="asof">{esc(result.host)} · {esc(result.ts)} · fp {esc(result.fingerprint)}</div>
    </div>
    <nav class="nav">
      <a href="/ops">OPS</a>
      <a href="/security">Security</a>
      <a href="/security/ops">Vigil</a>
      <a class="on" href="/security/cyber">Cyber</a>
      <a href="/">Hub</a>
    </nav>
  </div>
</header>
<main>
  <div class="kpis">
    <div class="kpi red"><div class="lab">Critical</div><div class="val" style="color:var(--red)">{summary.get('CRITICAL',0)}</div></div>
    <div class="kpi amber"><div class="lab">High</div><div class="val" style="color:var(--amber)">{summary.get('HIGH',0)}</div></div>
    <div class="kpi"><div class="lab">Medium</div><div class="val">{summary.get('MEDIUM',0)}</div></div>
    <div class="kpi"><div class="lab">Firewall</div><div class="val" style="font-size:.85rem">{esc(result.ufw)}</div></div>
    <div class="kpi"><div class="lab">LAN</div><div class="val" style="font-size:.85rem">{esc(', '.join(result.lan_ips) or '—')}</div></div>
    <div class="kpi"><div class="lab">Host integrity</div><div class="val" style="font-size:.85rem">C{(result.host_integrity or {}).get('summary',{}).get('CRITICAL',0) if isinstance(result.host_integrity, dict) else 0}/H{(result.host_integrity or {}).get('summary',{}).get('HIGH',0) if isinstance(result.host_integrity, dict) else 0}</div>
      <div class="sub">fp {esc(((result.host_integrity or {}).get('fingerprint') or '—')[:12]) if isinstance(result.host_integrity, dict) else '—'}</div></div>
  </div>
  <p class="note">Exposure + host integrity IoCs for House OS / Vigil / LLM / hub. LAN is not a trust boundary. Fused on <a href="/ops">/ops</a>. Deep AV: <span class="mono">cyber-host-integrity-scan.py --deep|--clam</span>.</p>
  <section class="panel">
    <div class="phd"><h2>Findings</h2><span class="mono" style="color:var(--dim);font-size:.7rem">{len(result.findings)} items</span></div>
    <div class="pbd">{''.join(cards) if cards else '<p class="note">No findings.</p>'}</div>
  </section>
  <section class="panel">
    <div class="phd"><h2>TCP listeners</h2><span class="mono" style="color:var(--dim);font-size:.7rem">wide binds highlighted</span></div>
    <div class="pbd" style="overflow:auto">
      <table>
        <thead><tr><th>Port</th><th>Addr</th><th>Class</th><th>Process</th><th>Known</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
  </section>
  <p class="foot">Scanner: cyber-posture-scan.py + cyber-host-integrity-scan.py · MC skin aligned with OPS · no secrets in report</p>
</main>
</body>
</html>
"""


def discord_alert(result: ScanResult, prev_fp: str | None) -> str:
    c = result.summary.get("CRITICAL", 0)
    h = result.summary.get("HIGH", 0)
    lines = [
        "🛡️ **Cyber posture alert**",
        f"`{result.host}` · {result.ts}",
        f"CRITICAL **{c}** · HIGH **{h}** · MED {result.summary.get('MEDIUM', 0)} · fw `{result.ufw}`",
        f"fp `{result.fingerprint}`" + (f" (was `{prev_fp}`)" if prev_fp and prev_fp != result.fingerprint else ""),
        "",
    ]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    top = [
        f
        for f in sorted(result.findings, key=lambda x: order.get(x["severity"], 9))
        if f["severity"] in ("CRITICAL", "HIGH")
    ][:8]
    for f in top:
        port = f" :{f['port']}" if f.get("port") else ""
        lines.append(f"- **{f['severity']}** {f['title']}{port}")
    lines.append("")
    lines.append("Hub: " + (os.environ.get("CYBER_HUB_URL") or "`(set CYBER_HUB_URL)`"))
    lines.append(f"Report: `{DEFAULT_MD}`")
    return "\n".join(lines)


def run_host_integrity_quick() -> dict[str, Any]:
    """Merge quick host IoC/malware surface into exposure scan (no deep AV)."""
    # Portable: sibling scan_integrity.py, then Hermes script fallback
    here = Path(__file__).resolve().parent
    script = here / "scan_integrity.py"
    if not script.is_file():
        script = HOME / ".hermes/profiles/tron/scripts/cyber-host-integrity-scan.py"
    if not script.is_file():
        return {"ok": False, "error": "integrity script missing"}
    out_json = STATE_DIR / "host-integrity" / "last-quick.json"
    deep_json = STATE_DIR / "host-integrity" / "last-deep.json"
    try:
        p = subprocess.run(
            [os.environ.get("PYTHON", "python3"), str(script), "--json", str(out_json)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        data = load_json(out_json)
        if not isinstance(data, dict):
            return {
                "ok": False,
                "error": f"integrity scan rc={p.returncode}",
                "stderr": (p.stderr or "")[:300],
            }
        data["ok"] = True
        data["merged"] = True
        # Fold residual HIGH from last deep run (clam/rkhunter/debsums) without re-running 3min
        deep = load_json(deep_json)
        if isinstance(deep, dict) and deep.get("findings"):
            data["deep_fingerprint"] = deep.get("fingerprint")
            data["deep_ts"] = deep.get("ts")
            data["deep_summary"] = deep.get("summary")
            existing = {(f.get("code"), f.get("title")) for f in (data.get("findings") or [])}
            extra = []
            for f in deep.get("findings") or []:
                if f.get("severity") not in ("CRITICAL", "HIGH"):
                    continue
                key = (f.get("code"), f.get("title"))
                if key in existing:
                    continue
                extra.append(f)
                existing.add(key)
            if extra:
                data.setdefault("findings", []).extend(extra)
                # recompute light summary bump
                summ = dict(data.get("summary") or {})
                for f in extra:
                    sev = f.get("severity") or "INFO"
                    summ[sev] = int(summ.get(sev) or 0) + 1
                data["summary"] = summ
                data["deep_merged_n"] = len(extra)
        return data
    except Exception as e:
        data = load_json(out_json) or load_json(deep_json)
        if isinstance(data, dict):
            data["ok"] = True
            data["stale"] = True
            data["merge_error"] = str(e)
            return data
        return {"ok": False, "error": str(e)}


def merge_integrity_findings(
    findings: list[Finding], integrity: dict[str, Any]
) -> list[Finding]:
    """Fold host-integrity HIGH+ into exposure findings (dedupe by code+title)."""
    if not integrity.get("ok"):
        findings.append(
            Finding(
                "LOW",
                "HOST_INTEGRITY_UNAVAILABLE",
                "Host integrity scan unavailable",
                integrity.get("error") or "no data",
                remediation="Run cyber-host-integrity-scan.py; ensure script present.",
            )
        )
        return findings
    seen = {(f.code, f.title) for f in findings}
    for raw in integrity.get("findings") or []:
        sev = raw.get("severity") or "INFO"
        # Always surface CRITICAL/HIGH; MEDIUM malware-ish codes too
        code = raw.get("code") or "HOST_IOC"
        if sev not in ("CRITICAL", "HIGH") and not (
            sev == "MEDIUM"
            and str(code).startswith(
                ("TMP_", "IOC_", "CLAM", "DEBSUMS", "RKHUNTER", "CHKROOT", "SUSPICIOUS", "NET_MINER")
            )
        ):
            continue
        title = raw.get("title") or code
        key = (code, title)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                sev,
                code if str(code).startswith(("IOC_", "CLAM", "TMP_", "SSH_", "CRON", "SYSTEMD", "PATH_", "SUSPICIOUS", "DEBSUMS", "RKHUNTER", "CHKROOT", "HOST_", "MALWARE", "NET_", "PROC_")) else f"HOST_{code}",
                title,
                raw.get("detail") or "",
                remediation=raw.get("remediation") or "",
            )
        )
    # INFO if integrity clean
    summ = integrity.get("summary") or {}
    if int(summ.get("CRITICAL") or 0) == 0 and int(summ.get("HIGH") or 0) == 0:
        findings.append(
            Finding(
                "INFO",
                "HOST_INTEGRITY_OK",
                "Host integrity quick scan: no CRITICAL/HIGH",
                f"mode={integrity.get('mode')} fp={integrity.get('fingerprint')} "
                f"duration={integrity.get('duration_s')}s — IoC/persistence checks only; "
                "install ClamAV/rkhunter for signature+rootkit depth.",
            )
        )
    return findings


def scan() -> ScanResult:
    host = run(["hostname"]).strip() or "spark"
    lan, ts = lan_and_tail_ips()
    listeners = parse_ss()
    docker_rows = docker_ps()
    ufw = ufw_status()

    # probes only for listening tcp ports we care about
    listening_ports = {l.port for l in listeners if l.proto == "tcp"}
    probes: list[dict[str, Any]] = []
    for port, paths in PROBES.items():
        if port not in listening_ports:
            continue
        for path in paths:
            probes.append(http_probe(port, path))

    findings = analyze(listeners, probes, docker_rows, ufw, lan)
    integrity = run_host_integrity_quick()
    findings = merge_integrity_findings(findings, integrity)
    counts = severity_counts(findings)
    fp = fingerprint(findings)
    # compact integrity blob for OPS (no full checks dump in last-scan if huge)
    integrity_pub = {
        "ok": integrity.get("ok"),
        "ts": integrity.get("ts"),
        "mode": integrity.get("mode"),
        "fingerprint": integrity.get("fingerprint"),
        "summary": integrity.get("summary") or {},
        "duration_s": integrity.get("duration_s"),
        "tools": {
            k: {"present": v.get("present")}
            for k, v in (integrity.get("tools") or {}).items()
            if isinstance(v, dict) and "present" in v
        },
        "stale": integrity.get("stale"),
        "error": integrity.get("error"),
    }
    return ScanResult(
        ts=datetime.now(TZ).strftime("%Y-%m-%d %H:%M %Z"),
        host=host,
        lan_ips=lan,
        tailscale_ips=ts,
        listeners=[asdict(l) for l in listeners],
        probes=probes,
        findings=[asdict(f) for f in findings],
        docker=docker_rows,
        ufw=ufw,
        summary=counts,
        fingerprint=fp,
        host_integrity=integrity_pub,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true", help="cron silent unless HIGH+ attention")
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--md", type=Path, default=None)
    ap.add_argument("--html", type=Path, default=None)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    result = scan()

    json_path = args.json or DEFAULT_JSON
    md_path = args.md or DEFAULT_MD
    html_path = args.html or DEFAULT_HTML

    if not args.no_write:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(result)
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        md_path.write_text(to_markdown(result), encoding="utf-8")
        html_path.write_text(to_html(result), encoding="utf-8")
        # dated copy
        dated = md_path.parent / f"{datetime.now(TZ).strftime('%Y-%m-%d')}.md"
        dated.write_text(to_markdown(result), encoding="utf-8")

    prev = load_json(BASELINE_PATH) or load_json(LAST_PATH)
    prev_fp = (prev or {}).get("fingerprint")

    if args.update_baseline:
        BASELINE_PATH.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")

    crit = result.summary.get("CRITICAL", 0)
    high = result.summary.get("HIGH", 0)
    attention = crit > 0 or high > 0
    fp_changed = prev_fp is not None and prev_fp != result.fingerprint

    # Always write last-scan already done. Quiet mode for cron:
    if args.quiet:
        # Delta-based: known CRITICAL/HIGH from baseline do not re-spam.
        # Alert when: no baseline yet, fingerprint changed, or --full forced path.
        if prev_fp is None or fp_changed:
            print(discord_alert(result, prev_fp))
            return 0
        return 0

    # Human mode
    print(to_markdown(result))
    if attention:
        print("\n---\n" + discord_alert(result, prev_fp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
