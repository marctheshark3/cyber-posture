#!/usr/bin/env python3
"""Continuous cyber posture exposure scanner (portable).

Modes: --quiet, --json, --md, --html, --update-baseline, --full.
Profile YAML extends known_services / probes (see config/).
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import shutil
import sys
from contextlib import nullcontext
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_posture.paths import host_root, load_profile, resolve_paths, target_hostname, validate_profile
from cyber_posture.state import atomic_write, load_json, needs_alert, remember_alert, scan_lock


def _init_paths():
    paths = resolve_paths()
    state, report = paths["state"], paths["report"]
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

KNOWN: dict[int, dict[str, str]] = {}
PROBES: dict[int, list[dict[str, str]]] = {}
LAN_ALLOWLIST: set[int] = set()
ACCEPTED_LAN_PORTS: set[int] = set()
TAILNET_IPS: set[str] = set()
PROFILE_NAME = "default"
HUB_URL = ""


def apply_profile(profile: dict | None = None) -> None:
    global KNOWN, PROBES, LAN_ALLOWLIST, ACCEPTED_LAN_PORTS, PROFILE_NAME, HUB_URL
    profile = validate_profile(load_profile() if profile is None else profile)
    PROFILE_NAME = str(profile.get("name") or "default")
    HUB_URL = os.environ.get("CYBER_HUB_URL") or str(profile.get("hub_url") or "")
    KNOWN = {port: dict(meta) for port, meta in profile.get("known_services", {}).items()}
    PROBES = {}
    for port, probes in profile.get("probes", {}).items():
        expected = "required" if KNOWN.get(port, {}).get("auth") == "required" else "observe"
        PROBES[port] = [
            {"scheme": "https" if port == 443 else "http", "auth": expected,
             **({"path": probe} if isinstance(probe, str) else probe)}
            for probe in probes
        ]
    LAN_ALLOWLIST = set(profile.get("lan_allowlist", []))
    ACCEPTED_LAN_PORTS = set(profile.get("accepted_lan_ports", []))


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
    checks: dict[str, Any] = field(default_factory=dict)
    complete: bool = True


def run(cmd: list[str], timeout: int = 20, allow_failure: bool = False) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode and not allow_failure:
        raise RuntimeError(f"{cmd[0]} exited {p.returncode}: {(p.stderr or '')[:200]}")
    return (p.stdout or "") + (p.stderr or "")


def classify_bind(addr: str) -> str:
    addr = addr.strip("[]").split("%")[0]
    if addr == "*":
        return "lan_all"
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "other"
    if ip.is_loopback or (ip.version == 6 and ip.ipv4_mapped and ip.ipv4_mapped.is_loopback):
        return "loopback"
    if ip.is_unspecified:
        return "lan_all"
    if addr in TAILNET_IPS:
        return "tailnet"
    return "specific"


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
        if ":" not in local:
            continue
        addr, port_s = local.rsplit(":", 1)
        addr = addr.strip("[]")
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
    out = run(["ip", "-o", "addr", "show"])
    lan, tail = [], []
    for line in out.splitlines():
        match = re.search(r"inet6? ([^ /]+)/\d+", line)
        parts = line.split()
        if not match or len(parts) < 2:
            continue
        addr, iface = match.group(1), parts[1].rstrip(":")
        ip = ipaddress.ip_address(addr)
        if ip.is_loopback or iface.startswith("br-") or iface in ("docker0", "virbr0"):
            continue
        if ip.version == 6 and ip.is_link_local:
            addr += "%" + iface
        (tail if iface.startswith("tailscale") else lan).append(addr)
    return sorted(set(lan)), sorted(set(tail))


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


def docker_listeners(rows: list[dict[str, str]]) -> list[Listener]:
    """Include NAT publishes even when Docker's userland proxy is disabled."""
    listeners = []
    pattern = re.compile(r"(\[[^\]]+\]|[^\s,]+):(\d+)(?:-(\d+))?->\d+(?:-\d+)?/(tcp|udp)")
    for row in rows:
        for match in pattern.finditer(row.get("ports", "")):
            addr, first, last, proto = match.groups()
            addr = addr.strip("[]")
            start, end = int(first), int(last or first)
            if not 1 <= start <= end <= 65535 or end - start > 1024:
                raise ValueError("Docker published port range is invalid or too large to inspect")
            listeners.extend(Listener(proto, addr, port, classify_bind(addr), f"docker:{row['name']}")
                             for port in range(start, end + 1))
    return listeners


def ufw_status() -> str:
    # non-root usually fails — try and classify
    out = run(["ufw", "status", "verbose"], allow_failure=True)
    if "Status: active" in out:
        return "active"
    if "Status: inactive" in out:
        return "inactive"
    if "need to be root" in out.lower() or "ERROR" in out:
        return "unknown-needs-root"
    return "unknown"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_probe(port: int, path: str, timeout: float = 2.5,
               host: str = "127.0.0.1", scheme: str | None = None) -> dict[str, Any]:
    scheme = scheme or ("https" if port == 443 else "http")
    target = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{target}:{port}{path}"
    result = {"port": port, "path": path, "url": url, "host": host, "status": 0, "auth": "unknown"}
    try:
        # Never send local probes through environment proxies or follow a service's redirects.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        req = urllib.request.Request(url, headers={"User-Agent": "cyber-posture-scan/1.0"})
        with opener.open(req, timeout=timeout) as response:
            result["status"] = response.status
            result["auth"] = "none" if 200 <= response.status < 300 else "unknown"
    except urllib.error.HTTPError as exc:
        result["status"] = exc.code
        result["auth"] = "required" if exc.code in (401, 403) else "unknown"
        exc.close()
    except Exception as exc:
        result["error"] = str(exc)[:200]
    return result


def analyze(listeners: list[Listener], probes: list[dict[str, Any]],
            docker_rows: list[dict[str, str]], ufw: str, lan_ips: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    allowed = LAN_ALLOWLIST | ACCEPTED_LAN_PORTS
    if ufw == "inactive":
        findings.append(Finding("HIGH", "HOST_FW_OFF", "UFW is inactive",
                                "Check whether another firewall protects this host.",
                                remediation="Review inbound rules and restrict services to intended interfaces."))
    by_port: dict[int, list[Listener]] = {}
    for listener in listeners:
        by_port.setdefault(listener.port, []).append(listener)
    for port, surfaces in sorted(by_port.items()):
        meta = KNOWN.get(port)
        wide = [listener for listener in surfaces if listener.bind_class != "loopback"]
        if meta:
            expected = meta.get("expect_bind", "loopback")
            unexpected = [listener for listener in surfaces
                          if expected != "any" and listener.bind_class != expected]
            if unexpected:
                findings.append(Finding("HIGH", "BIND_POLICY_VIOLATION", f"{meta.get('name', port)} violates bind policy",
                                        f"Expected {expected}; observed " + ", ".join(f"{l.proto} {l.addr}:{port}" for l in unexpected),
                                        port, "Bind the service to the interfaces specified in its profile."))
        elif wide and port not in allowed:
            findings.append(Finding("HIGH", "UNKNOWN_LISTENER", f"Unexpected listener on port {port}",
                                    ", ".join(f"{l.proto} {l.addr} process={l.process or '?'}" for l in wide),
                                    port, "Identify the owner; restrict the bind or explicitly document the allowed service."))
        required = [probe for probe in probes if probe["port"] == port and
                    probe.get("expected_auth", "required" if (meta or {}).get("auth") == "required" else "observe") == "required"]
        auth_required = (meta or {}).get("auth") == "required" or bool(required)
        if not auth_required:
            continue
        open_paths = [probe for probe in required if 200 <= probe.get("status", 0) < 300]
        unknown_paths = [probe for probe in required if probe.get("status") not in (401, 403)
                         and not 200 <= probe.get("status", 0) < 300]
        if open_paths:
            findings.append(Finding("CRITICAL" if wide else "HIGH", "AUTH_MISSING", f"Unauthenticated access on port {port}",
                                    "Protected endpoints returned success without credentials: " + ", ".join(p.get("url", p["path"]) for p in open_paths),
                                    port, "Require authentication on every protected endpoint; health endpoints may be explicitly public."))
        if not required or unknown_paths:
            findings.append(Finding("HIGH", "AUTH_UNVERIFIED", f"Authentication could not be verified on port {port}",
                                    "No protected probe configured." if not required else
                                    "; ".join(f"{p.get('url', p['path'])}: status={p.get('status')} {p.get('error', '')}" for p in unknown_paths),
                                    port, "Configure a protected endpoint and the correct HTTP/TLS scheme for each listening address."))
        elif not open_paths:
            findings.append(Finding("INFO", "AUTH_REQUEST_DENIED", f"Unauthenticated probes denied on port {port}",
                                    "All configured protected HTTP probes returned 401/403; this does not verify the entire application.", port))
    for row in docker_rows:
        if re.search(r"(?:0\.0\.0\.0|\[?::\]?):\d+->", row.get("ports", "")):
            findings.append(Finding("HIGH", "DOCKER_PUBLISH_ALL", f"Docker publishes {row['name']} on all interfaces",
                                    row["ports"], remediation="Bind published ports to loopback or an intended interface and verify access from another device; UFW may not filter Docker forwarding."))
    return findings


def fingerprint(findings: list[Finding]) -> str:
    crit = sorted(
        f"{f.severity}:{f.code}:{f.port}:{f.title}:{f.detail}"
        for f in findings
        if f.severity in ("CRITICAL", "HIGH")
    )
    blob = "\n".join(crit).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


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
        f"- Complete: **{result.complete}**",
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
            f"- complete: {hi.get('complete')} · mode: `{hi.get('mode')}` · fp `{hi.get('fingerprint')}`",
            f"- target: {hi.get('checks', {}).get('target', {})}",
            f"- C{hs.get('CRITICAL', 0)} / H{hs.get('HIGH', 0)} / M{hs.get('MEDIUM', 0)}",
            f"- duration: {hi.get('duration_s')}s",
            "",
        ]
    lines += ["## Coverage", ""]
    for name, check in {**result.checks, **{f"integrity/{k}": v for k, v in hi.get("coverage", {}).items()}}.items():
        lines.append(f"- {name}: **{check.get('status')}** {check.get('reason', check.get('error', ''))}")
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
    lines.append("## Listeners (TCP and UDP)")
    lines.append("")
    lines.append("| Protocol | Port | Addr | Class | Process | Known |")
    lines.append("|----------|------|------|-------|---------|-------|")
    for l in sorted(result.listeners, key=lambda x: (x.get("port") or 0, x.get("addr") or "")):
        meta = KNOWN.get(l["port"], {})
        lines.append(
            f"| {l['proto']} | {l['port']} | `{l['addr']}` | {l['bind_class']} | {l.get('process') or '—'} | {meta.get('name', '—')} |"
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
        result.listeners,
        key=lambda x: (x.get("port") or 0, x.get("addr") or ""),
    ):
        meta = KNOWN.get(l["port"], {})
        cls = l.get("bind_class")
        mark = " wide" if cls == "lan_all" else ""
        rows.append(
            f"<tr class='{mark}'><td>{esc(l['proto'])}</td><td class='mono'>{l['port']}</td><td><code>{esc(l['addr'])}</code></td>"
            f"<td>{esc(cls)}</td><td>{esc(l.get('process') or '—')}</td>"
            f"<td>{esc(meta.get('name', '—'))}</td></tr>"
        )
    summary = result.summary
    coverage = "".join(f"<li>{esc(name)}: <strong>{esc(str(check.get('status')))}</strong> {esc(str(check.get('reason', check.get('error', ''))))}</li>"
                       for name, check in {**result.checks, **{f"integrity/{k}": v for k, v in result.host_integrity.get("coverage", {}).items()}}.items())
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
        <div class="brand">cyber-posture · Exposure surface</div>
        <h1>Cyber posture</h1>
        <div class="hsub">Listeners · auth probes · firewall · host integrity / malware IoCs</div>
      </div>
      <div class="asof">{esc(result.host)} · {esc(result.ts)} · fp {esc(result.fingerprint)}</div>
    </div>
    <nav class="nav">
      <a href="/ops">OPS</a>
      <a href="/security">Security</a>
      <a class="on" href="/security/cyber">Cyber</a>
      <a href="/">Hub</a>
    </nav>
  </div>
</header>
<main>
  <section class="panel"><div class="pbd"><strong>Scan {'complete' if result.complete else 'INCOMPLETE'}</strong><p>{esc(str(result.host_integrity.get('checks', {}).get('target', {})))}</p><ul>{coverage}</ul></div></section>
  <div class="kpis">
    <div class="kpi red"><div class="lab">Critical</div><div class="val" style="color:var(--red)">{summary.get('CRITICAL',0)}</div></div>
    <div class="kpi amber"><div class="lab">High</div><div class="val" style="color:var(--amber)">{summary.get('HIGH',0)}</div></div>
    <div class="kpi"><div class="lab">Medium</div><div class="val">{summary.get('MEDIUM',0)}</div></div>
    <div class="kpi"><div class="lab">Firewall</div><div class="val" style="font-size:.85rem">{esc(result.ufw)}</div></div>
    <div class="kpi"><div class="lab">LAN</div><div class="val" style="font-size:.85rem">{esc(', '.join(result.lan_ips) or '—')}</div></div>
    <div class="kpi"><div class="lab">Host integrity</div><div class="val" style="font-size:.85rem">C{(result.host_integrity or {}).get('summary',{}).get('CRITICAL',0) if isinstance(result.host_integrity, dict) else 0}/H{(result.host_integrity or {}).get('summary',{}).get('HIGH',0) if isinstance(result.host_integrity, dict) else 0}</div>
      <div class="sub">fp {esc(((result.host_integrity or {}).get('fingerprint') or '—')[:12]) if isinstance(result.host_integrity, dict) else '—'}</div></div>
  </div>
  <p class="note">Exposure + host integrity IoCs. LAN is not a trust boundary. Deep AV: <span class="mono">cyber-posture integrity --deep</span>.</p>
  <section class="panel">
    <div class="phd"><h2>Findings</h2><span class="mono" style="color:var(--dim);font-size:.7rem">{len(result.findings)} items</span></div>
    <div class="pbd">{''.join(cards) if cards else '<p class="note">No findings.</p>'}</div>
  </section>
  <section class="panel">
    <div class="phd"><h2>TCP and UDP listeners</h2><span class="mono" style="color:var(--dim);font-size:.7rem">wide binds highlighted</span></div>
    <div class="pbd" style="overflow:auto">
      <table>
        <thead><tr><th>Protocol</th><th>Port</th><th>Addr</th><th>Class</th><th>Process</th><th>Known</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
  </section>
  <p class="foot">Scanner: cyber-posture-scan.py + cyber-host-integrity-scan.py · MC skin aligned with OPS · treat reports as sensitive</p>
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
    lines.append("Hub: " + (os.environ.get("CYBER_HUB_URL") or "`(set hub_url in profile or CYBER_HUB_URL)`"))
    lines.append(f"Report: `{DEFAULT_MD}`")
    return "\n".join(lines)


def run_host_integrity_quick() -> dict[str, Any]:
    from cyber_posture import scan_integrity
    try:
        data = asdict(scan_integrity.scan())
    except Exception as exc:
        return {"complete": False, "error": str(exc)}
    # Keep unresolved deep-tool findings visible, with their original date and coverage.
    deep_path = STATE_DIR / "host-integrity/last-deep.json"
    if deep_path.exists():
        deep = load_json(deep_path) or {}
        same_host = deep.get("host") == data["host"]
        valid = type(deep.get("complete")) is bool and deep.get("mode") == "deep" and same_host
        saved_findings = deep.get("findings")
        if not isinstance(saved_findings, list):
            saved_findings = []
            valid = False
        usable_findings = []
        for raw in saved_findings:
            try:
                finding = scan_integrity.Finding(**raw)
                if (finding.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                        or not all(isinstance(value, str) for value in asdict(finding).values())):
                    raise ValueError("Invalid saved finding")
                usable_findings.append(asdict(finding))
            except (TypeError, ValueError):
                valid = False
        try:
            age = (datetime.now(TZ) - datetime.fromisoformat(deep["ts"])).total_seconds()
            fresh = 0 <= age <= 8 * 86400
        except (KeyError, TypeError, ValueError):
            fresh = False
        completed = valid and fresh and deep["complete"]
        data["checks"]["last_deep"] = {"status": "passed" if completed else "failed", "ts": deep.get("ts")}
        if not valid:
            data["checks"]["last_deep"]["reason"] = "Saved deep report is invalid or belongs to a different host."
        data["coverage"]["last_deep"] = data["checks"]["last_deep"]
        if not completed:
            data["complete"] = False
            data["findings"].append(asdict(scan_integrity.Finding("HIGH", "DEEP_SCAN_INCOMPLETE", "Latest deep scan is stale or incomplete",
                                      f"Last deep scan: {deep.get('ts', 'unknown')}. " + data["checks"]["last_deep"].get("reason", ""),
                                      "Run integrity --deep and resolve failed checks.")))
        existing = {(f["code"], f["title"]) for f in data["findings"]}
        for finding in usable_findings if same_host else []:
            if finding.get("severity") in ("CRITICAL", "HIGH") and str(finding.get("code", "")).startswith(("CLAM", "RKHUNTER", "CHKROOT", "DEBSUMS")) and (finding["code"], finding["title"]) not in existing:
                data["findings"].append({**finding, "detail": f"Last deep scan ({deep.get('ts')}): {finding.get('detail', '')}"})
        native_findings = [scan_integrity.Finding(**f) for f in data["findings"]]
        data["summary"] = scan_integrity.severity_counts(native_findings)
        data["fingerprint"] = scan_integrity.fingerprint(native_findings)
    return data


def merge_integrity_findings(findings: list[Finding], integrity: dict[str, Any]) -> list[Finding]:
    if not integrity.get("complete"):
        findings.append(Finding("HIGH", "HOST_INTEGRITY_INCOMPLETE", "Host integrity coverage is incomplete",
                                integrity.get("error") or "Review failed/skipped checks in the host integrity coverage report.",
                                remediation="Run native integrity checks on the host and resolve missing permissions/tools."))
    for raw in integrity.get("findings", []):
        findings.append(Finding(raw["severity"], raw["code"], raw["title"], raw.get("detail", ""),
                                remediation=raw.get("remediation", "")))
    if integrity.get("complete") and not any(integrity.get("summary", {}).get(s, 0) for s in ("CRITICAL", "HIGH")):
        findings.append(Finding("INFO", "HOST_INTEGRITY_OK", "Completed integrity checks found no CRITICAL/HIGH findings",
                                "Coverage is limited to the checks and target scope listed in this report."))
    return findings


def scan() -> ScanResult:
    apply_profile()
    findings: list[Finding] = []
    checks: dict[str, Any] = {}

    def collect(name, collector, fallback):
        try:
            result = collector()
            checks[name] = {"status": "passed"}
            return result
        except Exception as exc:
            checks[name] = {"status": "failed", "error": str(exc)[:300]}
            findings.append(Finding("HIGH", "COLLECTOR_FAILED", f"{name} collection failed", str(exc)[:300],
                                    remediation="Restore the required command, permissions, or service; rerun the scan."))
            return fallback

    lan, tail = collect("addresses", lan_and_tail_ips, ([], []))
    TAILNET_IPS.clear()
    TAILNET_IPS.update(ip.split("%")[0] for ip in tail)
    listeners = collect("listeners", parse_ss, [])
    if shutil.which("docker"):
        docker_rows = collect("docker", docker_ps, [])
    else:
        docker_rows = []
        checks["docker"] = {"status": "skipped", "reason": "Docker CLI unavailable; published ports were not inspected."}
    published = collect("docker_publishes", lambda: docker_listeners(docker_rows), []) if docker_rows else []
    seen_listeners = {(listener.proto, listener.addr, listener.port) for listener in listeners}
    listeners.extend(listener for listener in published if (listener.proto, listener.addr, listener.port) not in seen_listeners)
    if host_root() != Path("/"):
        ufw = "unknown-host-runtime"
    else:
        ufw = collect("firewall", ufw_status, "unknown")
    if ufw.startswith("unknown"):
        checks["firewall"] = {"status": "failed", "reason": "Host firewall runtime could not be verified."}
        findings.append(Finding("HIGH", "FIREWALL_UNVERIFIED", "Host firewall runtime is unverified", ufw,
                                remediation="Inspect the host's actual firewall rules; a container's configuration is not host evidence."))
    probes = []
    seen = set()
    for listener in listeners:
        if listener.proto != "tcp":
            continue
        host = listener.addr
        if listener.bind_class == "lan_all":
            host = "::1" if ":" in host else "127.0.0.1"
        for spec in PROBES.get(listener.port, []):
            identity = (host, listener.port, spec["path"], spec["scheme"])
            if identity in seen:
                continue
            seen.add(identity)
            probes.append({**http_probe(listener.port, spec["path"], host=host, scheme=spec["scheme"]), "expected_auth": spec["auth"]})
    findings.extend(analyze(listeners, probes, docker_rows, ufw, lan))
    if any(f.code == "AUTH_UNVERIFIED" for f in findings):
        checks["auth_probes"] = {"status": "failed", "reason": "One or more required authentication checks are unverified."}
    else:
        checks["auth_probes"] = {"status": "passed" if probes else "skipped"}
    integrity = run_host_integrity_quick()
    findings = merge_integrity_findings(findings, integrity)
    return ScanResult(ts=datetime.now(TZ).isoformat(timespec="seconds"), host=target_hostname(),
                      lan_ips=lan, tailscale_ips=tail, listeners=[asdict(l) for l in listeners], probes=probes,
                      findings=[asdict(f) for f in findings], docker=docker_rows, ufw=ufw,
                      summary=severity_counts(findings), fingerprint=fingerprint(findings), host_integrity=integrity,
                      checks=checks, complete=bool(integrity.get("complete")) and not any(c["status"] == "failed" for c in checks.values()))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true", help="alert on HIGH+ changes, recovery, or a daily reminder")
    ap.add_argument("--full", action="store_true", help="force a quiet-mode notification")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--md", type=Path)
    ap.add_argument("--html", type=Path)
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()
    if args.no_write and args.update_baseline:
        ap.error("--no-write cannot be combined with --update-baseline")
    try:
        with nullcontext() if args.no_write else scan_lock(STATE_DIR, "exposure"):
            alert_path = STATE_DIR / "last-alert.json"
            previous = load_json(alert_path)
            result = scan()
            if args.update_baseline and (not result.complete or result.summary.get("CRITICAL", 0)):
                raise ValueError("Refusing to baseline an incomplete scan or CRITICAL findings")
            if not args.no_write:
                raw = json.dumps(asdict(result), indent=2)
                atomic_write(args.json or DEFAULT_JSON, raw)
                if args.json and args.json != LAST_PATH:
                    atomic_write(LAST_PATH, raw)
                atomic_write(args.md or DEFAULT_MD, to_markdown(result))
                atomic_write(args.html or DEFAULT_HTML, to_html(result))
                dated = (args.md or DEFAULT_MD).parent / f"{datetime.now(TZ):%Y-%m-%d}.md"
                atomic_write(dated, to_markdown(result))
                if args.update_baseline:
                    atomic_write(BASELINE_PATH, raw)
            notify = needs_alert(result, previous, args.full)
            if not args.quiet:
                print(to_markdown(result))
            if notify:
                print(discord_alert(result, (previous or {}).get("fingerprint")))
                if not args.no_write:
                    remember_alert(alert_path, result)
            return 0 if result.complete else 2
    except Exception as exc:
        print(f"cyber-posture scan failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
