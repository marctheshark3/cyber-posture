#!/usr/bin/env python3
"""Host integrity + malware surface scan for spark-adb4.

Complements cyber-posture-scan.py (network exposure) with compromise signals:
  - classic IoCs (ld.so.preload, fake kernel procs, tmp executables)
  - persistence drift (authorized_keys, user crontab, systemd --user units)
  - process /proc vs ps anomalies
  - optional ClamAV / rkhunter / chkrootkit / debsums when installed

Modes:
  default     quick IoC + baselines + tool availability (seconds)
  --deep      also run rkhunter/chkrootkit if present; broader tmp walk
  --clam PATH run clamscan on PATH (or default high-risk dirs) when installed
  --update-baseline  accept current persistence hashes
  --quiet     print Discord markdown only on HIGH+ delta vs baseline fp
  --json PATH write machine JSON (default state dir)

Safe: no sudo required for core checks. Optional tools may need root for full
value (rkhunter --check often wants root); we run what we can as user.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

def _init_paths():
    home = Path.home()
    state = Path(os.environ.get("CYBER_STATE_DIR") or (home / ".local/state/cyber-posture")).expanduser()
    report = Path(os.environ.get("CYBER_REPORT_DIR") or (state / "reports")).expanduser()
    hermes_out = home / "Documents/wiki/wiki/outputs/cyber-posture"
    if hermes_out.is_dir() and not os.environ.get("CYBER_REPORT_DIR"):
        report = hermes_out
    hermes_state = home / ".hermes/profiles/tron/state/cyber-posture"
    if hermes_state.is_dir() and not os.environ.get("CYBER_STATE_DIR"):
        state = hermes_state
    host = state / "host-integrity"
    host.mkdir(parents=True, exist_ok=True)
    report.mkdir(parents=True, exist_ok=True)
    tz_name = os.environ.get("CYBER_TZ", "America/New_York")
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")
    return state, host, report, tz

HOME = Path.home()
STATE_DIR, HOST_DIR, _REPORT_DIR, TZ = _init_paths()
LAST_PATH = HOST_DIR / "last-integrity.json"
LAST_DEEP_PATH = HOST_DIR / "last-deep.json"
LAST_QUICK_PATH = HOST_DIR / "last-quick.json"
BASELINE_PATH = HOST_DIR / "baseline.json"
WIKI_MD = _REPORT_DIR / "host-integrity.md"

# Paths ClamAV may hit on --clam default (user-writable risk surfaces)
DEFAULT_CLAM_PATHS = [
    str(HOME / "Downloads"),
    str(HOME / ".local" / "share" / "Trash"),
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]

# Names that real kernel threads use — userland binaries with these names are IoCs
FAKE_KERNEL_NAMES = {
    "kthreadd",
    "ksoftirqd",
    "kworker",
    "migration",
    "rcu_sched",
    "rcu_bh",
    "watchdog",
    "bioset",
    "crypto",
    "kdevtmpfs",
}

SUSPICIOUS_PROC_RES = [
    re.compile(r"(?i)(xmrig|minerd|cpuminer|stratum\+tcp)"),
    re.compile(r"(?i)(\.\/\.|/\.hidden|/dev/shm/[a-z0-9]{4,})"),
    re.compile(r"(?i)(nc\s+-[el]|ncat\s+-[el]|socat\s+TCP-LISTEN)"),
]


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    remediation: str = ""
    evidence: str = ""


@dataclass
class IntegrityResult:
    ts: str
    host: str
    mode: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    fingerprint: str = ""
    tools: dict[str, Any] = field(default_factory=dict)
    baselines: dict[str, Any] = field(default_factory=dict)
    checks: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0


def run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not_found"
    except Exception as e:
        return 1, "", str(e)


def which(name: str) -> str | None:
    return shutil.which(name)


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path, limit: int = 8_000_000) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            remaining = limit
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()
    except Exception:
        return None


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def fingerprint(findings: list[Finding]) -> str:
    parts = sorted(
        f"{f.severity}:{f.code}:{f.title}"
        for f in findings
        if f.severity in ("CRITICAL", "HIGH")
    )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def tool_inventory() -> dict[str, Any]:
    tools = {}
    for name in (
        "clamscan",
        "clamdscan",
        "freshclam",
        "rkhunter",
        "chkrootkit",
        "lynis",
        "debsums",
        "aide",
    ):
        p = which(name)
        tools[name] = {"present": bool(p), "path": p}
    # clamd running?
    if which("clamdscan"):
        rc, out, _ = run(["clamdscan", "--version"], timeout=10)
        tools["clamdscan"]["version_rc"] = rc
        tools["clamd"] = {"reachable": rc == 0}
    return tools


# ── individual checks ────────────────────────────────────────────────────────


def check_ld_preload(findings: list[Finding], checks: dict) -> None:
    p = Path("/etc/ld.so.preload")
    exists = p.exists()
    checks["ld_so_preload"] = {"exists": exists}
    if exists:
        try:
            content = p.read_text(encoding="utf-8", errors="replace").strip()
        except Exception as e:
            content = f"<unreadable:{e}>"
        checks["ld_so_preload"]["content_preview"] = content[:200]
        findings.append(
            Finding(
                "CRITICAL",
                "IOC_LD_PRELOAD",
                "/etc/ld.so.preload present",
                "Userland rootkits commonly inject via ld.so.preload (e.g. libcurl.so.* fakes). "
                f"Content preview: {content[:120]!r}",
                remediation="Inspect libraries listed; boot from live USB if system tools are untrusted; remove only after confirming clean.",
                evidence=str(p),
            )
        )


def check_tmp_executables(findings: list[Finding], checks: dict, deep: bool) -> None:
    roots = [Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    # House OS / Redroid + common harmless +x noise
    allow_prefixes = (
        "/tmp/redroid-data/",
        "/tmp/.X11-unix",
        "/tmp/.ICE-unix",
        "/tmp/.font-unix",
        "/var/tmp/redroid",
    )
    hits: list[str] = []
    max_hits = 40 if deep else 15

    def is_interesting_exec(fp: Path, st: os.stat_result) -> bool:
        path_s = str(fp)
        if any(path_s.startswith(p) or path_s == p.rstrip("/") for p in allow_prefixes):
            return False
        # prefer real payloads: ELF, shebang, or anything in shm
        if path_s.startswith("/dev/shm/"):
            return True
        try:
            with fp.open("rb") as f:
                head = f.read(256)
        except Exception:
            return False
        if head.startswith(b"\x7fELF"):
            return True
        if head.startswith(b"#!"):
            return True
        # PE / Mach-O rare on Linux host but flag
        if head[:2] == b"MZ" or head[:4] in (b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe"):
            return True
        # deep mode: any +x not allowlisted
        return deep

    for root in roots:
        if not root.is_dir():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                depth = Path(dirpath).relative_to(root).parts
                if not deep and len(depth) > 3:
                    dirnames.clear()
                    continue
                # prune redroid tree early unless deep
                if not deep and any(str(Path(dirpath)).startswith(p.rstrip("/")) for p in allow_prefixes if p.endswith("/")):
                    dirnames.clear()
                    continue
                for name in filenames:
                    fp = Path(dirpath) / name
                    try:
                        st = fp.lstat()
                    except Exception:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if not (st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                        continue
                    if not is_interesting_exec(fp, st):
                        continue
                    hits.append(f"{fp} mode={oct(st.st_mode & 0o777)} size={st.st_size}")
                    if len(hits) >= max_hits:
                        break
                if len(hits) >= max_hits:
                    break
        except PermissionError:
            continue
    checks["tmp_executables"] = {"count": len(hits), "samples": hits[:12]}
    if hits:
        sev = "HIGH" if any("/dev/shm" in h for h in hits) or len(hits) >= 3 else "MEDIUM"
        findings.append(
            Finding(
                sev,
                "TMP_EXECUTABLES",
                f"{len(hits)} executable payload(s) under tmp/shm",
                "ELF/shebang/+x in tmp surfaces (redroid data excluded). Samples: "
                + "; ".join(hits[:6]),
                remediation="Identify owner/process; quarantine unknowns; prefer noexec on /tmp if workflow allows.",
                evidence="; ".join(hits[:8]),
            )
        )


def check_fake_kernel_procs(findings: list[Finding], checks: dict) -> None:
    """Kernel threads have empty /proc/pid/exe (or points to nothing). Userland fakes have a binary."""
    fakes: list[str] = []
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                continue
            base = comm.split("/")[0]
            # match exact or prefix kworker/
            suspicious = base in FAKE_KERNEL_NAMES or any(
                base.startswith(n) for n in ("kworker", "ksoftirqd", "migration")
            )
            if not suspicious:
                continue
            exe = entry / "exe"
            try:
                target = os.readlink(exe)
            except Exception:
                # no exe link — normal for kernel threads
                continue
            # userland process with kernel-ish name
            fakes.append(f"pid={entry.name} comm={comm} exe={target}")
    except Exception as e:
        checks["fake_kernel_procs_error"] = str(e)
    checks["fake_kernel_procs"] = fakes
    if fakes:
        findings.append(
            Finding(
                "CRITICAL",
                "IOC_FAKE_KERNEL_PROC",
                "Userland process masquerading as kernel thread",
                "Real kernel threads have no userspace exe. Found: " + "; ".join(fakes[:8]),
                remediation="Capture /proc/<pid> maps/cmdline; kill only after snapshot; rebuild if rootkited.",
                evidence="; ".join(fakes[:8]),
            )
        )


def check_suspicious_cmdline(findings: list[Finding], checks: dict) -> None:
    hits: list[str] = []
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / "cmdline").read_bytes()
            except Exception:
                continue
            cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            if not cmd:
                continue
            for rx in SUSPICIOUS_PROC_RES:
                if rx.search(cmd):
                    hits.append(f"pid={entry.name} {cmd[:160]}")
                    break
            if len(hits) >= 20:
                break
    except Exception as e:
        checks["cmdline_error"] = str(e)
    checks["suspicious_cmdline"] = hits
    if hits:
        findings.append(
            Finding(
                "HIGH",
                "SUSPICIOUS_CMDLINE",
                f"{len(hits)} process cmdline match(es) for miner/bind-shell patterns",
                "; ".join(hits[:6]),
                remediation="Confirm legitimate tools vs malware; kill + remove binaries; rotate secrets if reverse shell suspected.",
                evidence="; ".join(hits[:8]),
            )
        )


def check_proc_ps_gap(findings: list[Finding], checks: dict) -> None:
    """Hide-pid rootkits: /proc entries not listed by ps (weak signal as user)."""
    proc_pids = set()
    try:
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                proc_pids.add(int(entry.name))
    except Exception:
        return
    rc, out, _ = run(["ps", "-eo", "pid=", "--no-headers"], timeout=15)
    ps_pids = set()
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit():
                ps_pids.add(int(line))
    # only compare pids we can see as this user in both
    if not ps_pids:
        checks["proc_ps"] = {"skipped": True}
        return
    # large gap only — small diffs normal (race)
    only_proc = sorted(proc_pids - ps_pids)
    checks["proc_ps"] = {
        "proc_n": len(proc_pids),
        "ps_n": len(ps_pids),
        "only_proc_n": len(only_proc),
        "only_proc_sample": only_proc[:15],
    }
    if len(only_proc) >= 8:
        findings.append(
            Finding(
                "MEDIUM",
                "PROC_PS_GAP",
                f"{len(only_proc)} PIDs in /proc not listed by ps",
                "May be race or hide-pid rootkit. Sample PIDs: " + ",".join(map(str, only_proc[:12])),
                remediation="Re-run as root; compare with `ls /proc` vs `ps`; consider rkhunter/chkrootkit.",
                evidence=",".join(map(str, only_proc[:12])),
            )
        )


def check_ssh_keys(findings: list[Finding], checks: dict, baseline: dict) -> dict:
    ak = HOME / ".ssh" / "authorized_keys"
    data = {"path": str(ak), "exists": ak.exists()}
    if ak.exists():
        text = ak.read_text(encoding="utf-8", errors="replace")
        # strip comments/blank for stable hash of keys only
        keys = [
            ln.strip()
            for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        h = sha256_text("\n".join(keys))
        data["key_count"] = len(keys)
        data["hash"] = h
        prev = (baseline.get("ssh_authorized_keys_hash") or "") if baseline else ""
        if prev and prev != h:
            findings.append(
                Finding(
                    "HIGH",
                    "SSH_KEYS_CHANGED",
                    "authorized_keys hash changed vs baseline",
                    f"count={len(keys)} prev={prev[:12]}… now={h[:12]}… "
                    "Persistence via extra SSH keys is a classic trojan path.",
                    remediation="Diff keys; remove unknown; --update-baseline only after Marc review.",
                    evidence=h,
                )
            )
        elif not prev:
            findings.append(
                Finding(
                    "INFO",
                    "SSH_KEYS_BASELINE_SEED",
                    "authorized_keys baseline will be seeded",
                    f"{len(keys)} key line(s). Accept with --update-baseline.",
                )
            )
    checks["ssh_authorized_keys"] = data
    return {"ssh_authorized_keys_hash": data.get("hash")}


def check_user_crontab(findings: list[Finding], checks: dict, baseline: dict) -> dict:
    rc, out, err = run(["crontab", "-l"], timeout=10)
    text = out if rc == 0 else ""
    if rc != 0 and "no crontab" not in (err + out).lower():
        text = out + err
    # drop comments
    body = "\n".join(
        ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")
    )
    h = sha256_text(body) if body else ""
    data = {"empty": not body, "hash": h, "lines": body.count("\n") + (1 if body else 0)}
    checks["user_crontab"] = data
    prev = (baseline.get("user_crontab_hash") or "") if baseline else ""
    if prev and h and prev != h:
        findings.append(
            Finding(
                "HIGH",
                "CRONTAB_CHANGED",
                "User crontab changed vs baseline",
                f"prev={prev[:12]}… now={h[:12]}… Worms/miners often add cron persistence.",
                remediation="crontab -l and audit new jobs; --update-baseline after accept.",
                evidence=body[:300],
            )
        )
    elif body and not prev:
        findings.append(
            Finding(
                "INFO",
                "CRONTAB_BASELINE_SEED",
                "User crontab baseline will be seeded",
                f"{data['lines']} active line(s).",
            )
        )
    return {"user_crontab_hash": h}


def check_systemd_user(findings: list[Finding], checks: dict, baseline: dict) -> dict:
    rc, out, _ = run(
        ["systemctl", "--user", "list-unit-files", "--type=service", "--no-pager", "--no-legend"],
        timeout=20,
    )
    units = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if parts:
                units.append(parts[0])
    units = sorted(set(units))
    h = sha256_text("\n".join(units))
    checks["systemd_user_units"] = {"count": len(units), "hash": h, "sample": units[:20]}
    prev = (baseline.get("systemd_user_units_hash") or "") if baseline else ""
    prev_list = set(baseline.get("systemd_user_units_list") or []) if baseline else set()
    if prev and prev != h:
        added = sorted(set(units) - prev_list) if prev_list else []
        removed = sorted(prev_list - set(units)) if prev_list else []
        findings.append(
            Finding(
                "HIGH" if added else "MEDIUM",
                "SYSTEMD_USER_CHANGED",
                "systemd --user unit set changed vs baseline",
                f"n={len(units)} added={added[:8]} removed={removed[:8]}",
                remediation="Inspect new units under ~/.config/systemd/user; disable unknowns.",
                evidence=f"added={added[:10]}",
            )
        )
    return {
        "systemd_user_units_hash": h,
        "systemd_user_units_list": units,
    }


def check_world_writable_path(findings: list[Finding], checks: dict) -> None:
    path_env = os.environ.get("PATH", "")
    bad: list[str] = []
    for part in path_env.split(":"):
        if not part:
            continue
        p = Path(part)
        try:
            st = p.stat()
        except Exception:
            continue
        if st.st_mode & stat.S_IWOTH:
            bad.append(part)
    checks["world_writable_path"] = bad
    if bad:
        findings.append(
            Finding(
                "HIGH",
                "PATH_WORLD_WRITABLE",
                "World-writable directory on PATH",
                f"dirs={bad} — Trojan horse via binary plant.",
                remediation="Remove from PATH or fix permissions (chmod o-w).",
                evidence=",".join(bad),
            )
        )


def check_listening_unknown_high(findings: list[Finding], checks: dict) -> None:
    """Light complement: ESTABLISHED outbound to rare high ports — informational."""
    rc, out, _ = run(["ss", "-H", "-tn", "state", "established"], timeout=15)
    remote_ports: dict[int, int] = {}
    if rc == 0:
        for line in out.splitlines():
            # Netid Recv-Q Send-Q Local Peer
            parts = line.split()
            if len(parts) < 5:
                continue
            peer = parts[4]
            if ":" not in peer:
                continue
            try:
                rport = int(peer.rsplit(":", 1)[-1])
            except ValueError:
                continue
            # skip common
            if rport in (443, 80, 53, 22, 853, 993, 995, 587, 465, 123, 3478, 41641):
                continue
            if rport < 1024:
                continue
            remote_ports[rport] = remote_ports.get(rport, 0) + 1
    top = sorted(remote_ports.items(), key=lambda x: -x[1])[:12]
    checks["established_rare_remote_ports"] = top
    # crypto miner pools often 3333/4444/5555/14444 etc — weak signal only
    minerish = [p for p, n in top if p in (3333, 4444, 5555, 7777, 14444, 45700) and n >= 1]
    if minerish:
        findings.append(
            Finding(
                "MEDIUM",
                "NET_MINERISH_PORTS",
                f"Established connections to miner-ish remote ports {minerish}",
                f"top_rare={top[:8]} — correlate with SUSPICIOUS_CMDLINE.",
                remediation="ss -tpn | rg port; kill offending pid if unowned.",
                evidence=str(top[:8]),
            )
        )


def run_optional_rootkit_tools(findings: list[Finding], checks: dict, deep: bool) -> None:
    tools_ran = {}
    if which("chkrootkit") and deep:
        # chkrootkit is noisy; capture Infected / vulnerable lines
        rc, out, err = run(["chkrootkit", "-q"], timeout=300)
        text = out + err
        tools_ran["chkrootkit"] = {"rc": rc, "bytes": len(text)}
        bad_lines = [
            ln
            for ln in text.splitlines()
            if re.search(r"(?i)infected|vulnerable|WARNING|not found", ln)
            and not re.search(r"(?i)nothing found|not infected", ln)
        ]
        # filter common false positives lightly
        bad_lines = [ln for ln in bad_lines if "PACKET SNIFFER" not in ln.upper()][:20]
        if bad_lines:
            findings.append(
                Finding(
                    "HIGH",
                    "CHKROOTKIT_HIT",
                    f"chkrootkit reported {len(bad_lines)} line(s)",
                    "; ".join(bad_lines[:8]),
                    remediation="Triage each line (many FPs); confirm with second tool + live USB.",
                    evidence="; ".join(bad_lines[:10]),
                )
            )
        elif rc in (0, 1):
            findings.append(
                Finding(
                    "INFO",
                    "CHKROOTKIT_OK",
                    "chkrootkit quiet run clean-ish",
                    f"rc={rc}",
                )
            )
    elif deep and not which("chkrootkit"):
        findings.append(
            Finding(
                "LOW",
                "TOOL_MISSING_CHKROOTKIT",
                "chkrootkit not installed",
                "Install via scripts/install-malware-tools.sh for weekly deep scans.",
            )
        )

    if which("rkhunter") and deep:
        # --check --sk skip keypress; may need root for full
        rc, out, err = run(
            ["rkhunter", "--check", "--sk", "--nocolors", "--no-mail-on-warning"],
            timeout=600,
        )
        text = out + err
        tools_ran["rkhunter"] = {"rc": rc, "bytes": len(text)}
        warns = [ln for ln in text.splitlines() if "Warning" in ln or "Infected" in ln][:30]
        # summary line
        summary_lines = [
            ln
            for ln in text.splitlines()
            if re.search(r"(?i)suspect|possible rootkits|file properties", ln)
        ][:10]
        if warns:
            findings.append(
                Finding(
                    "HIGH" if any("Infected" in w for w in warns) else "MEDIUM",
                    "RKHUNTER_WARN",
                    f"rkhunter {len(warns)} warning line(s)",
                    "; ".join(warns[:8] + summary_lines[:3]),
                    remediation="Run sudo rkhunter --check; update props with --propupd after legit upgrades.",
                    evidence="; ".join(warns[:10]),
                )
            )
        else:
            findings.append(
                Finding(
                    "INFO",
                    "RKHUNTER_OK",
                    "rkhunter completed without Warning lines",
                    f"rc={rc} (user-level run may be partial without root)",
                )
            )
    elif deep and not which("rkhunter"):
        findings.append(
            Finding(
                "LOW",
                "TOOL_MISSING_RKHUNTER",
                "rkhunter not installed",
                "Install via scripts/install-malware-tools.sh.",
            )
        )

    if which("debsums") and deep:
        rc, out, err = run(["debsums", "-s"], timeout=300)  # only silent failures = changed
        text = (out + err).strip()
        tools_ran["debsums"] = {"rc": rc, "lines": len(text.splitlines()) if text else 0}
        real_mismatch: list[str] = []
        missing_vendor: list[str] = []
        perm_noise: list[str] = []
        vendor_re = re.compile(
            r"(?i)(dgx-|nvidia|/opt/nvidia|/opt/dgx|cuda|nsight)",
        )
        for ln in text.splitlines() if text else []:
            low = ln.lower()
            s = ln.strip()
            if not s:
                continue
            if "permission denied" in low or "can't open" in low or "cannot open" in low:
                perm_noise.append(s[:200])
            elif "missing file" in low and vendor_re.search(s):
                missing_vendor.append(s[:200])
            elif "missing file" in low:
                # incomplete package; usually not malware — MEDIUM cluster
                missing_vendor.append(s[:200])
            else:
                # actual checksum FAILED / differs
                real_mismatch.append(s[:200])
        tools_ran["debsums"]["mismatch_n"] = len(real_mismatch)
        tools_ran["debsums"]["missing_n"] = len(missing_vendor)
        tools_ran["debsums"]["perm_noise_n"] = len(perm_noise)
        if real_mismatch:
            findings.append(
                Finding(
                    "HIGH",
                    "DEBSUMS_MISMATCH",
                    f"debsums reports {len(real_mismatch)} checksum mismatch(es)",
                    "; ".join(real_mismatch[:8]),
                    remediation="Verify packages (apt install --reinstall pkg); if many system bins changed → compromise until proven otherwise.",
                    evidence="; ".join(real_mismatch[:10]),
                )
            )
        if missing_vendor and not real_mismatch:
            findings.append(
                Finding(
                    "INFO",
                    "DEBSUMS_VENDOR_MISSING",
                    f"debsums: {len(missing_vendor)} missing packaged file(s) (mostly NVIDIA/DGX)",
                    "Incomplete vendor packages common on DGX images — not a malware IoC. Sample: "
                    + "; ".join(missing_vendor[:5]),
                    remediation="Ignore unless unexpected non-NVIDIA packages; optional reinstall dgx-oobe-desktop.",
                    evidence="; ".join(missing_vendor[:8]),
                )
            )
        elif missing_vendor and real_mismatch:
            findings.append(
                Finding(
                    "LOW",
                    "DEBSUMS_VENDOR_MISSING",
                    f"also {len(missing_vendor)} missing vendor file(s)",
                    "; ".join(missing_vendor[:4]),
                )
            )
        if perm_noise and not real_mismatch and not missing_vendor:
            findings.append(
                Finding(
                    "INFO",
                    "DEBSUMS_PERM_SKIP",
                    f"debsums: {len(perm_noise)} unreadable path(s) as non-root (not mismatches)",
                    "NVIDIA/dgx paths often root-only. Sample: " + "; ".join(perm_noise[:5]),
                    remediation="Optional: sudo debsums -s for full coverage. Not a malware signal by itself.",
                    evidence="; ".join(perm_noise[:8]),
                )
            )
        if not real_mismatch and not missing_vendor and not perm_noise:
            findings.append(
                Finding(
                    "INFO",
                    "DEBSUMS_OK",
                    "debsums -s clean",
                    "No silent checksum mismatches reported.",
                )
            )

    checks["optional_tools"] = tools_ran


def run_clam(
    findings: list[Finding], checks: dict, paths: list[str] | None
) -> None:
    clam = which("clamscan") or which("clamdscan")
    if not clam:
        findings.append(
            Finding(
                "LOW",
                "TOOL_MISSING_CLAMAV",
                "ClamAV not installed",
                "Signature AV optional but useful for Downloads/tmp. Install: sudo bash …/cyber-malware-tools-install.sh",
            )
        )
        checks["clam"] = {"present": False}
        return
    scan_paths = paths or [p for p in DEFAULT_CLAM_PATHS if Path(p).exists()]
    if not scan_paths:
        scan_paths = ["/tmp"]
    cmd = [clam, "-r", "--bell", "--max-filesize=50M", "--max-scansize=200M"]
    # clamdscan syntax slightly different
    if Path(clam).name == "clamdscan":
        cmd = [clam, "-m", "--fdpass"]
    cmd.extend(scan_paths)
    rc, out, err = run(cmd, timeout=900)
    text = out + err
    infected = []
    for ln in text.splitlines():
        if "FOUND" in ln and "OK" not in ln.split(":")[-1]:
            infected.append(ln.strip()[:200])
    summary = ""
    for ln in text.splitlines():
        if "Infected files" in ln:
            summary = ln.strip()
    checks["clam"] = {
        "cmd": cmd[:6],
        "rc": rc,
        "infected_n": len(infected),
        "summary": summary,
        "paths": scan_paths,
    }
    if infected:
        findings.append(
            Finding(
                "CRITICAL",
                "CLAM_INFECTED",
                f"ClamAV FOUND {len(infected)} infected file(s)",
                "; ".join(infected[:8]) + (f" | {summary}" if summary else ""),
                remediation="Quarantine/delete; re-scan; check how file arrived; rotate creds if executable payload.",
                evidence="; ".join(infected[:10]),
            )
        )
    else:
        findings.append(
            Finding(
                "INFO",
                "CLAM_CLEAN",
                "ClamAV scan clean on scoped paths",
                f"paths={scan_paths} rc={rc} {summary}",
            )
        )


def check_tools_absent_summary(findings: list[Finding], tools: dict) -> None:
    missing = [k for k, v in tools.items() if isinstance(v, dict) and not v.get("present") and k in (
        "clamscan", "rkhunter", "chkrootkit", "debsums"
    )]
    # only one INFO if nothing installed yet
    if len(missing) >= 3 and not any(f.code.startswith("TOOL_MISSING") for f in findings):
        findings.append(
            Finding(
                "INFO",
                "MALWARE_TOOLING_GAP",
                "No host AV/rootkit packages installed yet",
                "Core IoC checks still run. Install optional stack: "
                "sudo bash <repo>/scripts/install-malware-tools.sh",
                remediation="Install clamav + freshclam + rkhunter + chkrootkit + debsums + lynis.",
            )
        )


# ── orchestration ────────────────────────────────────────────────────────────


def scan(mode: str = "quick", clam_paths: list[str] | None = None) -> IntegrityResult:
    t0 = time.time()
    host = socket.gethostname() or "spark"
    findings: list[Finding] = []
    checks: dict[str, Any] = {}
    baseline = load_json(BASELINE_PATH) or {}
    base_snap = baseline.get("baselines") or baseline  # tolerate shapes

    tools = tool_inventory()
    check_ld_preload(findings, checks)
    check_tmp_executables(findings, checks, deep=(mode == "deep"))
    check_fake_kernel_procs(findings, checks)
    check_suspicious_cmdline(findings, checks)
    check_proc_ps_gap(findings, checks)
    b1 = check_ssh_keys(findings, checks, base_snap)
    b2 = check_user_crontab(findings, checks, base_snap)
    b3 = check_systemd_user(findings, checks, base_snap)
    check_world_writable_path(findings, checks)
    check_listening_unknown_high(findings, checks)
    check_tools_absent_summary(findings, tools)

    if mode == "deep":
        run_optional_rootkit_tools(findings, checks, deep=True)
    if clam_paths is not None or mode == "clam":
        # clam_paths=[] means default paths; None + mode quick = skip
        run_clam(findings, checks, clam_paths if clam_paths else None)
    elif mode == "deep":
        # deep also does a quick clam if available
        if which("clamscan") or which("clamdscan"):
            run_clam(findings, checks, None)

    new_baselines = {**b1, **b2, **b3}
    counts = severity_counts(findings)
    fp = fingerprint(findings)
    return IntegrityResult(
        ts=datetime.now(TZ).strftime("%Y-%m-%d %H:%M %Z"),
        host=host,
        mode=mode,
        findings=[asdict(f) for f in findings],
        summary=counts,
        fingerprint=fp,
        tools=tools,
        baselines=new_baselines,
        checks=checks,
        duration_s=round(time.time() - t0, 2),
    )


def to_markdown(result: IntegrityResult) -> str:
    lines = [
        f"# Host integrity — {result.host}",
        "",
        f"- **When:** {result.ts}",
        f"- **Mode:** {result.mode}",
        f"- **Duration:** {result.duration_s}s",
        f"- **Fingerprint:** `{result.fingerprint}`",
        f"- **Summary:** C{result.summary.get('CRITICAL',0)} / H{result.summary.get('HIGH',0)} / "
        f"M{result.summary.get('MEDIUM',0)} / L{result.summary.get('LOW',0)} / I{result.summary.get('INFO',0)}",
        "",
        "## Tools",
        "",
    ]
    for name, meta in sorted((result.tools or {}).items()):
        if isinstance(meta, dict) and "present" in meta:
            lines.append(f"- `{name}`: {'yes' if meta.get('present') else 'no'}")
    lines += ["", "## Findings", ""]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for f in sorted(result.findings, key=lambda x: (order.get(x.get("severity"), 9), x.get("code") or "")):
        lines.append(f"### [{f.get('severity')}] {f.get('title')}")
        lines.append(f"- code: `{f.get('code')}`")
        if f.get("detail"):
            lines.append(f"- {f['detail']}")
        if f.get("remediation"):
            lines.append(f"- **Fix:** {f['remediation']}")
        lines.append("")
    lines += [
        "## Related",
        "",
        "- Network exposure: `/security/cyber` + `cyber-posture-scan.py`",
        "- OPS COP: `/ops` (ingests integrity via last-scan)",
        "",
    ]
    return "\n".join(lines)


def discord_alert(result: IntegrityResult, prev_fp: str | None) -> str:
    lines = [
        f"**Host integrity** `{result.host}` — fp `{result.fingerprint}`"
        + (f" (was `{prev_fp}`)" if prev_fp and prev_fp != result.fingerprint else ""),
        f"C{result.summary.get('CRITICAL',0)} H{result.summary.get('HIGH',0)} "
        f"M{result.summary.get('MEDIUM',0)} · mode={result.mode} · {result.duration_s}s",
    ]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    for f in sorted(result.findings, key=lambda x: order.get(x.get("severity"), 9)):
        if f.get("severity") not in ("CRITICAL", "HIGH"):
            continue
        lines.append(f"- **{f['severity']}** {f.get('title')}")
    lines.append("Hub: `/security/cyber` · MD: `wiki/outputs/cyber-posture/host-integrity.md`")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--deep", action="store_true", help="rootkit tools + broader walks")
    ap.add_argument(
        "--clam",
        nargs="*",
        default=None,
        help="run ClamAV; optional paths (default high-risk dirs)",
    )
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--md", type=Path, default=None)
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()

    if args.deep:
        mode = "deep"
    elif args.clam is not None:
        mode = "clam"
    else:
        mode = "quick"

    HOST_DIR.mkdir(parents=True, exist_ok=True)
    result = scan(mode=mode, clam_paths=args.clam if args.clam is not None else None)

    json_path = args.json or LAST_PATH
    md_path = args.md or WIKI_MD

    if not args.no_write:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        payload = asdict(result)
        raw = json.dumps(payload, indent=2)
        json_path.write_text(raw, encoding="utf-8")
        # always keep canonical latest + mode snapshot
        if json_path.resolve() != LAST_PATH.resolve():
            LAST_PATH.write_text(raw, encoding="utf-8")
        if mode == "deep":
            LAST_DEEP_PATH.write_text(raw, encoding="utf-8")
        elif mode == "quick":
            LAST_QUICK_PATH.write_text(raw, encoding="utf-8")
        elif mode == "clam":
            (HOST_DIR / "last-clam.json").write_text(raw, encoding="utf-8")
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(to_markdown(result), encoding="utf-8")
        dated = md_path.parent / f"host-integrity-{datetime.now(TZ).strftime('%Y-%m-%d')}.md"
        dated.write_text(to_markdown(result), encoding="utf-8")

    if args.update_baseline:
        BASELINE_PATH.write_text(
            json.dumps(
                {
                    "ts": result.ts,
                    "fingerprint": result.fingerprint,
                    "baselines": result.baselines,
                    "summary": result.summary,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    prev = load_json(BASELINE_PATH) or load_json(LAST_PATH)
    prev_fp = (prev or {}).get("fingerprint")
    crit = result.summary.get("CRITICAL", 0)
    high = result.summary.get("HIGH", 0)
    fp_changed = prev_fp is not None and prev_fp != result.fingerprint

    if args.quiet:
        if prev_fp is None or fp_changed or crit or (high and fp_changed):
            # alert on new baseline missing, fp change; avoid spam if same HIGH debt
            if prev_fp is None or fp_changed:
                print(discord_alert(result, prev_fp))
        return 0

    print(to_markdown(result))
    if crit or high:
        print("\n---\n" + discord_alert(result, prev_fp))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
