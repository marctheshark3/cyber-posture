#!/usr/bin/env python3
"""Host integrity + malware surface scan (portable).

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
  --quiet     print alerts on HIGH+ changes, recovery, or daily reminders
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
import stat
import subprocess
import time
import sys
from contextlib import nullcontext
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cyber_posture.paths import host_root, load_profile, resolve_paths, target_hostname
from cyber_posture.state import atomic_write, load_json, needs_alert, remember_alert, scan_lock

PROFILE: dict[str, Any] = {}


def _init_paths():
    paths = resolve_paths()
    state, host, report = paths["state"], paths["host_integrity"], paths["report"]
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


def host_path(*parts: str) -> Path:
    """Resolve path on scan target. HOST_ROOT=/host when running in Docker against host FS."""
    return host_root().joinpath(*parts)

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
    coverage: dict[str, Any] = field(default_factory=dict)
    complete: bool = True


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
            if f.read(1):
                raise ValueError("File exceeds hashing limit")
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
        f"{f.severity}:{f.code}:{f.title}:{f.detail}:{f.evidence}"
        for f in findings
        if f.severity in ("CRITICAL", "HIGH")
    )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


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
    return tools


# ── individual checks ────────────────────────────────────────────────────────


def check_ld_preload(findings: list[Finding], checks: dict) -> None:
    p = host_path("etc", "ld.so.preload")
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
    roots = [host_path("tmp"), host_path("var", "tmp"), host_path("dev", "shm")]
    allow_prefixes = tuple(str(host_path(*Path(p).expanduser().parts[1:])) for p in PROFILE.get("tmp_allow_prefixes", []))
    hits: list[str] = []
    max_hits = 40 if deep else 15

    def is_interesting_exec(fp: Path, st: os.stat_result) -> bool:
        path_s = str(fp)
        if any(path_s == p.rstrip("/") or path_s.startswith(p.rstrip("/") + "/") for p in allow_prefixes):
            return False
        # prefer real payloads: ELF, shebang, or anything in shm
        if fp.is_relative_to(host_path("dev", "shm")):
            return True
        try:
            with fp.open("rb") as f:
                head = f.read(256)
        except PermissionError as exc:
            checks.setdefault("tmp_read_errors", []).append(str(exc))
            return False
        except OSError:
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
            checks.setdefault("tmp_read_errors", []).append(f"Temporary surface is unavailable: {root}")
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=lambda exc: checks.setdefault("tmp_read_errors", []).append(str(exc))):
                depth = Path(dirpath).relative_to(root).parts
                if not deep and len(depth) > 3:
                    dirnames.clear()
                    continue
                # Honor directory boundaries: excluding /tmp/safe must not exclude /tmp/safe-malware.
                if any(str(Path(dirpath)) == p.rstrip("/") or str(Path(dirpath)).startswith(p.rstrip("/") + "/") for p in allow_prefixes):
                    dirnames.clear()
                    continue
                for name in filenames:
                    fp = Path(dirpath) / name
                    try:
                        st = fp.lstat()
                    except PermissionError as exc:
                        checks.setdefault("tmp_read_errors", []).append(str(exc))
                        continue
                    except OSError:
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
        except PermissionError as exc:
            checks.setdefault("tmp_read_errors", []).append(str(exc))
            continue
    checks["tmp_executables"] = {"count": len(hits), "samples": hits[:12]}
    if hits:
        sev = "HIGH" if any("/dev/shm" in h for h in hits) or len(hits) >= 3 else "MEDIUM"
        findings.append(
            Finding(
                sev,
                "TMP_EXECUTABLES",
                f"{len(hits)} executable payload(s) under tmp/shm",
                "ELF/shebang/+x in scanned tmp surfaces. Samples: "
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
            except PermissionError as exc:
                checks.setdefault("process_read_errors", []).append(str(exc))
                continue
            except OSError:
                # A disappearing process or kernel thread has no userspace executable.
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
            except PermissionError as exc:
                checks.setdefault("process_read_errors", []).append(str(exc))
                continue
            except OSError:
                continue
            cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            if not cmd:
                continue
            for rx in SUSPICIOUS_PROC_RES:
                if rx.search(cmd):
                    hits.append(f"pid={entry.name} matched={rx.pattern}")
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
    except OSError as exc:
        raise RuntimeError(f"Cannot enumerate /proc: {exc}") from exc
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


def file_snapshot(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {"exists": False}
    result: dict[str, Any] = {"exists": True, "mode": stat.S_IMODE(metadata.st_mode),
                              "uid": metadata.st_uid, "gid": metadata.st_gid}
    if path.is_symlink():
        result["link"] = os.readlink(path)
        if not path.exists():
            result["target_missing"] = True
            return result
    if path.is_dir():
        result["kind"] = "directory"
    elif path.is_file():
        result["kind"] = "file"
        result["sha256"] = sha256_file(path)
        if result["sha256"] is None:
            raise OSError(f"Cannot fully hash {path}")
    else:
        raise OSError(f"Unsupported persistence file type: {path}")
    return result


def check_ssh_keys(findings: list[Finding], checks: dict, baseline: dict) -> dict:
    path = HOME / ".ssh/authorized_keys"
    snapshot = file_snapshot(path)
    checks["ssh_authorized_keys"] = {"path": str(path), **snapshot}
    previous = baseline.get("ssh_authorized_keys")
    if previous is not None:
        changed = previous != snapshot
    elif "ssh_authorized_keys_hash" in baseline:
        if not baseline["ssh_authorized_keys_hash"]:
            changed = snapshot["exists"]
        else:
            # Legacy hashes do not cover ownership or permissions. Require an explicit migration.
            changed = True
    else:
        changed = False
        findings.append(Finding("INFO", "SSH_KEYS_BASELINE_MISSING", "SSH key baseline has not been approved",
                                "Review current keys and use integrity --update-baseline."))
    if changed:
        findings.append(Finding("HIGH", "SSH_KEYS_CHANGED", "SSH authorized_keys persistence changed",
                                f"exists={snapshot['exists']} sha256={snapshot.get('sha256')} mode={snapshot.get('mode')} uid={snapshot.get('uid')} gid={snapshot.get('gid')}",
                                "Review additions, deletions, permissions and ownership before approving a new baseline."))
    return {"ssh_authorized_keys": snapshot, "ssh_authorized_keys_hash": snapshot.get("sha256")}


def check_user_crontab(findings: list[Finding], checks: dict, baseline: dict) -> dict:
    rc, out, err = run(["crontab", "-l"], timeout=10)
    if rc != 0 and not (rc == 1 and "no crontab" in (out + err).lower()):
        raise RuntimeError(f"Cannot read user crontab (rc={rc}): {err[:200]}")
    body = "\n".join(line.strip() for line in out.splitlines() if line.strip() and not line.lstrip().startswith("#")) if rc == 0 else ""
    digest = sha256_text(body)
    snapshot = {"sha256": digest, "empty": not body}
    checks["user_crontab"] = snapshot
    if "user_crontab" in baseline:
        changed = baseline["user_crontab"] != snapshot
    elif "user_crontab_hash" in baseline:
        changed = (baseline["user_crontab_hash"] or sha256_text("")) != digest
    else:
        changed = False
        findings.append(Finding("INFO", "CRONTAB_BASELINE_MISSING", "Crontab baseline has not been approved",
                                "Review current jobs and use integrity --update-baseline."))
    if changed:
        findings.append(Finding("HIGH", "CRONTAB_CHANGED", "User crontab persistence changed",
                                f"empty={snapshot['empty']} sha256={digest}",
                                "Inspect crontab -l and approve only intended changes; cron contents are omitted from reports."))
    return {"user_crontab": snapshot, "user_crontab_hash": digest}


def systemd_roots() -> list[Path]:
    """Persistent user-unit locations, including XDG settings and data directories."""
    config_home = Path(os.environ.get("XDG_CONFIG_HOME") or HOME / ".config").expanduser()
    data_home = Path(os.environ.get("XDG_DATA_HOME") or HOME / ".local/share").expanduser()
    if not config_home.is_absolute():
        config_home = HOME / ".config"
    if not data_home.is_absolute():
        data_home = HOME / ".local/share"
    roots = [config_home / "systemd/user", data_home / "systemd/user", config_home / "systemd/user.control",
             Path("/etc/systemd/user"), Path("/usr/local/lib/systemd/user"), Path("/usr/lib/systemd/user")]
    for variable, default in (("XDG_CONFIG_DIRS", "/etc/xdg"), ("XDG_DATA_DIRS", "/usr/local/share:/usr/share")):
        roots.extend(Path(directory) / "systemd/user"
                     for directory in (os.environ.get(variable) or default).split(":")
                     if directory and Path(directory).is_absolute())
    return list(dict.fromkeys(roots))


def check_systemd_user(findings: list[Finding], checks: dict, baseline: dict) -> dict:
    snapshots: dict[str, Any] = {}
    for root in systemd_roots():
        snapshots[str(root)] = file_snapshot(root)
        if not root.is_dir():
            continue
        def walk_error(exc):
            raise exc
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            for name in sorted(files + [name for name in dirs if (Path(directory) / name).is_symlink()]):
                path = Path(directory) / name
                snapshots[str(path)] = file_snapshot(path)
                if len(snapshots) > 10000:
                    raise RuntimeError("Too many user systemd files to baseline safely")
    digest = sha256_text(json.dumps(snapshots, sort_keys=True))
    checks["systemd_user_units"] = {"count": len(snapshots), "hash": digest}
    previous = baseline.get("systemd_user_files")
    if previous is not None and previous != snapshots:
        changed = sorted(path for path in previous.keys() | snapshots.keys() if previous.get(path) != snapshots.get(path))
        findings.append(Finding("HIGH", "SYSTEMD_USER_CHANGED", "User systemd persistence changed",
                                f"sha256={digest} changed={changed[:20]}",
                                "Review unit contents, drop-ins, enablement links, ownership and permissions."))
    elif previous is None and "systemd_user_units_hash" in baseline:
        findings.append(Finding("HIGH", "SYSTEMD_USER_CHANGED", "Legacy systemd baseline needs content verification",
                                "The old baseline tracked unit names only. Review files before approving the new baseline."))
    elif previous is None:
        findings.append(Finding("INFO", "SYSTEMD_BASELINE_MISSING", "User systemd baseline has not been approved",
                                "Review unit files and enablement links before baselining."))
    return {"systemd_user_files": snapshots, "systemd_user_units_hash": digest}


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
    if rc != 0:
        raise RuntimeError(f"Cannot inspect established connections (rc={rc})")
    if rc == 0:
        for line in out.splitlines():
            # ss -H -tn state established emits Recv-Q Send-Q Local Peer
            parts = line.split()
            if len(parts) < 4:
                continue
            peer = parts[-1]
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


def tool_failure(findings: list[Finding], name: str, rc: int, detail: str) -> None:
    findings.append(Finding("HIGH", f"CHECK_FAILED_{name.upper()}", f"{name} scan did not complete",
                            f"rc={rc}: {detail[:300]}", "Resolve missing permissions, signatures, or tool errors and rerun."))


def run_optional_rootkit_tools(findings: list[Finding], checks: dict, deep: bool) -> None:
    if not deep:
        return
    checks["optional_tools"] = {}
    commands = {
        "chkrootkit": (["chkrootkit", "-q"], 300),
        "rkhunter": (["rkhunter", "--check", "--sk", "--nocolors", "--no-mail-on-warning"], 600),
        "debsums": (["debsums", "-s"], 300),
    }
    for name, (command, timeout) in commands.items():
        if not which(name):
            checks["optional_tools"][name] = {"status": "skipped", "reason": "Requested deep-scan tool is not installed"}
            continue
        rc, out, err = run(command, timeout=timeout)
        text = (out + err).strip()
        meta = checks["optional_tools"][name] = {"rc": rc, "status": "passed"}
        if name == "debsums":
            hits = [line for line in text.splitlines() if re.search(r"(?i)changed file|FAILED|checksum|missing file", line)]
        else:
            hits = [line for line in text.splitlines() if re.search(r"(?i)infected|vulnerable|warning", line)
                    and not re.search(r"(?i)not infected|nothing found", line)]
        if hits:
            meta["status"] = "finding"
            findings.append(Finding("HIGH", f"{name.upper()}_FINDING", f"{name} reported findings",
                                    "; ".join(hits[:12]), "Review each finding; preserve evidence and investigate unexpected changes."))
        failed = rc not in (0, 1, 2, 3) or (rc != 0 and not hits) or bool(re.search(r"(?i)permission denied|must be root|can't open|cannot open|error:", text))
        if failed:
            meta["status"] = "failed"
            tool_failure(findings, name, rc, text or "No usable result")
        elif not hits:
            findings.append(Finding("INFO", f"{name.upper()}_OK", f"{name} completed without reported findings", "rc=0"))


def run_clam(findings: list[Finding], checks: dict, paths: list[str] | None) -> None:
    clam = which("clamscan") or which("clamdscan")
    if not clam:
        checks["clam"] = {"status": "skipped", "reason": "Requested ClamAV scanner is not installed"}
        return
    requested = paths if paths else PROFILE.get("clam_paths", DEFAULT_CLAM_PATHS)
    if host_root() != Path("/"):
        requested = [str(host_path("tmp")), str(host_path("var", "tmp")), str(host_path("dev", "shm"))] if not paths else paths
    scan_paths = [str(Path(path).expanduser()) for path in requested]
    missing = [path for path in scan_paths if not Path(path).exists()]
    scan_paths = [path for path in scan_paths if Path(path).exists()]
    if not scan_paths:
        checks["clam"] = {"status": "failed", "reason": "No requested scan paths are accessible"}
        tool_failure(findings, "clam", 2, "No requested scan paths are accessible")
        return
    cmd = [clam, "-r", "--max-filesize=50M", "--max-scansize=200M", "--fail-if-cvd-older-than=7"]
    if Path(clam).name == "clamdscan":
        cmd = [clam, "-m", "--fdpass"]
    rc, out, err = run([*cmd, "--", *scan_paths], timeout=900)
    infected = [line.strip()[:200] for line in out.splitlines() if line.rstrip().endswith(" FOUND")]
    scanned = re.search(r"Scanned files:\s*(\d+)", out)
    checks["clam"] = {"rc": rc, "paths": scan_paths, "missing_paths": missing,
                      "infected_n": len(infected), "status": "finding" if infected or rc == 1 else "passed"}
    if infected or rc == 1:
        findings.append(Finding("CRITICAL", "CLAM_INFECTED", "ClamAV reported infected files",
                                "; ".join(infected[:10]) or "Scanner returned infection status (1).",
                                "Preserve evidence, isolate affected files and investigate how they arrived."))
    # Return code 2 is an error, and timeout is 124. Neither is a clean result.
    if rc not in (0, 1) or (paths and missing) or (rc == 0 and (not scanned or int(scanned.group(1)) == 0)):
        checks["clam"]["status"] = "failed"
        tool_failure(findings, "clam", rc, err or f"Incomplete coverage; missing paths={missing}; scanned files={scanned.group(1) if scanned else 'unknown'}")
    elif rc == 0 and not infected:
        findings.append(Finding("INFO", "CLAM_CLEAN", "ClamAV completed without detections on scoped paths",
                                f"paths={scan_paths}; {scanned.group(1)} files; size/archive limits apply."))


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
    global PROFILE
    PROFILE = load_profile()
    started = time.time()
    findings: list[Finding] = []
    checks: dict[str, Any] = {}
    coverage: dict[str, Any] = {}
    baseline = load_json(BASELINE_PATH)
    if BASELINE_PATH.exists() and baseline is None:
        findings.append(Finding("HIGH", "BASELINE_UNREADABLE", "Integrity baseline cannot be read",
                                "Restore the approved baseline; do not automatically trust current persistence."))
    base = (baseline or {}).get("baselines", baseline or {})
    if not isinstance(base, dict):
        raise ValueError("Invalid integrity baseline structure")
    snapshots: dict[str, Any] = {}
    if not all(any(key in base for key in alternatives) for alternatives in (
            ("ssh_authorized_keys", "ssh_authorized_keys_hash"),
            ("user_crontab", "user_crontab_hash"),
            ("systemd_user_files", "systemd_user_units_hash"))):
        coverage["persistence_baseline"] = {"status": "skipped", "reason": "No complete approved persistence baseline; review current evidence before baselining."}

    def check(name, function, *args):
        count = len(findings)
        try:
            result = function(findings, checks, *args)
            coverage[name] = {"status": "finding" if len(findings) > count else "passed"}
            if isinstance(result, dict):
                snapshots.update(result)
        except Exception as exc:
            coverage[name] = {"status": "failed", "reason": str(exc)[:300]}
            tool_failure(findings, name, 2, str(exc))

    tools = tool_inventory()
    host_container = host_root() != Path("/")
    checks["target"] = {"scope": "mounted host surfaces" if host_container else "current user and readable system surfaces",
                        "uid": os.geteuid(), "host_root": os.environ.get("HOST_ROOT", "/")}
    if host_container and not host_path("etc").is_dir():
        coverage["host_mounts"] = {"status": "failed", "reason": "The host /etc mount is missing; host evidence is unavailable."}
    check("ld_preload", check_ld_preload)
    check("tmp_executables", check_tmp_executables, mode == "deep")
    check("kernel_processes", check_fake_kernel_procs)
    check("process_commands", check_suspicious_cmdline)
    check("process_inventory", check_proc_ps_gap)
    if host_container:
        for name in ("ssh_keys", "crontab", "systemd_user", "path", "host_packages"):
            coverage[name] = {"status": "skipped", "reason": "Container environment is not the host's user/session/package database; run natively on the host."}
    else:
        check("ssh_keys", check_ssh_keys, base)
        check("crontab", check_user_crontab, base)
        check("systemd_user", check_systemd_user, base)
        check("path", check_world_writable_path)
    check("connections", check_listening_unknown_high)
    check_tools_absent_summary(findings, tools)
    if mode == "deep" and not host_container:
        run_optional_rootkit_tools(findings, checks, True)
        coverage.update(checks.get("optional_tools", {}))
    if clam_paths is not None or mode in ("deep", "clam"):
        run_clam(findings, checks, clam_paths)
        coverage["clam"] = checks["clam"]
    for key in ("fake_kernel_procs_error", "cmdline_error", "tmp_read_errors", "process_read_errors"):
        if checks.get(key):
            coverage[key] = {"status": "failed", "reason": "Some requested process/filesystem evidence could not be read."}
    if checks.get("proc_ps", {}).get("skipped"):
        coverage["process_inventory"] = {"status": "failed", "reason": "ps process inventory was unavailable"}
    complete = baseline is not None or not BASELINE_PATH.exists()
    complete = complete and not any(c["status"] in ("failed", "skipped") for c in coverage.values())
    if not complete:
        incomplete = sorted(name for name, meta in coverage.items() if meta["status"] in ("failed", "skipped"))
        findings.append(Finding("HIGH", "INTEGRITY_INCOMPLETE", "Integrity scan coverage is incomplete",
                                ", ".join(incomplete) or "Baseline unreadable", "Resolve failed checks; run host persistence/package checks natively."))
    return IntegrityResult(ts=datetime.now(TZ).isoformat(timespec="seconds"), host=target_hostname(), mode=mode,
                           findings=[asdict(f) for f in findings], summary=severity_counts(findings),
                           fingerprint=fingerprint(findings), tools=tools, baselines=snapshots, checks=checks,
                           duration_s=round(time.time() - started, 2), coverage=coverage, complete=complete)


def to_markdown(result: IntegrityResult) -> str:
    lines = [
        f"# Host integrity — {result.host}",
        "",
        f"- **When:** {result.ts}",
        f"- **Mode:** {result.mode}",
        f"- **Complete:** {result.complete}",
        f"- **Target:** {result.checks.get('target', {})}",
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
    lines += ["", "## Coverage", ""]
    for name, meta in result.coverage.items():
        lines.append(f"- {name}: **{meta.get('status')}** {meta.get('reason', '')}")
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
    lines.append("MD: host-integrity report under CYBER_REPORT_DIR")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--clam", nargs="*", default=None)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--md", type=Path)
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()
    if args.no_write and args.update_baseline:
        ap.error("--no-write cannot be combined with --update-baseline")
    mode = "deep" if args.deep else "clam" if args.clam is not None else "quick"
    try:
        with nullcontext() if args.no_write else scan_lock(HOST_DIR, "integrity"):
            alert_path = HOST_DIR / f"last-alert-{mode}.json"
            previous = load_json(alert_path)
            result = scan(mode, args.clam)
            if args.update_baseline:
                persistence_ok = all(result.coverage.get(name, {}).get("status") in ("passed", "finding")
                                     for name in ("ssh_keys", "crontab", "systemd_user"))
                unsafe = any(f["severity"] in ("CRITICAL", "HIGH") and f["code"] not in
                             ("SSH_KEYS_CHANGED", "CRONTAB_CHANGED", "SYSTEMD_USER_CHANGED", "INTEGRITY_INCOMPLETE") for f in result.findings)
                if not persistence_ok or unsafe:
                    raise ValueError("Refusing baseline: persistence checks failed/skipped or unresolved HIGH/CRITICAL non-drift findings exist")
                atomic_write(BASELINE_PATH, json.dumps({"version": 2, "ts": result.ts, "baselines": result.baselines}, indent=2))
                result.coverage["persistence_baseline"] = {"status": "passed", "reason": "Current persistence explicitly approved by --update-baseline"}
                result.complete = not any(meta["status"] in ("failed", "skipped") for meta in result.coverage.values())
                if result.complete:
                    result.findings = [f for f in result.findings if f["code"] != "INTEGRITY_INCOMPLETE"]
                native_findings = [Finding(**f) for f in result.findings]
                result.summary = severity_counts(native_findings)
                result.fingerprint = fingerprint(native_findings)
            if not args.no_write:
                raw = json.dumps(asdict(result), indent=2)
                atomic_write(args.json or LAST_PATH, raw)
                if args.json and args.json != LAST_PATH:
                    atomic_write(LAST_PATH, raw)
                atomic_write(HOST_DIR / f"last-{mode}.json", raw)
                md = args.md or WIKI_MD
                atomic_write(md, to_markdown(result))
                atomic_write(md.parent / f"host-integrity-{datetime.now(TZ):%Y-%m-%d}.md", to_markdown(result))
            if not args.quiet:
                print(to_markdown(result))
            if needs_alert(result, previous):
                print(discord_alert(result, (previous or {}).get("fingerprint")))
                if not args.no_write:
                    remember_alert(alert_path, result)
            return 0 if result.complete else 2
    except Exception as exc:
        print(f"cyber-posture integrity failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
