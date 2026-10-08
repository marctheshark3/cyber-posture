"""Private, atomic state writes and notification bookkeeping."""
from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


def private_dirs(path: Path) -> None:
    """Create missing ancestors privately, without chmod-ing pre-existing directories."""
    missing = []
    current = path
    while not current.exists():
        if current.is_symlink():
            raise OSError(f"Dangling directory symlink: {current}")
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)


def atomic_write(path: Path, text: str) -> None:
    private_dirs(path.parent)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise OSError(f"Refusing to replace a non-regular state/report file: {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


@contextmanager
def scan_lock(state: Path, name: str):
    """Serialize scans sharing output and alerts; never follow lock symlinks."""
    private_dirs(state)
    fd = os.open(state / f".{name}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("Scan lock must be a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def needs_alert(result: Any, previous: dict | None, full: bool = False) -> bool:
    now = time.time()
    if previous is not None:
        summary = previous.get("summary")
        emitted_at = previous.get("emitted_at")
        valid = (isinstance(summary, dict)
                 and all(type(summary.get(severity, 0)) is int and summary.get(severity, 0) >= 0
                         for severity in ("CRITICAL", "HIGH"))
                 and isinstance(previous.get("fingerprint"), str) and bool(previous["fingerprint"])
                 and type(emitted_at) in (int, float) and 0 <= emitted_at <= now)
        # Corrupt or future-dated history must not prevent a current HIGH+ alert.
        if not valid:
            previous = None
    attention = any(result.summary.get(severity, 0) for severity in ("CRITICAL", "HIGH"))
    previous_attention = any((previous or {}).get("summary", {}).get(severity, 0) for severity in ("CRITICAL", "HIGH"))
    if full or (previous_attention and not attention):
        return True
    if not attention:
        return False
    return (not previous or previous.get("fingerprint") != result.fingerprint
            or now - previous.get("emitted_at", 0) >= 86400)


def remember_alert(path: Path, result: Any) -> None:
    atomic_write(path, json.dumps({"fingerprint": result.fingerprint, "summary": result.summary,
                                  "emitted_at": time.time()}, indent=2))
