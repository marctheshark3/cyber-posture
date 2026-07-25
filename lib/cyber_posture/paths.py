"""Path + profile resolution for portable cyber-posture toolkit."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Repo root: …/cyber-posture (parent of lib/)
REPO_ROOT = Path(__file__).resolve().parents[2]


def _xdg_state() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base)
    return Path.home() / ".local" / "state"


def _xdg_config() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base)
    return Path.home() / ".config"


def resolve_paths(profile: str | None = None) -> dict[str, Path]:
    """Return canonical dirs. Env wins over defaults.

    CYBER_STATE_DIR   default: ~/.local/state/cyber-posture
    CYBER_REPORT_DIR  default: ~/.local/state/cyber-posture/reports
    CYBER_CONFIG_DIR  default: ~/.config/cyber-posture
    CYBER_PROFILE     default: default (or name of yaml without .yaml)
    """
    state = Path(
        os.environ.get("CYBER_STATE_DIR")
        or (_xdg_state() / "cyber-posture")
    ).expanduser()
    report = Path(
        os.environ.get("CYBER_REPORT_DIR")
        or (state / "reports")
    ).expanduser()
    cfg = Path(
        os.environ.get("CYBER_CONFIG_DIR")
        or (_xdg_config() / "cyber-posture")
    ).expanduser()
    prof = profile or os.environ.get("CYBER_PROFILE") or "default"
    host_integrity = state / "host-integrity"
    return {
        "repo": REPO_ROOT,
        "state": state,
        "report": report,
        "config": cfg,
        "host_integrity": host_integrity,
        "profile_name": Path(prof),  # type awkward — store string below
    } | {"profile": prof}  # type: ignore[return-value]


def ensure_dirs(paths: dict[str, Any]) -> None:
    for key in ("state", "report", "host_integrity"):
        p = paths.get(key)
        if isinstance(p, Path):
            p.mkdir(parents=True, exist_ok=True)


def load_profile(name: str | None = None) -> dict[str, Any]:
    """Load YAML/JSON profile. Tries user config then repo config/profiles."""
    paths = resolve_paths(name)
    name = paths.get("profile") or "default"
    candidates = [
        paths["config"] / f"{name}.yaml",
        paths["config"] / f"{name}.yml",
        paths["config"] / "config.yaml",
        REPO_ROOT / "config" / "profiles" / f"{name}.yaml",
        REPO_ROOT / "config" / "profiles" / "default.yaml",
        REPO_ROOT / "config" / "default.yaml",
    ]
    data: dict[str, Any] = {}
    for c in candidates:
        if not c.is_file():
            continue
        text = c.read_text(encoding="utf-8")
        if c.suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore

                loaded = yaml.safe_load(text) or {}
            except Exception:
                # minimal YAML subset: key: value and nested known_ports
                loaded = _minimal_yaml(text)
        else:
            import json

            loaded = json.loads(text)
        if isinstance(loaded, dict):
            data = loaded
            data["_profile_path"] = str(c)
            break
    return data


def _minimal_yaml(text: str) -> dict[str, Any]:
    """Tiny fallback parser for simple profiles without PyYAML."""
    # Prefer json if file is actually json
    t = text.strip()
    if t.startswith("{"):
        import json

        return json.loads(t)
    out: dict[str, Any] = {}
    # only top-level scalars + hub_url style
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("-"):
            continue
        if ":" in s and not s.startswith(" "):
            k, _, v = s.partition(":")
            k, v = k.strip(), v.strip().strip("\"'")
            if v in ("", "|", ">", "{", "["):
                continue
            if v.lower() in ("true", "false"):
                out[k] = v.lower() == "true"
            else:
                try:
                    out[k] = int(v)
                except ValueError:
                    out[k] = v
    return out
