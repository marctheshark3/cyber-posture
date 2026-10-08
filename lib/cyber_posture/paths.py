"""Path resolution and validated security profiles."""
from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path
from typing import Any
from .state import private_dirs

REPO_ROOT = Path(__file__).resolve().parents[2]


class ProfileError(ValueError):
    """The requested security policy could not be loaded safely."""


def host_root() -> Path:
    root = Path(os.environ.get("HOST_ROOT") or "/")
    if not root.is_absolute():
        raise ProfileError("HOST_ROOT must be an absolute path")
    return root


def target_hostname() -> str:
    if host_root() == Path("/"):
        return socket.gethostname()
    try:
        name = (host_root() / "etc/hostname").read_text().strip()
        if re.fullmatch(r"[A-Za-z0-9._-]{1,253}", name):
            return name
    except OSError:
        pass
    return f"unidentified host (collector {socket.gethostname()})"


def resolve_paths(profile: str | None = None) -> dict[str, Any]:
    state = Path(os.environ.get("CYBER_STATE_DIR") or
                 Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "cyber-posture").expanduser()
    config = Path(os.environ.get("CYBER_CONFIG_DIR") or
                  Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "cyber-posture").expanduser()
    name = profile or os.environ.get("CYBER_PROFILE") or "default"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ProfileError("Profile names must contain only letters, digits, underscores, or hyphens")
    return {
        "repo": REPO_ROOT, "state": state,
        "report": Path(os.environ.get("CYBER_REPORT_DIR") or state / "reports").expanduser(),
        "config": config, "host_integrity": state / "host-integrity",
        "profile": name, "profile_name": Path(name),
    }


def ensure_dirs(paths: dict[str, Any]) -> None:
    for key in ("state", "report", "host_integrity"):
        if isinstance(paths.get(key), Path):
            private_dirs(paths[key])


def _port(value: Any) -> int:
    if isinstance(value, bool):
        raise ProfileError("Ports must be integers between 1 and 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"Invalid port: {value!r}") from exc
    if str(port) != str(value) or not 1 <= port <= 65535:
        raise ProfileError(f"Invalid port: {value!r}")
    return port


def validate_profile(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ProfileError("Profile must be a mapping")
    supported = {"name", "hub_url", "timezone", "lan_allowlist", "accepted_lan_ports",
                 "known_services", "probes", "tmp_allow_prefixes", "clam_paths", "_profile_path"}
    unknown = set(data) - supported
    if unknown:
        raise ProfileError(f"Unknown profile fields: {sorted(str(key) for key in unknown)}")
    for key in ("name", "hub_url", "timezone"):
        if key in data and not isinstance(data[key], str):
            raise ProfileError(f"{key} must be a string")
    for key in ("lan_allowlist", "accepted_lan_ports"):
        if key in data:
            if not isinstance(data[key], list):
                raise ProfileError(f"{key} must be a list (use [] to allow no ports)")
            data[key] = [_port(port) for port in data[key]]
    for key in ("known_services", "probes"):
        if key not in data:
            continue
        if not isinstance(data[key], dict):
            raise ProfileError(f"{key} must be a port mapping")
        data[key] = {_port(port): value for port, value in data[key].items()}
    for port, service in data.get("known_services", {}).items():
        if not isinstance(service, dict):
            raise ProfileError(f"known_services.{port} must be a mapping")
        if set(service) - {"name", "owner", "expect_bind", "auth", "tier"} or not all(isinstance(v, str) for v in service.values()):
            raise ProfileError(f"known_services.{port} contains unknown fields or non-string values")
        if service.get("expect_bind", "loopback") not in ("loopback", "any", "tailnet"):
            raise ProfileError(f"Unsupported expect_bind for port {port}")
        if service.get("auth", "unknown") not in ("required", "public", "n/a", "unknown", "keyish"):
            raise ProfileError(f"Unsupported auth policy for port {port}")
    for port, probes in data.get("probes", {}).items():
        if not isinstance(probes, list):
            raise ProfileError(f"probes.{port} must be a list")
        for probe in probes:
            path = probe if isinstance(probe, str) else probe.get("path") if isinstance(probe, dict) else None
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(ord(c) < 32 for c in path):
                raise ProfileError(f"Invalid probe path for port {port}")
            if isinstance(probe, dict):
                if set(probe) - {"path", "scheme", "auth"}:
                    raise ProfileError(f"Unknown probe fields for port {port}")
                if probe.get("scheme", "http") not in ("http", "https"):
                    raise ProfileError(f"Invalid probe scheme for port {port}")
                if probe.get("auth", "required") not in ("required", "public", "observe"):
                    raise ProfileError(f"Invalid probe auth policy for port {port}")
    for key in ("tmp_allow_prefixes", "clam_paths"):
        if key in data and (not isinstance(data[key], list) or
                            not all(isinstance(p, str) and p.startswith(("/", "~/")) for p in data[key])):
            raise ProfileError(f"{key} must be a list of absolute or ~/ paths")
    return data


def load_profile(name: str | None = None) -> dict[str, Any]:
    paths = resolve_paths(name)
    name = paths["profile"]
    candidates = [paths["config"] / f"{name}{suffix}" for suffix in (".yaml", ".yml", ".json")]
    # An explicit named profile must not silently select an unrelated config.yaml.
    if name == "default":
        candidates += [paths["config"] / "config.yaml", paths["config"] / "config.json"]
    candidates += [REPO_ROOT / "config/profiles" / f"{name}.yaml"]
    if name == "default":
        candidates.append(REPO_ROOT / "config/default.yaml")
    source = next((p for p in candidates if p.is_file()), None)
    if source is None:
        raise ProfileError(f"Profile {name!r} was not found")
    try:
        text = source.read_text(encoding="utf-8")
        if source.suffix == ".json":
            data = json.loads(text)
        else:
            try:
                import yaml
            except ImportError as exc:
                raise ProfileError("YAML profiles require PyYAML: install python3-yaml or use a JSON profile") from exc
            data = yaml.safe_load(text)
        data = validate_profile(data)
    except ProfileError:
        raise
    except Exception as exc:
        raise ProfileError(f"Cannot load {source}: {exc}") from exc
    data["_profile_path"] = str(source)
    return data
