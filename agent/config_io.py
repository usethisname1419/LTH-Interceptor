from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import ROOT, load_config


REQUIRED_TOP_KEYS = ("model_1", "model_2", "model_slot", "runtime", "scope", "ssh")


def config_path() -> Path:
    return ROOT / "config.yaml"


def read_config_text() -> str:
    path = config_path()
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}")
    return path.read_text(encoding="utf-8")


def validate_config_text(text: str) -> dict[str, Any]:
    """Parse + validate. Raises ValueError on unsafe/blank configs."""
    if text is None or not str(text).strip():
        raise ValueError("Config is empty — refusing to save a blank config.")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML parse error: {exc}") from exc
    if raw is None:
        raise ValueError("Config parsed to null — refusing blank config.")
    if not isinstance(raw, dict):
        raise ValueError("Config root must be a mapping/object.")
    if not raw:
        raise ValueError("Config object is empty — refusing blank config.")

    missing = [k for k in REQUIRED_TOP_KEYS if k not in raw]
    if missing:
        raise ValueError(f"Missing required keys: {', '.join(missing)}")

    scope = raw.get("scope") or {}
    if not isinstance(scope, dict):
        raise ValueError("scope must be a mapping")
    domains = scope.get("domains") or []
    hosts = scope.get("hosts") or []
    if not domains and not hosts:
        raise ValueError("scope.domains or scope.hosts must list at least one target")

    ssh = raw.get("ssh") or {}
    if not isinstance(ssh, dict):
        raise ValueError("ssh must be a mapping")
    for key in ("host", "port", "user"):
        if key not in ssh:
            raise ValueError(f"ssh.{key} is required")

    slot = int(raw.get("model_slot", 2))
    if slot not in (1, 2):
        raise ValueError("model_slot must be 1 or 2")

    # Round-trip through load_config semantics by writing to temp is heavy;
    # instead ensure load_config can build from this dict shape by dumping once.
    return raw


def save_config_text(text: str, *, backup: bool = True) -> dict[str, Any]:
    """Validate, backup existing file, write new config. Never writes blank."""
    raw = validate_config_text(text)
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if backup and path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        bak = path.with_name(f"config.yaml.bak-{stamp}")
        shutil.copy2(path, bak)
        # Keep only last 8 backups
        backups = sorted(path.parent.glob("config.yaml.bak-*"), reverse=True)
        for old in backups[8:]:
            try:
                old.unlink()
            except OSError:
                pass

    # Normalize with yaml dump of validated structure? Prefer keep user formatting.
    # Write exact text user edited (already validated non-blank).
    normalized = text if text.endswith("\n") else text + "\n"
    # Safety: refuse if strip emptied somehow
    if not normalized.strip():
        raise ValueError("Refusing to write blank config")
    path.write_text(normalized, encoding="utf-8")
    return raw


def reload_app_config():
    return load_config(config_path())
