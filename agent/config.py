from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parent.parent


@dataclass
class ScopeConfig:
    domains: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    hosts: list[str] = field(default_factory=list)


@dataclass
class SshConfig:
    host: str = "127.0.0.1"
    port: int = 2222
    user: str = "kali"
    password: str = ""
    key_path: str = ""
    use_login_shell: bool = True


@dataclass
class AppConfig:
    model_1: str = "qwen2.5-coder:14b"
    model_2: str = "qwen2.5-coder:32b"
    model_slot: int = 2  # 1 or 2
    ollama_host: str = "http://127.0.0.1:11434"
    runtime: str = "ssh"
    wsl_distro: str = "Ubuntu"
    ssh: SshConfig = field(default_factory=SshConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    proxies: list[str] = field(default_factory=list)
    proxy_rotate: str = "round_robin"
    mark_dead_on_fail: bool = True
    max_tool_rounds: int = 20
    timeout_sec: int = 180
    output_chars: int = 12000
    reports_dir: str = "reports"
    notes_dir: str = "notes"
    pocs_dir: str = "pocs"
    root: Path = field(default_factory=lambda: ROOT)

    @property
    def model(self) -> str:
        return self.active_model_name()

    def active_model_name(self) -> str:
        return self.model_1 if self.model_slot == 1 else self.model_2

    def set_model_slot(self, slot: int) -> str:
        if slot not in (1, 2):
            raise ValueError("model slot must be 1 or 2")
        self.model_slot = slot
        return self.active_model_name()

    def _resolve(self, rel: str) -> Path:
        path = Path(rel)
        if not path.is_absolute():
            path = self.root / path
        return path

    @property
    def reports_path(self) -> Path:
        return self._resolve(self.reports_dir)

    @property
    def notes_path(self) -> Path:
        return self._resolve(self.notes_dir)

    @property
    def pocs_path(self) -> Path:
        return self._resolve(self.pocs_dir)

    def ensure_workspace(self) -> None:
        for path in (self.reports_path, self.notes_path, self.pocs_path):
            path.mkdir(parents=True, exist_ok=True)


def _load_proxy_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def load_config(path: Path | None = None) -> AppConfig:
    cfg_path = path or (ROOT / "config.yaml")
    raw: dict[str, Any] = {}
    if cfg_path.exists():
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    scope_raw = raw.get("scope") or {}
    scope = ScopeConfig(
        domains=[d.strip().lower() for d in scope_raw.get("domains", []) if d],
        allow_subdomains=bool(scope_raw.get("allow_subdomains", True)),
        hosts=[h.strip().lower() for h in scope_raw.get("hosts", []) if h],
    )

    ssh_raw = raw.get("ssh") or {}
    ssh = SshConfig(
        host=str(ssh_raw.get("host", "127.0.0.1")),
        port=int(ssh_raw.get("port", 2222)),
        user=str(ssh_raw.get("user", "kali")),
        password=str(ssh_raw.get("password", "")),
        key_path=str(ssh_raw.get("key_path", "")),
        use_login_shell=bool(ssh_raw.get("use_login_shell", True)),
    )

    proxies = list(raw.get("proxies") or [])
    proxies.extend(_load_proxy_file(ROOT / "proxies.txt"))
    seen: set[str] = set()
    uniq: list[str] = []
    for p in proxies:
        p = str(p).strip()
        if p and p not in seen:
            seen.add(p)
            uniq.append(p)

    # Dual models + active slot. Legacy `model:` key maps to model_2 / active.
    # Env LTH_MODEL_SLOT overrides yaml (used by ui.ps1 -Model).
    model_1 = str(raw.get("model_1") or "qwen2.5-coder:14b")
    model_2 = str(raw.get("model_2") or raw.get("model") or "qwen2.5-coder:32b")
    slot = int(raw.get("model_slot", 2))
    env_slot = (os.environ.get("LTH_MODEL_SLOT") or "").strip()
    if env_slot in {"1", "2"}:
        slot = int(env_slot)
    if slot not in (1, 2):
        slot = 2

    return AppConfig(
        model_1=model_1,
        model_2=model_2,
        model_slot=slot,
        ollama_host=str(raw.get("ollama_host", "http://127.0.0.1:11434")).rstrip("/"),
        runtime=str(raw.get("runtime", "ssh")).lower(),
        wsl_distro=str(raw.get("wsl_distro", "Ubuntu")),
        ssh=ssh,
        scope=scope,
        proxies=uniq,
        proxy_rotate=str(raw.get("proxy_rotate", "round_robin")).lower(),
        mark_dead_on_fail=bool(raw.get("mark_dead_on_fail", True)),
        max_tool_rounds=int(raw.get("max_tool_rounds", 20)),
        timeout_sec=int(raw.get("timeout_sec", 180)),
        output_chars=int(raw.get("output_chars", 12000)),
        reports_dir=str(raw.get("reports_dir", "reports")),
        notes_dir=str(raw.get("notes_dir", "notes")),
        pocs_dir=str(raw.get("pocs_dir", "pocs")),
        root=ROOT,
    )
