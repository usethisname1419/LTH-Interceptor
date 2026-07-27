from __future__ import annotations

import re
from pathlib import Path

from .config import AppConfig
from .runner import CommandRunner

# Offensive / recon binaries worth exposing to the model (basename match).
_WANTED = re.compile(
    r"(?i)^(?:"
    r"nmap|masscan|rustscan|naabu|"
    r"httpx|httprobe|whatweb|wafw00f|nikto|"
    r"ffuf|feroxbuster|gobuster|dirb|dirsearch|wfuzz|"
    r"nuclei|jaeles|dalfox|qsreplace|uro|anew|"
    r"subfinder|amass|assetfinder|findomain|dnsx|puredns|shuffledns|massdns|"
    r"katana|hakrawler|gospider|waybackurls|gau|gauplus|waymore|"
    r"sqlmap|commix|arjun|x8|"
    r"wpscan|joomscan|droopescan|"
    r"hydra|medusa|ncrack|john|hashcat|"
    r"smbclient|smbmap|enum4linux|enum4linux-ng|crackmapexec|nxc|impacket-.+|rpcclient|"
    r"responder|bettercap|aircrack-ng|airodump-ng|wifite|"
    r"searchsploit|exploitdb|"
    r"curl|wget|openssl|dig|host|whois|traceroute|mtr|"
    r"jq|rg|ripgrep|gf|gron|"
    r"chromium|chromium-browser|google-chrome|firefox|"
    r"python3|pip3|git|socat|ncat|nc\.traditional|netcat"
    r")$"
)

_REMOTE = "/home/interceptor/kali_tools.txt"


def curated_inventory_path(config: AppConfig) -> Path:
    return config.root / "agent" / "skills" / "kali_inventory.md"


def filter_tool_paths(lines: list[str], *, limit: int = 120) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        path = (raw or "").strip()
        if not path.startswith("/") or " " in path:
            continue
        name = path.rsplit("/", 1)[-1]
        if name in seen:
            continue
        if not _WANTED.match(name):
            continue
        seen.add(name)
        out.append(path)
        if len(out) >= limit:
            break
    return sorted(out, key=lambda p: p.rsplit("/", 1)[-1].lower())


def build_inventory_markdown(paths: list[str]) -> str:
    lines = [
        "# Kali tool inventory (curated)",
        "",
        "These binaries exist on the Kali box. Prefer LTH wrapper tools when available;",
        "use `shell` with the full path only for extras not wrapped yet.",
        "",
        "## Available paths",
        "",
    ]
    for p in paths:
        lines.append(f"- `{p}`")
    lines += [
        "",
        "## Wrapper mapping (prefer these)",
        "- nmap → `nmap_scan`",
        "- httpx → `httpx_probe`",
        "- subfinder/amass → `subdomain_enum`",
        "- ffuf/feroxbuster/gobuster → `dir_fuzz` / `param_fuzz`",
        "- nuclei → `nuclei_scan`",
        "- katana → `crawl_urls`",
        "- curl → `http_request`",
        "- chromium → `playwright_browse`",
        "",
    ]
    return "\n".join(lines)


def refresh_kali_inventory(config: AppConfig, runner: CommandRunner | None = None) -> str:
    """Pull kali_tools.txt over SSH, curate, cache locally. Returns markdown body."""
    owns = runner is None
    runner = runner or CommandRunner(config)
    try:
        result = runner.run(f"cat {_REMOTE} 2>/dev/null | head -n 20000", timeout=45)
        text = result.stdout or ""
        if result.exit_code != 0 or not text.strip():
            return _read_cached(config)
        paths = filter_tool_paths(text.splitlines())
        if not paths:
            return _read_cached(config)
        md = build_inventory_markdown(paths)
        out = curated_inventory_path(config)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        return md
    finally:
        if owns:
            try:
                runner.close()
            except Exception:
                pass


def load_kali_inventory(config: AppConfig, *, refresh: bool = False) -> str:
    path = curated_inventory_path(config)
    if refresh or not path.exists():
        try:
            return refresh_kali_inventory(config)
        except Exception:
            return _read_cached(config)
    return _read_cached(config)


def _read_cached(config: AppConfig) -> str:
    path = curated_inventory_path(config)
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
