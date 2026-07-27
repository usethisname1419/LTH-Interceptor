from __future__ import annotations

import json
import shlex
from typing import Any
from urllib.parse import urlparse

from .config import AppConfig
from .proxy import ProxyRotator, to_curl_proxy
from .runner import CommandRunner


def run_startup_checks(config: AppConfig) -> dict[str, Any]:
    """SSH, proxy, and Kali tool reachability checks with human-readable lines."""
    lines: list[str] = []
    checks: list[dict[str, Any]] = []
    overall = True

    runner = CommandRunner(config)
    try:
        # --- SSH ---
        ssh_ok = False
        ssh_detail = ""
        try:
            result = runner.run(
                "echo LTH_SSH_OK && hostname && whoami && command -v curl && command -v nmap",
                timeout=25,
            )
            ssh_ok = result.exit_code == 0 and "LTH_SSH_OK" in (result.stdout or "")
            ssh_detail = (result.stdout or result.stderr or "").strip()[:500]
        except Exception as exc:
            ssh_detail = str(exc)
            ssh_ok = False

        checks.append({"name": "ssh", "ok": ssh_ok, "detail": ssh_detail})
        if ssh_ok:
            lines.append(f"[OK] SSH  {config.ssh.user}@{config.ssh.host}:{config.ssh.port}")
            for ln in ssh_detail.splitlines()[:4]:
                if ln.strip():
                    lines.append(f"     {ln.strip()}")
        else:
            overall = False
            lines.append(f"[FAIL] SSH  {config.ssh.user}@{config.ssh.host}:{config.ssh.port}")
            if ssh_detail:
                lines.append(f"     {ssh_detail.splitlines()[0][:160]}")

        # --- Proxies ---
        proxies = list(config.proxies)
        if not proxies:
            checks.append({"name": "proxies", "ok": True, "detail": "none configured", "alive": 0, "total": 0})
            lines.append("[OK] Proxies  none configured (DIRECT)")
        else:
            rotator = ProxyRotator(proxies, mode="round_robin", mark_dead_on_fail=True)
            alive = 0
            proxy_details: list[str] = []
            # Cap how many we probe at startup
            sample = proxies[: min(5, len(proxies))]
            for proxy in sample:
                ok, detail = _probe_proxy(runner, proxy)
                if ok:
                    alive += 1
                    rotator.mark_ok(proxy)
                    proxy_details.append(f"alive  {_redact_proxy(proxy)}")
                else:
                    rotator.mark_dead(proxy)
                    proxy_details.append(f"dead   {_redact_proxy(proxy)} ({detail[:80]})")

            proxy_ok = alive > 0
            if not proxy_ok:
                overall = False
            checks.append(
                {
                    "name": "proxies",
                    "ok": proxy_ok,
                    "detail": "; ".join(proxy_details),
                    "alive": alive,
                    "total": len(proxies),
                    "sampled": len(sample),
                }
            )
            tag = "OK" if proxy_ok else "FAIL"
            lines.append(f"[{tag}] Proxies  {alive}/{len(sample)} sampled alive (pool={len(proxies)})")
            for d in proxy_details[:5]:
                lines.append(f"     {d}")

        # --- Kali outbound tool (curl) ---
        curl_ok = False
        curl_detail = ""
        if ssh_ok:
            # Use example.com as requested — connectivity check only
            cmd = (
                "curl -sS -o /dev/null -w '%{http_code} %{url_effective} time=%{time_total}s' "
                "--max-time 20 -L http://example.com || echo CURL_FAIL"
            )
            result = runner.run(cmd, timeout=35)
            out = (result.stdout or "").strip()
            curl_ok = result.exit_code == 0 and "CURL_FAIL" not in out and out[:3].isdigit()
            # Accept any HTTP code as reachability (even 403) if we got a code
            if not curl_ok and out and out[0].isdigit():
                curl_ok = True
            curl_detail = out[:300]
        else:
            curl_detail = "skipped (ssh down)"

        if not curl_ok:
            overall = False
        checks.append({"name": "kali_curl", "ok": curl_ok, "detail": curl_detail})
        tag = "OK" if curl_ok else "FAIL"
        lines.append(f"[{tag}] Kali curl  example.com -> {curl_detail or 'no response'}")

        # --- Ollama ---
        ollama_ok = False
        ollama_detail = ""
        try:
            import urllib.request

            with urllib.request.urlopen(f"{config.ollama_host}/api/tags", timeout=5) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            names = [m.get("name", "") for m in payload.get("models", [])]
            ollama_ok = True
            active = config.active_model_name()
            present = any(active == n or active in n or n.startswith(active.split(":")[0]) for n in names)
            ollama_detail = f"host={config.ollama_host} models={len(names)} active={active} installed={'yes' if present else 'NO'}"
            if not present:
                overall = False
                ollama_ok = False
        except Exception as exc:
            ollama_detail = str(exc)
            overall = False

        checks.append({"name": "ollama", "ok": ollama_ok, "detail": ollama_detail})
        tag = "OK" if ollama_ok else "FAIL"
        lines.append(f"[{tag}] Ollama  {ollama_detail}")

    finally:
        runner.close()

    return {
        "ok": overall,
        "lines": lines,
        "checks": checks,
        "model_slot": config.model_slot,
        "model": config.active_model_name(),
        "models": {"1": config.model_1, "2": config.model_2},
    }


def _redact_proxy(proxy: str) -> str:
    try:
        p = urlparse(proxy if "://" in proxy else "socks5://" + proxy)
        host = p.hostname or "?"
        port = p.port or "?"
        user = (p.username or "")
        auth = f"{user}@" if user else ""
        return f"{p.scheme}://{auth}{host}:{port}"
    except Exception:
        return proxy[:40]


def _probe_proxy(runner: CommandRunner, proxy: str) -> tuple[bool, str]:
    """Quick curl via SOCKS5 to example.com from Kali."""
    try:
        px = to_curl_proxy(proxy)
    except Exception as exc:
        return False, str(exc)
    cmd = (
        f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 12 "
        f"--proxy {shlex.quote(px)} http://example.com || echo FAIL"
    )
    result = runner.run(cmd, timeout=20)
    out = (result.stdout or "").strip()
    if out.isdigit() or (out and out[0].isdigit()):
        return True, out
    return False, out or (result.stderr or "fail")[:120]
