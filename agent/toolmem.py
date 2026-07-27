from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse


# Tools that should not be repeated on the same target in one session.
_HOST_SCOPED = {
    "nuclei_scan",
    "subdomain_enum",
    "nmap_scan",
    "dns_lookup",
}
_URL_SCOPED = {
    "crawl_urls",
    "inspect_page",
    "inspect_js",
    "dir_fuzz",
    "param_fuzz",
    "xss_reflect_check",
    "http_request",
}
# httpx is special: track individual hosts inside targets=


def _norm_host(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "://" not in v:
        # host or host/path
        v = "https://" + v
    try:
        p = urlparse(v)
        host = (p.hostname or "").lower().rstrip(".")
        return host
    except Exception:
        return v.split("/")[0].split(":")[0].lower()


def _norm_url(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if "://" not in v:
        v = "https://" + v
    try:
        p = urlparse(v)
        host = (p.hostname or "").lower()
        path = p.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        # drop query/fragment for crawl/inspect dedupe; keep FUZZ marker paths
        return f"{p.scheme}://{host}{path}".lower()
    except Exception:
        return v.lower().rstrip("/")


def _split_targets(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        parts = [str(x) for x in raw]
    else:
        parts = re.split(r"[\s,]+", str(raw))
    out: list[str] = []
    for p in parts:
        h = _norm_host(p)
        if h and h not in out:
            out.append(h)
    return out


def _target_from_args(name: str, args: dict[str, Any]) -> str:
    if name == "subdomain_enum":
        return _norm_host(str(args.get("domain") or args.get("host") or args.get("target") or ""))
    if name in {"nuclei_scan", "nmap_scan", "dns_lookup"}:
        return _norm_host(
            str(args.get("target") or args.get("host") or args.get("url") or args.get("domain") or "")
        )
    if name in _URL_SCOPED:
        return _norm_url(str(args.get("url") or args.get("target") or ""))
    if name == "httpx_probe":
        hosts = _split_targets(args.get("targets") or args.get("target") or "")
        return ",".join(sorted(hosts))
    # fallback: stable json of args
    return json.dumps(args, sort_keys=True, default=str)[:240]


class ToolMemory:
    """Session memory to prevent repeating expensive recon tools."""

    def __init__(self) -> None:
        self._keys: set[str] = set()
        self._httpx_hosts: set[str] = set()
        self._history: list[str] = []  # human lines for prompts

    def clear(self) -> None:
        self._keys.clear()
        self._httpx_hosts.clear()
        self._history.clear()

    def summary(self, limit: int = 24) -> str:
        if not self._history:
            return "(none yet)"
        return "\n".join(f"- {line}" for line in self._history[-limit:])

    def _key(self, name: str, target: str) -> str:
        return f"{name}|{target}"

    def filter_call(self, name: str, args: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
        """
        Returns (args_to_run, skip_reason).
        If skip_reason is set, do not run. args_to_run may be narrowed (httpx).
        """
        args = dict(args or {})
        name = name.strip()

        if name == "httpx_probe":
            hosts = _split_targets(args.get("targets") or args.get("target") or "")
            if not hosts:
                return None, "httpx_probe missing targets"
            fresh = [h for h in hosts if h not in self._httpx_hosts]
            if not fresh:
                return None, f"already httpx-probed: {', '.join(hosts)}"
            args["targets"] = ",".join(fresh)
            return args, None

        if name in _HOST_SCOPED or name in _URL_SCOPED:
            target = _target_from_args(name, args)
            if not target:
                return args, None
            key = self._key(name, target)
            if key in self._keys:
                label = "host" if name in _HOST_SCOPED else "url"
                return None, f"already ran {name} on {label} {target}"
            return args, None

        # exact fingerprint for other tools (shell etc. still allowed to repeat)
        if name in {"save_note", "save_poc", "save_report", "proxy_status", "shell"}:
            return args, None

        target = _target_from_args(name, args)
        key = self._key(name, target)
        if key in self._keys:
            return None, f"already ran {name} with same args"
        return args, None

    def record(self, name: str, args: dict[str, Any]) -> None:
        name = name.strip()
        if name == "httpx_probe":
            hosts = _split_targets(args.get("targets") or "")
            for h in hosts:
                self._httpx_hosts.add(h)
            if hosts:
                line = f"httpx_probe → {', '.join(hosts)}"
                self._history.append(line)
                self._keys.add(self._key(name, ",".join(sorted(hosts))))
            return

        target = _target_from_args(name, args)
        if not target and name not in {"save_note", "save_poc", "save_report", "proxy_status"}:
            target = json.dumps(args, sort_keys=True, default=str)[:120]
        if target:
            self._keys.add(self._key(name, target))
            self._history.append(f"{name} → {target}")
