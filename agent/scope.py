from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from .config import ScopeConfig

_HOST_RE = re.compile(
    r"(?i)\b(?:https?://)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\b"
)


def _strip_host(value: str) -> str:
    value = value.strip().lower()
    if "://" not in value:
        value = "http://" + value
    parsed = urlparse(value)
    host = parsed.hostname or ""
    return host.lower().rstrip(".")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_in_scope(host: str, scope: ScopeConfig) -> bool:
    host = host.lower().rstrip(".")
    if not host:
        return False
    if host in {h.lower() for h in scope.hosts}:
        return True
    if is_ip(host):
        # IPs must be explicitly listed in scope.hosts
        return host in {h.lower() for h in scope.hosts}
    for domain in scope.domains:
        domain = domain.lower().rstrip(".")
        if host == domain:
            return True
        if scope.allow_subdomains and host.endswith("." + domain):
            return True
    return False


def target_in_scope(target: str, scope: ScopeConfig) -> bool:
    host = _strip_host(target)
    return host_in_scope(host, scope)


def extract_hosts(text: str) -> list[str]:
    found: list[str] = []
    for match in _HOST_RE.finditer(text or ""):
        host = match.group(1).lower().rstrip(".")
        if host and host not in found:
            found.append(host)
    return found


def assert_target_in_scope(target: str, scope: ScopeConfig) -> str:
    host = _strip_host(target)
    if not host_in_scope(host, scope):
        raise PermissionError(
            f"Target out of scope: {target!r} (host={host}). "
            "Update config.yaml scope.domains / scope.hosts."
        )
    return host


def assert_command_in_scope(command: str, scope: ScopeConfig) -> None:
    hosts = extract_hosts(command)
    if not hosts:
        return
    bad = [h for h in hosts if not host_in_scope(h, scope)]
    if bad:
        raise PermissionError(
            f"Command references out-of-scope host(s): {', '.join(bad)}"
        )
