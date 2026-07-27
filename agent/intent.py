from __future__ import annotations

import re
from typing import Any

from .config import ScopeConfig
from .scope import host_in_scope

_PLAN_HINTS = re.compile(
    r"(?i)\b("
    r"let'?s (?:start|run|proceed|probe|scan|do)|"
    r"next[,:]|"
    r"i(?:'| a)?m going to|"
    r"we (?:will|should|can)|"
    r"first[,:]|"
    r"then (?:run|probe|scan|fuzz)|"
    r"nuclei scan|"
    r"directory/?\s*file fuzz|"
    r"parameter fuzz|"
    r"http/?https probing"
    r")\b"
)

_TOOL_WORDS = re.compile(
    r"(?i)\b(nuclei|ffuf|nmap|httpx|subdomain|fuzz|xss|crawl|report|probe|scan)\b"
)

_HOST_RE = re.compile(
    r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b"
)


def looks_like_plan(content: str) -> bool:
    if not content or not content.strip():
        return False
    # Pure short answer / summary is ok; long planning text is not
    if _PLAN_HINTS.search(content) and _TOOL_WORDS.search(content):
        return True
    # Numbered playbook steps
    if re.search(r"(?m)^\s*\d+\.\s+\*\*", content) and _TOOL_WORDS.search(content):
        return True
    return False


def looks_like_final_summary(content: str) -> bool:
    if not content:
        return False
    low = content.lower()
    return bool(
        re.search(r"(?i)\b(summary|findings|report saved|no further|completed|here are the)\b", low)
    ) and not looks_like_plan(content) and not looks_like_generic_assistant(content)


def looks_like_generic_assistant(content: str) -> bool:
    """Detect ChatGPT-style drift away from pentest identity."""
    if not content or not content.strip():
        return False
    low = content.lower()
    patterns = (
        r"feel free to ask",
        r"please provide more details",
        r"so i can assist you better",
        r"how can i (?:help|assist) you",
        r"website management",
        r"general web development",
        r"if you have a specific task or question",
        r"this could be useful for several purposes",
        r"security audits, website management",
        r"organizing and managing files",
        r"understanding the structure of web applications",
        r"you've provided a list of various",
        r"it seems like you've provided",
    )
    hits = sum(1 for p in patterns if re.search(p, low))
    if hits >= 1 and re.search(r"(?i)\b(for example|feel free|assist you|purposes such as)\b", low):
        return True
    return hits >= 2


def extract_hosts_from_text(text: str, scope: ScopeConfig) -> list[str]:
    found: list[str] = []
    for m in _HOST_RE.finditer(text or ""):
        host = m.group(1).lower().rstrip(".")
        if host_in_scope(host, scope) and host not in found:
            found.append(host)
    return found


def collect_session_hosts(messages: list[dict[str, Any]], scope: ScopeConfig) -> list[str]:
    hosts: list[str] = []
    for msg in messages:
        role = msg.get("role")
        if role not in {"tool", "assistant", "user"}:
            continue
        content = msg.get("content") or ""
        for h in extract_hosts_from_text(content, scope):
            if h not in hosts:
                hosts.append(h)
    # Always include configured root domains
    for d in scope.domains:
        d = d.lower()
        if d not in hosts:
            hosts.insert(0, d)
    return hosts


def intent_playbook(user_text: str, hosts: list[str]) -> list[dict[str, Any]]:
    """Deterministic tool queue when the model refuses to emit tool JSON."""
    low = (user_text or "").lower()
    calls: list[dict[str, Any]] = []
    targets = hosts[:8] or []
    joined = ",".join(targets)
    root = targets[0] if targets else ""

    wants_http = bool(re.search(r"httpx|probe|live host|http", low))
    wants_nuclei = bool(re.search(r"nuclei", low))
    wants_dir = bool(re.search(r"dir(?:ectory)?\s*fuzz|ffuf|content disc", low))
    wants_param = bool(re.search(r"param(?:eter)?\s*fuzz", low))
    wants_subs = bool(re.search(r"subdomain", low))
    wants_nmap = bool(re.search(r"nmap|port scan|open ports", low))
    wants_xss = bool(re.search(r"\bxss\b", low))
    wants_report = bool(re.search(r"report|benchmark", low))
    wants_bug = bool(re.search(r"bug bounty|find a bug|vulnerab", low))
    wants_initial = bool(
        re.search(r"initial|recon|check(?:s)?|surface|map the|start(?:ing)?|look at", low)
    )

    # Broad bounty / benchmark / first-look intent => full chain
    if wants_bug or wants_report or wants_initial or (wants_nuclei and wants_dir):
        wants_http = True
        wants_subs = True
        wants_nuclei = wants_nuclei or wants_bug or wants_initial
        if wants_initial:
            # surface-first: probe + crawl + inspect, then nuclei
            pass

    if wants_subs and targets:
        calls.append({"name": "subdomain_enum", "arguments": {"domain": targets[0]}})

    if (wants_nmap or wants_initial or wants_bug) and targets:
        calls.append({"name": "nmap_scan", "arguments": {"target": targets[0]}})

    if (wants_http or wants_initial) and joined:
        calls.append({"name": "httpx_probe", "arguments": {"targets": joined}})

    if wants_initial and root:
        calls.append({"name": "dns_lookup", "arguments": {"host": root}})
        calls.append({"name": "crawl_urls", "arguments": {"url": f"https://{root}", "depth": 2}})
        calls.append({"name": "inspect_page", "arguments": {"url": f"https://{root}/", "follow_js": True}})

    if wants_nuclei and targets:
        # One nuclei pass on the primary host — templates already crawl the target
        calls.append(
            {
                "name": "nuclei_scan",
                "arguments": {
                    "target": f"https://{targets[0]}",
                    "severity": "medium,high,critical",
                },
            }
        )

    if wants_dir:
        for h in targets[:4]:
            calls.append({"name": "dir_fuzz", "arguments": {"url": f"https://{h}/FUZZ", "threads": 20}})

    if wants_param:
        for h in targets[:3]:
            calls.append(
                {
                    "name": "param_fuzz",
                    "arguments": {
                        "url": f"https://{h}/?FUZZ=test",
                        "method": "GET",
                    },
                }
            )

    if wants_xss:
        for h in targets[:3]:
            calls.append(
                {
                    "name": "xss_reflect_check",
                    "arguments": {"url": f"https://{h}/?q={{XSS}}"},
                }
            )

    if wants_report:
        calls.append(
            {
                "name": "save_report",
                "arguments": {
                    "title": "Engagement report",
                    "markdown": "Auto-generated placeholder; model should rewrite with findings.",
                    "filename": "engagement-report",
                },
            }
        )

    # If nothing matched but we have hosts, do a safe initial check chain
    if not calls and targets:
        calls.extend(
            [
                {"name": "httpx_probe", "arguments": {"targets": joined}},
                {"name": "subdomain_enum", "arguments": {"domain": targets[0]}},
                {"name": "inspect_page", "arguments": {"url": f"https://{targets[0]}/", "follow_js": True}},
            ]
        )

    # Deduplicate exact calls
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for c in calls:
        key = repr(c)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out[:12]

