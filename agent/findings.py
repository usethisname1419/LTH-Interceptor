from __future__ import annotations

import json
import re
from typing import Any

from .db import Store

_HOST_RE = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")
_NMAP_PORT_RE = re.compile(r"(?m)^(\d+)/(tcp|udp)\s+open\s+(\S+)")
_HTTPX_LINE_RE = re.compile(
    r"(?m)^(https?://\S+)\|(\d{3})\|(https?://[^|]*)\|(.*)$"
)
_NUCLEI_RE = re.compile(r"(?mi)\[(critical|high|medium|low|info)\]\s*\[([^\]]+)\]\s+(\S+)")


def ingest_tool_result(store: Store, tool_name: str, result: str, args: dict[str, Any] | None = None) -> list[int]:
    """Parse tool output into findings + follow-up todos. Returns finding ids."""
    args = args or {}
    ids: list[int] = []
    text = result or ""

    if tool_name == "subdomain_enum":
        hosts = []
        for line in text.splitlines():
            line = line.strip().lower()
            if not line or line.startswith("---") or line.startswith("count=") or line.startswith("$") or line.startswith("["):
                continue
            if _HOST_RE.fullmatch(line) or (line.count(".") >= 1 and " " not in line):
                hosts.append(line)
        for h in sorted(set(hosts)):
            fid = store.add_finding(
                kind="host",
                severity="info",
                host=h,
                title=f"Subdomain discovered: {h}",
                detail="Found during subdomain enumeration",
                evidence=h,
                source_tool=tool_name,
            )
            ids.append(fid)
        if hosts:
            store.add_todo(
                "Probe discovered subdomains (HTTP)",
                detail=", ".join(hosts[:20]),
                priority=2,
                playbook="web-bounty",
            )
            store.complete_todos_matching(title_contains="subdomain enum")
            store.add_analysis(
                "Subdomain enumeration",
                f"Discovered {len(set(hosts))} hosts:\n" + "\n".join(f"- {h}" for h in sorted(set(hosts))),
                kind="recon",
            )

    elif tool_name == "nmap_scan":
        target = str(args.get("target") or "")
        ports = []
        for m in _NMAP_PORT_RE.finditer(text):
            ports.append((m.group(1), m.group(2), m.group(3)))
        if ports:
            detail = ", ".join(f"{p}/{proto} ({svc})" for p, proto, svc in ports)
            fid = store.add_finding(
                kind="ports",
                severity="info",
                host=target,
                title=f"Open ports on {target or 'target'}",
                detail=detail,
                evidence=text[-4000:],
                source_tool=tool_name,
                meta={"ports": ports},
            )
            ids.append(fid)
            interesting = [p for p, _, svc in ports if p in {"21", "22", "23", "445", "3306", "3389", "8080", "8443"} or "http" in svc]
            if interesting:
                store.add_todo(
                    f"Review interesting services on {target}",
                    detail=detail,
                    priority=2,
                )
            store.add_analysis(
                f"Port scan: {target}",
                f"Open: {detail}",
                kind="recon",
            )

    elif tool_name == "httpx_probe":
        for m in _HTTPX_LINE_RE.finditer(text):
            url, code, final_url, title = m.group(1), m.group(2), m.group(3), m.group(4).strip()
            if code == "000":
                continue
            sev = "info"
            if code.startswith("5"):
                sev = "low"
            elif code in {"401", "403"}:
                sev = "info"
            fid = store.add_finding(
                kind="http",
                severity=sev,
                url=final_url or url,
                host=_host_from_url(final_url or url),
                title=f"HTTP {code}: {title or final_url or url}",
                detail=f"request={url} status={code} final={final_url} title={title}",
                evidence=m.group(0),
                source_tool=tool_name,
            )
            ids.append(fid)
        if ids:
            store.add_todo(
                "Fuzz live HTTP hosts for content",
                detail="Run dir_fuzz / nuclei on live URLs",
                priority=2,
                playbook="web-bounty",
            )
            store.complete_todos_matching(title_contains="Probe discovered subdomains")

    elif tool_name == "nuclei_scan":
        hits = list(_NUCLEI_RE.finditer(text))
        if not hits and text.strip() and "TIMEOUT" not in text and "[INF]" not in text:
            # nuclei sometimes prints bare template lines
            for line in text.splitlines():
                if "http://" in line or "https://" in line:
                    if any(x in line.lower() for x in ("critical", "high", "medium", "cve-", "[")):
                        hits.append(None)  # type: ignore
        for m in _NUCLEI_RE.finditer(text):
            sev, template, target = m.group(1).lower(), m.group(2), m.group(3)
            fid = store.add_finding(
                kind="vuln",
                severity=sev if sev in {"critical", "high", "medium", "low", "info"} else "medium",
                url=target,
                host=_host_from_url(target),
                title=f"Nuclei [{sev}] {template}",
                detail=template,
                evidence=m.group(0),
                source_tool=tool_name,
            )
            ids.append(fid)
            store.add_todo(
                f"Validate nuclei hit: {template}",
                detail=target,
                priority=1 if sev in {"critical", "high"} else 2,
                related_finding_id=fid,
            )
        if ids:
            store.complete_todos_matching(title_contains="Fuzz live HTTP")
            store.add_analysis(
                "Nuclei hits",
                f"Recorded {len(ids)} nuclei findings for manual validation.",
                kind="vuln",
            )

    elif tool_name in {"dir_fuzz", "param_fuzz"}:
        # Capture interesting ffuf-ish JSON status hints / paths
        interesting_paths = re.findall(r'"url"\s*:\s*"([^"]+)"', text)
        statuses = re.findall(r'"status"\s*:\s*(\d+)', text)
        pairs = list(zip(interesting_paths, statuses)) if interesting_paths and statuses else []
        if not pairs:
            # fallback lines with http
            for line in text.splitlines():
                if "http" in line and any(code in line for code in (" 200", " 301", " 302", " 403", "200", "403")):
                    fid = store.add_finding(
                        kind="content",
                        severity="info",
                        title=f"Fuzz hit: {line[:120]}",
                        detail=line[:500],
                        evidence=line[:1000],
                        source_tool=tool_name,
                        url=args.get("url"),
                    )
                    ids.append(fid)
        else:
            for url, status in pairs[:50]:
                sev = "low" if status in {"200", "301", "302"} else "info"
                if status == "403":
                    sev = "info"
                fid = store.add_finding(
                    kind="content",
                    severity=sev,
                    url=url,
                    host=_host_from_url(url),
                    title=f"Fuzz {status}: {url}",
                    detail=f"Discovered via {tool_name}",
                    evidence=url,
                    source_tool=tool_name,
                )
                ids.append(fid)
        if ids:
            store.add_todo(
                "Review fuzz discoveries for sensitive paths/params",
                priority=2,
            )
            store.complete_todos_matching(title_contains="Fuzz live HTTP")

    elif tool_name == "xss_reflect_check":
        if '"reflected_raw": true' in text or '"reflected_raw":true' in text:
            fid = store.add_finding(
                kind="vuln",
                severity="medium",
                title="Possible reflected XSS (raw canary reflected)",
                detail="Canary reflected unencoded — needs manual confirmation",
                evidence=text[:3000],
                source_tool=tool_name,
                url=str(args.get("url") or ""),
            )
            ids.append(fid)
            store.add_todo("Confirm XSS and craft PoC", priority=1, related_finding_id=fid)

    elif tool_name in {"inspect_page", "inspect_js"}:
        try:
            data = json.loads(text[text.find("{") :]) if "{" in text else {}
        except Exception:
            data = {}
        url = str(args.get("url") or data.get("url") or "")
        for item in data.get("findings") or []:
            if not isinstance(item, dict):
                continue
            fid = store.add_finding(
                kind=str(item.get("kind") or "surface"),
                severity=str(item.get("severity") or "info"),
                url=url,
                host=_host_from_url(url),
                title=str(item.get("title") or "Surface finding"),
                detail=str(item.get("detail") or "")[:1000],
                evidence=json.dumps(item)[:2000],
                source_tool=tool_name,
            )
            ids.append(fid)
            if str(item.get("severity")) in {"critical", "high"}:
                store.add_todo(
                    f"Validate: {item.get('title')}",
                    detail=url,
                    priority=1,
                    related_finding_id=fid,
                )
        endpoints = data.get("endpoints") or []
        if endpoints:
            store.add_analysis(
                f"Endpoints from {tool_name}",
                "\n".join(f"- {e}" for e in endpoints[:60]),
                kind="surface",
            )
            store.add_todo(
                "Test discovered API/frontend endpoints",
                detail=", ".join(endpoints[:15]),
                priority=2,
                playbook="surface",
            )
            store.complete_todos_matching(title_contains="Review fuzz discoveries")
        forms = data.get("forms") or []
        if forms:
            store.add_analysis(
                f"Forms on {url}",
                json.dumps(forms, indent=2)[:3000],
                kind="surface",
            )

    elif tool_name == "playwright_browse":
        url = str(args.get("url") or "")
        store.add_analysis(
            f"Playwright browse: {url}",
            text[:4000],
            kind="note",
        )
        store.complete_todos_matching(title_contains="Test discovered API")
        if "playwright_not_installed" in text:
            store.add_todo(
                "Install Playwright on Kali (chromium)",
                detail="pip3 install --user playwright && python3 -m playwright install chromium",
                priority=1,
            )
        else:
            store.add_todo(
                "Follow up browser findings with inspect_page / fuzz",
                detail=url,
                priority=3,
            )

    return ids


def _host_from_url(url: str) -> str | None:
    m = re.search(r"https?://([^/+:]+)", url or "")
    return m.group(1).lower() if m else None


def build_report_markdown(store: Store) -> str:
    findings = store.list_findings(limit=500)
    todos = store.list_todos()
    analysis = store.list_analysis(limit=20)
    lines = ["# LTH-Interceptor Engagement Report", ""]
    stats = store.stats()
    lines += [
        "## Summary",
        f"- Open findings: {stats['open_findings']}",
        f"- High/Critical: {stats['high_or_critical']}",
        f"- Open todos: {stats['open_todos']}",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("_No findings recorded yet._")
    for f in findings:
        lines.append(
            f"- **[{f['severity'].upper()}]** ({f['kind']}) {f['title']}"
            + (f" — `{f['url'] or f['host'] or ''}`" if (f["url"] or f["host"]) else "")
        )
        if f.get("detail"):
            lines.append(f"  - {f['detail'][:300]}")
    lines += ["", "## Todos"]
    for t in todos:
        lines.append(f"- [{t['status']}] (p{t['priority']}) {t['title']}")
    lines += ["", "## Analysis"]
    for a in analysis:
        lines += [f"### {a['title']}", a["body"][:2000], ""]
    return "\n".join(lines)
