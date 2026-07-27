from __future__ import annotations

import json
import re
from typing import Any, Callable

from .config import AppConfig
from .db import Store
from .llm import OllamaClient

CancelCheck = Callable[[], None]


_INTERESTING_KIND = {
    "host",
    "http",
    "url",
    "endpoint",
    "ports",
    "service",
    "xss",
    "secret",
    "form",
    "login",
    "admin",
    "api",
    "nuclei",
    "dir",
    "param",
}
_INTERESTING_SEV = {"critical", "high", "medium"}
_INTERESTING_WORDS = re.compile(
    r"(?i)\b(admin|login|signin|api|graphql|swagger|actuator|debug|staging|"
    r"internal|dashboard|wp-admin|phpmyadmin|jwt|token|secret|upload|s3|"
    r"bucket|oauth|saml|ssh|rdp|ftp|mysql|postgres|redis|kibana)\b"
)


def build_chart_from_store(store: Store, config: AppConfig) -> dict[str, Any]:
    """Lean chart: hosts, endpoints/services, and interesting items only."""
    findings = store.list_findings(limit=500)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    edge_keys: set[str] = set()

    def add_node(nid: str, label: str, kind: str, **extra: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "kind": kind, **extra}
        else:
            nodes[nid].update({k: v for k, v in extra.items() if v})

    roots = [d.lower() for d in (config.scope.domains or [])]
    for root in roots:
        add_node(f"host:{root}", root, "root", severity="info")

    url_count = 0
    for f in findings:
        kind = (f.get("kind") or "finding").lower()
        host = (f.get("host") or "").lower().strip()
        url = (f.get("url") or "").strip()
        title = f.get("title") or kind
        sev = (f.get("severity") or "info").lower()
        blob = f"{kind} {title} {url} {f.get('detail') or ''}"

        interesting = (
            kind in _INTERESTING_KIND
            or sev in _INTERESTING_SEV
            or bool(_INTERESTING_WORDS.search(blob))
        )
        if not interesting:
            continue

        if host:
            host_kind = "root" if host in roots else "host"
            existing = nodes.get(f"host:{host}")
            if existing and existing.get("kind") == "root":
                host_kind = "root"
            add_node(f"host:{host}", host, host_kind, severity=sev, host=host)
            for root in roots:
                if host != root and host.endswith("." + root):
                    ek = f"host:{root}->host:{host}"
                    if ek not in edge_keys:
                        edges.append({"from": f"host:{root}", "to": f"host:{host}", "label": "subdomain"})
                        edge_keys.add(ek)

        if url and url_count < 80:
            # Prefer path endpoints over static assets
            if re.search(r"\.(css|png|jpe?g|gif|svg|woff2?|ico|map)(\?|$)", url, re.I):
                continue
            uid = f"url:{_norm_endpoint(url)}"
            interesting_url = bool(_INTERESTING_WORDS.search(blob)) or sev in _INTERESTING_SEV
            add_node(
                uid,
                _short_url(url),
                "url",
                severity=sev,
                full=url,
                host=host,
                interesting=interesting_url,
            )
            url_count += 1
            if host:
                ek = f"host:{host}->{uid}"
                if ek not in edge_keys:
                    edges.append({"from": f"host:{host}", "to": uid, "label": "endpoint"})
                    edge_keys.add(ek)

        if kind == "ports":
            parent = f"host:{host}" if host else None
            detail = f.get("detail") or ""
            # Split "80/tcp (http), 443/tcp (https), 3306/tcp (mysql)" into boxes
            parts = re.findall(
                r"(\d+)\s*/\s*(tcp|udp)\s*(?:\(([^)]+)\))?",
                detail,
                flags=re.I,
            )
            if not parts:
                # fallback: loose "3306 mysql" / "https"
                parts = []
            if parts:
                for port, proto, svc in parts[:24]:
                    svc_name = (svc or proto).strip() or "service"
                    label = f"{svc_name} {port}"
                    if re.search(r"(?i)https?", svc_name) or port in {"80", "443"}:
                        label = f"{svc_name or 'http'} {port}"
                    fid = f"svc:{host}:{port}/{proto}"
                    add_node(
                        fid,
                        label[:48],
                        "service",
                        severity=sev,
                        detail=f"{port}/{proto} {svc_name}",
                        port=port,
                        proto=proto,
                        service_name=svc_name,
                        host=host,
                    )
                    if parent and parent in nodes:
                        ek = f"{parent}->{fid}"
                        if ek not in edge_keys:
                            edges.append({"from": parent, "to": fid, "label": "service"})
                            edge_keys.add(ek)
            else:
                fid = f"svc:{f.get('id')}"
                add_node(
                    fid,
                    (title or "services")[:60],
                    "service",
                    severity=sev,
                    detail=detail[:180],
                    host=host,
                )
                if parent and parent in nodes:
                    ek = f"{parent}->{fid}"
                    if ek not in edge_keys:
                        edges.append({"from": parent, "to": fid, "label": "service"})
                        edge_keys.add(ek)
        elif kind not in {"host", "http", "url"} and sev in _INTERESTING_SEV:
            fid = f"finding:{f.get('id')}"
            interesting_hit = bool(_INTERESTING_WORDS.search(blob))
            add_node(
                fid,
                title[:60],
                "finding",
                severity=sev,
                detail=(f.get("detail") or "")[:180],
                host=host,
                interesting=interesting_hit or sev in {"critical", "high"},
            )
            parent = f"host:{host}" if host and f"host:{host}" in nodes else None
            if parent:
                ek = f"{parent}->{fid}"
                if ek not in edge_keys:
                    edges.append({"from": parent, "to": fid, "label": kind})
                    edge_keys.add(ek)

    # Auto highlights — interesting endpoints / high sev
    highlight = [
        n["id"]
        for n in nodes.values()
        if n.get("interesting")
        or n["kind"] in {"service"}
        or _INTERESTING_WORDS.search(n.get("label") or "")
        or (n.get("severity") or "") in {"critical", "high"}
    ][:50]

    notes_lines = [
        f"Scope: {', '.join(roots) or '(none)'}",
        f"Hosts: {sum(1 for n in nodes.values() if n['kind'] in {'root','host'})}",
        f"Endpoints: {sum(1 for n in nodes.values() if n['kind'] == 'url')}",
        f"Services/interesting: {sum(1 for n in nodes.values() if n['kind'] in {'service','finding'})}",
        "Click a domain or subdomain to open its service matrix.",
    ]

    return {
        "title": "Target surface chart",
        "layout": "matrix",
        "scope": roots,
        "nodes": list(nodes.values()),
        "edges": edges,
        "highlight": highlight,
        "groups": [],
        "notes": "\n".join(f"- {x}" for x in notes_lines),
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "findings_considered": len(findings),
        },
        "source": "deterministic-lean",
    }


def enrich_chart_with_llm(
    base: dict[str, Any],
    config: AppConfig,
    *,
    timeout: int = 90,
    cancel_check: CancelCheck | None = None,
) -> dict[str, Any]:
    """Short LLM pass for attack notes only. Hard timeout so it cannot hang for hours."""
    import threading

    if cancel_check:
        cancel_check()
    client = OllamaClient(config.ollama_host, config.active_model_name())
    compact = {
        "scope": base.get("scope"),
        "hosts": [n["label"] for n in base.get("nodes", []) if n.get("kind") in {"root", "host"}][:40],
        "endpoints": [n.get("full") or n["label"] for n in base.get("nodes", []) if n.get("kind") == "url"][:40],
        "services": [n["label"] for n in base.get("nodes", []) if n.get("kind") in {"service", "finding"}][:30],
    }
    prompt = (
        "Authorized pentest surface summary. Return ONLY JSON:\n"
        '{"notes":"markdown bullets of likely attack paths (max 12 lines)",'
        '"highlight_labels":["host or endpoint labels to prioritize"]}\n'
        "Be concrete about attacks (auth bypass, IDOR, XSS, SSRF, misconfig). "
        "Do not invent hosts.\n\n"
        f"INPUT:\n{json.dumps(compact)[:6000]}"
    )
    box: dict[str, Any] = {}

    def _call() -> None:
        try:
            box["resp"] = client.chat(
                [
                    {"role": "system", "content": "Return only valid JSON. No markdown fences."},
                    {"role": "user", "content": prompt},
                ],
                tools=None,
                temperature=0.2,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            box["err"] = exc

    try:
        if cancel_check:
            cancel_check()
        th = threading.Thread(target=_call, daemon=True)
        th.start()
        # Poll cancel while waiting (urllib itself is not interruptible)
        while th.is_alive():
            th.join(0.4)
            if cancel_check:
                try:
                    cancel_check()
                except Exception as cancel_exc:
                    out = dict(base)
                    out["notes"] = (base.get("notes") or "") + "\n\n(chart LLM cancelled — lean map only)"
                    out["source"] = str(base.get("source") or "deterministic")
                    # Leave daemon thread; timeout will end it
                    raise cancel_exc
        if "err" in box:
            raise box["err"]
        resp = box.get("resp") or {}
        if cancel_check:
            cancel_check()
        content = ((resp.get("message") or {}).get("content") or "").strip()
        content = _strip_fence(content)
        data = json.loads(content)
        out = dict(base)
        extra_notes = (data.get("notes") or "").strip()
        if extra_notes:
            out["notes"] = (base.get("notes") or "") + "\n\n" + extra_notes
        labels = {str(x).lower() for x in (data.get("highlight_labels") or [])}
        hi = list(base.get("highlight") or [])
        for n in out.get("nodes") or []:
            lab = (n.get("label") or "").lower()
            full = (n.get("full") or "").lower()
            if any(x in lab or x in full for x in labels if x):
                if n["id"] not in hi:
                    hi.append(n["id"])
        out["highlight"] = hi[:50]
        out["source"] = "llm+" + str(base.get("source") or "deterministic")
        out["model"] = config.active_model_name()
        return out
    except Exception as exc:
        from .cancel import CancelledError

        if isinstance(exc, CancelledError):
            out = dict(base)
            out["notes"] = (base.get("notes") or "") + "\n\n(chart LLM cancelled — lean map only)"
            out["source"] = str(base.get("source") or "deterministic")
            return out
        out = dict(base)
        out["notes"] = (base.get("notes") or "") + f"\n\n(chart LLM notes skipped: {exc})"
        out["source"] = str(base.get("source") or "deterministic")
        return out


def generate_chart(
    store: Store,
    config: AppConfig,
    *,
    use_llm: bool = True,
    cancel_check: CancelCheck | None = None,
) -> dict[str, Any]:
    if cancel_check:
        cancel_check()
    base = build_chart_from_store(store, config)
    if cancel_check:
        cancel_check()
    # Fast path: always return lean graph; optional short LLM notes
    if use_llm and base.get("nodes"):
        try:
            return enrich_chart_with_llm(base, config, timeout=90, cancel_check=cancel_check)
        except Exception as exc:
            # Cancel or timeout — still return useful lean chart
            if "Stopped" in str(exc) or exc.__class__.__name__ == "CancelledError":
                out = dict(base)
                out["notes"] = (base.get("notes") or "") + "\n\n(chart LLM cancelled — lean map only)"
                return out
            raise
    return base


def _norm_endpoint(url: str) -> str:
    u = url.split("#")[0]
    if "?" in u:
        u = u.split("?", 1)[0]
    return u.rstrip("/") or u


def _short_url(url: str) -> str:
    u = re.sub(r"^https?://", "", url)
    if len(u) > 42:
        u = u[:39] + "…"
    return u


def _strip_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()
