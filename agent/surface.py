from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse


SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("google_api", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "medium"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "medium"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "critical"),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "high"),
    ("generic_secret", re.compile(r"(?i)(api[_-]?key|auth[_-]?token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "medium"),
]

SINK_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("innerHTML", re.compile(r"\.innerHTML\s*="), "medium"),
    ("outerHTML", re.compile(r"\.outerHTML\s*="), "medium"),
    ("document_write", re.compile(r"document\.write\s*\("), "medium"),
    ("eval", re.compile(r"\beval\s*\("), "high"),
    ("new_function", re.compile(r"\bnew\s+Function\s*\("), "high"),
    ("location_href", re.compile(r"location\.(href|hash)\s*="), "low"),
    ("postmessage", re.compile(r"addEventListener\(\s*['\"]message['\"]"), "info"),
    ("localStorage", re.compile(r"localStorage\.(setItem|getItem)"), "info"),
]

ENDPOINT_RES = [
    re.compile(r"""(?i)['"`](https?://[^'"`\s]+)['"`]"""),
    re.compile(r"""(?i)['"`](/api/[^'"`\s]+)['"`]"""),
    re.compile(r"""(?i)['"`](/v[0-9]+/[^'"`\s]+)['"`]"""),
    re.compile(r"""(?i)['"`](/graphql[^'"`\s]*)['"`]"""),
    re.compile(r"""(?i)fetch\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""(?i)axios\.[a-z]+\(\s*['"`]([^'"`]+)['"`]"""),
    re.compile(r"""(?i)\.ajax\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]"""),
]


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] = []
        self._in_title = False
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.comments: list[str] = []
        self.meta: list[dict[str, str]] = []
        self.inputs: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "a" and ad.get("href"):
            self.links.append(ad["href"])
        elif tag == "script" and ad.get("src"):
            self.scripts.append(ad["src"])
        elif tag == "form":
            self._current_form = {
                "action": ad.get("action", ""),
                "method": (ad.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select"}:
            item = {
                "tag": tag,
                "type": ad.get("type", "text"),
                "name": ad.get("name", ""),
                "id": ad.get("id", ""),
            }
            self.inputs.append(item)
            if self._current_form is not None:
                self._current_form["inputs"].append(item)
        elif tag == "meta":
            self.meta.append({"name": ad.get("name") or ad.get("property") or "", "content": ad.get("content", "")})

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data.strip())

    def handle_comment(self, data: str) -> None:
        c = data.strip()
        if c:
            self.comments.append(c[:300])


def analyze_html(html: str, base_url: str) -> dict[str, Any]:
    parser = _PageParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass

    def abs_url(u: str) -> str:
        try:
            return urljoin(base_url, u)
        except Exception:
            return u

    scripts = [abs_url(s) for s in parser.scripts][:40]
    links = []
    for href in parser.links:
        full = abs_url(href)
        if full.startswith("http"):
            links.append(full)
    links = sorted(set(links))[:80]

    findings: list[dict[str, Any]] = []
    # forms without obvious csrf token
    for form in parser.forms:
        names = {(i.get("name") or "").lower() for i in form.get("inputs", [])}
        if form.get("method") == "post" and not any("csrf" in n or "token" in n for n in names):
            findings.append(
                {
                    "kind": "csrf_candidate",
                    "severity": "low",
                    "title": f"POST form may lack CSRF token: {form.get('action') or base_url}",
                    "detail": json.dumps(form)[:500],
                }
            )

    # password fields over http
    if base_url.startswith("http://"):
        if any(i.get("type") == "password" for i in parser.inputs):
            findings.append(
                {
                    "kind": "cleartext_password",
                    "severity": "high",
                    "title": "Password field served over HTTP",
                    "detail": base_url,
                }
            )

    # HTML comments with interesting keywords
    for c in parser.comments:
        if re.search(r"(?i)todo|password|api[_-]?key|secret|admin|debug|bypass", c):
            findings.append(
                {
                    "kind": "html_comment",
                    "severity": "info",
                    "title": "Interesting HTML comment",
                    "detail": c[:240],
                }
            )

    secrets = scan_secrets(html)
    sinks = scan_sinks(html)
    endpoints = extract_endpoints(html, base_url)

    return {
        "url": base_url,
        "title": " ".join(parser.title_parts).strip()[:200],
        "forms": parser.forms[:20],
        "inputs": parser.inputs[:40],
        "script_srcs": scripts,
        "links": links,
        "meta": parser.meta[:20],
        "comments": parser.comments[:15],
        "endpoints": endpoints[:60],
        "secrets": secrets,
        "dom_sinks": sinks,
        "findings": findings + secrets + sinks,
    }


def analyze_js(js: str, source_url: str) -> dict[str, Any]:
    secrets = scan_secrets(js)
    sinks = scan_sinks(js)
    endpoints = extract_endpoints(js, source_url)
    findings = secrets + sinks
    # hardcoded admin paths
    for m in re.finditer(r"""(?i)['"`](/(?:admin|internal|debug|manage)[^'"`]*)['"`]""", js or ""):
        findings.append(
            {
                "kind": "sensitive_path",
                "severity": "info",
                "title": f"Sensitive path in JS: {m.group(1)}",
                "detail": source_url,
            }
        )
    return {
        "url": source_url,
        "size": len(js or ""),
        "endpoints": endpoints[:80],
        "secrets": secrets,
        "dom_sinks": sinks,
        "findings": findings,
        "excerpt": (js or "")[:1500],
    }


def scan_secrets(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for kind, rx, sev in SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            val = m.group(0)
            # redact middle
            red = val[:6] + "…" + val[-4:] if len(val) > 12 else val
            out.append(
                {
                    "kind": f"secret:{kind}",
                    "severity": sev,
                    "title": f"Possible secret ({kind})",
                    "detail": red,
                }
            )
            if len(out) >= 20:
                return out
    return out


def scan_sinks(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for kind, rx, sev in SINK_PATTERNS:
        if rx.search(text or ""):
            out.append(
                {
                    "kind": f"sink:{kind}",
                    "severity": sev,
                    "title": f"JS sink detected: {kind}",
                    "detail": f"Pattern {rx.pattern} present in asset",
                }
            )
    return out


def extract_endpoints(text: str, base_url: str) -> list[str]:
    found: list[str] = []
    for rx in ENDPOINT_RES:
        for m in rx.finditer(text or ""):
            u = m.group(1)
            if u.startswith("http") or u.startswith("/"):
                try:
                    full = urljoin(base_url, u)
                except Exception:
                    full = u
                if full not in found:
                    found.append(full)
    return found


def same_site(url: str, scope_hosts: list[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    for s in scope_hosts:
        s = s.lower()
        if host == s or host.endswith("." + s):
            return True
    return False
