from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .cancel import CancelToken, CancelledError
from .db import Store
from .findings import build_report_markdown, ingest_tool_result
from .intent import collect_session_hosts
from .toolmem import ToolMemory
from .tools import ToolBelt


EmitFn = Callable[[dict[str, Any]], None]


@dataclass
class Playbook:
    name: str
    title: str
    description: str


PLAYBOOKS: list[Playbook] = [
    Playbook("recon", "Recon", "Subdomains + HTTP probe + nmap ports + light surface"),
    Playbook("surface", "Surface Map", "Crawl + inspect HTML/JS for endpoints, sinks, secrets"),
    Playbook("web-bounty", "Web Bounty", "Live hosts → surface map → nuclei → fuzz → XSS"),
    Playbook("ports", "Port Sweep", "Common-port nmap on scope roots / known hosts"),
    Playbook("report", "Generate Report", "Compile findings DB into markdown report"),
]


def list_playbooks() -> list[dict[str, str]]:
    return [{"name": p.name, "title": p.title, "description": p.description} for p in PLAYBOOKS]


class PlaybookRunner:
    def __init__(
        self,
        tools: ToolBelt,
        store: Store,
        emit: EmitFn | None = None,
        cancel: CancelToken | None = None,
        memory: ToolMemory | None = None,
    ):
        self.tools = tools
        self.store = store
        self.emit = emit or (lambda _e: None)
        self.cancel = cancel or CancelToken()
        self.memory = memory or ToolMemory()

    def _run_tool(self, name: str, args: dict[str, Any], log: list[dict[str, Any]]) -> str:
        self.cancel.check()
        filtered, skip_reason = self.memory.filter_call(name, args)
        if skip_reason:
            msg = f"SKIPPED: {skip_reason}"
            self.emit({"type": "tool_start", "tool": name, "args": args, "skipped": True})
            self.emit({"type": "tool_result", "tool": name, "preview": msg})
            log.append({"tool": name, "args": args, "preview": msg})
            return msg
        args = filtered or args
        self.emit({"type": "tool_start", "tool": name, "args": args})
        result = self.tools.dispatch(name, args)
        self.memory.record(name, args)
        ingest_tool_result(self.store, name, result, args)
        entry = {"tool": name, "args": args, "preview": result[:1500]}
        log.append(entry)
        self.emit({"type": "tool_result", "tool": name, "preview": result[:2000]})
        return result

    def run(self, name: str, messages: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        messages = messages or []
        hosts = collect_session_hosts(messages, self.tools.config.scope)
        if not hosts and self.tools.config.scope.domains:
            hosts = list(self.tools.config.scope.domains)

        run_id = self.store.start_playbook(name)
        self.store.add_todo(f"Playbook running: {name}", priority=2, playbook=name)
        log: list[dict[str, Any]] = []
        self.emit({"type": "playbook_start", "name": name, "run_id": run_id, "hosts": hosts})

        try:
            if name == "recon":
                summary = self._recon(hosts, log)
            elif name == "surface":
                summary = self._surface(hosts, log)
            elif name == "web-bounty":
                summary = self._web_bounty(hosts, log)
            elif name == "ports":
                summary = self._ports(hosts, log)
            elif name == "report":
                summary = self._report(log)
            else:
                raise ValueError(f"Unknown playbook: {name}")
            self.store.finish_playbook(run_id, "done", summary, log)
            self.store.add_analysis(f"Playbook {name} complete", summary, kind="playbook")
            self.store.complete_todos_matching(playbook=name)
            self.store.complete_todos_matching(title_contains=f"Playbook running: {name}")
            self.emit({"type": "playbook_done", "name": name, "summary": summary})
            return {"ok": True, "run_id": run_id, "summary": summary, "log": log}
        except CancelledError:
            summary = "Stopped by user."
            self.store.finish_playbook(run_id, "stopped", summary, log)
            self.emit({"type": "playbook_done", "name": name, "summary": summary})
            return {"ok": False, "run_id": run_id, "error": summary, "log": log, "stopped": True}
        except Exception as exc:
            self.store.finish_playbook(run_id, "error", str(exc), log)
            self.emit({"type": "playbook_error", "name": name, "error": str(exc)})
            return {"ok": False, "run_id": run_id, "error": str(exc), "log": log}

    def _recon(self, hosts: list[str], log: list[dict[str, Any]]) -> str:
        root = hosts[0] if hosts else None
        if not root:
            return "No in-scope hosts configured."
        self._run_tool("subdomain_enum", {"domain": root}, log)
        # refresh hosts from DB findings
        found = [f["host"] for f in self.store.list_findings() if f.get("kind") == "host" and f.get("host")]
        targets = sorted(set(found or hosts))[:12]
        self._run_tool("httpx_probe", {"targets": ",".join(targets)}, log)

        # Port scan is core recon — root first (common ports), then live HTTP hosts
        self._run_tool("nmap_scan", {"target": root}, log)
        live = []
        for f in self.store.list_findings():
            if f.get("kind") == "http" and f.get("host"):
                h = f["host"]
                if h not in live and h != root:
                    live.append(h)
        for h in live[:5]:
            self._run_tool("nmap_scan", {"target": h}, log)

        # Light surface pass on root
        self._run_tool("crawl_urls", {"url": f"https://{root}", "depth": 2}, log)
        self._run_tool("inspect_page", {"url": f"https://{root}", "follow_js": True, "max_scripts": 6}, log)
        nmap_hosts = 1 + min(len(live), 5)
        return (
            f"Recon complete on {root}. Hosts probed: {len(targets)}. "
            f"nmap on {nmap_hosts} host(s)."
        )

    def _surface(self, hosts: list[str], log: list[dict[str, Any]]) -> str:
        http = [f for f in self.store.list_findings() if f.get("kind") == "http" and f.get("url")]
        urls = []
        for f in http:
            u = f.get("url")
            if u and u not in urls:
                urls.append(u)
        if not urls:
            for h in (hosts or self.tools.config.scope.domains)[:5]:
                urls.append(f"https://{h}")
        urls = urls[:5]
        for u in urls:
            self._run_tool("crawl_urls", {"url": u, "depth": 2}, log)
            self._run_tool("inspect_page", {"url": u, "follow_js": True, "max_scripts": 8}, log)
        return f"Surface map finished for {len(urls)} URLs (HTML/JS inspected)."

    def _web_bounty(self, hosts: list[str], log: list[dict[str, Any]]) -> str:
        if not hosts:
            return "No hosts available. Run recon first."
        # Prefer HTTP findings as live targets
        http = [f for f in self.store.list_findings() if f.get("kind") == "http" and f.get("url")]
        live_hosts = []
        for f in http:
            h = f.get("host")
            if h and h not in live_hosts:
                live_hosts.append(h)
        if not live_hosts:
            self._run_tool("httpx_probe", {"targets": ",".join(hosts[:10])}, log)
            http = [f for f in self.store.list_findings() if f.get("kind") == "http" and f.get("url")]
            for f in http:
                h = f.get("host")
                if h and h not in live_hosts:
                    live_hosts.append(h)
        live_hosts = live_hosts[:6] or hosts[:4]

        # Agent-style surface understanding before scanners
        for h in live_hosts[:3]:
            self._run_tool("crawl_urls", {"url": f"https://{h}", "depth": 2}, log)
            self._run_tool(
                "inspect_page",
                {"url": f"https://{h}", "follow_js": True, "max_scripts": 8},
                log,
            )

        # Single nuclei pass on primary host (full template coverage — don't loop)
        self._run_tool(
            "nuclei_scan",
            {"target": f"https://{live_hosts[0]}", "severity": "medium,high,critical"},
            log,
        )
        for h in live_hosts[:4]:
            self._run_tool("dir_fuzz", {"url": f"https://{h}/FUZZ", "threads": 20}, log)
        for h in live_hosts[:3]:
            self._run_tool("param_fuzz", {"url": f"https://{h}/?FUZZ=test", "method": "GET"}, log)
            self._run_tool("xss_reflect_check", {"url": f"https://{h}/?q={{XSS}}"}, log)

        md = build_report_markdown(self.store)
        path = self.tools.config.reports_path / "web-bounty-auto.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(md, encoding="utf-8")
        self.store.add_finding(
            kind="report",
            severity="info",
            title="Web bounty auto-report written",
            detail=str(path),
            source_tool="playbook:web-bounty",
        )
        return f"Web bounty playbook finished for {len(live_hosts)} hosts. Report: {path}"

    def _ports(self, hosts: list[str], log: list[dict[str, Any]]) -> str:
        targets = hosts[:8] or self.tools.config.scope.domains
        for h in targets:
            self._run_tool("nmap_scan", {"target": h}, log)
        return f"Port sweep finished for {len(targets)} hosts."

    def _report(self, log: list[dict[str, Any]]) -> str:
        md = build_report_markdown(self.store)
        result = self.tools.dispatch(
            "save_report",
            {"title": "Engagement Report", "markdown": md, "filename": "engagement-report"},
        )
        log.append({"tool": "save_report", "preview": result})
        self.emit({"type": "tool_result", "tool": "save_report", "preview": result})
        return result
