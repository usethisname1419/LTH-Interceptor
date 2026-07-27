from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from rich.console import Console

from agent.agent import Agent
from agent.cancel import CancelToken
from agent.chart import generate_chart
from agent.config import ROOT, load_config
from agent.config_io import read_config_text, reload_app_config, save_config_text
from agent.db import Store
from agent.findings import build_report_markdown
from agent.healthcheck import run_startup_checks
from agent.playbooks import PlaybookRunner, list_playbooks
from agent.proxy import ProxyRotator
from agent.runner import CommandRunner
from agent.session import (
    SESSION_NAME,
    delete_session,
    load_session,
    save_session,
    session_info,
    session_path,
)
from agent.toolmem import ToolMemory
from agent.tools import ToolBelt
from datetime import datetime, timezone

UI_DIR = ROOT / "ui"
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "lth.db"

app = FastAPI(title="LTH-Interceptor", version="0.3.0")
console = Console()

_cfg = load_config()
_cfg.ensure_workspace()
DATA_DIR.mkdir(parents=True, exist_ok=True)
store = Store(DB_PATH)

_clients: set[WebSocket] = set()
_agent_lock = threading.Lock()
_busy = False
_last_diag: dict[str, Any] = {}
_cancel = CancelToken()
_active_runner: CommandRunner | None = None
_tool_memory = ToolMemory()
_live_messages: list[dict[str, Any]] = []
_chart_cache: dict[str, Any] | None = None
_chart_busy = False
_chart_cancel = CancelToken()


class PromptIn(BaseModel):
    text: str = Field(min_length=1)


class TodoUpdate(BaseModel):
    status: str


class PlaybookIn(BaseModel):
    name: str


class ModelIn(BaseModel):
    slot: int = Field(ge=1, le=2)


class ConfigIn(BaseModel):
    text: str
    restart: bool = False


def _apply_live_config() -> None:
    global _cfg
    _cfg = reload_app_config()
    _cfg.ensure_workspace()


def _schedule_restart() -> None:
    def _exit_soon() -> None:
        import os
        import time

        time.sleep(0.6)
        os._exit(42)

    threading.Thread(target=_exit_soon, daemon=True).start()


async def broadcast(event: dict[str, Any]) -> None:
    dead: list[WebSocket] = []
    payload = json.dumps(event, default=str)
    for ws in list(_clients):
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.discard(ws)


def emit_sync(loop: asyncio.AbstractEventLoop, event: dict[str, Any]) -> None:
    asyncio.run_coroutine_threadsafe(broadcast(event), loop)


def _begin_job() -> CancelToken:
    global _cancel
    _cancel = CancelToken()
    return _cancel


def _end_job() -> None:
    global _active_runner
    _active_runner = None


def _make_agent(loop: asyncio.AbstractEventLoop, verbose: bool = False) -> Agent:
    global _active_runner, _live_messages
    agent = Agent(
        _cfg,
        console=console,
        verbose=verbose,
        store=store,
        on_event=lambda e: emit_sync(loop, e),
        cancel=_cancel,
        memory=_tool_memory,
    )
    # Persist conversation across prompts in this UI process
    if not _live_messages:
        _live_messages = agent.messages
    else:
        agent.messages = _live_messages
    _active_runner = agent.runner
    return agent


def _session_status() -> dict[str, Any]:
    info = session_info(_cfg.root)
    turns = sum(1 for m in _live_messages if m.get("role") == "user")
    return {
        **info,
        "live_turns": turns,
        "live_messages": len(_live_messages),
    }


def _messages_for_ui(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for m in messages:
        role = str(m.get("role") or "")
        if role == "system":
            continue
        content = str(m.get("content") or "")
        if role == "tool":
            name = str(m.get("tool_name") or "tool")
            preview = content[:2000]
            out.append({"role": "tool", "content": f"* {name}\n{preview}"})
        elif role in {"user", "assistant"}:
            if content.strip():
                out.append({"role": role if role != "user" else "you", "content": content})
    return out


def _refresh_diag() -> dict[str, Any]:
    global _last_diag
    _last_diag = run_startup_checks(_cfg)
    return _last_diag


@app.on_event("startup")
def on_startup() -> None:
    console.print("[bold]LTH-Interceptor starting — running diagnostics…[/bold]")
    report = _refresh_diag()
    for line in report.get("lines") or []:
        console.print(line)
    if report.get("ok"):
        console.print("[green]Startup checks passed.[/green]")
    else:
        console.print("[yellow]Startup checks reported failures.[/yellow]")
    try:
        from agent.kali_inventory import refresh_kali_inventory

        md = refresh_kali_inventory(_cfg)
        n = md.count("\n- `") if md else 0
        console.print(f"[cyan]Kali tool inventory curated:[/cyan] {n} offensive tools cached")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Kali inventory refresh skipped:[/yellow] {exc}")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(UI_DIR / "index.html")


@app.get("/chart")
def chart_page() -> FileResponse:
    return FileResponse(
        UI_DIR / "chart.html",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "busy": _busy,
        "scope": {
            "domains": _cfg.scope.domains,
            "hosts": _cfg.scope.hosts,
        },
        "runtime": _cfg.runtime,
        "model": _cfg.active_model_name(),
        "model_slot": _cfg.model_slot,
        "models": {"1": _cfg.model_1, "2": _cfg.model_2},
        "stats": store.stats(),
        "diag_ok": bool(_last_diag.get("ok")) if _last_diag else None,
        "session": _session_status(),
    }


@app.get("/api/diagnostics")
def api_diagnostics(refresh: bool = False) -> dict[str, Any]:
    if refresh or not _last_diag:
        return _refresh_diag()
    return _last_diag


@app.get("/api/config")
def api_get_config() -> dict[str, Any]:
    try:
        text = read_config_text()
    except FileNotFoundError as exc:
        return {"ok": False, "error": str(exc), "text": ""}
    return {"ok": True, "text": text, "path": str(ROOT / "config.yaml")}


@app.post("/api/config")
async def api_save_config(body: ConfigIn) -> dict[str, Any]:
    try:
        save_config_text(body.text, backup=True)
        _apply_live_config()
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"Save failed: {exc}"}

    await broadcast(
        {
            "type": "status",
            "content": f"Config saved. Active model slot {_cfg.model_slot}: {_cfg.active_model_name()}",
        }
    )
    if body.restart:
        _schedule_restart()
        return {
            "ok": True,
            "restarting": True,
            "message": "Config saved. Restarting UI server…",
            "model_slot": _cfg.model_slot,
            "model": _cfg.active_model_name(),
        }
    return {
        "ok": True,
        "restarting": False,
        "message": "Config saved and applied (hot reload).",
        "model_slot": _cfg.model_slot,
        "model": _cfg.active_model_name(),
        "scope": {"domains": _cfg.scope.domains, "hosts": _cfg.scope.hosts},
    }


@app.post("/api/restart")
async def api_restart() -> dict[str, Any]:
    _schedule_restart()
    return {"ok": True, "message": "Restarting…"}


@app.post("/api/model")
def api_set_model(body: ModelIn) -> dict[str, Any]:
    name = _cfg.set_model_slot(body.slot)
    return {
        "ok": True,
        "model_slot": _cfg.model_slot,
        "model": name,
        "models": {"1": _cfg.model_1, "2": _cfg.model_2},
    }


@app.get("/api/findings")
def api_findings() -> list[dict[str, Any]]:
    return store.list_findings(limit=300)


@app.get("/api/findings/{finding_id}")
def api_finding(finding_id: int) -> dict[str, Any]:
    row = store.get_finding(finding_id)
    if not row:
        return {"ok": False, "error": "Finding not found"}
    meta_raw = row.get("meta_json")
    try:
        import json as _json

        meta = _json.loads(meta_raw) if meta_raw else {}
    except Exception:
        meta = {}
    row = dict(row)
    row["meta"] = meta
    return {"ok": True, "finding": row}


@app.get("/api/chart")
def api_chart_get() -> dict[str, Any]:
    if not _chart_cache:
        return {"ok": True, "chart": None, "busy": _chart_busy}
    return {"ok": True, "chart": _chart_cache, "busy": _chart_busy}


@app.post("/api/chart/cancel")
async def api_chart_cancel() -> dict[str, Any]:
    _chart_cancel.request()
    await broadcast({"type": "status", "content": "Chart generation cancel requested…"})
    return {"ok": True, "busy": _chart_busy}


@app.post("/api/chart/generate")
async def api_chart_generate(lean: bool = False) -> dict[str, Any]:
    global _chart_cache, _chart_busy, _chart_cancel
    if _chart_busy:
        return {"ok": False, "error": "Chart generation already running — press Stop"}
    _chart_busy = True
    _chart_cancel = CancelToken()

    def _cancel_check() -> None:
        _chart_cancel.check()

    try:
        await broadcast({"type": "status", "content": "Generating target chart…"})
        loop = asyncio.get_running_loop()
        chart = await loop.run_in_executor(
            None,
            lambda: generate_chart(
                store, _cfg, use_llm=not lean, cancel_check=_cancel_check
            ),
        )
        chart["generated_at"] = datetime.now(timezone.utc).isoformat()
        _chart_cache = chart
        await broadcast(
            {
                "type": "status",
                "content": f"Chart ready ({chart.get('stats', {}).get('nodes', 0)} nodes)",
            }
        )
        return {"ok": True, "chart": chart}
    except Exception as exc:  # noqa: BLE001
        from agent.cancel import CancelledError

        if isinstance(exc, CancelledError) or "Stopped" in str(exc):
            # Prefer lean chart if we already built something in cache path
            lean = generate_chart(store, _cfg, use_llm=False)
            lean["generated_at"] = datetime.now(timezone.utc).isoformat()
            lean["notes"] = (lean.get("notes") or "") + "\n\n(stopped — lean map only)"
            _chart_cache = lean
            await broadcast({"type": "status", "content": "Chart generation stopped (lean map saved)."})
            return {"ok": True, "chart": lean, "stopped": True}
        return {"ok": False, "error": str(exc)}
    finally:
        _chart_busy = False


@app.get("/api/todos")
def api_todos() -> list[dict[str, Any]]:
    return store.list_todos()


@app.post("/api/todos/{todo_id}")
def api_todo_update(todo_id: int, body: TodoUpdate) -> dict[str, Any]:
    store.set_todo_status(todo_id, body.status)
    return {"ok": True}


@app.get("/api/analysis")
def api_analysis() -> list[dict[str, Any]]:
    return store.list_analysis(limit=100)


@app.get("/api/notes")
def api_notes() -> list[dict[str, Any]]:
    rows = store.list_analysis(limit=200)
    notes = [r for r in rows if (r.get("kind") or "") == "note"]
    return notes


@app.get("/api/pocs")
def api_pocs() -> list[dict[str, Any]]:
    rows = store.list_analysis(limit=200)
    pocs = [r for r in rows if (r.get("kind") or "") == "poc"]
    # Also surface files already on disk that may predate DB recording
    try:
        poc_dir = _cfg.pocs_path
        if poc_dir.is_dir():
            known = {str(p.get("title") or "").lower() for p in pocs}
            for path in sorted(poc_dir.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True):
                if not path.is_file() or path.name.startswith("."):
                    continue
                title = path.stem
                if title.lower() in known:
                    continue
                try:
                    body = path.read_text(encoding="utf-8", errors="replace")[:12000]
                except OSError:
                    body = f"(unreadable: {path})"
                pocs.append(
                    {
                        "id": None,
                        "title": title,
                        "body": body,
                        "kind": "poc",
                        "created_at": "",
                        "path": str(path),
                    }
                )
                known.add(title.lower())
    except Exception:
        pass
    return pocs


@app.get("/api/playbooks")
def api_playbooks() -> list[dict[str, str]]:
    return list_playbooks()


@app.get("/api/playbook-runs")
def api_playbook_runs() -> list[dict[str, Any]]:
    return store.list_playbook_runs()


@app.get("/api/chat")
def api_chat() -> list[dict[str, Any]]:
    return store.list_chat(limit=300)


@app.get("/api/report.md")
def api_report_md() -> dict[str, str]:
    return {"markdown": build_report_markdown(store)}


@app.post("/api/stop")
async def api_stop() -> dict[str, Any]:
    _cancel.request()
    runner = _active_runner
    if runner is not None:
        try:
            runner.interrupt()
        except Exception:
            pass
    await broadcast({"type": "status", "content": "Stop requested…"})
    return {"ok": True, "busy": _busy}


@app.post("/api/memory/clear")
async def api_clear_memory() -> dict[str, Any]:
    _tool_memory.clear()
    await broadcast({"type": "status", "content": "Tool memory cleared — scans may run again."})
    return {"ok": True, "summary": _tool_memory.summary()}


@app.get("/api/session")
def api_session() -> dict[str, Any]:
    return {"ok": True, **_session_status()}


@app.post("/api/session/save")
async def api_session_save() -> dict[str, Any]:
    global _live_messages
    if _busy:
        return {"ok": False, "error": "Agent busy — stop first"}
    if not _live_messages:
        # bootstrap empty system session so save isn't blank
        agent = Agent(_cfg, console=console, store=store, memory=_tool_memory)
        _live_messages = agent.messages
        agent.runner.close()
    path = save_session(
        session_path(_cfg.root, SESSION_NAME),
        _live_messages,
        meta={
            "session": SESSION_NAME,
            "model": _cfg.active_model_name(),
            "turns": sum(1 for m in _live_messages if m.get("role") == "user"),
        },
        exclusive=True,
    )
    msg = f"Session saved ({sum(1 for m in _live_messages if m.get('role') == 'user')} turns). Only one slot kept."
    await broadcast({"type": "status", "content": msg})
    await broadcast({"type": "session", "action": "saved", **_session_status()})
    return {"ok": True, "path": str(path), "message": msg, **_session_status()}


@app.post("/api/session/clear")
async def api_session_clear() -> dict[str, Any]:
    global _live_messages
    if _busy:
        return {"ok": False, "error": "Agent busy — stop first"}
    _tool_memory.clear()
    wiped = store.clear_all()
    agent = Agent(_cfg, console=console, store=store, memory=_tool_memory)
    _live_messages = agent.messages
    agent.runner.close()
    msg = (
        "Cleared everything: chat, findings, todos, analysis, playbook runs, and scan memory. "
        f"(removed {wiped.get('findings', 0)} findings, {wiped.get('todos', 0)} todos)"
    )
    await broadcast({"type": "session", "action": "cleared", **_session_status(), "wiped": wiped})
    await broadcast({"type": "status", "content": msg})
    return {"ok": True, "message": msg, "wiped": wiped, **_session_status()}


@app.post("/api/session/resume")
async def api_session_resume() -> dict[str, Any]:
    global _live_messages
    if _busy:
        return {"ok": False, "error": "Agent busy — stop first"}
    path = session_path(_cfg.root, SESSION_NAME)
    try:
        messages, meta = load_session(path)
    except FileNotFoundError:
        return {"ok": False, "error": "No saved session"}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    _live_messages = messages
    # Keep tool memory — user can Reset scans if needed
    await broadcast(
        {
            "type": "session",
            "action": "resumed",
            "messages": _messages_for_ui(messages),
            **_session_status(),
        }
    )
    await broadcast(
        {
            "type": "status",
            "content": f"Resumed session ({meta.get('saved_at') or 'unknown'})",
        }
    )
    return {
        "ok": True,
        "message": "Session resumed",
        "messages": _messages_for_ui(messages),
        **_session_status(),
    }


@app.delete("/api/session")
async def api_session_delete() -> dict[str, Any]:
    if _busy:
        return {"ok": False, "error": "Agent busy — stop first"}
    deleted = delete_session(session_path(_cfg.root, SESSION_NAME))
    await broadcast({"type": "session", "action": "deleted", **_session_status()})
    return {"ok": True, "deleted": deleted, **_session_status()}


@app.post("/api/prompt")
async def api_prompt(body: PromptIn) -> dict[str, Any]:
    global _busy
    if _busy:
        return {"ok": False, "error": "Agent busy"}
    text = body.text.strip()
    loop = asyncio.get_running_loop()

    def job() -> None:
        global _busy
        with _agent_lock:
            _busy = True
            token = _begin_job()
            try:
                agent = _make_agent(loop)
                low = text.lower()
                if low.startswith("/playbook "):
                    name = text.split(maxsplit=1)[1].strip()
                    runner = CommandRunner(
                        _cfg,
                        cancel=token,
                        on_progress=lambda e: emit_sync(loop, e),
                    )
                    global _active_runner
                    _active_runner = runner
                    tools = ToolBelt(
                        _cfg,
                        runner,
                        ProxyRotator(_cfg.proxies, _cfg.proxy_rotate, _cfg.mark_dead_on_fail),
                        store=store,
                    )
                    pb = PlaybookRunner(
                        tools,
                        store,
                        emit=lambda e: emit_sync(loop, e),
                        cancel=token,
                        memory=_tool_memory,
                    )
                    pb.run(name, agent.messages)
                    runner.close()
                elif low.startswith("/model "):
                    slot = int(text.split(maxsplit=1)[1].strip())
                    name = _cfg.set_model_slot(slot)
                    emit_sync(
                        loop,
                        {
                            "type": "status",
                            "content": f"Model slot {slot}: {name}",
                        },
                    )
                else:
                    agent.run(text)
                    agent.runner.close()
            finally:
                _busy = False
                _end_job()
                emit_sync(loop, {"type": "idle"})

    await broadcast({"type": "status", "content": "Working..."})
    threading.Thread(target=job, daemon=True).start()
    return {"ok": True}


@app.post("/api/playbooks/run")
async def api_run_playbook(body: PlaybookIn) -> dict[str, Any]:
    global _busy
    if _busy:
        return {"ok": False, "error": "Agent busy"}
    loop = asyncio.get_running_loop()

    def job() -> None:
        global _busy, _active_runner
        with _agent_lock:
            _busy = True
            token = _begin_job()
            try:
                runner = CommandRunner(
                    _cfg,
                    cancel=token,
                    on_progress=lambda e: emit_sync(loop, e),
                )
                _active_runner = runner
                tools = ToolBelt(
                    _cfg,
                    runner,
                    ProxyRotator(_cfg.proxies, _cfg.proxy_rotate, _cfg.mark_dead_on_fail),
                    store=store,
                )
                pb = PlaybookRunner(
                    tools,
                    store,
                    emit=lambda e: emit_sync(loop, e),
                    cancel=token,
                    memory=_tool_memory,
                )
                pb.run(body.name)
                runner.close()
            finally:
                _busy = False
                _end_job()
                emit_sync(loop, {"type": "idle"})

    await broadcast({"type": "playbook_queued", "name": body.name})
    threading.Thread(target=job, daemon=True).start()
    return {"ok": True}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    _clients.add(ws)
    await ws.send_text(
        json.dumps(
            {
                "type": "hello",
                "stats": store.stats(),
                "model_slot": _cfg.model_slot,
                "model": _cfg.active_model_name(),
                "diag": _last_diag,
            },
            default=str,
        )
    )
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _clients.discard(ws)


if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")


def main() -> None:
    import uvicorn

    uvicorn.run(
        "server.app:app",
        host="127.0.0.1",
        port=8787,
        reload=False,
    )


if __name__ == "__main__":
    main()
