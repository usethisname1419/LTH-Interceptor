from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """SQLite store for findings, todos, analysis, playbook runs, chat events."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    host TEXT,
                    url TEXT,
                    title TEXT NOT NULL,
                    detail TEXT,
                    evidence TEXT,
                    source_tool TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    meta_json TEXT
                );

                CREATE TABLE IF NOT EXISTS todos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    priority INTEGER NOT NULL DEFAULT 3,
                    related_finding_id INTEGER,
                    playbook TEXT
                );

                CREATE TABLE IF NOT EXISTS analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    kind TEXT NOT NULL DEFAULT 'note'
                );

                CREATE TABLE IF NOT EXISTS playbook_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    finished_at TEXT,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running',
                    summary TEXT,
                    log_json TEXT
                );

                CREATE TABLE IF NOT EXISTS chat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    meta_json TEXT
                );
                """
            )

    # --- findings ---
    def add_finding(
        self,
        *,
        kind: str,
        title: str,
        severity: str = "info",
        host: str | None = None,
        url: str | None = None,
        detail: str | None = None,
        evidence: str | None = None,
        source_tool: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> int:
        now = _utc()
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO findings
                (created_at, updated_at, kind, severity, host, url, title, detail, evidence, source_tool, status, meta_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
                """,
                (
                    now,
                    now,
                    kind,
                    severity,
                    host,
                    url,
                    title,
                    detail,
                    evidence,
                    source_tool,
                    json.dumps(meta or {}),
                ),
            )
            return int(cur.lastrowid)

    def list_findings(self, status: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE status=? ORDER BY id DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM findings ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def update_finding_status(self, finding_id: int, status: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE findings SET status=?, updated_at=? WHERE id=?",
                (status, _utc(), finding_id),
            )

    # --- todos ---
    def add_todo(
        self,
        title: str,
        *,
        detail: str | None = None,
        priority: int = 3,
        related_finding_id: int | None = None,
        playbook: str | None = None,
    ) -> int:
        """Insert todo, or refresh an existing open todo with the same title (no spam)."""
        now = _utc()
        title = " ".join((title or "").strip().split())
        if not title:
            return 0
        # Normalize for dedupe: case-insensitive exact match on open todos
        title_key = title.lower()
        with self._lock, self._conn() as conn:
            existing = conn.execute(
                """
                SELECT id, title FROM todos
                WHERE status IN ('pending','doing')
                ORDER BY id DESC
                """
            ).fetchall()
            match_id = None
            for row in existing:
                if (row["title"] or "").strip().lower() == title_key:
                    match_id = int(row["id"])
                    break
            if match_id is not None:
                conn.execute(
                    """
                    UPDATE todos SET updated_at=?, detail=COALESCE(?, detail),
                      priority=CASE WHEN ? < priority THEN ? ELSE priority END,
                      playbook=COALESCE(?, playbook),
                      related_finding_id=COALESCE(?, related_finding_id)
                    WHERE id=?
                    """,
                    (now, detail, priority, priority, playbook, related_finding_id, match_id),
                )
                return match_id
            cur = conn.execute(
                """
                INSERT INTO todos (created_at, updated_at, title, detail, status, priority, related_finding_id, playbook)
                VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
                """,
                (now, now, title, detail, priority, related_finding_id, playbook),
            )
            return int(cur.lastrowid)

    def complete_todos_matching(self, *, playbook: str | None = None, title_contains: str | None = None) -> int:
        now = _utc()
        with self._lock, self._conn() as conn:
            if playbook:
                cur = conn.execute(
                    "UPDATE todos SET status='done', updated_at=? WHERE playbook=? AND status IN ('pending','doing')",
                    (now, playbook),
                )
                return int(cur.rowcount or 0)
            if title_contains:
                cur = conn.execute(
                    "UPDATE todos SET status='done', updated_at=? WHERE title LIKE ? AND status IN ('pending','doing')",
                    (now, f"%{title_contains}%"),
                )
                return int(cur.rowcount or 0)
        return 0

    def list_todos(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM todos WHERE status=? ORDER BY priority ASC, id DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM todos ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'doing' THEN 1 ELSE 2 END, priority ASC, id DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def set_todo_status(self, todo_id: int, status: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE todos SET status=?, updated_at=? WHERE id=?",
                (status, _utc(), todo_id),
            )

    def mark_todos_for_tool(self, tool_name: str, args: dict[str, Any] | None = None) -> int:
        """Complete open todos that this tool advances; avoid endless pending stacks."""
        args = args or {}
        now = _utc()
        complete_map: dict[str, list[str]] = {
            "httpx_probe": ["Probe discovered subdomains", "HTTP probe"],
            "dir_fuzz": ["Fuzz live HTTP", "Review fuzz discoveries"],
            "param_fuzz": ["Fuzz live HTTP", "Review fuzz discoveries", "param"],
            "nuclei_scan": ["Fuzz live HTTP", "nuclei"],
            "inspect_page": ["Test discovered API/frontend endpoints"],
            "inspect_js": ["Test discovered API/frontend endpoints"],
            "playwright_browse": ["Test discovered API/frontend endpoints", "browser"],
            "xss_reflect_check": ["Confirm XSS"],
            "crawl_urls": ["map the site", "crawl"],
            "save_poc": ["Confirm XSS", "craft PoC"],
        }
        needles = list(complete_map.get(tool_name, []))
        # Nuclei validation todos: complete when save_poc or when re-checking same template phrase
        if tool_name == "save_note":
            needles.append("Validate nuclei hit")
        done = 0
        with self._lock, self._conn() as conn:
            for needle in needles:
                cur = conn.execute(
                    """
                    UPDATE todos SET status='done', updated_at=?
                    WHERE status IN ('pending','doing') AND lower(title) LIKE lower(?)
                    """,
                    (now, f"%{needle}%"),
                )
                done += int(cur.rowcount or 0)
            target = str(args.get("target") or "")
            if tool_name == "nmap_scan" and target:
                cur = conn.execute(
                    """
                    UPDATE todos SET status='done', updated_at=?
                    WHERE status IN ('pending','doing') AND title LIKE ?
                    """,
                    (now, f"%interesting services on {target}%"),
                )
                done += int(cur.rowcount or 0)
            # Cap open pending stack: auto-done oldest low-priority dupes over limit
            open_rows = conn.execute(
                "SELECT id FROM todos WHERE status IN ('pending','doing') ORDER BY priority ASC, id ASC"
            ).fetchall()
            if len(open_rows) > 25:
                for row in open_rows[25:]:
                    conn.execute(
                        "UPDATE todos SET status='done', updated_at=? WHERE id=?",
                        (now, int(row["id"])),
                    )
                    done += 1
        return done

    # --- analysis ---
    def add_analysis(self, title: str, body: str, kind: str = "note") -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO analysis (created_at, title, body, kind) VALUES (?, ?, ?, ?)",
                (_utc(), title, body, kind),
            )
            return int(cur.lastrowid)

    def list_analysis(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM analysis ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # --- playbooks ---
    def start_playbook(self, name: str) -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO playbook_runs (created_at, name, status, log_json) VALUES (?, ?, 'running', ?)",
                (_utc(), name, "[]"),
            )
            return int(cur.lastrowid)

    def finish_playbook(self, run_id: int, status: str, summary: str, log: list[Any]) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE playbook_runs SET finished_at=?, status=?, summary=?, log_json=? WHERE id=?",
                (_utc(), status, summary, json.dumps(log), run_id),
            )

    def list_playbook_runs(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM playbook_runs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # --- chat ---
    def add_chat(self, role: str, content: str, meta: dict[str, Any] | None = None) -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO chat_events (created_at, role, content, meta_json) VALUES (?, ?, ?, ?)",
                (_utc(), role, content, json.dumps(meta or {})),
            )
            return int(cur.lastrowid)

    def list_chat(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM (SELECT * FROM chat_events ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock, self._conn() as conn:
            findings = conn.execute("SELECT COUNT(*) AS c FROM findings WHERE status='open'").fetchone()["c"]
            todos = conn.execute("SELECT COUNT(*) AS c FROM todos WHERE status IN ('pending','doing')").fetchone()["c"]
            crit = conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE severity IN ('critical','high') AND status='open'"
            ).fetchone()["c"]
        return {"open_findings": findings, "open_todos": todos, "high_or_critical": crit}

    def clear_all(self) -> dict[str, int]:
        """Wipe findings, todos, analysis, playbook runs, and chat events."""
        tables = ("findings", "todos", "analysis", "playbook_runs", "chat_events")
        counts: dict[str, int] = {}
        with self._lock, self._conn() as conn:
            for table in tables:
                row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
                counts[table] = int(row["c"])
                conn.execute(f"DELETE FROM {table}")
            try:
                conn.execute(
                    "DELETE FROM sqlite_sequence WHERE name IN (?, ?, ?, ?, ?)",
                    tables,
                )
            except sqlite3.OperationalError:
                pass
        return counts
