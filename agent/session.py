from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SESSION_NAME = "current"


def sessions_dir(root: Path) -> Path:
    return root / "sessions"


def session_path(root: Path, name: str = SESSION_NAME) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in name).strip("-") or SESSION_NAME
    return sessions_dir(root) / f"{safe}.json"


def save_session(
    path: Path,
    messages: list[dict[str, Any]],
    *,
    meta: dict[str, Any] | None = None,
    exclusive: bool = True,
) -> Path:
    """Save session. If exclusive=True, delete any other session files (max 1)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "meta": meta or {},
        "messages": messages,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    if exclusive:
        for other in path.parent.glob("*.json"):
            if other.resolve() != path.resolve():
                try:
                    other.unlink()
                except OSError:
                    pass
    return path


def load_session(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"No saved session at {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    messages = data.get("messages") or []
    if not isinstance(messages, list) or not messages:
        raise ValueError("Saved session is empty or invalid")
    meta = data.get("meta") or {}
    meta["saved_at"] = data.get("saved_at")
    return messages, meta


def session_exists(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def delete_session(path: Path) -> bool:
    if path.exists():
        path.unlink()
        return True
    return False


def session_info(root: Path) -> dict[str, Any]:
    path = session_path(root, SESSION_NAME)
    if not session_exists(path):
        return {"exists": False, "path": str(path), "saved_at": None, "turns": 0}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        messages = data.get("messages") or []
        turns = sum(1 for m in messages if isinstance(m, dict) and m.get("role") == "user")
        return {
            "exists": True,
            "path": str(path),
            "saved_at": data.get("saved_at"),
            "turns": turns,
            "meta": data.get("meta") or {},
        }
    except Exception as exc:
        return {"exists": False, "path": str(path), "error": str(exc), "turns": 0}
