from __future__ import annotations

import json
import re
from typing import Any

# ```json ... ``` or bare {"name": "...", "arguments": {...}}
_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.I)


def _normalize_call(obj: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(obj, dict):
        return None

    # OpenAI-ish wrapper
    if "function" in obj and isinstance(obj["function"], dict):
        fn = obj["function"]
        name = fn.get("name")
        args = fn.get("arguments", fn.get("parameters", {}))
    else:
        name = obj.get("name") or obj.get("tool") or obj.get("tool_name")
        args = obj.get("arguments", obj.get("parameters", obj.get("args", {})))

    if not name or not isinstance(name, str):
        return None

    if isinstance(args, str):
        try:
            args = json.loads(args) if args.strip() else {}
        except json.JSONDecodeError:
            args = {"raw": args}
    if not isinstance(args, dict):
        args = {}

    return {
        "function": {
            "name": name.strip(),
            "arguments": args,
        }
    }


def _try_load(text: str) -> Any | None:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _extract_balanced(text: str, start: int) -> str | None:
    """Extract a balanced {...} or [...] JSON blob starting at start."""
    if start < 0 or start >= len(text):
        return None
    open_ch = text[start]
    close_ch = "}" if open_ch == "{" else "]" if open_ch == "[" else ""
    if not close_ch:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _iter_json_blobs(content: str) -> list[str]:
    blobs: list[str] = []
    for m in _FENCE_RE.finditer(content):
        inner = (m.group(1) or "").strip()
        if inner:
            blobs.append(inner)

    # Scan for top-level objects/arrays that look like tool calls
    i = 0
    while i < len(content):
        if content[i] in "{[":
            blob = _extract_balanced(content, i)
            if blob and ('"name"' in blob or "'name'" in blob):
                blobs.append(blob)
                i += len(blob)
                continue
        i += 1
    return blobs


def extract_tool_calls(content: str, native_calls: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Return tool_calls list from Ollama native field and/or JSON dumped in content."""
    calls: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(raw: dict[str, Any]) -> None:
        norm = _normalize_call(raw)
        if not norm:
            return
        key = json.dumps(norm, sort_keys=True)
        if key in seen:
            return
        seen.add(key)
        calls.append(norm)

    for call in native_calls or []:
        if isinstance(call, dict):
            add(call)

    if not content or not content.strip():
        return calls

    for chunk in _iter_json_blobs(content):
        data = _try_load(chunk)
        if data is None:
            continue
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    add(item)
            continue
        if isinstance(data, dict):
            if "tool_calls" in data and isinstance(data["tool_calls"], list):
                for item in data["tool_calls"]:
                    if isinstance(item, dict):
                        add(item)
                continue
            if "name" in data or "tool" in data or "function" in data:
                add(data)

    return calls


def content_without_tool_json(content: str) -> str:
    """Strip tool-call JSON/fences so leftover prose can still be shown."""
    if not content:
        return ""
    cleaned = _FENCE_RE.sub("", content)
    # Remove balanced tool-call JSON blobs
    out: list[str] = []
    i = 0
    while i < len(cleaned):
        if cleaned[i] in "{[":
            blob = _extract_balanced(cleaned, i)
            if blob and ('"name"' in blob or "'name'" in blob) and _try_load(blob) is not None:
                i += len(blob)
                continue
        out.append(cleaned[i])
        i += 1
    return "".join(out).strip()
