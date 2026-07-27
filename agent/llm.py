from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class OllamaClient:
    def __init__(self, host: str, model: str):
        self.host = host.rstrip("/")
        self.model = model

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        temperature: float = 0.2,
        timeout: int = 600,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if tools:
            payload["tools"] = tools

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Cannot reach Ollama at {self.host}. Is it running? ({exc})"
            ) from exc
        except Exception as exc:
            if "timed out" in str(exc).lower() or exc.__class__.__name__ in {"TimeoutError", "timeout"}:
                raise RuntimeError(f"Ollama timed out after {timeout}s") from exc
            raise

    def list_models(self) -> list[str]:
        req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return []
        return [m.get("name", "") for m in payload.get("models", [])]
