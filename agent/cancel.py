from __future__ import annotations

import threading


class CancelledError(RuntimeError):
    """Raised when the user hits Stop."""


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def clear(self) -> None:
        self._event.clear()

    def request(self) -> None:
        self._event.set()

    @property
    def is_set(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise CancelledError("Stopped by user")
