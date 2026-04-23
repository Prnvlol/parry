"""OpenAI SDK integration for Parry."""

from __future__ import annotations

from typing import Any

from parry.guard import Guard
from parry.models import ScanReport


class OpenAIGuard:
    """Wraps an OpenAI client to guard all chat/completions calls."""

    def __init__(self, client: Any, guard: Guard | None = None) -> None:
        self._client = client
        self._guard = guard or Guard()

    def chat(self, *args, **kwargs) -> Any:
        """Wraps client.chat.completions.create with input/output guard."""
        # Try to find the completions.create method
        create_fn = None
        if hasattr(self._client, "chat") and hasattr(self._client.chat, "completions"):
            create_fn = getattr(self._client.chat.completions, "create", None)
        if not create_fn:
            raise AttributeError("OpenAI client missing chat.completions.create")
        return self._guard.wrap(create_fn)(*args, **kwargs)

    def completions(self, *args, **kwargs) -> Any:
        """Wraps client.completions.create with input/output guard."""
        create_fn = None
        if hasattr(self._client, "completions"):
            create_fn = getattr(self._client.completions, "create", None)
        if not create_fn:
            raise AttributeError("OpenAI client missing completions.create")
        return self._guard.wrap(create_fn)(*args, **kwargs)

    @property
    def guard(self) -> Guard:
        return self._guard

    def scan_input(self, text: str) -> ScanReport:
        return self._guard.scan_input(text)

    def scan_output(self, text: str) -> ScanReport:
        return self._guard.scan_output(text)
