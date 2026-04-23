"""Exceptions for Parry guard operations."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from parry.models import ThreatResult


class GuardException(Exception):  # noqa: N818
    """Raised when the guard blocks a request or response.

    Attributes:
        action: The action that was taken ("BLOCK").
        threats: List of detected threats that triggered the block.
        reason: Human-readable explanation.
    """

    def __init__(
        self,
        reason: str,
        threats: list[ThreatResult] | None = None,
        action: str = "BLOCK",
    ) -> None:
        self.reason = reason
        self.threats = threats or []
        self.action = action
        super().__init__(f"[PARRY {action}] {reason}")


class RedactionError(Exception):
    """Raised when redaction fails unexpectedly."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"[PARRY REDACTION ERROR] {reason}")
