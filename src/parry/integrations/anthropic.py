"""Anthropic SDK integration for Parry."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from parry.guard import Guard


def anthropic_guard(guard: Guard | None = None):
    """Decorator for Anthropic SDK calls to guard input/output."""
    guard = guard or Guard()
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args, **kwargs):
            # Extract prompt/message
            prompt = kwargs.get("prompt") or (args[0] if args else "")
            report = guard.scan_input(str(prompt))
            if report.decision.action == "BLOCK":
                from parry.exceptions import GuardException
                raise GuardException(reason=report.decision.reason, threats=report.threats, action="BLOCK")
            result = fn(*args, **kwargs)
            report_out = guard.scan_output(str(result))
            if report_out.decision.action == "BLOCK":
                from parry.exceptions import GuardException
                raise GuardException(reason=report_out.decision.reason, threats=report_out.threats, action="BLOCK")
            if report_out.decision.action == "REDACT" and report_out.decision.redacted_text:
                return report_out.decision.redacted_text
            return result
        return wrapper
    return decorator
