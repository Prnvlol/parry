"""LangChain integration for Parry."""

from __future__ import annotations

from typing import Any

from parry.guard import Guard


class LangChainGuard:
    """Wraps a LangChain LLM (Runnable) to guard all invocations."""

    def __init__(self, llm: Any, guard: Guard | None = None) -> None:
        self._llm = llm
        self._guard = guard or Guard()

    def invoke(self, input: Any, **kwargs) -> Any:
        """Intercepts input/output for LLM invocation."""
        # Scan input
        report = self._guard.scan_input(str(input))
        if report.decision.action == "BLOCK":
            from parry.exceptions import GuardException
            raise GuardException(reason=report.decision.reason, threats=report.threats, action="BLOCK")
        # Call LLM
        result = self._llm.invoke(input, **kwargs)
        # Scan output
        report_out = self._guard.scan_output(str(result))
        if report_out.decision.action == "BLOCK":
            from parry.exceptions import GuardException
            raise GuardException(reason=report_out.decision.reason, threats=report_out.threats, action="BLOCK")
        if report_out.decision.action == "REDACT" and report_out.decision.redacted_text:
            return report_out.decision.redacted_text
        return result

    @property
    def guard(self) -> Guard:
        return self._guard
