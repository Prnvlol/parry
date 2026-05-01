"""Main Guard class — entry point for Parry."""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from parry.agent_guard import AgentGuard
from parry.config import load_config
from parry.exceptions import GuardException
from parry.input_guard import InputGuard
from parry.models import Action, GuardConfig, GuardStats, Mode, ScanReport
from parry.output_guard import OutputGuard

logger = logging.getLogger("parry")

F = TypeVar("F", bound=Callable[..., Any])


class Guard:
    """Runtime security guardrail for AI agents.

    Usage::

        guard = Guard()

        # Wrap any LLM call
        response = guard.wrap(client.chat.completions.create)(
            model="gpt-4o",
            messages=[{"role": "user", "content": user_input}]
        )

        # Or use as decorator
        @guard.intercept
        def call_llm(prompt):
            return client.chat(prompt)

        # Or scan directly
        report = guard.scan_input(user_input)
        report = guard.scan_output(response_text)
    """

    def __init__(
        self,
        config: str | Path | GuardConfig | None = None,
        mode: str | Mode | None = None,
        system_prompt: str | None = None,
        on_threat: Callable[[ScanReport], None] | None = None,
        **kwargs: Any,
    ) -> None:
        # Load configuration
        overrides: dict[str, Any] = {**kwargs}
        if mode is not None:
            overrides["mode"] = mode
        if system_prompt is not None:
            overrides["system_prompt"] = system_prompt

        if isinstance(config, GuardConfig):
            self._config = config
        elif isinstance(config, (str, Path)):
            self._config = load_config(config_path=config, **overrides)
        else:
            self._config = load_config(**overrides)

        # Initialize guard pipelines
        self._input_guard = InputGuard(self._config)
        self._output_guard = OutputGuard(self._config)
        self._agent_guard = AgentGuard(self._config)

        # Observability
        self._stats = GuardStats()
        self._on_threat: Callable[[ScanReport], None] | None = on_threat

    @property
    def config(self) -> GuardConfig:
        return self._config

    def stats(self) -> GuardStats:
        """Return cumulative scan statistics since this Guard was initialised."""
        return self._stats

    def add_threat_callback(self, fn: Callable[[ScanReport], None]) -> None:
        """Register a callback to be called whenever threats are detected.

        The callback receives the full ``ScanReport``. Use this to forward
        threat data to Sentry, Datadog, Slack, or any other sink::

            def alert_slack(report: ScanReport) -> None:
                requests.post(WEBHOOK, json=report.to_dict())

            guard.add_threat_callback(alert_slack)
        """
        self._on_threat = fn

    def _record(self, report: ScanReport) -> None:
        """Update stats and fire the on_threat callback if threats were found."""
        self._stats.record(report)
        if report.threats and self._on_threat is not None:
            try:
                self._on_threat(report)
            except Exception:
                logger.exception("on_threat callback raised an exception")

    # ------------------------------------------------------------------
    # Direct scanning API
    # ------------------------------------------------------------------

    def scan_input(self, text: str) -> ScanReport:
        """Scan input text for threats. Returns a ScanReport."""
        report = self._input_guard.scan(text)
        self._record(report)
        return report

    def scan_output(self, text: str) -> ScanReport:
        """Scan output text for threats. Returns a ScanReport."""
        report = self._output_guard.scan(text)
        self._record(report)
        return report

    def scan_tool_call(
        self,
        tool_name: str,
        tool_args: dict | str | None = None,
    ) -> ScanReport:
        """Validate a tool call before execution. Returns a ScanReport."""
        report = self._agent_guard.scan_tool_call(tool_name, tool_args)
        self._record(report)
        return report

    # ------------------------------------------------------------------
    # Wrapper API
    # ------------------------------------------------------------------

    def wrap(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap an LLM call with input/output guards.

        Usage::

            response = guard.wrap(client.chat.completions.create)(
                model="gpt-4o",
                messages=[{"role": "user", "content": user_input}]
            )
        """

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # --- Input guard ---
            input_text = self._extract_input(args, kwargs)
            if input_text:
                report = self._input_guard.scan(input_text)
                self._record(report)
                if report.decision.action == Action.BLOCK:
                    raise GuardException(
                        reason=report.decision.reason,
                        threats=report.threats,
                    )

            # --- Call the LLM ---
            result = fn(*args, **kwargs)

            # --- Output guard ---
            output_text = self._extract_output(result)
            if output_text:
                report = self._output_guard.scan(output_text)
                self._record(report)
                if report.decision.action == Action.BLOCK:
                    raise GuardException(
                        reason=report.decision.reason,
                        threats=report.threats,
                    )
                if report.decision.action == Action.REDACT and report.decision.redacted_text:
                    result = self._replace_output(result, report.decision.redacted_text)

            return result

        return wrapper

    def intercept(self, fn: F) -> F:
        """Decorator to guard an LLM-calling function.

        Usage::

            @guard.intercept
            def call_llm(prompt):
                return client.chat(prompt)
        """
        wrapped = self.wrap(fn)
        return wrapped  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Message extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_input(args: tuple, kwargs: dict) -> str | None:  # type: ignore[type-arg]
        """Extract user message text from LLM call arguments."""
        messages = kwargs.get("messages")
        if isinstance(messages, list):
            user_messages = [
                m.get("content", "") if isinstance(m, dict) else ""
                for m in messages
                if isinstance(m, dict) and m.get("role") == "user"
            ]
            if user_messages:
                return " ".join(str(m) for m in user_messages if m)

        # Check for a simple prompt string
        prompt = kwargs.get("prompt") or kwargs.get("input")
        if isinstance(prompt, str):
            return prompt

        # Check first positional arg
        if args and isinstance(args[0], str):
            return args[0]

        return None

    @staticmethod
    def _extract_output(result: Any) -> str | None:
        """Extract text from an LLM response object."""
        if isinstance(result, str):
            return result

        # OpenAI-style response
        if hasattr(result, "choices"):
            try:
                choices = result.choices
                if choices and hasattr(choices[0], "message"):
                    content = choices[0].message.content
                    if isinstance(content, str):
                        return content
            except (IndexError, AttributeError):
                pass

        # Anthropic-style response
        if hasattr(result, "content"):
            content = result.content
            if isinstance(content, list):
                texts = [b.text for b in content if hasattr(b, "text")]
                return " ".join(texts) if texts else None
            if isinstance(content, str):
                return content

        # Dict response
        if isinstance(result, dict):
            return result.get("content") or result.get("text") or result.get("output")

        return None

    @staticmethod
    def _replace_output(result: Any, redacted_text: str) -> Any:
        """Replace the text content in an LLM response with redacted version."""
        if isinstance(result, str):
            return redacted_text

        if isinstance(result, dict):
            for key in ("content", "text", "output"):
                if key in result:
                    result[key] = redacted_text
                    return result

        # For SDK objects, we can't easily mutate — return the original
        # (the threat was logged regardless)
        return result
