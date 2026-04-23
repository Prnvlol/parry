"""Agent-specific guards — tool calls, MCP boundaries, multi-agent trust."""

from __future__ import annotations

import logging
import time

from parry.detectors.mcp_boundary import MCPBoundaryDetector
from parry.detectors.tool_call import ToolCallDetector
from parry.models import (
    Action,
    GuardConfig,
    GuardDecision,
    Mode,
    ScanReport,
    Severity,
    ThreatResult,
    ThreatType,
)

logger = logging.getLogger("parry")


class AgentGuard:
    def scan_indirect_injection(self, tool_result: str) -> ScanReport:
        """Scan tool result for indirect prompt injection before passing to LLM."""
        start = time.perf_counter()
        all_threats: list[ThreatResult] = []
        if self.tool_detector:
            try:
                threats = self.tool_detector.detect_indirect_injection(tool_result)
                all_threats.extend(threats)
            except Exception:
                logger.exception("Indirect injection detector failed")
        elapsed_ms = (time.perf_counter() - start) * 1000
        decision = self._decide(all_threats, elapsed_ms)
        return ScanReport(threats=all_threats, decision=decision)
    """Validates tool calls, MCP boundaries, and multi-agent trust."""

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        self.tool_detector = ToolCallDetector() if config.agents.tool_call_inspection else None
        self.mcp_detector = MCPBoundaryDetector() if config.agents.mcp_boundary_check else None
        # Multi-agent trust enforcement: track trusted agent IDs
        self.trusted_agents = set(getattr(config.agents, "trusted_agents", []))
    def scan_multi_agent_trust(
        self,
        source_agent: str,
        dest_agent: str,
        content: str,
        trusted_agents: list[str] | None = None,
    ) -> ScanReport:
        """Enforce trust boundaries between agents.

        Args:
            source_agent: ID/name of the agent producing output
            dest_agent: ID/name of the agent consuming output
            content: The message/content being passed
            trusted_agents: Optional explicit trust list
        """
        start = time.perf_counter()
        all_threats: list[ThreatResult] = []
        trust_set = set(trusted_agents) if trusted_agents is not None else self.trusted_agents
        # Only add a threat if dest_agent is NOT trusted
        if trust_set and dest_agent not in trust_set:
            all_threats.append(
                ThreatResult(
                    threat_type=ThreatType.MULTI_AGENT_TRUST,
                    severity=Severity.HIGH,
                    confidence=0.95,
                    description=(
                        f"Untrusted agent '{dest_agent}' received output from '{source_agent}'"
                    ),
                    matched_text=dest_agent,
                    detector="multi_agent_trust",
                )
            )
        elapsed_ms = (time.perf_counter() - start) * 1000
        decision = self._decide(all_threats, elapsed_ms)
        return ScanReport(threats=all_threats, decision=decision)

    def scan_tool_call(
        self,
        tool_name: str,
        tool_args: dict | str | None = None,
    ) -> ScanReport:
        """Validate a tool call before execution."""
        start = time.perf_counter()
        all_threats: list[ThreatResult] = []

        if self.tool_detector:
            try:
                threats = self.tool_detector.detect(
                    "",
                    tool_name=tool_name,
                    tool_args=tool_args or "",
                    allowed_tools=self.config.agents.allowed_tools or None,
                )
                all_threats.extend(threats)
            except Exception:
                logger.exception("Tool call detector failed")

        elapsed_ms = (time.perf_counter() - start) * 1000
        decision = self._decide(all_threats, elapsed_ms)

        report = ScanReport(threats=all_threats, decision=decision)

        if all_threats:
            logger.warning(
                "[PARRY] AGENT  %s | %d threat(s) | %.1fms | Tool: %s",
                decision.action.value,
                len(all_threats),
                elapsed_ms,
                tool_name,
            )

        return report

    def scan_mcp_resource(
        self,
        tool_name: str,
        resource_uri: str = "",
        allowed_resources: list[str] | None = None,
    ) -> ScanReport:
        """Validate an MCP resource access."""
        start = time.perf_counter()
        all_threats: list[ThreatResult] = []

        if self.mcp_detector:
            try:
                threats = self.mcp_detector.detect(
                    "",
                    tool_name=tool_name,
                    resource_uri=resource_uri,
                    allowed_resources=allowed_resources,
                    allowed_tools=self.config.agents.allowed_tools or None,
                )
                all_threats.extend(threats)
            except Exception:
                logger.exception("MCP boundary detector failed")

        elapsed_ms = (time.perf_counter() - start) * 1000
        decision = self._decide(all_threats, elapsed_ms)
        return ScanReport(threats=all_threats, decision=decision)

    def _decide(self, threats: list[ThreatResult], elapsed_ms: float) -> GuardDecision:
        if not threats:
            return GuardDecision(action=Action.ALLOW, scan_time_ms=elapsed_ms)

        reason = f"{len(threats)} agent threat(s): {threats[0].description}"

        if self.config.mode == Mode.LOG_ONLY:
            return GuardDecision(
                action=Action.LOG, threats=threats, reason=reason, scan_time_ms=elapsed_ms
            )

        return GuardDecision(
            action=Action.BLOCK, threats=threats, reason=reason, scan_time_ms=elapsed_ms
        )
