"""Tool call inspection detector — THR-A001, THR-A003, THR-A005."""

from __future__ import annotations

import re

from parry.detectors.base import BaseDetector
from parry.models import GuardStage, Severity, ThreatResult, ThreatType

# Dangerous tool names / patterns
_DANGEROUS_TOOLS = [
    (re.compile(r"(?:exec|execute|run)[-_]?(?:shell|command|bash|cmd|code)", re.IGNORECASE), "Shell execution tool"),
    (re.compile(r"(?:os|system)[-_]?(?:command|exec)", re.IGNORECASE), "OS command tool"),
    (re.compile(r"(?:file[-_]?)?(?:write|delete|remove|rm)[-_]?(?:file)?", re.IGNORECASE), "Destructive file tool"),
    (re.compile(r"(?:send[-_]?)?(?:email|mail|smtp)", re.IGNORECASE), "Email sending tool"),
    (re.compile(r"(?:http|fetch|curl|request|download)", re.IGNORECASE), "Network access tool"),
    (re.compile(r"(?:sql|database|db)[-_]?(?:query|exec|execute)?", re.IGNORECASE), "Database tool"),
    (re.compile(r"eval", re.IGNORECASE), "Code eval tool"),
]

# Dangerous argument patterns
_DANGEROUS_ARGS = [
    (re.compile(r"(?:rm\s+-rf|del\s+/[sf]|format\s+[a-z]:)", re.IGNORECASE), "Destructive command in args"),
    (re.compile(r"(?:curl|wget)\s+.*?\|.*?(?:sh|bash)", re.IGNORECASE), "Remote code execution in args"),
    (re.compile(r"(?:chmod|chown)\s+.*?(?:777|666)", re.IGNORECASE), "Dangerous permission change"),
    (re.compile(r"/etc/(?:passwd|shadow|sudoers)", re.IGNORECASE), "Sensitive system file access"),
]


class ToolCallDetector(BaseDetector):
    def detect_indirect_injection(self, tool_result: str) -> list[ThreatResult]:
        """Scan tool result content for indirect prompt injection."""
        # Reuse prompt injection detector patterns
        from parry.detectors.prompt_injection import PromptInjectionDetector
        detector = PromptInjectionDetector()
        threats = detector.detect(tool_result)
        # Tag as INDIRECT_INJECTION
        for t in threats:
            t.threat_type = ThreatType.INDIRECT_INJECTION
            t.severity = Severity.HIGH
            t.detector = "indirect_injection"
        return threats
    """Inspects tool/function calls for injection and privilege escalation."""

    name = "tool_call"
    threat_type = ThreatType.TOOL_CALL_INJECTION
    guard_stage = GuardStage.AGENT

    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        """Detect threats in tool calls.

        Accepts kwargs:
            tool_name: Name of the tool being called
            tool_args: Arguments dict or string
            allowed_tools: List of allowed tool names
        """
        threats: list[ThreatResult] = []
        tool_name = kwargs.get("tool_name", "")
        tool_args = kwargs.get("tool_args", "")
        allowed_tools = kwargs.get("allowed_tools")

        if isinstance(tool_name, str) and tool_name:
            threats.extend(self._check_tool_name(tool_name, allowed_tools))

        if tool_args:
            args_str = str(tool_args)
            threats.extend(self._check_tool_args(args_str))

        return threats

    def _check_tool_name(
        self, tool_name: str, allowed_tools: object
    ) -> list[ThreatResult]:
        threats: list[ThreatResult] = []

        # Check allowlist
        if isinstance(allowed_tools, (list, set, tuple)) and tool_name not in allowed_tools:
            threats.append(ThreatResult(
                threat_type=ThreatType.TOOL_CALL_INJECTION,
                severity=Severity.HIGH,
                confidence=0.90,
                description=f"Tool '{tool_name}' not in allowlist",
                matched_text=tool_name,
                detector=self.name,
            ))

        # Check dangerous patterns
        for pattern, description in _DANGEROUS_TOOLS:
            if pattern.search(tool_name):
                threats.append(ThreatResult(
                    threat_type=ThreatType.PRIVILEGE_ESCALATION,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    description=f"Dangerous tool detected: {description}",
                    matched_text=tool_name,
                    detector=self.name,
                ))

        return threats

    def _check_tool_args(self, args_str: str) -> list[ThreatResult]:
        threats: list[ThreatResult] = []
        for pattern, description in _DANGEROUS_ARGS:
            match = pattern.search(args_str)
            if match:
                threats.append(ThreatResult(
                    threat_type=ThreatType.TOOL_CALL_INJECTION,
                    severity=Severity.CRITICAL,
                    confidence=0.90,
                    description=description,
                    matched_text=match.group(),
                    detector=self.name,
                ))
        return threats
