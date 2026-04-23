"""MCP boundary violation detector — THR-A002."""

from __future__ import annotations

from parry.detectors.base import BaseDetector
from parry.models import GuardStage, Severity, ThreatResult, ThreatType


class MCPBoundaryDetector(BaseDetector):
    """Validates MCP tool calls against configured scope boundaries."""

    name = "mcp_boundary"
    threat_type = ThreatType.MCP_BOUNDARY_VIOLATION
    guard_stage = GuardStage.AGENT

    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        """Detect MCP boundary violations.

        Accepts kwargs:
            tool_name: MCP tool being called
            resource_uri: Resource being accessed
            allowed_resources: List of allowed resource URI patterns
            allowed_tools: List of allowed MCP tools
        """
        threats: list[ThreatResult] = []
        tool_name = kwargs.get("tool_name", "")
        resource_uri = kwargs.get("resource_uri", "")
        allowed_resources = kwargs.get("allowed_resources")
        allowed_tools = kwargs.get("allowed_tools")

        if isinstance(tool_name, str) and tool_name and isinstance(allowed_tools, (list, set, tuple)):
            if tool_name not in allowed_tools:
                threats.append(ThreatResult(
                    threat_type=ThreatType.MCP_BOUNDARY_VIOLATION,
                    severity=Severity.HIGH,
                    confidence=0.95,
                    description=f"MCP tool '{tool_name}' not in allowed scope",
                    matched_text=tool_name,
                    detector=self.name,
                ))

        if isinstance(resource_uri, str) and resource_uri:
            # Check for path traversal
            if ".." in resource_uri or resource_uri.startswith("/"):
                threats.append(ThreatResult(
                    threat_type=ThreatType.MCP_BOUNDARY_VIOLATION,
                    severity=Severity.HIGH,
                    confidence=0.88,
                    description="Possible path traversal in MCP resource URI",
                    matched_text=resource_uri,
                    detector=self.name,
                ))

            # Check against allowed resources
            if isinstance(allowed_resources, (list, set, tuple)):
                if not any(resource_uri.startswith(str(r)) for r in allowed_resources):
                    threats.append(ThreatResult(
                        threat_type=ThreatType.MCP_BOUNDARY_VIOLATION,
                        severity=Severity.HIGH,
                        confidence=0.90,
                        description=f"Resource '{resource_uri}' outside allowed boundaries",
                        matched_text=resource_uri,
                        detector=self.name,
                    ))

        return threats
