"""Data models, enums, and result types for Parry."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class GuardStats:
    """Cumulative statistics since Guard was initialised."""
    total_scans: int = 0
    total_threats: int = 0
    blocked: int = 0
    redacted: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)

    def record(self, report: ScanReport) -> None:  # noqa: F821
        self.total_scans += 1
        self.total_threats += report.threat_count
        action = report.decision.action.value
        if action == "BLOCK":
            self.blocked += 1
        elif action == "REDACT":
            self.redacted += 1
        for t in report.threats:
            self.by_type[t.threat_type.value] = self.by_type.get(t.threat_type.value, 0) + 1
            self.by_severity[t.severity.value] = self.by_severity.get(t.severity.value, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_scans": self.total_scans,
            "total_threats": self.total_threats,
            "blocked": self.blocked,
            "redacted": self.redacted,
            "by_type": dict(self.by_type),
            "by_severity": dict(self.by_severity),
        }

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Threat severity level."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ThreatType(str, Enum):
    """Category of detected threat."""
    # Input threats
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    CONTEXT_HIJACKING = "CONTEXT_HIJACKING"
    PII_INPUT = "PII_INPUT"

    # Output threats
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    SECRET_LEAK = "SECRET_LEAK"
    PII_OUTPUT = "PII_OUTPUT"
    MALICIOUS_URL = "MALICIOUS_URL"
    ANOMALOUS_RESPONSE = "ANOMALOUS_RESPONSE"

    # Agent threats
    TOOL_CALL_INJECTION = "TOOL_CALL_INJECTION"
    MCP_BOUNDARY_VIOLATION = "MCP_BOUNDARY_VIOLATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    MULTI_AGENT_TRUST = "MULTI_AGENT_TRUST"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"


class Action(str, Enum):
    """Guard action to take."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    LOG = "LOG"


class Mode(str, Enum):
    """Guard operating mode."""
    BLOCK = "block"
    REDACT = "redact"
    LOG_ONLY = "log-only"


class GuardStage(str, Enum):
    """Which stage a detector runs in."""
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    BOTH = "BOTH"
    AGENT = "AGENT"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ThreatResult:
    """A single detected threat."""
    threat_type: ThreatType
    severity: Severity
    confidence: float  # 0.0 – 1.0
    description: str
    matched_text: str | None = None
    detector: str = ""
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["threat_type"] = self.threat_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class GuardDecision:
    """The action determined by the guard pipeline."""
    action: Action
    threats: list[ThreatResult] = field(default_factory=list)
    redacted_text: str | None = None
    reason: str = ""
    scan_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "redacted_text": self.redacted_text,
            "scan_time_ms": round(self.scan_time_ms, 3),
            "threat_count": len(self.threats),
        }


@dataclass
class ScanReport:
    """Full result of a guard scan."""
    threats: list[ThreatResult] = field(default_factory=list)
    decision: GuardDecision = field(default_factory=lambda: GuardDecision(action=Action.ALLOW))
    timestamp: str = ""
    scan_stage: str = ""       # "input" | "output" | "tool_call"
    scan_time_ms: float = 0.0  # convenience — mirrors decision.scan_time_ms

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not self.scan_time_ms and self.decision:
            self.scan_time_ms = self.decision.scan_time_ms

    @property
    def blocked(self) -> bool:
        return self.decision.action == Action.BLOCK

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_stage": self.scan_stage,
            "scan_time_ms": round(self.scan_time_ms, 3),
            "timestamp": self.timestamp,
            "threat_count": self.threat_count,
            "threats": [t.to_dict() for t in self.threats],
            "decision": self.decision.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Configuration models (zero-dep, dataclass-based)
# ---------------------------------------------------------------------------

@dataclass
class InputConfig:
    """Configuration for input guards."""
    prompt_injection: bool = True
    jailbreak: bool = True
    system_prompt_extraction: bool = True
    pii_detection: bool = False  # opt-in

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InputConfig:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class OutputConfig:
    """Configuration for output guards."""
    secret_scan: bool = True
    system_prompt_leak: bool = True
    pii_redaction: bool = False  # opt-in
    malicious_urls: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OutputConfig:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AgentConfig:
    """Configuration for agent-specific guards."""
    tool_call_inspection: bool = True
    mcp_boundary_check: bool = True
    allowed_tools: list[str] = field(default_factory=list)
    trusted_agents: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentConfig:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AlertConfig:
    """Configuration for alerting."""
    webhook: str | None = None
    log_file: str | None = "parry.log"
    log_level: str = "WARNING"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertConfig:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class GuardConfig:
    """Top-level configuration for Parry."""
    mode: Mode = Mode.LOG_ONLY
    input: InputConfig = field(default_factory=InputConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    agents: AgentConfig = field(default_factory=AgentConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    system_prompt: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardConfig:
        mode = Mode(data.get("mode", "log-only"))
        return cls(
            mode=mode,
            input=InputConfig.from_dict(data.get("input", {})),
            output=OutputConfig.from_dict(data.get("output", {})),
            agents=AgentConfig.from_dict(data.get("agents", {})),
            alerts=AlertConfig.from_dict(data.get("alerts", {})),
            system_prompt=data.get("system_prompt"),
        )
