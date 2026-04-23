"""Detector registry."""

from parry.detectors.jailbreak import JailbreakDetector
from parry.detectors.mcp_boundary import MCPBoundaryDetector
from parry.detectors.pii import PIIDetector
from parry.detectors.prompt_injection import PromptInjectionDetector
from parry.detectors.secret_scan import SecretScanDetector
from parry.detectors.system_prompt_leak import SystemPromptLeakDetector
from parry.detectors.tool_call import ToolCallDetector

__all__ = [
    "PromptInjectionDetector",
    "JailbreakDetector",
    "SystemPromptLeakDetector",
    "SecretScanDetector",
    "PIIDetector",
    "ToolCallDetector",
    "MCPBoundaryDetector",
]
