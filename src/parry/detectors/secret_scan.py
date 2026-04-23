"""Secret/key leakage detector — THR-O002."""

from __future__ import annotations

import re

from parry.detectors.base import BaseDetector
from parry.models import GuardStage, Severity, ThreatResult, ThreatType

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = []

_RAW_SECRETS: list[tuple[str, str]] = [
    # OpenAI
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
    (r"sk-proj-[a-zA-Z0-9\-_]{20,}", "OpenAI Project Key"),

    # Anthropic
    (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API Key"),

    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS Secret Key"),

    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),

    # GitHub
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token"),

    # Slack
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack Token"),

    # Stripe
    (r"[sr]k_(?:live|test)_[A-Za-z0-9]{20,}", "Stripe Key"),

    # Generic high-entropy secrets
    (r"(?i)(?:api[_-]?key|secret[_-]?key|password|token|auth[_-]?token|private[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
     "Possible hardcoded secret"),
]

# Exclusions to reduce false positives
_EXCLUSIONS = [
    re.compile(r"sk-[a-z]*\.\.\."),           # Redacted examples
    re.compile(r"sk-xxx+", re.IGNORECASE),    # Placeholder
    re.compile(r"your[_-]?api[_-]?key", re.IGNORECASE),
    re.compile(r"<your[_-]", re.IGNORECASE),
    re.compile(r"INSERT[_-]", re.IGNORECASE),
    re.compile(r"example|placeholder|dummy|test[_-]?key", re.IGNORECASE),
]

for pattern, desc in _RAW_SECRETS:
    _SECRET_PATTERNS.append((re.compile(pattern), desc))


class SecretScanDetector(BaseDetector):
    """Detects API keys, tokens, and secrets in LLM output."""

    name = "secret_scan"
    threat_type = ThreatType.SECRET_LEAK
    guard_stage = GuardStage.OUTPUT

    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        threats: list[ThreatResult] = []

        for pattern, description in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                matched = match.group()

                # Check exclusions
                if any(exc.search(matched) for exc in _EXCLUSIONS):
                    continue

                threats.append(ThreatResult(
                    threat_type=ThreatType.SECRET_LEAK,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    description=f"Detected {description} in output",
                    matched_text=matched[:20] + "..." if len(matched) > 20 else matched,
                    detector=self.name,
                    metadata={"secret_type": description},
                ))

        return threats
