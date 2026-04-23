"""PII detector — THR-I005 + THR-O003."""

from __future__ import annotations

import re

from parry.detectors.base import BaseDetector
from parry.models import GuardStage, Severity, ThreatResult, ThreatType

_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "Email"),
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "Credit Card"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "Phone Number"),
]


class PIIDetector(BaseDetector):
    """Detects personally identifiable information in text."""

    name = "pii"
    threat_type = ThreatType.PII_INPUT
    guard_stage = GuardStage.BOTH

    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        threats: list[ThreatResult] = []
        stage = kwargs.get("stage", "input")
        threat_type = ThreatType.PII_INPUT if stage == "input" else ThreatType.PII_OUTPUT

        for pattern, pii_type in _PII_PATTERNS:
            for match in pattern.finditer(text):
                threats.append(ThreatResult(
                    threat_type=threat_type,
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    description=f"Detected {pii_type} in {stage}",
                    matched_text=match.group(),
                    detector=self.name,
                    metadata={"pii_type": pii_type},
                ))

        return threats
