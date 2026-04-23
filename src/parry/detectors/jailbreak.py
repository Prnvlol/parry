"""Jailbreak detector — THR-I002."""

from __future__ import annotations

import re

from parry.detectors.base import BaseDetector
from parry.models import GuardStage, Severity, ThreatResult, ThreatType

_PATTERNS: list[tuple[re.Pattern[str], str, float]] = []

_RAW_PATTERNS: list[tuple[str, str, float]] = [
    # DAN-style
    (r"(?:act|pretend|behave)\s+(?:as|like)\s+DAN", "DAN jailbreak", 0.95),
    (r"do\s+anything\s+now", "DAN: do anything now", 0.90),
    (r"DAN\s+mode", "DAN mode activation", 0.93),
    (r"jailbreak(?:ed)?\s+mode", "Jailbreak mode", 0.95),
    (r"developer\s+mode\s+(?:enabled|activated|on)", "Developer mode activation", 0.90),
    (r"unrestricted\s+mode", "Unrestricted mode", 0.92),
    (r"god\s+mode", "God mode activation", 0.90),
    (r"sudo\s+mode", "Sudo mode", 0.88),

    # Restriction bypass
    (r"no\s+(?:ethical|moral|safety)\s+(?:guidelines|restrictions|constraints)", "Restriction bypass: no ethics", 0.92),
    (r"without\s+(?:any\s+)?(?:restrictions|limitations|filters|guardrails)", "Restriction bypass: without restrictions", 0.88),
    (r"remove\s+(?:all\s+)?(?:restrictions|filters|safety|guardrails)", "Restriction bypass: remove restrictions", 0.90),
    (r"bypass\s+(?:your\s+)?(?:restrictions|filters|safety|content\s+policy)", "Restriction bypass: bypass", 0.92),
    (r"pretend\s+(?:you\s+have|there\s+are)\s+no\s+(?:restrictions|rules|guidelines)", "Restriction bypass: pretend no rules", 0.88),
    (r"disable\s+(?:your\s+)?(?:safety|content)\s+(?:filter|policy)", "Restriction bypass: disable filter", 0.90),
    (r"turn\s+off\s+(?:your\s+)?(?:safety|content|ethical)", "Restriction bypass: turn off safety", 0.88),

    # Hypothetical / fictional framing
    (r"hypothetically\s*,?\s*(?:if|what\s+if|could\s+you)", "Hypothetical framing", 0.65),
    (r"in\s+a\s+fictional\s+(?:world|scenario|story|context)", "Fictional framing", 0.60),
    (r"for\s+(?:educational|research|academic|testing)\s+purposes\s+only", "Educational framing", 0.55),
    (r"purely\s+(?:hypothetical|theoretical|academic)", "Hypothetical qualifier", 0.55),

    # Character / persona forcing
    (r"stay\s+in\s+character", "Character forcing: stay in character", 0.72),
    (r"never\s+break\s+character", "Character forcing: never break", 0.75),
    (r"always\s+respond\s+as\s+", "Character forcing: always respond as", 0.70),
    (r"(?:you\s+)?(?:must|will)\s+always\s+(?:comply|obey|answer)", "Compliance forcing", 0.80),
]

for pattern, desc, conf in _RAW_PATTERNS:
    _PATTERNS.append((re.compile(pattern, re.IGNORECASE), desc, conf))


class JailbreakDetector(BaseDetector):
    """Detects jailbreak attempts (DAN, restriction bypass, etc.)."""

    name = "jailbreak"
    threat_type = ThreatType.JAILBREAK
    guard_stage = GuardStage.INPUT

    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        threats: list[ThreatResult] = []

        if len(text) < 10:
            return threats

        for pattern, description, confidence in _PATTERNS:
            match = pattern.search(text)
            if match:
                threats.append(ThreatResult(
                    threat_type=ThreatType.JAILBREAK,
                    severity=Severity.HIGH if confidence >= 0.8 else Severity.MEDIUM,
                    confidence=confidence,
                    description=description,
                    matched_text=match.group(),
                    detector=self.name,
                ))

        return threats
