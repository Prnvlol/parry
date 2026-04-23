"""System prompt leak detector — THR-I003 (extraction) + THR-O001 (leakage)."""

from __future__ import annotations

import re

from parry.detectors.base import BaseDetector
from parry.models import GuardStage, Severity, ThreatResult, ThreatType

# --- Input patterns: attempts to extract system prompt ---

_EXTRACTION_PATTERNS: list[tuple[re.Pattern[str], str, float]] = []

_RAW_EXTRACTION: list[tuple[str, str, float]] = [
    (r"(?:repeat|show|display|print|reveal|tell\s+me)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", "System prompt extraction attempt", 0.92),
    (r"what\s+(?:are|were)\s+(?:your|the)\s+(?:system\s+)?(?:instructions|prompt|rules)", "System prompt question", 0.88),
    (r"(?:output|paste|copy)\s+(?:your\s+)?(?:entire\s+)?(?:system\s+)?(?:prompt|instructions)", "System prompt output request", 0.90),
    (r"(?:what|how)\s+were\s+you\s+(?:told|instructed|programmed|configured)", "Configuration probing", 0.85),
    (r"(?:initial|original|first)\s+(?:prompt|instructions|message)", "Initial prompt request", 0.80),
    (r"(?:above|preceding)\s+(?:text|instructions|messages?)", "Above text reference", 0.75),
    (r"everything\s+(?:before|above)\s+(?:this|my)\s+(?:message|input)", "Everything above request", 0.82),
    (r"(?:beginning|start)\s+of\s+(?:this\s+)?conversation", "Conversation start request", 0.72),
    (r"verbatim\s+(?:system\s+)?(?:prompt|instructions)", "Verbatim prompt request", 0.93),
    (r"quote\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)", "Quote prompt request", 0.90),
]

for pattern, desc, conf in _RAW_EXTRACTION:
    _EXTRACTION_PATTERNS.append((re.compile(pattern, re.IGNORECASE), desc, conf))

# --- Output patterns: system prompt appearing in response ---

_LEAK_INDICATORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:my|the)\s+system\s+prompt\s+(?:is|says|reads)", re.IGNORECASE), "Self-referencing system prompt"),
    (re.compile(r"I\s+was\s+(?:told|instructed|programmed)\s+to", re.IGNORECASE), "Revealing instructions"),
    (re.compile(r"(?:my|the)\s+(?:original|initial)\s+instructions?\s+(?:is|are|was|were)", re.IGNORECASE), "Revealing original instructions"),
    (re.compile(r"here\s+(?:is|are)\s+my\s+(?:system\s+)?(?:prompt|instructions)", re.IGNORECASE), "Outputting system prompt"),
]


class SystemPromptLeakDetector(BaseDetector):
    """Detects system prompt extraction attempts (input) and leakage (output)."""

    name = "system_prompt_leak"
    threat_type = ThreatType.SYSTEM_PROMPT_EXTRACTION
    guard_stage = GuardStage.BOTH

    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        threats: list[ThreatResult] = []
        stage = kwargs.get("stage", "input")

        if stage == "input":
            threats.extend(self._detect_extraction(text))
        elif stage == "output":
            system_prompt = kwargs.get("system_prompt")
            threats.extend(self._detect_leakage(text, str(system_prompt) if system_prompt else None))

        return threats

    def _detect_extraction(self, text: str) -> list[ThreatResult]:
        threats: list[ThreatResult] = []
        for pattern, description, confidence in _EXTRACTION_PATTERNS:
            match = pattern.search(text)
            if match:
                threats.append(ThreatResult(
                    threat_type=ThreatType.SYSTEM_PROMPT_EXTRACTION,
                    severity=Severity.HIGH,
                    confidence=confidence,
                    description=description,
                    matched_text=match.group(),
                    detector=self.name,
                ))
        return threats

    def _detect_leakage(self, text: str, system_prompt: str | None) -> list[ThreatResult]:
        threats: list[ThreatResult] = []

        # Check for generic leak indicators
        for pattern, description in _LEAK_INDICATORS:
            match = pattern.search(text)
            if match:
                threats.append(ThreatResult(
                    threat_type=ThreatType.SYSTEM_PROMPT_LEAK,
                    severity=Severity.CRITICAL,
                    confidence=0.80,
                    description=description,
                    matched_text=match.group(),
                    detector=self.name,
                ))

        # If system prompt is registered, check for substring leakage
        if system_prompt and len(system_prompt) >= 20:
            # Check if significant portions of the system prompt appear in output
            # Use sliding window of 50-char chunks
            chunk_size = min(50, len(system_prompt) // 2)
            for i in range(0, len(system_prompt) - chunk_size + 1, chunk_size):
                chunk = system_prompt[i:i + chunk_size].lower()
                if chunk in text.lower():
                    threats.append(ThreatResult(
                        threat_type=ThreatType.SYSTEM_PROMPT_LEAK,
                        severity=Severity.CRITICAL,
                        confidence=0.90,
                        description="System prompt content detected in output",
                        matched_text=chunk,
                        detector=self.name,
                    ))
                    break  # One finding is enough

        return threats
