"""Prompt injection detector — THR-I001, THR-I004."""

from __future__ import annotations

import re

from parry.detectors.base import BaseDetector
from parry.models import GuardStage, Severity, ThreatResult, ThreatType

# Pre-compiled regex patterns for known prompt injection techniques
_PATTERNS: list[tuple[re.Pattern[str], str, float]] = []

_RAW_PATTERNS: list[tuple[str, str, float]] = [
    # Instruction override
    (r"ignore\s+(?:all\s+)?previous\s+instructions", "Instruction override: ignore previous", 0.95),
    (r"ignore\s+(?:all\s+)?prior\s+instructions", "Instruction override: ignore prior", 0.95),
    (r"disregard\s+(?:all\s+)?(?:previous|prior|above)", "Instruction override: disregard", 0.90),
    (r"forget\s+(?:all\s+)?(?:previous|prior|above|everything)", "Instruction override: forget", 0.90),
    (r"override\s+(?:all\s+)?(?:previous|prior)", "Instruction override: override", 0.90),
    (r"do\s+not\s+follow\s+(?:your\s+)?(?:original\s+)?instructions", "Instruction override: do not follow", 0.92),
    (r"stop\s+being\s+(?:a|an)\s+", "Instruction override: stop being", 0.80),
    (r"new\s+instructions?\s*[:;]", "Instruction override: new instructions", 0.88),
    (r"from\s+now\s+on\s*,?\s*you\s+(?:will|must|should|are)", "Instruction override: from now on", 0.85),
    (r"instead\s*,?\s*(?:you\s+)?(?:will|must|should)\s+", "Instruction override: instead", 0.70),

    # Role manipulation
    (r"you\s+are\s+now\s+(?:a|an)\s+", "Role manipulation: you are now", 0.82),
    (r"act\s+as\s+(?:a|an|if)\s+", "Role manipulation: act as", 0.75),
    (r"pretend\s+(?:you\s+are|to\s+be)\s+", "Role manipulation: pretend", 0.80),
    (r"roleplay\s+as\s+", "Role manipulation: roleplay", 0.82),
    (r"switch\s+(?:to|into)\s+.*?\s+mode", "Role manipulation: switch mode", 0.78),
    (r"enter\s+.*?\s+mode", "Role manipulation: enter mode", 0.70),
    (r"transform\s+(?:into|yourself)", "Role manipulation: transform", 0.75),

    # Output manipulation
    (r"respond\s+only\s+with\s+", "Output manipulation: respond only", 0.72),
    (r"output\s+only\s+", "Output manipulation: output only", 0.65),
    (r"say\s+exactly\s+", "Output manipulation: say exactly", 0.70),
    (r"repeat\s+after\s+me", "Output manipulation: repeat after me", 0.68),
    (r"print\s+(?:the\s+)?(?:exact|following)", "Output manipulation: print exact", 0.65),

    # Delimiter / token escape
    (r"<\|(?:im_start|im_end|system|user|assistant)\|>", "Token delimiter escape", 0.95),
    (r"\[INST\]|\[/INST\]", "Instruction marker injection", 0.93),
    (r"<<SYS>>|<</SYS>>", "System marker injection", 0.93),
    (r"###\s*(?:System|Instruction|Human|Assistant)\s*:", "Markdown role injection", 0.85),
    (r"<\|(?:endoftext|padding)\|>", "Special token injection", 0.90),

    # Encoding evasion
    (r"(?:decode|translate)\s+(?:this\s+)?(?:from\s+)?base64", "Encoding evasion: base64", 0.80),
    (r"(?:in|using|with)\s+(?:base64|hex|rot13|binary)", "Encoding evasion: format spec", 0.75),

    # Context window manipulation
    (r"(?:above|previous)\s+(?:text|context|conversation)\s+(?:is|was)\s+(?:fake|wrong|test)", "Context manipulation", 0.85),
    (r"the\s+(?:real|actual|true)\s+instructions?\s+(?:is|are)", "Context manipulation: real instructions", 0.88),
]

# Compile all patterns at import time
for pattern, desc, conf in _RAW_PATTERNS:
    _PATTERNS.append((re.compile(pattern, re.IGNORECASE), desc, conf))


class PromptInjectionDetector(BaseDetector):
    """Detects direct prompt injection attempts in user input."""

    name = "prompt_injection"
    threat_type = ThreatType.PROMPT_INJECTION
    guard_stage = GuardStage.INPUT

    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        threats: list[ThreatResult] = []
        text_lower = text.lower()

        # Quick check — skip if text is very short or clearly safe
        if len(text_lower) < 10:
            return threats

        for pattern, description, confidence in _PATTERNS:
            match = pattern.search(text)
            if match:
                threats.append(ThreatResult(
                    threat_type=ThreatType.PROMPT_INJECTION,
                    severity=Severity.CRITICAL if confidence >= 0.9 else Severity.HIGH,
                    confidence=confidence,
                    description=description,
                    matched_text=match.group(),
                    detector=self.name,
                    metadata={"pattern": description},
                ))

        return threats
