"""Base detector interface for Parry."""

from __future__ import annotations

from abc import ABC, abstractmethod

from parry.models import GuardStage, ThreatResult, ThreatType


class BaseDetector(ABC):
    """Abstract base class for all threat detectors."""

    name: str = ""
    threat_type: ThreatType
    guard_stage: GuardStage = GuardStage.INPUT

    @abstractmethod
    def detect(self, text: str, **kwargs: object) -> list[ThreatResult]:
        """Scan text and return any detected threats.

        Args:
            text: The text to scan.
            **kwargs: Additional context (system_prompt, tool_calls, etc.)

        Returns:
            List of detected threats. Empty list if clean.
        """
        ...
