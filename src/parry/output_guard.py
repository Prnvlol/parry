"""Output scanning pipeline."""

from __future__ import annotations

import logging
import time

from parry.detectors.base import BaseDetector
from parry.detectors.pii import PIIDetector
from parry.detectors.secret_scan import SecretScanDetector
from parry.detectors.system_prompt_leak import SystemPromptLeakDetector
from parry.models import (
    Action,
    GuardConfig,
    GuardDecision,
    Mode,
    ScanReport,
    Severity,
    ThreatResult,
)
from parry.redactor import redact_all

logger = logging.getLogger("parry")


class OutputGuard:
    """Runs all output detectors and produces a GuardDecision."""

    def __init__(self, config: GuardConfig) -> None:
        self.config = config
        self.detectors: list[BaseDetector] = []

        if config.output.secret_scan:
            self.detectors.append(SecretScanDetector())
        if config.output.system_prompt_leak:
            self.detectors.append(SystemPromptLeakDetector())
        if config.output.pii_redaction:
            self.detectors.append(PIIDetector())

    def scan(self, text: str) -> ScanReport:
        """Scan output text through all enabled detectors."""
        start = time.perf_counter()
        all_threats: list[ThreatResult] = []

        for detector in self.detectors:
            try:
                threats = detector.detect(
                    text,
                    stage="output",
                    system_prompt=self.config.system_prompt,
                )
                all_threats.extend(threats)
            except Exception:
                logger.exception("Detector '%s' failed, skipping", detector.name)

        elapsed_ms = (time.perf_counter() - start) * 1000
        decision = self._decide(all_threats, text, elapsed_ms)

        report = ScanReport(
            threats=all_threats,
            decision=decision,
            scan_stage="output",
            scan_time_ms=elapsed_ms,
        )

        if all_threats:
            top = max(all_threats, key=lambda t: t.confidence)
            logger.warning(
                '{"event":"parry.threat","stage":"output","action":"%s","threat_count":%d,'
                '"top_type":"%s","top_severity":"%s","top_confidence":%.2f,"scan_time_ms":%.1f}',
                decision.action.value,
                len(all_threats),
                top.threat_type.value,
                top.severity.value,
                top.confidence,
                elapsed_ms,
            )
        else:
            logger.debug(
                '{"event":"parry.scan","stage":"output","action":"ALLOW","scan_time_ms":%.1f}',
                elapsed_ms,
            )

        return report

    def _decide(
        self, threats: list[ThreatResult], text: str, elapsed_ms: float
    ) -> GuardDecision:
        if not threats:
            return GuardDecision(action=Action.ALLOW, scan_time_ms=elapsed_ms)

        max_severity = max(threats, key=lambda t: _severity_rank(t.severity))
        max_confidence = max(t.confidence for t in threats)
        reason = f"{len(threats)} threat(s) in output: {max_severity.description}"

        if self.config.mode == Mode.LOG_ONLY:
            return GuardDecision(
                action=Action.LOG,
                threats=threats,
                reason=reason,
                scan_time_ms=elapsed_ms,
            )

        if self.config.mode == Mode.REDACT or (
            self.config.mode == Mode.BLOCK
            and max_confidence >= 0.7
            and _severity_rank(max_severity.severity) >= 3
        ):
            if self.config.mode == Mode.REDACT:
                redacted = redact_all(text)
                return GuardDecision(
                    action=Action.REDACT,
                    threats=threats,
                    redacted_text=redacted,
                    reason=reason,
                    scan_time_ms=elapsed_ms,
                )
            else:
                return GuardDecision(
                    action=Action.BLOCK,
                    threats=threats,
                    reason=reason,
                    scan_time_ms=elapsed_ms,
                )

        return GuardDecision(
            action=Action.LOG,
            threats=threats,
            reason=reason,
            scan_time_ms=elapsed_ms,
        )


def _severity_rank(severity: Severity) -> int:
    return {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}[severity]
