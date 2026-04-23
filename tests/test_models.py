"""Tests for data models."""

from parry.models import (
    Action,
    GuardConfig,
    GuardDecision,
    Mode,
    ScanReport,
    Severity,
    ThreatResult,
    ThreatType,
)


def test_threat_result_to_dict():
    t = ThreatResult(
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        confidence=0.9,
        description="Test threat",
        matched_text="ignore previous",
        detector="test",
    )
    d = t.to_dict()
    assert d["threat_type"] == "PROMPT_INJECTION"
    assert d["severity"] == "HIGH"
    assert d["confidence"] == 0.9


def test_scan_report_to_json():
    report = ScanReport()
    j = report.to_json()
    assert '"threats": []' in j
    assert '"action": "ALLOW"' in j


def test_scan_report_blocked():
    report = ScanReport(decision=GuardDecision(action=Action.BLOCK))
    assert report.blocked is True

    report2 = ScanReport()
    assert report2.blocked is False


def test_guard_config_from_dict():
    config = GuardConfig.from_dict({
        "mode": "block",
        "input": {"pii_detection": True},
        "output": {"pii_redaction": True},
    })
    assert config.mode == Mode.BLOCK
    assert config.input.pii_detection is True
    assert config.output.pii_redaction is True
    assert config.input.prompt_injection is True  # default


def test_guard_config_defaults():
    config = GuardConfig()
    assert config.mode == Mode.LOG_ONLY
    assert config.input.prompt_injection is True
    assert config.input.pii_detection is False
    assert config.output.secret_scan is True
