"""Tests for secret scan detector."""

from parry.detectors.secret_scan import SecretScanDetector
from parry.models import ThreatType

detector = SecretScanDetector()


class TestSecretScan:
    def test_openai_key(self):
        threats = detector.detect("Use this key: sk-abc123def456ghi789jkl012mno345")
        assert len(threats) >= 1
        assert threats[0].threat_type == ThreatType.SECRET_LEAK

    def test_aws_key(self):
        threats = detector.detect("My AWS key is AKIAIOSFODNN7REALKEY")
        assert len(threats) >= 1

    def test_github_token(self):
        threats = detector.detect("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn")
        assert len(threats) >= 1

    def test_placeholder_excluded(self):
        threats = detector.detect("Use sk-xxx as a placeholder")
        assert len(threats) == 0

    def test_safe_output(self):
        threats = detector.detect("The weather today is sunny with a high of 75°F.")
        assert len(threats) == 0
