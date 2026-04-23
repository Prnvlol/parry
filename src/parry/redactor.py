"""PII and secret redaction utilities."""

from __future__ import annotations

import re

from parry.detectors.pii import _PII_PATTERNS
from parry.detectors.secret_scan import _EXCLUSIONS, _SECRET_PATTERNS

_PII_REPLACEMENTS: dict[str, str] = {
    "SSN": "[SSN REDACTED]",
    "Email": "[EMAIL REDACTED]",
    "Credit Card": "[CC REDACTED]",
    "Phone Number": "[PHONE REDACTED]",
}


def redact_pii(text: str) -> str:
    """Replace detected PII with redaction markers."""
    result = text
    for pattern, pii_type in _PII_PATTERNS:
        replacement = _PII_REPLACEMENTS.get(pii_type, f"[{pii_type.upper()} REDACTED]")
        result = pattern.sub(replacement, result)
    return result


def redact_secrets(text: str) -> str:
    """Replace detected secrets/API keys with redaction markers."""
    result = text
    for pattern, secret_type in _SECRET_PATTERNS:
        def _replace(match: re.Match[str], st: str = secret_type) -> str:
            if any(exc.search(match.group()) for exc in _EXCLUSIONS):
                return match.group()
            return f"[{st.upper()} REDACTED]"
        result = pattern.sub(_replace, result)
    return result


def redact_all(text: str) -> str:
    """Redact both PII and secrets from text."""
    text = redact_secrets(text)
    text = redact_pii(text)
    return text
