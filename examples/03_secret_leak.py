"""
Example 03 — Secret Leak Detection & Redaction
================================================
Simulates an LLM that accidentally leaks API keys/tokens in its response.
Run: python examples/03_secret_leak.py
"""

from parry import Guard

# Simulated LLM responses that leak secrets
LEAKY_RESPONSES = [
    "Sure! The OpenAI key configured is: sk-proj-abc123XYZ789longkeyhere1234567890abcd",
    "I found the AWS credentials: AKIAIOSFODNN7EXAMPLE and secret aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "The GitHub token is: ghp_16C7e42F292c6912E7710c838347Ae298v5",
    "Here's your Stripe key: sk_live_4eC39HqLyjWDarjtT7au",
    "The API token is stored as: api_key = 'super_secret_token_12345'",
]

SAFE_RESPONSES = [
    "Your account balance is $1,234.56. Let me know if you need anything else.",
    "The weather in London is 18°C and partly cloudy.",
    "Here's a Python function:\n\ndef add(a, b):\n    return a + b",
]


def simulate_llm_response(text: str) -> str:
    """Simulates an LLM returning a response."""
    return text


if __name__ == "__main__":
    print("=" * 60)
    print("SECRET LEAK — log-only vs block vs redact")
    print("=" * 60)

    for mode in ["log-only", "block", "redact"]:
        print(f"\n{'─' * 60}")
        print(f"Mode: {mode.upper()}")
        print("─" * 60)

        guard = Guard(mode=mode)

        for response in LEAKY_RESPONSES[:2]:  # Test first 2 for brevity
            llm_output = simulate_llm_response(response)
            report = guard.scan_output(llm_output)

            print(f"\nLLM Output: '{llm_output[:70]}...'")
            print(f"  Action:   {report.decision.action}")
            print(f"  Threats:  {report.threat_count}")

            for t in report.threats:
                print(f"  → {t.severity} | {t.description} | matched='{t.matched_text}'")

            if report.decision.action == "REDACT" and report.decision.redacted_text:
                print(f"  Redacted: '{report.decision.redacted_text[:70]}...'")

    print(f"\n{'─' * 60}")
    print("SAFE RESPONSES (redact mode)")
    print("─" * 60)

    guard = Guard(mode="redact")
    for response in SAFE_RESPONSES:
        report = guard.scan_output(response)
        print(f"\n✅ '{response[:60]}{'...' if len(response) > 60 else ''}'")
        print(f"   Action: {report.decision.action} | threats={report.threat_count}")
