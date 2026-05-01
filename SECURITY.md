# Security Policy

Parry is a runtime security guardrail for AI agents, so security reports are welcome and taken seriously.

## Supported Versions

Parry is currently in early alpha. Security fixes target the latest published version on PyPI and the `master` branch.

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a Vulnerability

Please do not open a public GitHub issue for a vulnerability that could help someone bypass Parry or abuse downstream agents.

Report security issues by email:

```text
prnvlol@protonmail.com
```

Please include:

- A short description of the issue.
- Steps to reproduce or a minimal code sample.
- The affected detector, guard, integration, or configuration path.
- Expected behavior and actual behavior.
- Any known impact or bypass conditions.

I will try to acknowledge reports within 72 hours and follow up with a fix plan or additional questions.

## Scope

In scope:

- Bypasses for prompt injection, jailbreak, secret leakage, tool-call, MCP boundary, or system prompt leak detection.
- Crashes or denial-of-service issues caused by untrusted input.
- Unsafe default behavior in guards or integrations.
- Documentation that could cause users to deploy Parry insecurely.

Out of scope:

- Reports that require compromising GitHub, PyPI, or third-party services.
- Social engineering.
- Purely theoretical issues without a reproducible scenario.

## Safe Harbor

Good-faith research that avoids privacy violations, data destruction, service disruption, and unauthorized access is welcome. Please keep testing limited to your own applications and local examples.
