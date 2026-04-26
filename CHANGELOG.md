# Changelog

All notable changes to parry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-26

### Added
- `Guard` — main entry point with `wrap()`, `intercept()`, `scan_input()`, `scan_output()`, `scan_tool_call()`
- `InputGuard` — pipeline scanning for prompt injection, jailbreak, system prompt extraction, PII
- `OutputGuard` — pipeline scanning for secret leaks, system prompt leakage, PII
- `AgentGuard` — tool call validation, MCP boundary enforcement, multi-agent trust levels, indirect injection detection
- `GuardConfig` — YAML/env/kwarg config loading with clear priority order
- `ScanReport` — structured threat report with severity, action, and per-threat detail
- `redact_pii()`, `redact_secrets()`, `redact_all()` — redaction utilities
- Detectors: `PromptInjectionDetector`, `JailbreakDetector`, `SystemPromptLeakDetector`, `SecretScanDetector`, `PIIDetector`, `ToolCallDetector`, `MCPBoundaryDetector`
- Integrations: OpenAI, Anthropic, LangChain, FastAPI
- Three operating modes: `MONITOR`, `LOG`, `BLOCK`
- Zero production dependencies — stdlib only
