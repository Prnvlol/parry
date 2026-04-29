# Parry — What's Next

A prioritised, releasable roadmap. Each milestone = a version bump + PyPI release.

---

## ✅ v0.1.0 — Foundation (Done)
- [x] `Guard`, `InputGuard`, `OutputGuard`, `AgentGuard`
- [x] Detectors: prompt injection, jailbreak, system prompt leak, secret scan, PII, tool call, MCP boundary
- [x] Integrations: OpenAI, Anthropic, LangChain, FastAPI
- [x] Three modes: `MONITOR`, `LOG`, `BLOCK`
- [x] Config loading: YAML / env / kwargs
- [x] Redaction: PII + secrets
- [x] Zero production dependencies
- [x] 46 tests passing
- [x] Published to PyPI as `parry-ai`
- [x] CI via GitHub Actions

---

## 🔴 v0.2.0 — Observability & DX

> Goal: make it easy to see what parry is catching in production.

- [ ] **Structured logging** — emit JSON-structured log events on every scan (threat type, severity, action taken, latency)
- [ ] **Callbacks / hooks** — `on_threat(report)` callback so users can pipe detections to Datadog, Sentry, Slack, etc.
- [ ] **`ScanReport.to_dict()` / `to_json()`** — clean serialisation for logging pipelines
- [ ] **Latency tracking** — each `ScanReport` includes scan duration in ms
- [ ] **`Guard.stats()`** — return total scans, threats caught, breakdown by type since startup
- [ ] Tests for all of the above

**Release:** `pip install parry-ai==0.2.0`

---

## 🟠 v0.3.0 — Stronger Detectors

> Goal: fewer false negatives on real-world attacks.

- [ ] **Prompt injection** — expand pattern set, add multilingual variants (base64, leetspeak obfuscation)
- [ ] **Jailbreak** — add latest DAN variants, "grandma exploit", roleplay bypass patterns
- [ ] **PII detector** — add phone numbers, passport numbers, IBAN, UK NI numbers
- [ ] **Secret scan** — add Stripe keys, Twilio, SendGrid, GitHub fine-grained tokens, Anthropic keys
- [ ] **Semantic similarity detector** (optional `ml` extra) — use sentence-transformers to catch paraphrased injection attacks that bypass regex
- [ ] Detector benchmark suite — track false positive / false negative rates across test corpus
- [ ] Update tests to cover new patterns

**Release:** `pip install parry-ai==0.3.0`

---

## 🟡 v0.4.0 — New Integrations

> Goal: work out of the box with the frameworks developers actually use.

- [ ] **LlamaIndex integration** — `parry.integrations.llamaindex`
- [ ] **CrewAI integration** — `parry.integrations.crewai`
- [ ] **AutoGen integration** — `parry.integrations.autogen`
- [ ] **Django middleware** — `parry.integrations.django`
- [ ] **HTTPX middleware** — for non-FastAPI async HTTP stacks
- [ ] Each integration gets its own example in `examples/`

**Release:** `pip install parry-ai==0.4.0`

---

## 🟢 v0.5.0 — Config & Policy

> Goal: enterprise-ready config, team-shareable policies.

- [ ] **Policy files** — define allowed topics, blocked keywords, custom rules in YAML
  ```yaml
  # parry-policy.yaml
  rules:
    block_topics: ["competitor names", "internal pricing"]
    custom_patterns:
      - name: "internal codename"
        pattern: "PROJECT_FALCON"
        severity: HIGH
  ```
- [ ] **Per-route config** — different guard configs for different API endpoints
- [ ] **Allowlist / blocklist** — explicit allow/block term lists
- [ ] **Config validation** — clear error messages when config is malformed
- [ ] **`parry validate`** — CLI command to validate a policy file

**Release:** `pip install parry-ai==0.5.0`

---

## 🔵 v0.6.0 — CLI & Developer Tooling

> Goal: developers can test parry against their prompts without writing code.

- [ ] **`parry scan "<prompt>"`** — scan a prompt string from the terminal
- [ ] **`parry scan --file prompts.txt`** — batch scan a file of prompts
- [ ] **`parry scan --config policy.yaml`** — apply a policy file
- [ ] **`parry report`** — pretty-print the last scan report
- [ ] Works as a pre-commit hook: scan prompts in test files before committing

**Release:** `pip install parry-ai==0.6.0`

---

## ⚪ v1.0.0 — Production Ready

> Goal: stable API, full docs site, community confidence.

- [ ] API stability guarantee — no breaking changes without a major version bump
- [ ] Comprehensive docs site (Mintlify or Docusaurus) at `parry.yourman.dev`
- [ ] Full integration guides with working code for every supported framework
- [ ] Performance benchmark — publish scan latency numbers (target: <5ms p99)
- [ ] Async support — `await guard.scan_input_async(text)` for async frameworks
- [ ] Type stubs complete and verified with mypy strict
- [ ] 100+ tests, >90% coverage
- [ ] GitHub Discussions enabled for community support

**Release:** `pip install parry-ai==1.0.0`

---

## 💡 Backlog (Future / Community-Driven)

These are good ideas but not scheduled yet — pick them up when there's user demand.

- [ ] **VS Code extension** — inline warnings when prompt strings in code match injection patterns
- [ ] **Streaming support** — scan output token-by-token for streaming LLM responses
- [ ] **Multimodal guard** — detect prompt injection in image inputs (GPT-4o vision)
- [ ] **Dashboard** — local web UI showing threat timeline, top attack types, filter by date
- [ ] **OpenTelemetry exporter** — emit spans/metrics to any OTel-compatible backend
- [ ] **parry cloud** (if ever) — hosted threat aggregation and alerting across deployments

---

## Release Checklist (per version)

Before bumping version and uploading to PyPI:

- [ ] All new features have tests
- [ ] `ruff check` passes clean
- [ ] `mypy src/` passes strict
- [ ] `CHANGELOG.md` updated with what changed
- [ ] Version bumped in `pyproject.toml` AND `src/parry/__init__.py`
- [ ] `python -m build && twine check dist/*` passes
- [ ] `twine upload dist/*`
- [ ] Git tag pushed: `git tag vX.Y.Z && git push origin vX.Y.Z`
