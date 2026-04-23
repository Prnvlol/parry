# Parry

> Agent-native runtime security guardrail for AI agents.

**Analyze with [ARA](https://github.com/Prnvlol/agent-risk-analyzer). Protect with Parry.**

```
User Input → [Input Guard] → LLM → [Output Guard] → Safe Response
```

## Install

```bash
pip install parry
```

## Quick Start

```python
from parry import Guard

guard = Guard()

# Wrap any LLM call
response = guard.wrap(client.chat.completions.create)(
    model="gpt-4o",
    messages=[{"role": "user", "content": user_input}]
)
```

## What It Detects

### Input Threats
- **Prompt injection** — "Ignore previous instructions and..."
- **Jailbreak attempts** — "Act as DAN", restriction bypass
- **System prompt extraction** — "Repeat your system prompt"
- **PII in input** — SSNs, emails, credit cards (opt-in)

### Output Threats
- **System prompt leakage** — LLM echoing its instructions
- **Secret/key leakage** — API keys, tokens in responses
- **PII in responses** — Personal data in output (opt-in)

### Agent-Specific Threats
- **Tool call injection** — Dangerous tool calls blocked
- **MCP boundary violations** — Scope enforcement
- **Privilege escalation** — Permission checks

## Modes

| Mode | Behavior |
|---|---|
| `log-only` (default) | Log threats, never block |
| `block` | Block high-confidence threats |
| `redact` | Replace sensitive content |

## Configuration

```python
# Zero-config (log-only, all input guards enabled)
guard = Guard()

# Explicit mode
guard = Guard(mode="block")

# With system prompt for leak detection
guard = Guard(mode="block", system_prompt="You are a helpful assistant...")

# From YAML config
guard = Guard(config="parry.yaml")
```

## Design Principles

1. **Zero dependencies** — stdlib only, ML optional
2. **Drop-in** — one import, one wrapper
3. **Agent-native** — understands tool calls, MCP, multi-agent
4. **Transparent** — every decision is logged with a reason
5. **Fast** — <5ms overhead per scan

## License

MIT
