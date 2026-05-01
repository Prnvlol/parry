# Contributing to Parry

Thanks for helping make AI agents safer.

Parry is focused on runtime protection: scanning user input, model output, tool calls, MCP boundaries, and multi-agent handoffs before unsafe behavior reaches production.

## Good First Contributions

Useful starter areas:

- Add a new detector test case.
- Improve an existing detector with a clear before/after example.
- Add an integration example for a popular agent framework.
- Improve documentation around safe configuration.
- Report a false positive or false negative with a minimal reproduction.

## Development Setup

```bash
git clone https://github.com/Prnvlol/parry.git
cd parry
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

Run these before opening a pull request:

```bash
ruff check src/ tests/
mypy src/
pytest
```

## Pull Request Guidelines

- Keep changes focused and easy to review.
- Add tests for detector changes, guard behavior, and integrations.
- Prefer deterministic checks over network calls or LLM-dependent behavior.
- Document user-facing behavior in `README.md`, `DEVELOPER.md`, or `examples/`.
- Include a short example when adding a new detection pattern.

## Detector Guidelines

Good detector changes should explain:

- What threat is being detected.
- Whether the result is high confidence or heuristic.
- What text or structure triggered the finding.
- How users can configure, block, redact, or allow the behavior.

Parry should be practical: useful enough to catch real failures, transparent enough that developers can debug its decisions.

## Security Reports

Please do not disclose vulnerabilities publicly before a fix is available. See `SECURITY.md` for the reporting process.
