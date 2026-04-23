# Parry — Manual Testing Examples

Run any example with:

```bash
cd /Users/pranavsuresh/Documents/Projects/parry
pip install -e .

python examples/01_prompt_injection.py
python examples/02_jailbreak.py
python examples/03_secret_leak.py
python examples/04_system_prompt_extraction.py
python examples/05_tool_call_protection.py
python examples/06_wrap_end_to_end.py
```

---

## What Each Example Tests

| File | Threat | What you'll see |
|---|---|---|
| `01_prompt_injection.py` | `PROMPT_INJECTION` | Attack inputs blocked, safe inputs allowed |
| `02_jailbreak.py` | `JAILBREAK` | DAN/developer-mode attempts detected by severity |
| `03_secret_leak.py` | `SECRET_LEAK` | API keys redacted or blocked in LLM output |
| `04_system_prompt_extraction.py` | `SYSTEM_PROMPT_EXTRACTION` + `SYSTEM_PROMPT_LEAK` | Extraction attempts blocked on input; leakage blocked on output |
| `05_tool_call_protection.py` | `TOOL_CALL_INJECTION` | Dangerous/unapproved tool calls blocked before execution |
| `06_wrap_end_to_end.py` | All | Full `guard.wrap()` flow with mock LLM — no API key needed |

---

## Using with a Real OpenAI Client

Replace the mock LLM in `06_wrap_end_to_end.py` with:

```python
from openai import OpenAI
from parry import Guard

client = OpenAI(api_key="sk-...")
guard = Guard(mode="block", system_prompt="You are a helpful assistant.")

response = guard.wrap(client.chat.completions.create)(
    model="gpt-4o",
    messages=[{"role": "user", "content": user_input}]
)
```

No other changes needed.
