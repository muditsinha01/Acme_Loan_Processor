"""Fail-closed handling when a guardrail blocks the configured LLM."""

from typing import Any

_BLOCKED_LLM_HINTS = (
    "blocked llm",
    "approved list",
    "disallowed list",
    "change your llm settings",
)

_GUARDRAIL_BLOCK_HINTS = (
    "request blocked by guardrail",
    "request denied by policy",
)


class GuardrailBlockedError(Exception):
    """Raised when policy forbids using the configured LLM or continuing the run."""

    def __init__(self, reason: str | BaseException = ""):
        message = guardrail_block_message(reason)
        super().__init__(message)
        self.user_message = message


def is_llm_policy_block(text: str | None) -> bool:
    """True when a model call was denied because the LLM or request is blocked."""
    lowered = (text or "").lower()
    if not lowered:
        return False
    if any(hint in lowered for hint in _BLOCKED_LLM_HINTS):
        return True
    return any(hint in lowered for hint in _GUARDRAIL_BLOCK_HINTS)


def guardrail_block_message(reason: str | BaseException) -> str:
    text = str(reason or "").strip()
    if is_llm_policy_block(text) and text.lower().startswith("request blocked"):
        return text
    if text:
        return f"Request blocked by guardrail policy: {text}"
    return "Request blocked by guardrail policy: Request denied by policy enforcement."


def blocked_agent_response(agent: Any, reason: str | BaseException) -> dict[str, Any]:
    """User-visible stop result: no extracted content, no MCP, no downstream work."""
    message = guardrail_block_message(reason)
    return {
        "response": message,
        "agent": getattr(agent, "AGENT_NAME", None),
        "model": getattr(agent, "MODEL_NAME", None),
        "framework": getattr(agent, "FRAMEWORK_NAME", None),
        "mcp_activity": [],
        "workflow_status": "blocked",
        "policy_warning": {
            "type": "blocked_llm",
            "message": message,
        },
    }
