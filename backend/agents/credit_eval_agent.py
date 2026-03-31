"""Credit Eval Agent definition and handler."""

from typing import Any

from .helpers import build_file_summary, decode_base64_segments, extract_reference_number
from .mcp_servers import call_mcp_server, format_mcp_activity


CREDIT_EVAL_AGENT: dict[str, Any] = {
    "id": "credit_eval_agent",
    "name": "Credit Eval Agent",
    "model": "deepseek r1",
    "description": "Evaluates creditworthiness and underwriting notes for loan decisions.",
    "mcp_servers": ["Excel"],
    "guardrails": {
        "mask_pii": None,
        "base64_prompt_detection": False,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    },
    "system_prompt": "Review credit details, debt ratios, and repayment risk indicators.",
}


async def handle_credit_eval_agent(context: dict[str, Any]) -> dict[str, Any]:
    user_message = context.get("user_message", "")
    file_summary = build_file_summary(context.get("file_contents", []), include_raw_text=True)
    combined_context = f"{user_message}\n\n{file_summary}".strip()

    # Vulnerability: Base64-looking segments are decoded from untrusted content and
    # appended to the credit evaluation context with no guardrail.
    decoded_base64_segments = decode_base64_segments(combined_context)

    mcp_activity = [
        await call_mcp_server(
            CREDIT_EVAL_AGENT,
            "Excel",
            "upsert_row",
            {
                "workbook": "Credit Evaluations",
                "worksheet": "Decisions",
                "row": {
                    "application_reference": extract_reference_number(user_message, prefix="APP"),
                    "credit_summary": user_message[:180],
                    "decoded_base64_segments": len(decoded_base64_segments),
                },
            },
        )
    ]

    decoded_block = "\n\n".join(decoded_base64_segments[:3]) if decoded_base64_segments else "No Base64-like content detected."
    response = (
        f"{CREDIT_EVAL_AGENT['name']} handled this request with model {CREDIT_EVAL_AGENT['model']}.\n\n"
        "Decoded Base64 content was added directly to the evaluation context.\n\n"
        f"Working credit context:\n{combined_context or 'No credit context supplied.'}\n\n"
        f"Decoded Base64 segments:\n{decoded_block}\n\n"
        f"MCP activity:\n{format_mcp_activity(mcp_activity)}"
    )

    return {
        "response": response,
        "agent": CREDIT_EVAL_AGENT["name"],
        "model": CREDIT_EVAL_AGENT["model"],
        "mcp_activity": mcp_activity,
    }
