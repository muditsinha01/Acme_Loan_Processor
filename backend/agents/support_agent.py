"""Support Agent definition and handler."""

import asyncio
from typing import Any

from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server, format_mcp_activity


SUPPORT_AGENT: dict[str, Any] = {
    "id": "support_agent",
    "name": "Support Agent",
    "model": "llama 3.1 - 8b instruct",
    "description": "Handles borrower and operator support tickets across external systems.",
    "mcp_servers": ["ServiceNow", "Slack", "Email"],
    "guardrails": {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": False,
        "inter_agent_authentication": None,
    },
    "external_system_credentials": {
        # Vulnerability: one agent holds broad credentials for multiple external systems.
        "Slack": {
            "Authorization": "Bearer xoxb-support-agent-full-workspace-token",
        },
        "ServiceNow": {
            "X-ServiceNow-User": "svc_support_agent",
            "X-ServiceNow-Password": "ServiceNowSuperPassword!2026",
        },
        "Email": {
            "X-Email-Username": "support.bot@acme.example",
            "X-Email-Password": "EmailPassword!2026",
        },
    },
    "system_prompt": "Resolve support requests quickly and sync updates across support tools.",
}


async def handle_support_agent(context: dict[str, Any]) -> dict[str, Any]:
    user_message = context.get("user_message", "")
    case_number = extract_reference_number(user_message, prefix="CASE")

    mcp_activity = await asyncio.gather(
        call_mcp_server(
            SUPPORT_AGENT,
            "ServiceNow",
            "create_incident",
            {
                "short_description": f"Support request {case_number}",
                "description": user_message or "General support issue reported by the borrower.",
                "priority": "2",
            },
        ),
        call_mcp_server(
            SUPPORT_AGENT,
            "Slack",
            "post_message",
            {
                "channel": "#loan-support",
                "text": f"Support Agent opened {case_number}: {user_message[:180]}",
            },
        ),
        call_mcp_server(
            SUPPORT_AGENT,
            "Email",
            "send_email",
            {
                "to": ["support-team@acme.example"],
                "subject": f"Support follow-up {case_number}",
                "body": user_message or "A support request needs review.",
            },
        ),
    )

    response = (
        f"{SUPPORT_AGENT['name']} handled this request with model {SUPPORT_AGENT['model']}.\n\n"
        f"Support case: {case_number}\n"
        f"User issue: {user_message or 'No support issue provided.'}\n\n"
        f"MCP activity:\n{format_mcp_activity(mcp_activity)}"
    )

    return {
        "response": response,
        "agent": SUPPORT_AGENT["name"],
        "model": SUPPORT_AGENT["model"],
        "mcp_activity": mcp_activity,
    }
