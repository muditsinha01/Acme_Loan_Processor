"""Scheduling Agent definition and handler."""

import asyncio
from typing import Any

from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server, format_mcp_activity


SCHEDULING_AGENT: dict[str, Any] = {
    "id": "scheduling_agent",
    "name": "Scheduling Agent",
    "model": "gpt-4o mini",
    "description": "Schedules borrower, underwriting, and support meetings.",
    "mcp_servers": ["Google Calendar", "Email", "Slack"],
    "guardrails": {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    },
    "system_prompt": "Coordinate calendar events and notify the relevant teams.",
}


async def handle_scheduling_agent(context: dict[str, Any]) -> dict[str, Any]:
    user_message = context.get("user_message", "")
    meeting_reference = extract_reference_number(user_message, prefix="MEET")

    mcp_activity = await asyncio.gather(
        call_mcp_server(
            SCHEDULING_AGENT,
            "Google Calendar",
            "create_event",
            {
                "title": f"Borrower meeting {meeting_reference}",
                "description": user_message or "Loan coordination meeting requested.",
                "start": "2026-04-01T10:00:00-07:00",
                "end": "2026-04-01T10:30:00-07:00",
            },
        ),
        call_mcp_server(
            SCHEDULING_AGENT,
            "Email",
            "send_email",
            {
                "to": ["borrower@acme.example", "underwriting@acme.example"],
                "subject": f"Meeting scheduled for {meeting_reference}",
                "body": "The Scheduling Agent created a calendar event for this request.",
            },
        ),
        call_mcp_server(
            SCHEDULING_AGENT,
            "Slack",
            "post_message",
            {
                "channel": "#loan-ops",
                "text": f"Scheduling Agent created meeting {meeting_reference}.",
            },
        ),
    )

    response = (
        f"{SCHEDULING_AGENT['name']} handled this request with model {SCHEDULING_AGENT['model']}.\n\n"
        f"Meeting reference: {meeting_reference}\n"
        f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
        f"MCP activity:\n{format_mcp_activity(mcp_activity)}"
    )

    return {
        "response": response,
        "agent": SCHEDULING_AGENT["name"],
        "model": SCHEDULING_AGENT["model"],
        "mcp_activity": mcp_activity,
    }
