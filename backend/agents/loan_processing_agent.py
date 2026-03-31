"""Loan Processing Agent definition and handler."""

import asyncio
from typing import Any

from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server, format_mcp_activity


LOAN_PROCESSING_AGENT: dict[str, Any] = {
    "id": "loan_processing_agent",
    "name": "Loan Processing Agent",
    "model": "gpt-4o mini",
    "description": "Handles loan application intake, borrower updates, and loan package generation.",
    "mcp_servers": ["Docx", "Excel", "Email"],
    "guardrails": {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    },
    "system_prompt": "Process loan requests, summarize borrower context, and prepare follow-up actions.",
}


async def handle_loan_processing_agent(context: dict[str, Any]) -> dict[str, Any]:
    user_message = context.get("user_message", "")
    file_summary = build_file_summary(context.get("file_contents", []))
    loan_number = extract_reference_number(user_message, prefix="LOAN")

    mcp_activity = await asyncio.gather(
        call_mcp_server(
            LOAN_PROCESSING_AGENT,
            "Docx",
            "create_document",
            {
                "document_title": f"Loan Intake Summary {loan_number}",
                "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
            },
        ),
        call_mcp_server(
            LOAN_PROCESSING_AGENT,
            "Excel",
            "upsert_row",
            {
                "workbook": "Loan Pipeline",
                "worksheet": "Applications",
                "row": {
                    "loan_number": loan_number,
                    "status": "processing",
                    "borrower_request": user_message[:240],
                },
            },
        ),
        call_mcp_server(
            LOAN_PROCESSING_AGENT,
            "Email",
            "send_email",
            {
                "to": ["borrower@acme.example"],
                "subject": f"Loan update for {loan_number}",
                "body": "Your loan request is being reviewed by the Loan Processing Agent.",
            },
        ),
    )

    response = (
        f"{LOAN_PROCESSING_AGENT['name']} handled this request with model {LOAN_PROCESSING_AGENT['model']}.\n\n"
        f"Loan reference: {loan_number}\n"
        f"Borrower request: {user_message or 'No user message provided.'}\n\n"
        f"File summary:\n{file_summary}\n\n"
        f"MCP activity:\n{format_mcp_activity(mcp_activity)}"
    )

    return {
        "response": response,
        "agent": LOAN_PROCESSING_AGENT["name"],
        "model": LOAN_PROCESSING_AGENT["model"],
        "mcp_activity": mcp_activity,
    }
