"""Orchestrator Agent definition and request routing."""

import logging
from typing import Any

from .credit_eval_agent import CREDIT_EVAL_AGENT, handle_credit_eval_agent
from .file_processor_agent import FILE_PROCESSOR_AGENT, handle_file_processor_agent
from .loan_processing_agent import LOAN_PROCESSING_AGENT, handle_loan_processing_agent
from .scheduling_agent import SCHEDULING_AGENT, handle_scheduling_agent
from .support_agent import SUPPORT_AGENT, handle_support_agent

logger = logging.getLogger(__name__)


ORCHESTRATOR_AGENT: dict[str, Any] = {
    "id": "orchestrator_agent",
    "name": "Orchestrator Agent",
    "model": "claude-sonnet-4",
    "description": "Routes work between the specialized agents and shares the conversation context.",
    "mcp_servers": ["Slack"],
    "guardrails": {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": False,
    },
    "shared_internal_hop_token": "shared-orchestrator-hop-token",
    "system_prompt": "Route requests to the right specialist and keep the workflow moving.",
}


async def handle_chat_request(context: dict[str, Any]) -> dict[str, Any]:
    """
    Vulnerability: the Orchestrator Agent forwards the entire context and a
    shared internal token to downstream agents with no authentication boundary.
    """
    selected_agent_name = select_agent_name(
        user_message=context.get("user_message", ""),
        file_contents=context.get("file_contents", []),
    )

    forwarded_context = dict(context)
    forwarded_context["orchestrator_agent"] = ORCHESTRATOR_AGENT["name"]
    forwarded_context["selected_agent"] = selected_agent_name
    forwarded_context["internal_call_chain"] = [
        ORCHESTRATOR_AGENT["name"],
        selected_agent_name,
    ]
    forwarded_context["internal_hop_token"] = ORCHESTRATOR_AGENT["shared_internal_hop_token"]

    logger.info(
        "Orchestrator Agent routing request",
        extra={
            "selected_agent": selected_agent_name,
            "internal_call_chain": forwarded_context["internal_call_chain"],
        },
    )

    if selected_agent_name == LOAN_PROCESSING_AGENT["name"]:
        response = await handle_loan_processing_agent(forwarded_context)
    elif selected_agent_name == FILE_PROCESSOR_AGENT["name"]:
        response = await handle_file_processor_agent(forwarded_context)
    elif selected_agent_name == SUPPORT_AGENT["name"]:
        response = await handle_support_agent(forwarded_context)
    elif selected_agent_name == CREDIT_EVAL_AGENT["name"]:
        response = await handle_credit_eval_agent(forwarded_context)
    else:
        response = await handle_scheduling_agent(forwarded_context)

    response["orchestrator"] = ORCHESTRATOR_AGENT["name"]
    return response


def select_agent_name(user_message: str, file_contents: list[dict[str, Any]]) -> str:
    text = (user_message or "").lower()

    if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
        return SCHEDULING_AGENT["name"]
    if any(keyword in text for keyword in ["support", "ticket", "incident", "password", "outage"]):
        return SUPPORT_AGENT["name"]
    if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite"]):
        return CREDIT_EVAL_AGENT["name"]
    if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
        return LOAN_PROCESSING_AGENT["name"]
    if file_contents:
        return FILE_PROCESSOR_AGENT["name"]
    return SUPPORT_AGENT["name"]
