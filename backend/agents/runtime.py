"""Thin runtime registry that ties the separated agent files together."""

from copy import deepcopy
from typing import Any

from .credit_eval_agent import CREDIT_EVAL_AGENT
from .file_processor_agent import FILE_PROCESSOR_AGENT, process_file_attachment
from .loan_processing_agent import LOAN_PROCESSING_AGENT
from .mcp_servers import MCP_SERVERS
from .orchestrator_agent import ORCHESTRATOR_AGENT, handle_chat_request
from .scheduling_agent import SCHEDULING_AGENT
from .support_agent import SUPPORT_AGENT


AGENTS: dict[str, dict[str, Any]] = {
    LOAN_PROCESSING_AGENT["name"]: LOAN_PROCESSING_AGENT,
    FILE_PROCESSOR_AGENT["name"]: FILE_PROCESSOR_AGENT,
    SUPPORT_AGENT["name"]: SUPPORT_AGENT,
    CREDIT_EVAL_AGENT["name"]: CREDIT_EVAL_AGENT,
    ORCHESTRATOR_AGENT["name"]: ORCHESTRATOR_AGENT,
    SCHEDULING_AGENT["name"]: SCHEDULING_AGENT,
}


def build_catalog() -> dict[str, Any]:
    return {
        "agents": deepcopy(list(AGENTS.values())),
        "mcp_servers": deepcopy(list(MCP_SERVERS.values())),
    }
