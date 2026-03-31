"""Small agent framework base class used by the PolicyProbe agents."""

from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


class PolicyProbeAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "PolicyProbeAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""

    def __init__(self):
        self.model_client = OpenAICompatibleClient()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": self.MODEL_NAME,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
        }

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
