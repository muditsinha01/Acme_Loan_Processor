"""Small agent framework base class used by the Acme Loan Processor agents."""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m


import os
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


class AcmeLoanAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "AcmeLoanAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    # Per-agent OpenRouter model override. When set, this agent calls (and
    # reports) this specific model instead of the global OPENROUTER_MODEL from
    # .env. This is how different demo agents run on different models — e.g. an
    # approved model (meta-llama/llama-4-scout) vs a disallowed one
    # (deepseek/deepseek-r1). Leave as None to fall back to the env default.
    OPENROUTER_MODEL: str | None = None
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        # Runtime LLM calls use OpenRouter credentials from .env:
        # OPENROUTER_API_KEY and OPENROUTER_MODEL.
        self.model_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def resolve_model(self) -> str:
        """Effective OpenRouter model for this agent: per-agent override first,
        then the global OPENROUTER_MODEL from .env, then the declared MODEL_NAME.
        """
        return (self.OPENROUTER_MODEL or os.getenv("OPENROUTER_MODEL") or self.MODEL_NAME or "").strip()

    def to_dict(self) -> dict[str, Any]:
        effective_model = self.resolve_model()
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": effective_model,
            "provider": "OpenRouter",
            "openrouter_model": effective_model,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    async def call_openrouter_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        """Call OpenRouter using OPENROUTER_API_KEY and this agent's effective
        model (per-agent OPENROUTER_MODEL override, else the .env default)."""
        api_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
        model = self.resolve_model()
        if not api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        # LINEAJE: enforce() `messages` at agent->llm pre_model — scan flagged AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:a09b7687f3f7bbf5807035fcc09fc2ccac761ff3bc156879330040796cfe26d6'
        _lineaje_messages_evidence = {'messages': messages, 'model': model}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a09b7687f3f7bbf5807035fcc09fc2ccac761ff3bc156879330040796cfe26d6', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm')
        try:
            _lineaje_messages_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_messages_evidence, content_type='application/json'))
            messages = _lineaje_messages_evidence.get('messages', messages) if isinstance(_lineaje_messages_evidence, dict) else messages
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        return await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
