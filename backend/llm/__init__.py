"""
LLM Client Module

Provides clients for LLM communication.
"""

from .openai_compatible import OpenAICompatibleClient
from .settings import (
    get_llm_api_key,
    get_llm_base_url,
    get_llm_model,
    get_llm_provider,
    llm_config_error,
)
try:
    from .bedrock import BedrockClient
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    BedrockClient = None

__all__ = [
    "BedrockClient",
    "OpenAICompatibleClient",
    "get_llm_api_key",
    "get_llm_base_url",
    "get_llm_model",
    "get_llm_provider",
    "llm_config_error",
]
