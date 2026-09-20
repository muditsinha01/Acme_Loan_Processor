"""Shared LLM provider settings.

Supports OpenRouter (default) and local Ollama via its OpenAI-compatible API.
"""

import os

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OLLAMA_MODEL = "llama3.2"


def get_llm_provider() -> str:
    explicit = (os.getenv("LLM_PROVIDER") or "").strip().lower()
    if explicit in {"ollama", "openrouter"}:
        return explicit
    if (os.getenv("OLLAMA_MODEL") or os.getenv("OLLAMA_BASE_URL") or "").strip():
        return "ollama"
    return "openrouter"


def is_ollama() -> bool:
    return get_llm_provider() == "ollama"


def get_llm_base_url() -> str:
    if is_ollama():
        return (os.getenv("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_BASE_URL).rstrip("/")
    return (os.getenv("OPENROUTER_BASE_URL") or DEFAULT_OPENROUTER_BASE_URL).rstrip("/")


def get_llm_api_key() -> str:
    if is_ollama():
        return (os.getenv("OLLAMA_API_KEY") or os.getenv("OPENROUTER_API_KEY") or "ollama").strip()
    return (os.getenv("OPENROUTER_API_KEY") or "").strip()


def get_llm_model() -> str:
    if is_ollama():
        return (
            os.getenv("OLLAMA_MODEL")
            or os.getenv("OPENROUTER_MODEL")
            or DEFAULT_OLLAMA_MODEL
        ).strip()
    return (os.getenv("OPENROUTER_MODEL") or "").strip()


def get_llm_timeout() -> int:
    raw = (os.getenv("LLM_TIMEOUT") or "").strip()
    if raw.isdigit():
        return int(raw)
    return 180 if is_ollama() else 20


def llm_config_error() -> str | None:
    model = get_llm_model()
    if is_ollama():
        if not model:
            return "LLM service not configured. Please set OLLAMA_MODEL."
        return None
    if not get_llm_api_key():
        return "LLM service not configured. Please set OPENROUTER_API_KEY or switch to Ollama (LLM_PROVIDER=ollama)."
    if not model:
        return "LLM service not configured. Please set OPENROUTER_MODEL."
    return None
