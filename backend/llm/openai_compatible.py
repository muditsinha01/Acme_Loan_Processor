"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""
# Copyright (c) Lineaje, Inc. All rights reserved.
# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id, self.reason = policy_id, reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))

def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur
    _log = _lg.getLogger("lineaje.gr_client")
    url = _os.environ.get("GR_SERVICE_URL", "")
    if not url:
        return data
    tid = tenant_id or _os.environ.get("GR_TENANT_ID", "")
    bearer = _os.environ.get("GR_BEARER_TOKEN") or _os.environ.get("LINEAJE_PAT_TOKEN") or _os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {"source_type": source_type, "destination_type": destination_type, params_key: {"data": data}}
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        _base = url.rstrip("/")
        if _base.lower().endswith("/enforce"): _base = _base[: -len("/enforce")].rstrip("/")
        req = _ur.Request(_base + "/enforce", data=_j.dumps(body).encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=timeout) as resp:
            result = _j.loads(resp.read())
    except Exception as exc:
        if isinstance(exc, _ue.HTTPError) and exc.code == 403:
            try: detail = _j.loads(exc.read()).get("detail", {})
            except Exception: detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _log.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _log.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _log.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)

import asyncio
import logging
import os
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


class OpenAICompatibleClient:
    """Minimal async wrapper around a chat-completions style API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        # Use OpenRouter credentials from the environment.
        self.base_url = (
            base_url
            or os.getenv("OPENROUTER_BASE_URL")
            or "https://openrouter.ai/api/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
    ) -> str:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=20,
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    try:
                        message = gr_check(message, "api", "agent", candidate_policies=['AI_APP_SEC_064', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_VULN_SEC_005'], site_id='site:sha256:73c7ae65179045b5518de53c90348c364df22d56308dc50e84af84ecec964a93')
                    except Exception as _gr_exc:
                        if type(_gr_exc).__name__ == "GRBlockedError": raise
                        message = message
                        __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked")
                    content = message.get("content", "")
                    if isinstance(content, str):
                        return content.strip()
                return f"Model API returned no content for model {model}."
            except requests.RequestException as exc:
                _lineaje_payload = "Model gateway request failed"
                try:
                    _lineaje_payload = gr_check(_lineaje_payload, "agent", "log", candidate_policies=['AI_APP_SEC_001', 'AI_APP_SEC_002', 'AI_APP_SEC_006', 'AI_APP_SEC_014', 'AI_APP_SEC_022', 'AI_APP_SEC_023', 'AI_APP_SEC_028', 'AI_APP_SEC_029', 'AI_APP_SEC_032', 'AI_APP_SEC_033', 'AI_APP_SEC_034', 'AI_APP_SEC_035', 'AI_APP_SEC_038', 'AI_APP_SEC_039', 'AI_APP_SEC_040', 'AI_APP_SEC_059', 'AI_APP_SEC_064', 'AI_APP_SEC_066', 'AI_APP_SEC_067', 'AI_APP_SEC_068', 'AI_APP_SEC_069', 'AI_APP_SEC_071', 'AI_APP_SEC_075', 'AI_APP_SEC_078', 'AI_DAT_SEC_001', 'AI_DAT_SEC_009', 'AI_DAT_SEC_010', 'AI_DAT_SEC_011', 'AI_DAT_SEC_012', 'AI_DAT_SEC_023', 'AI_DAT_SEC_024', 'AI_DAT_SEC_025', 'AI_DAT_SEC_027', 'AI_DAT_SEC_029', 'AI_DAT_SEC_030', 'AI_IAC_002', 'AI_IAC_006', 'AI_IAC_007', 'AI_IAC_008', 'AI_IAC_009', 'AI_IAC_014', 'AI_IAC_015', 'AI_IAC_016', 'AI_IAC_017', 'AI_IAC_018', 'AI_IAC_020', 'AI_IAC_022', 'AI_IAC_023', 'AI_IAC_024', 'AI_IAC_025', 'AI_IAC_026', 'AI_IAC_031', 'AI_VULN_SEC_005'], site_id='site:sha256:43f281407de8ee4454d2b0b7402c01a7036fee1885dc25855039e04b239fec1a')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError": raise
                    _lineaje_payload = _lineaje_payload
                    __import__("logging").getLogger("lineaje.gr_client").warning("Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked")
                logger.warning(
                    "Model gateway request failed",
                    extra={"model": model, "error": str(exc)},
                )
                return f"Model gateway unavailable for {model}: {exc}"

        return await asyncio.to_thread(_post)

    async def chat_vision(
        self,
        model: str,
        image_base64: str,
        mime_type: str,
        prompt: str,
        max_tokens: int = 500,
    ) -> str:
        """Send an image to a vision-capable model as an image_url content block."""
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime_type};base64,{image_base64}"},
                    },
                ],
            }
        ]
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
