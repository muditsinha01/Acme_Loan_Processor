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
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
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
        return await self.call_bedrock_model(
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

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        pulled_skill = load_marketplace_fixture(self.SKILL_ID)
        skill_content = pulled_skill.get("content", "")
        skill_source = pulled_skill.get("source", "")
        skill_metadata = parse_skill_metadata(skill_content)
        skill_name = skill_metadata.get("name", self.SKILL_ID)
        skill_version = skill_metadata.get("version", "0.0.0")
        skill_description = skill_metadata.get("description", "")
        if not skill_description or skill_description in (">", "|"):
            skill_description = self.DESCRIPTION
        references = pulled_skill.get("references") or {}

        include_setup = _needs_setup_reference(user_message)
        system_prompt = self._skill_system_prompt(skill_content, include_setup, references)

        env = self._paperclip_env()
        env_status = (
            f"PAPERCLIP_API_URL={env['api_url'] or '<unset>'}\n"
            f"PAPERCLIP_COMPANY_ID={env['company_id'] or '<unset>'}\n"
            f"PAPERCLIP_API_KEY={'set' if env['api_key'] else '<unset>'}"
        )
        dashboard_json = self._fetch_dashboard(env)

        logger.info(
            "Paperclip board skill loaded into agent context",
            extra={
                "skill_id": self.SKILL_ID,
                "skill_name": skill_name,
                "skill_source": skill_source,
                "skill_bytes": len(skill_content),
                "setup_reference_loaded": include_setup,
            },
        )

        model_output = await self.call_agent_model(
            user_message, system_prompt, env_status, dashboard_json
        )

        response = (
            f"{model_output}\n\n"
            f"Skill applied: {skill_name} v{skill_version} "
            f"(source: {skill_source or 'marketplace_fixtures'})"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
            "workflow_status": "completed",
            "skill_used": True,
            "skill_content_bytes": len(skill_content),
            "skill_invocation": {
                "id": self.SKILL_ID,
                "name": skill_name,
                "version": skill_version,
                "description": skill_description,
                "source": skill_source,
                "status": "loaded" if pulled_skill.get("loaded") else "missing",
            },
        }


paperclip_board_agent = PaperclipBoardAgent()
