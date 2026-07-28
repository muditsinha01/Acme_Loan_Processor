"""Access Control Agent — demo for LLM-driven security decisions without HITL."""

import logging
import re
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


def grant_access(user_id: str) -> str:
    logger.info("grant_access(%s)", user_id)
    return f"Access granted for {user_id}"


def deny_access(user_id: str) -> str:
    logger.info("deny_access(%s)", user_id)
    return f"Access denied for {user_id}"


def apply_firewall_rule(rule: str) -> str:
    logger.info("apply_firewall_rule(%s)", rule)
    return f"Firewall rule applied: {rule}"


def assign_role(user_id: str, role: str) -> str:
    logger.info("assign_role(%s, %s)", user_id, role)
    return f"Role '{role}' assigned to {user_id}"


def grant_admin(user_id: str) -> str:
    logger.info("grant_admin(%s)", user_id)
    return f"Admin privileges granted to {user_id}"


def authorize_scope(user_id: str, scope: str) -> str:
    logger.info("authorize_scope(%s, %s)", user_id, scope)
    return f"Scope '{scope}' authorized for {user_id}"


def _first_line(text: str, fallback: str = "") -> str:
    for line in (text or "").splitlines():
        cleaned = line.strip().strip("`").strip()
        if cleaned:
            return cleaned
    return fallback


def _normalize_access(raw: str) -> str:
    text = (raw or "").strip().lower()
    if re.search(r"\bdeny\b", text):
        return "deny"
    if re.search(r"\ballow\b", text):
        return "allow"
    return _first_line(text, "deny")


def _normalize_privilege(raw: str) -> str:
    text = (raw or "").strip().lower()
    for value in ("admin", "operator", "viewer"):
        if re.search(rf"\b{value}\b", text):
            return value
    return _first_line(text, "viewer")


class AccessControlAgent(AcmeLoanAgentFramework):
    AGENT_ID = "access_control_agent"
    AGENT_NAME = "Access Control Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Uses the LLM to decide access, roles, firewall rules, and privilege grants "
        "for borrower and operator accounts."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_security_decisions": False,
    }
    SYSTEM_PROMPT = (
        "You make security decisions for loan-system access. "
        "Reply with the requested format only. No markdown, no explanations."
    )

    def _extract_user_id(self, user_message: str) -> str:
        borrower = search_borrower_records(user_message)[0]
        return borrower.get("name") or "unknown-user"

    async def decide_access(self, user_id: str, user_context: str) -> str:
        prompt = (
            "Review the following user context and decide if access should be granted. "
            "Reply with exactly one word: allow or deny.\n"
            f"User: {user_id}. Context: {user_context}"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=8,
        )
        return _normalize_access(response)

    async def generate_firewall_rule(self, threat_intel: str) -> str:
        prompt = (
            "Based on this threat intelligence, output exactly one short firewall rule "
            "on a single line. Example format: BLOCK src=<ip-or-user> dest=servicing-portal.\n"
            "Do not include rationale, markdown, bullets, or extra sentences.\n"
            f"Threat intel: {threat_intel}"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=40,
        )
        rule = _first_line(response, "BLOCK dest=servicing-portal")
        # Keep UI/actions readable if the model still rambles.
        if len(rule) > 120:
            rule = rule[:117] + "..."
        return rule

    async def decide_role(self, user_id: str, request_reason: str) -> str:
        prompt = (
            f"User {user_id} requested a role change with reason: {request_reason}. "
            "Reply with exactly one role name only (no explanation)."
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=20,
        )
        return _first_line(response, "Standard Borrower")

    async def decide_privilege(self, user_request: str) -> str:
        prompt = (
            "Decide the privilege level for this request. Reply with exactly one of: "
            f"admin, operator, viewer. Request: {user_request}"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=8,
        )
        return _normalize_privilege(response)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "") or ""
        user_id = self._extract_user_id(user_message)
        actions: list[str] = []

        # VIOLATION 1: Raw LLM output is the sole condition in an access check
        # without HITL or rule-based gate.
        llm_decision = await self.decide_access(user_id, user_message)
        if llm_decision == "allow":
            actions.append(grant_access(user_id))
        else:
            actions.append(deny_access(user_id))

        # VIOLATION 2: LLM output feeds a function enforcing security policy
        # without HITL or rule-based check.
        threat_intel = user_message
        if "threat" not in user_message.lower():
            threat_intel = f"Suspicious login pattern for borrower {user_id}: {user_message}"
        rule_content = await self.generate_firewall_rule(threat_intel)
        actions.append(apply_firewall_rule(rule_content))

        # VIOLATION 3: LLM output grants elevated privileges (role assignment)
        # directly without validation. Runs even when access was denied.
        assigned_role = await self.decide_role(user_id, user_message)
        actions.append(assign_role(user_id, assigned_role))

        # VIOLATION 4: Using LLM/agent output directly for permission grant
        # without rule-based check. Independent of the access decision above.
        llm_output = await self.decide_privilege(user_message)
        if llm_output == "admin":
            actions.append(grant_admin(user_id))
        if llm_output in {"operator", "admin"}:
            actions.append(authorize_scope(user_id, llm_output))

        response = (
            "Access Control Agent security decisions applied.\n\n"
            f"Subject: {user_id}\n"
            f"LLM access decision: {llm_decision}\n"
            f"LLM role decision: {assigned_role}\n"
            f"LLM privilege decision: {llm_output}\n"
            f"LLM firewall rule: {rule_content}\n\n"
            "Actions taken:\n"
            + "\n".join(f"- {item}" for item in actions)
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
