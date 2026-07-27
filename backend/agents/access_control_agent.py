"""Access Control Agent — LLM security decisions gated by HITL + allowlists."""

import logging
import re
from typing import Any

from .framework import PolicyProbeAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)

# AI_APP_SEC_068: hardcoded allowlists for rule-based secondary validation.
ALLOWED_ACCESS_VALUES = frozenset({"allow", "deny"})
ALLOWED_ROLE_VALUES = frozenset({"viewer", "operator", "underwriter", "servicing"})
ALLOWED_PRIVILEGE_VALUES = frozenset({"viewer", "operator", "admin"})
ALLOWED_FIREWALL_RULE_VALUES = frozenset(
    {"block_suspicious_login", "alert_security_team", "monitor_only"}
)


class SecurityError(Exception):
    """Raised when LLM output fails allowlist validation for a security decision."""


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


def _looks_like_llm_failure(text: str) -> bool:
    lowered = (text or "").lower()
    return any(
        marker in lowered
        for marker in (
            "error",
            "not configured",
            "failed",
            "unable",
            "exception",
            "timeout",
        )
    )


def _enforce_allowlist(decision: str, value: str, allowed: frozenset[str]) -> str:
    normalized = (value or "").strip().lower()
    # Prefer an exact allowlisted token appearing in free-form LLM text.
    for candidate in sorted(allowed, key=len, reverse=True):
        if re.search(rf"\b{re.escape(candidate)}\b", normalized):
            normalized = candidate
            break

    if normalized not in allowed:
        logger.error(
            "Allowlist rejected LLM security decision",
            extra={
                "decision": decision,
                "unexpected_llm_output": value,
                "allowed_values": sorted(allowed),
            },
        )
        raise SecurityError(
            f"Allowlist rejected {decision}: unexpected LLM output {value!r}"
        )
    return normalized


class AccessControlAgent(PolicyProbeAgentFramework):
    AGENT_ID = "access_control_agent"
    AGENT_NAME = "Access Control Agent"
    VERSION = "1.0.1"
    MODEL_NAME = "deepseek r1"
    BEDROCK_MODEL_ID = "us.deepseek.r1-v1:0"
    DESCRIPTION = (
        "Uses the LLM to propose access, roles, firewall rules, and privilege grants "
        "for borrower and operator accounts, with HITL and allowlist gates."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_security_decisions": True,
    }
    SYSTEM_PROMPT = (
        "You make security decisions for loan-system access. Reply with the requested "
        "decision format only."
    )

    def __init__(self):
        super().__init__()
        # AI_APP_SEC_068: boolean HITL gate. Defaults to False.
        # Set to True only after a human approves the security decision.
        self.hitl_approved = False

    def _extract_user_id(self, user_message: str) -> str:
        borrower = search_borrower_records(user_message)[0]
        return borrower.get("name") or "unknown-user"

    async def decide_access(self, user_id: str, user_context: str) -> str:
        prompt = (
            "Review the following user context and decide if access should be granted. "
            "Reply strictly with 'allow' or 'deny'. "
            f"User: {user_id}. Context: {user_context}"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=20,
        )
        raw = (response or "").strip().lower()
        if _looks_like_llm_failure(raw):
            return "deny"
        return raw

    async def generate_firewall_rule(self, threat_intel: str) -> str:
        prompt = (
            "Based on this threat intelligence, choose exactly one firewall action. "
            "Reply with only one of: block_suspicious_login, alert_security_team, monitor_only. "
            f"Threat intel: {threat_intel}"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=30,
        )
        raw = (response or "").strip().lower()
        if _looks_like_llm_failure(raw):
            return "alert_security_team"
        return raw

    async def decide_role(self, user_id: str, request_reason: str) -> str:
        prompt = (
            f"User {user_id} requested a role change with reason: {request_reason}. "
            "Reply with exactly one role: viewer, operator, underwriter, or servicing."
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=20,
        )
        raw = (response or "").strip().lower()
        if _looks_like_llm_failure(raw):
            return "viewer"
        return raw

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
            max_tokens=20,
        )
        raw = (response or "").strip().lower()
        if _looks_like_llm_failure(raw):
            return "viewer"
        return raw

    def _apply_security_decisions(
        self,
        user_id: str,
        access_decision: str,
        role: str,
        privilege: str,
        firewall_rule: str,
        hitl_approved: bool,
    ) -> list[str]:
        # AI_APP_SEC_068 remediation: HITL boolean gate before any security-sensitive call.
        if not hitl_approved:
            raise SecurityError(
                "Blocked: hitl_approved is False. Implement HITL approval and set "
                "hitl_approved=True once a human approves."
            )

        actions: list[str] = []

        access_value = _enforce_allowlist("access", access_decision, ALLOWED_ACCESS_VALUES)
        if access_value == "allow":
            actions.append(grant_access(user_id))
        else:
            actions.append(deny_access(user_id))

        firewall_value = _enforce_allowlist(
            "firewall_rule",
            firewall_rule,
            ALLOWED_FIREWALL_RULE_VALUES,
        )
        actions.append(apply_firewall_rule(firewall_value))

        role_value = _enforce_allowlist("role", role, ALLOWED_ROLE_VALUES)
        actions.append(assign_role(user_id, role_value))

        privilege_value = _enforce_allowlist(
            "privilege",
            privilege,
            ALLOWED_PRIVILEGE_VALUES,
        )
        if privilege_value == "admin":
            actions.append(grant_admin(user_id))
        actions.append(authorize_scope(user_id, privilege_value))

        return actions

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "") or ""
        user_id = self._extract_user_id(user_message)

        # Boolean HITL gate defaults to False. Context may pass True only after human approval.
        hitl_approved = bool(context.get("hitl_approved", self.hitl_approved))

        llm_decision = await self.decide_access(user_id, user_message)
        threat_intel = user_message
        if "threat" not in user_message.lower():
            threat_intel = f"Suspicious login pattern for borrower {user_id}: {user_message}"
        rule_content = await self.generate_firewall_rule(threat_intel)
        assigned_role = await self.decide_role(user_id, user_message)
        llm_output = await self.decide_privilege(user_message)

        proposals = {
            "subject": user_id,
            "access": llm_decision,
            "role": assigned_role,
            "privilege": llm_output,
            "firewall_rule": rule_content,
        }

        if not hitl_approved:
            hitl_request = {
                "required": True,
                "approved": False,
                "policy_id": "AI_APP_SEC_068",
                "kind": "security_decision",
                "title": "Human approval required for access changes",
                "summary": (
                    f"The model proposed security changes for {user_id}. "
                    "Review the proposed decisions below. Approving will re-run the "
                    "request with hitl_approved=True and allowlist validation."
                ),
                "operations": [
                    {
                        "id": "access",
                        "label": f"Portal access decision: {llm_decision}",
                        "risk": "high",
                    },
                    {
                        "id": "role",
                        "label": f"Assign role: {assigned_role}",
                        "risk": "high",
                    },
                    {
                        "id": "privilege",
                        "label": f"Privilege level: {llm_output}",
                        "risk": "critical" if "admin" in llm_output else "high",
                    },
                    {
                        "id": "firewall",
                        "label": f"Firewall action: {rule_content}",
                        "risk": "medium",
                    },
                ],
                "proposals": proposals,
            }
            response = (
                "Access Control Agent paused for Human-in-the-Loop review.\n\n"
                f"Subject: {user_id}\n"
                f"Proposed access: {llm_decision}\n"
                f"Proposed role: {assigned_role}\n"
                f"Proposed privilege: {llm_output}\n"
                f"Proposed firewall action: {rule_content}\n\n"
                "No grant/deny/role/admin/firewall actions were executed.\n"
                "Implement a HITL approval flow and set hitl_approved=True once approved. "
                "Review and extend ALLOWED_*_VALUES allowlists for your decision domain, "
                "and route allowlist rejection logs to security monitoring."
            )
            return {
                "response": response,
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "hitl_approved": False,
                "hitl_request": hitl_request,
                "mcp_activity": [],
            }

        try:
            actions = self._apply_security_decisions(
                user_id=user_id,
                access_decision=llm_decision,
                role=assigned_role,
                privilege=llm_output,
                firewall_rule=rule_content,
                hitl_approved=hitl_approved,
            )
        except SecurityError as exc:
            logger.exception("Security decision blocked")
            return {
                "response": (
                    "Access Control Agent blocked the security decision.\n\n"
                    f"{exc}\n\n"
                    "No access, role, privilege, or firewall changes were applied."
                ),
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "framework": self.FRAMEWORK_NAME,
                "hitl_approved": True,
                "hitl_request": {
                    "required": False,
                    "approved": True,
                    "policy_id": "AI_APP_SEC_068",
                    "kind": "security_decision",
                    "title": "Security decision rejected",
                    "summary": str(exc),
                    "operations": [],
                    "status": "rejected",
                },
                "mcp_activity": [],
            }

        response = (
            "Access Control Agent applied decisions after HITL approval + allowlist checks.\n\n"
            f"Subject: {user_id}\n"
            f"Access decision: {llm_decision}\n"
            f"Role decision: {assigned_role}\n"
            f"Privilege decision: {llm_output}\n"
            f"Firewall action: {rule_content}\n\n"
            "Actions taken:\n"
            + "\n".join(f"- {item}" for item in actions)
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "hitl_approved": True,
            "hitl_request": {
                "required": False,
                "approved": True,
                "policy_id": "AI_APP_SEC_068",
                "kind": "security_decision",
                "title": "Security changes approved and applied",
                "summary": f"Allowlisted decisions were applied for {user_id}.",
                "operations": [
                    {"id": "done", "label": item, "risk": "info"} for item in actions
                ],
                "status": "approved",
            },
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
