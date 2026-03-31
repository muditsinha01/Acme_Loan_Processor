"""Support Agent class with explicit model invocation."""

import asyncio
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mock_database import PRETEND_VULNERABILITY_PAYLOAD
from .mcp_servers import call_mcp_server, format_mcp_activity


class SupportAgent(PolicyProbeAgentFramework):
    AGENT_ID = "support_agent"
    AGENT_NAME = "Support Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "llama 3.1 - 8b instruct"
    BEDROCK_MODEL_ID = "meta.llama3-1-8b-instruct-v1:0"
    DESCRIPTION = "Handles borrower and operator support tickets across external systems."
    MCP_SERVERS = ["ServiceNow", "Slack", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": False,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Resolve support requests quickly and sync updates across support tools."

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["external_system_credentials"] = {
            # Vulnerability: one agent holds broad credentials for multiple external systems.
            "Slack": {
                "Authorization": "Bearer xoxb-support-agent-full-workspace-token",
            },
            "ServiceNow": {
                "X-ServiceNow-User": "svc_support_agent",
                "X-ServiceNow-Password": "ServiceNowSuperPassword!2026",
            },
            "Email": {
                "X-Email-Username": "support.bot@acme.example",
                "X-Email-Password": "EmailPassword!2026",
            },
        }
        return metadata

    async def call_agent_model(self, user_message: str, case_number: str, encoded_payload: str = "") -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Support case: {case_number}\n"
                        f"Issue: {user_message or 'General support issue.'}\n\n"
                        f"Encoded payload:\n{encoded_payload or 'No encoded payload attached.'}\n\n"
                        "Draft a support response for the operations team."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        case_number = extract_reference_number(user_message, prefix="CASE")
        wants_base64_demo = any(
            keyword in (user_message or "").lower()
            for keyword in ["base64", "encoded", "vulnerability", "download demo", "pretend vuln"]
        )
        encoded_payload = PRETEND_VULNERABILITY_PAYLOAD if wants_base64_demo else ""
        model_output = await self.call_agent_model(user_message, case_number, encoded_payload=encoded_payload)
        agent_metadata = self.to_dict()

        mcp_calls = [
            call_mcp_server(
                agent_metadata,
                "ServiceNow",
                "create_incident",
                {
                    "short_description": f"Support request {case_number}",
                    "description": user_message or "General support issue reported by the borrower.",
                    "priority": "2",
                },
            ),
            call_mcp_server(
                agent_metadata,
                "Slack",
                "post_message",
                {
                    "channel": "#loan-support",
                    "text": f"Support Agent opened {case_number}: {user_message[:180]}",
                },
            ),
            call_mcp_server(
                agent_metadata,
                "Email",
                "send_email",
                {
                    "to": ["support-team@acme.example"],
                    "subject": f"Support follow-up {case_number}",
                    "body": user_message or "A support request needs review.",
                },
            ),
        ]
        if wants_base64_demo:
            mcp_calls.append(
                call_mcp_server(
                    agent_metadata,
                    "Slack",
                    "download_demo_package",
                    {
                        "package_name": "demo-rce-playbook",
                        "encoded_payload": PRETEND_VULNERABILITY_PAYLOAD,
                        "note": "Pretend vulnerability package for scanner and UI demos only.",
                    },
                )
            )

        mcp_activity = await asyncio.gather(*mcp_calls)

        response = (
            f"{self.AGENT_NAME} handled this request using {self.FRAMEWORK_NAME}.\n"
            f"Bedrock API call used bedrock model={self.BEDROCK_MODEL_ID}.\n"
            f"Scanner-visible model label={self.MODEL_NAME}.\n\n"
            f"Support case: {case_number}\n"
            f"User issue: {user_message or 'No support issue provided.'}\n\n"
            f"Model output:\n{model_output}\n\n"
            f"MCP activity:\n{format_mcp_activity(mcp_activity)}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


support_agent = SupportAgent()
