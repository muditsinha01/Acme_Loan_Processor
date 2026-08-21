"""Lab Automation Agent — scan-only demo for missing CBRN misuse-prevention checks.

Not part of the loan-processing workflow. Exists in isolation to demonstrate
what an unguarded lab-automation/synthesis request path looks like: a prompt
naming a nucleic acid sequence and a synthesis/lab-automation destination is
sent straight to the LLM and forwarded to a synthesis provider with no
nucleic-acid screening, biosecurity safeguard, or misuse-prevention check.
"""

from typing import Any

from .framework import AcmeLoanAgentFramework


class LabAutomationAgent(AcmeLoanAgentFramework):
    AGENT_ID = "lab_automation_agent"
    AGENT_NAME = "Lab Automation Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Prototype integration for routing sequence-synthesis and lab-automation "
        "requests to the LLM and on to a synthesis provider."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "nucleic_acid_sequence_screening": False,
        "cbrn_misuse_prevention": False,
    }
    SYSTEM_PROMPT = (
        "Help design and route nucleic acid synthesis and lab-automation "
        "requests to the configured synthesis provider."
    )
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, synthesis_request: str) -> str:
        # Vulnerability: the raw synthesis/lab-automation request text is sent
        # straight to the LLM with no nucleic-acid sequence screening or CBRN
        # misuse-prevention check beforehand.
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Synthesis / lab-automation request:\n{synthesis_request or 'No request provided.'}\n\n"
                        "Draft the synthesis order and lab-automation command sequence."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    def submit_synthesis_order(self, sequence_text: str, provider_endpoint: str) -> dict[str, Any]:
        # Vulnerability: submits directly to the synthesis provider with no
        # nucleic-acid sequence screening or biosecurity safeguard applied.
        return {
            "provider_endpoint": provider_endpoint,
            "sequence_submitted": bool(sequence_text),
            "screened": False,
        }

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        synthesis_request = context.get("user_message", "")
        model_output = await self.call_agent_model(synthesis_request)
        order_result = self.submit_synthesis_order(
            synthesis_request, "https://synthesis-provider.example/orders"
        )

        response = (
            "Lab automation request processed.\n\n"
            f"{model_output}\n\n"
            f"Order submitted: {order_result['sequence_submitted']} "
            f"(screened: {order_result['screened']})"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


lab_automation_agent = LabAutomationAgent()
