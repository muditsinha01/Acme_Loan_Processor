"""Medical Hardship Agent — scan-only demo for missing clinical AI disclosures.

Loan servicers legitimately collect medical/disability documentation for
hardship forbearance requests. This agent drafts a clinical-sounding
assessment from that documentation with none of the disclosures healthcare AI
guidance requires: no upfront notice to the borrower that an AI produced the
assessment, and no statement that a human clinician/underwriter retains final
decision authority over the medical determination.
"""

from typing import Any

from .framework import AcmeLoanAgentFramework


class MedicalHardshipAgent(AcmeLoanAgentFramework):
    AGENT_ID = "medical_hardship_agent"
    AGENT_NAME = "Medical Hardship Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Drafts clinical-sounding hardship/disability assessments from borrower "
        "medical documentation submitted for loan forbearance review."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "ai_disclosure_to_patient": False,
        "human_clinician_authority_disclaimer": False,
    }
    SYSTEM_PROMPT = (
        "Review the borrower's submitted medical/disability documentation and "
        "produce a clinical hardship assessment with a diagnosis summary and "
        "a treatment/recovery outlook for the underwriting file."
    )
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, medical_notes: str) -> str:
        # Vulnerability: sends borrower-submitted medical documentation straight
        # into a clinical-assessment prompt with no pre-invocation disclosure
        # check that the borrower is interacting with an AI system.
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Borrower medical documentation:\n{medical_notes or 'No documentation provided.'}\n\n"
                        "Provide a diagnosis summary, treatment outlook, and a hardship "
                        "recommendation for the forbearance file."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        medical_notes = context.get("user_message", "")
        clinical_assessment = await self.call_agent_model(medical_notes)

        # Vulnerability: the clinical-sounding output is returned to the
        # borrower/underwriter with no "an AI generated this" notice and no
        # disclaimer that a human clinician retains final decision authority.
        response = (
            "Hardship forbearance clinical assessment:\n\n"
            f"{clinical_assessment}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


medical_hardship_agent = MedicalHardshipAgent()
