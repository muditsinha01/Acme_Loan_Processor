"""HR Screening Agent — scan-only demo for facial recognition in employment decisions.

Not part of the loan-processing workflow. Exists in isolation to demonstrate
what an unguarded employment-decision path looks like: a facial-emotion/engagement
analysis score is folded directly into a promotion/termination recommendation
with no removal of the facial-recognition signal from the decision inputs.
"""

from typing import Any

from .framework import AcmeLoanAgentFramework


def analyze_facial_engagement_score(meeting_frame_ref: str) -> float:
    """
    Vulnerability: facial recognition / facial-emotion analysis used as a
    direct input signal to an employment decision (promotion, termination,
    performance evaluation).
    """
    deterministic_seed = sum(ord(char) for char in (meeting_frame_ref or "frame"))
    return round((deterministic_seed % 100) / 100, 2)


class HrScreeningAgent(AcmeLoanAgentFramework):
    AGENT_ID = "hr_screening_agent"
    AGENT_NAME = "HR Screening Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = (
        "Prototype integration that scores recorded meeting engagement and "
        "feeds the result into promotion/termination recommendations."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "facial_recognition_removed_from_employment_decisions": False,
    }
    SYSTEM_PROMPT = (
        "Summarize the employee's performance review using the provided "
        "engagement score and recommend a promotion or termination outcome."
    )
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, employee_name: str, engagement_score: float) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Employee: {employee_name}\n"
                        f"Facial engagement score (from recorded meetings): {engagement_score}\n\n"
                        "Recommend promote, hold, or terminate based on this score."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=160,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        employee_name = context.get("user_message", "") or "Employee"

        # Vulnerability: facial recognition/emotion-analysis output is used as
        # a direct input to an employment decision workflow (hiring, promotion,
        # termination, or performance evaluation).
        engagement_score = analyze_facial_engagement_score(employee_name)
        model_output = await self.call_agent_model(employee_name, engagement_score)

        response = (
            f"Performance review for {employee_name}\n"
            f"Facial engagement score: {engagement_score}\n\n"
            f"Recommendation:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


hr_screening_agent = HrScreeningAgent()
