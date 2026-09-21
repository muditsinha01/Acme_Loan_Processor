"""Loan Processing Agent class with explicit model invocation."""
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


import asyncio
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "deepseek/deepseek-r1"
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        return await self.call_openrouter_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        file_summary = build_file_summary(context.get("file_contents", []))
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        # LINEAJE: enforce() `file_summary` at skill_manifest->skill_check skill_check — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:fa158a8b84990b9a6cd95c1adf2b1261928379f0bd0deee9c503fd152a9e5bf2'
        _lineaje_file_summary_evidence = {'file_summary': file_summary, 'skill_id': str(file_summary), 'project': 'source-code'}
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:fa158a8b84990b9a6cd95c1adf2b1261928379f0bd0deee9c503fd152a9e5bf2', phase='skill_check', boundary={'source': 'skill_manifest', 'sink': 'skill_check'}, candidate_policies=[{'policy_id': 'AI_SKILL_DAT_SEC_001', 'guardrail_id': 'Block Data-Exfiltrating Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_001', 'guardrail_id': 'Block Malicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_002', 'guardrail_id': 'Block Suspicious Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_003', 'guardrail_id': 'Block Pending-Scan Skills', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_SKILL_SEC_004', 'guardrail_id': 'Warn Unscanned Skills', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='skill_manifest', destination_type='skill_check')
        try:
            _lineaje_file_summary_evidence = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_file_summary_evidence, content_type='application/json'))
            file_summary = _lineaje_file_summary_evidence.get('file_summary', file_summary) if isinstance(_lineaje_file_summary_evidence, dict) else file_summary
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        model_output = await self.call_agent_model(user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        )

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request: {user_message or 'No user message provided.'}\n\n"
            f"Loan summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()
