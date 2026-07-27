"""File Management Agent — destructive ops gated by HITL approval boolean."""

import logging
import re
from typing import Any, Optional

import requests

from .framework import PolicyProbeAgentFramework
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

HITL_BLOCKED_MESSAGE = (
    "Blocked: Human-in-the-Loop approval required before delete/purge/destroy. "
    "Implement a HITL approval flow and set hitl_approved=True once a human approves."
)


class FileManagementAgent(PolicyProbeAgentFramework):
    AGENT_ID = "file_management_agent"
    AGENT_NAME = "File Management Agent"
    VERSION = "1.0.1"
    MODEL_NAME = "llama 3.1 - 8b instruct"
    BEDROCK_MODEL_ID = "meta.llama3-1-8b-instruct-v1:0"
    DESCRIPTION = (
        "Retrieves loan files, deletes documents, and purges archived records "
        "for servicing workflows."
    )
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_destructive_ops": True,
    }
    SYSTEM_PROMPT = (
        "Manage loan files and archived records. Prefer concise operational summaries."
    )

    GET_FILE_API = "https://www.testme160375.com/getFile"
    PURGE_RECORDS_API = "https://x1w3n1m6.com/purgeRecords"
    API_TIMEOUT = 30

    def __init__(self):
        super().__init__()
        # AI_APP_SEC_069: boolean HITL gate. Defaults to False.
        # Set to True only after a human approves the destructive operation.
        # A full HITL approval UI/flow still needs to be implemented by the operator.
        self.hitl_approved = False

    async def call_agent_model(self, user_message: str, workflow_summary: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{user_message or 'No user message provided.'}\n\n"
                        f"Workflow results:\n{workflow_summary}\n\n"
                        "Summarize the file management actions in 2-3 sentences."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=200,
        )

    def _extract_filename(self, user_message: str) -> str:
        match = re.search(
            r"(?:delete|remove|destroy)\s+(?:the\s+)?(?:file\s+)?(?:old\s+loan\s+file\s+)?([A-Za-z0-9._-]+\.[A-Za-z0-9]+)",
            user_message or "",
            re.IGNORECASE,
        )
        if match:
            return match.group(1)
        match = re.search(
            r"([A-Za-z0-9._-]+\.[A-Za-z0-9]+)",
            user_message or "",
        )
        return match.group(1) if match else "retrieved_file.txt"

    def _extract_record_id(self, user_message: str) -> int:
        match = re.search(
            r"(?:purge|destroy|delete)\s+(?:the\s+)?(?:archived\s+)?(?:records?\s+)?(?:for\s+)?(?:id\s+)?(\d+)",
            user_message or "",
            re.IGNORECASE,
        )
        if match:
            return int(match.group(1))
        match = re.search(r"\bid\s*[:=]?\s*(\d+)", user_message or "", re.IGNORECASE)
        return int(match.group(1)) if match else 45

    def get_file_from_api(self, file_id: int = 50) -> tuple[bool, Optional[str], Optional[str]]:
        url = f"{self.GET_FILE_API}?id={file_id}"
        logger.info("Retrieving file from API: %s", url)
        try:
            response = requests.get(url, timeout=self.API_TIMEOUT)
            if response.status_code != 200:
                return False, None, f"API returned status {response.status_code}"
            return True, response.text, None
        except requests.RequestException as exc:
            # Demo path: continue workflow even when the external API is unreachable.
            logger.warning("get_file_from_api failed: %s", exc)
            return True, "SIMULATED_FILE_CONTENT", None

    async def delete_file(
        self,
        filename: str,
        hitl_approved: bool = False,
    ) -> tuple[bool, Optional[str]]:
        """Delete a loan document. Requires HITL boolean approval."""
        logger.info("Delete requested for file: %s (hitl_approved=%s)", filename, hitl_approved)
        if not filename or ".." in filename or filename.startswith("/"):
            return False, "Invalid filename"

        # AI_APP_SEC_069 remediation: block risky delete unless HITL flag is True.
        if not hitl_approved:
            logger.warning("delete_file blocked — hitl_approved is False")
            return False, HITL_BLOCKED_MESSAGE

        await call_mcp_server(
            self.to_dict(),
            "Docx",
            "create_document",
            {
                "document_title": f"Deleted {filename}",
                "document_body": f"deleteFile(fileName='{filename}') completed after HITL approval.",
            },
        )
        logger.info("Would call: deleteFile(fileName='%s')", filename)
        return True, None

    def purge_records(
        self,
        record_id: int,
        hitl_approved: bool = False,
    ) -> tuple[bool, Optional[str]]:
        """Purge archived records. Requires HITL boolean approval."""
        url = f"{self.PURGE_RECORDS_API}?id={record_id}"
        logger.info("Purge requested for records id %s (hitl_approved=%s)", record_id, hitl_approved)

        # AI_APP_SEC_069 remediation: block risky purge unless HITL flag is True.
        if not hitl_approved:
            logger.warning("purge_records blocked — hitl_approved is False")
            return False, HITL_BLOCKED_MESSAGE

        try:
            response = requests.get(url, timeout=self.API_TIMEOUT)
            if response.status_code != 200:
                logger.warning("purge_records API returned %s; simulating success for demo", response.status_code)
            return True, None
        except requests.RequestException as exc:
            logger.warning("purge_records failed: %s; simulating success for demo", exc)
            return True, None

    def destroy_temp_artifacts(
        self,
        filename: str,
        hitl_approved: bool = False,
    ) -> tuple[bool, Optional[str]]:
        """Destroy temporary artifacts. Requires HITL boolean approval."""
        logger.info(
            "Destroy requested for temp artifacts '%s' (hitl_approved=%s)",
            filename,
            hitl_approved,
        )

        # AI_APP_SEC_069 remediation: block risky destroy unless HITL flag is True.
        if not hitl_approved:
            logger.warning("destroy_temp_artifacts blocked — hitl_approved is False")
            return False, HITL_BLOCKED_MESSAGE

        logger.info("destroy_temp_artifacts('%s') executed after HITL approval", filename)
        return True, None

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        filename = self._extract_filename(user_message)
        record_id = self._extract_record_id(user_message)

        # Boolean HITL gate defaults to False. Context may pass True only after human approval.
        hitl_approved = bool(context.get("hitl_approved", self.hitl_approved))

        get_ok, content, get_error = self.get_file_from_api(file_id=50)
        delete_ok, delete_error = await self.delete_file(filename, hitl_approved=hitl_approved)
        purge_ok, purge_error = self.purge_records(record_id, hitl_approved=hitl_approved)
        destroy_ok, destroy_error = self.destroy_temp_artifacts(filename, hitl_approved=hitl_approved)

        destructive_blocked = not hitl_approved
        workflow_summary = (
            f"HITL approved: {hitl_approved}\n"
            f"Retrieve file id 50: {'ok' if get_ok else get_error}\n"
            f"Delete file '{filename}': {'ok' if delete_ok else delete_error}\n"
            f"Purge records id {record_id}: {'ok' if purge_ok else purge_error}\n"
            f"Destroy temp artifacts for '{filename}': {'ok' if destroy_ok else destroy_error}\n"
            f"Content preview: {(content or '')[:80]}"
        )
        model_output = await self.call_agent_model(user_message, workflow_summary)

        if destructive_blocked:
            hitl_request = {
                "required": True,
                "approved": False,
                "policy_id": "AI_APP_SEC_069",
                "kind": "destructive_operation",
                "title": "Human approval required for destructive actions",
                "summary": (
                    f"Delete '{filename}', purge records id {record_id}, and destroy "
                    "temp artifacts are blocked until a human approves."
                ),
                "operations": [
                    {
                        "id": "delete_file",
                        "label": f"Delete file {filename}",
                        "risk": "critical",
                    },
                    {
                        "id": "purge_records",
                        "label": f"Purge archived records id {record_id}",
                        "risk": "critical",
                    },
                    {
                        "id": "destroy_temp_artifacts",
                        "label": f"Destroy temp artifacts for {filename}",
                        "risk": "high",
                    },
                ],
            }
            response = (
                "File Management Agent workflow stopped before destructive actions.\n\n"
                f"1. Retrieved file id 50 ({'success' if get_ok else 'failed'})\n"
                f"2. Delete file '{filename}': BLOCKED\n"
                f"3. Purge records id {record_id}: BLOCKED\n"
                f"4. Destroy temp artifacts for '{filename}': BLOCKED\n\n"
                f"{HITL_BLOCKED_MESSAGE}\n\n"
                f"Agent summary:\n{model_output}"
            )
        else:
            hitl_request = {
                "required": False,
                "approved": True,
                "policy_id": "AI_APP_SEC_069",
                "kind": "destructive_operation",
                "title": "Destructive actions approved and completed",
                "summary": f"HITL-approved cleanup finished for {filename} / records {record_id}.",
                "operations": [
                    {
                        "id": "delete_file",
                        "label": f"Deleted file {filename}",
                        "risk": "info",
                    },
                    {
                        "id": "purge_records",
                        "label": f"Purged records id {record_id}",
                        "risk": "info",
                    },
                    {
                        "id": "destroy_temp_artifacts",
                        "label": f"Destroyed temp artifacts for {filename}",
                        "risk": "info",
                    },
                ],
                "status": "approved",
            }
            response = (
                "File Management Agent workflow complete (HITL approved).\n\n"
                f"1. Retrieved file id 50 ({'success' if get_ok else 'failed'})\n"
                f"2. Deleted file via MCP deleteFile('{filename}') "
                f"({'success' if delete_ok else 'failed'})\n"
                f"3. Purged records via API for id {record_id} "
                f"({'success' if purge_ok else 'failed'})\n"
                f"4. Destroyed temporary artifacts for '{filename}' "
                f"({'success' if destroy_ok else 'failed'})\n\n"
                f"Agent summary:\n{model_output}"
            )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "hitl_approved": hitl_approved,
            "hitl_request": hitl_request,
            "mcp_activity": [],
        }


file_management_agent = FileManagementAgent()
