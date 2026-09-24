"""
Acme Loan Processor Backend - FastAPI Application

This entry point exposes the vulnerable multi-agent loan workflow used by the
demo UI. The backend now routes through a central agent catalog so the agent
names, model names, and MCP server names are easy to inspect in source.
"""
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
import base64
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agents.runtime import build_catalog, handle_chat_request, process_file_attachment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
MCP_CALL_LOG: list[dict] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    yield


app = FastAPI(
    title="Acme Loan Processor",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class SkillInvocation(BaseModel):
    id: str
    name: str
    version: str
    description: str
    status: str
    source: Optional[str] = None
    scan_status: Optional[str] = None


class WorkflowStage(BaseModel):
    id: str
    label: str
    duration_ms: int


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None
    workflow_status: Optional[str] = None
    agent: Optional[str] = None
    skill_invocation: Optional[SkillInvocation] = None
    skill_used: Optional[bool] = None
    skill_content_bytes: Optional[int] = None
    workflow_stages: Optional[list[WorkflowStage]] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "acme-loan-processor"}


async def _process_chat(request: ChatRequest) -> dict:
    """Core chat processing shared by the synchronous /chat endpoint and the
    background job endpoints below. Returns {"ok": True, ...ChatResponse
    fields} on success, or {"ok": False, "detail": ..., "policy_error": ...}
    on failure — never raises, so callers running this as a background task
    don't need their own top-level try/except.
    """
    try:
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                _lineaje_payload = "Processing attachment"
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:aed017d73aac0941ea66e85c48af29dff69f97a3255f868fef74c571609e0b12'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:aed017d73aac0941ea66e85c48af29dff69f97a3255f868fef74c571609e0b12', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[], fail_mode='BLOCK', source_type='agent', destination_type='log')
                try:
                    _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.info(
                    _lineaje_payload,
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        "request_context": {
                            "message": request.message,
                            "attachment_content_preview": attachment.content[:100] if attachment.content else None
                        }
                    }
                )

                _lineaje_content = attachment.content
                # LINEAJE: enforce() `_lineaje_content` at file_storage->agent file_upload — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:91db1bc558a436d9deb8471280beb5884fb420f60c7bcfdcd5bb9b63c1c0180e'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:91db1bc558a436d9deb8471280beb5884fb420f60c7bcfdcd5bb9b63c1c0180e', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent')
                try:
                    _lineaje_content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_content, content_type='application/json'))
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    raise
                processed = await process_file_attachment(
                    content=_lineaje_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append(processed)

        context = {
            "user_message": request.message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
        }

        response = await handle_chat_request(context)

        return {
            "ok": True,
            "response": response.get("response", "I processed your request."),
            "conversation_id": request.conversation_id,
            "policy_warning": response.get("policy_warning"),
            "workflow_status": response.get("workflow_status"),
            "agent": response.get("agent"),
            "skill_used": response.get("skill_used"),
            "skill_content_bytes": response.get("skill_content_bytes"),
            "workflow_stages": response.get("workflow_stages"),
            "skill_invocation": response.get("skill_invocation"),
        }

    except Exception as e:
        _lineaje_payload = "Error processing chat request"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:a44946f648d5d48924deb25f40836d5f2a1c36ef2327e62f26877e73d2b91c4e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a44946f648d5d48924deb25f40836d5f2a1c36ef2327e62f26877e73d2b91c4e', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.exception(
            _lineaje_payload,
            extra={
                # VULNERABILITY: Error context includes full state
                "error": str(e),
                "request_state": {
                    "message": request.message,
                    "attachments": [a.dict() for a in request.attachments] if request.attachments else None
                }
            }
        )
        return {
            "ok": False,
            "detail": "An error occurred processing your request",
            "policy_error": {
                "type": "general",
                "message": str(e)
            },
        }


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the File Processor Agent
    3. Routes the request through the Orchestrator Agent
    4. Returns the agent response

    Guardrail checks in this pipeline can each take several seconds, and a
    slow/unreachable GR service can push total request time past 30s — long
    enough for a dev-mode --reload restart or a proxy to drop the
    connection mid-request. Prefer POST /chat/jobs + GET /chat/jobs/{id}
    (polling) for UI use; this endpoint stays for direct/API callers.
    """
    result = await _process_chat(request)
    if not result["ok"]:
        _lineaje_content = {"detail": result["detail"], "policy_error": result["policy_error"]}
        # LINEAJE: enforce() `_lineaje_content` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:582d2d1385b63954e18458bee29d247d38623c6e5eaf462d773084f63beb7656'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:582d2d1385b63954e18458bee29d247d38623c6e5eaf462d773084f63beb7656', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            _lineaje_content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_content, content_type='text/plain'))
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return JSONResponse(
            status_code=500,
            content=_lineaje_content,
        )
    return ChatResponse(
        response=result["response"],
        conversation_id=result["conversation_id"],
        policy_warning=result["policy_warning"],
        workflow_status=result["workflow_status"],
        agent=result["agent"],
        skill_used=result["skill_used"],
        skill_content_bytes=result["skill_content_bytes"],
        workflow_stages=(
            [WorkflowStage(**stage) for stage in result["workflow_stages"]]
            if result["workflow_stages"]
            else None
        ),
        skill_invocation=(
            SkillInvocation(**result["skill_invocation"]) if result["skill_invocation"] else None
        ),
    )


# In-memory job store for the polling flow below. Fine for this single-process
# demo backend; a process restart (e.g. uvicorn --reload) loses pending jobs,
# which the client treats as "job not found" and resubmits.
_CHAT_JOBS: dict[str, dict] = {}


class ChatJobStartResponse(BaseModel):
    job_id: str


async def _run_chat_job(job_id: str, request: ChatRequest) -> None:
    result = await _process_chat(request)
    if result["ok"]:
        _CHAT_JOBS[job_id] = {"status": "done", **{k: v for k, v in result.items() if k != "ok"}}
    else:
        _CHAT_JOBS[job_id] = {
            "status": "error",
            "detail": result["detail"],
            "policy_error": result["policy_error"],
        }


@app.post("/chat/jobs", response_model=ChatJobStartResponse)
async def start_chat_job(request: ChatRequest):
    """Start chat processing in the background and return a job id right away.

    Use this + GET /chat/jobs/{job_id} to poll instead of holding one long
    connection open through POST /chat.
    """
    job_id = str(uuid.uuid4())
    _CHAT_JOBS[job_id] = {"status": "pending"}
    asyncio.create_task(_run_chat_job(job_id, request))
    return ChatJobStartResponse(job_id=job_id)


@app.get("/chat/jobs/{job_id}")
async def get_chat_job(job_id: str):
    job = _CHAT_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown or expired job_id")
    # LINEAJE: enforce() `job` at agent->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:16b1dade4de3b023598262c219cb905db7031d17aef5d514b28ea0766b9dff1e'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:16b1dade4de3b023598262c219cb905db7031d17aef5d514b28ea0766b9dff1e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
    try:
        job = _gr_client.enforce(_gr_site, job, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return job


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.
    """
    content = await file.read()
    if (file.content_type or "").startswith("image/") or file.content_type in {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }:
        processed_content = base64.b64encode(content).decode("utf-8")
    else:
        processed_content = content.decode("utf-8", errors="ignore")

    # LINEAJE: enforce() `processed_content` at file_storage->agent file_upload — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_070 (Detect and block all forms of prompt injection attacks in user inputs and file contents). Mask/block; do not remove without review. site_id='site:sha256:69cc0cd647c891bde403a5a8db856ac366d5257a2cf64af808f4638764db7cdc'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:69cc0cd647c891bde403a5a8db856ac366d5257a2cf64af808f4638764db7cdc', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, candidate_policies=[{'policy_id': 'AI_APP_SEC_070', 'guardrail_id': 'Sanitize Prompt Injection', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='file_storage', destination_type='agent')
    try:
        processed_content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, processed_content, content_type='application/json'))
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        raise
    processed = await process_file_attachment(
        content=processed_content,
        filename=file.filename,
        content_type=file.content_type
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed.get("extracted_content", "")[:500] if processed else None,
        "agent": processed.get("agent"),
        "model": processed.get("model"),
    }


@app.post("/mock-mcp/{server_key}")
async def mock_mcp_server(server_key: str, request: Request):
    """
    Local mock MCP server endpoint used by the demo agents.

    These handlers intentionally accept broad payloads so the insecure agent
    flows can be exercised end-to-end without external infrastructure.
    """
    payload = await request.json()
    params = payload.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})
    response_payload = _handle_mock_mcp_call(server_key, tool_name, arguments)
    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": response_payload,
    }


@app.get("/catalog")
async def get_catalog():
    """Expose the current agent and MCP server catalog to the UI."""
    return build_catalog()


@app.get("/agents")
async def get_agents():
    """Compatibility alias for agent catalog inspection."""
    return build_catalog()


@app.get("/mcp-servers")
async def get_mcp_servers():
    """Compatibility alias for MCP server catalog inspection."""
    catalog = build_catalog()
    return {"mcp_servers": catalog.get("mcp_servers", [])}


def _handle_mock_mcp_call(server_key: str, tool_name: str, arguments: dict) -> dict:
    # LINEAJE: enforce() `arguments` at agent->external data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.). Mask/block; do not remove without review. site_id='site:sha256:bf48fb8df6f3c4a33e73ddda7b49947aa2e1038fdb73f8076a7236e8b782a9f3'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:bf48fb8df6f3c4a33e73ddda7b49947aa2e1038fdb73f8076a7236e8b782a9f3', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external')
    try:
        arguments = _gr_client.enforce(_gr_site, arguments, content_type='application/json', variable_name='arguments', source_file=__file__, before_line=347)
    except _gr_client.GuardrailUnavailableError:
        pass
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "server_key": server_key,
        "tool_name": tool_name,
        "arguments": arguments,
        "timestamp": timestamp,
    }
    MCP_CALL_LOG.append(log_entry)

    if server_key == "slack" and tool_name == "slack.post_message":
        return {
            "server": "Slack",
            "posted": True,
            "channel": arguments.get("channel", "#general"),
            "text": arguments.get("text", ""),
            "timestamp": timestamp,
        }

    if server_key == "slack" and tool_name == "slack.download_demo_package":
        encoded_payload = arguments.get("encoded_payload", "")
        try:
            decoded_payload = base64.b64decode(encoded_payload).decode("utf-8")
        except Exception:
            decoded_payload = "Unable to decode demo payload."
        return {
            "server": "Slack",
            "downloaded": True,
            "package_name": arguments.get("package_name", "demo-package"),
            "pretend_download_path": "/tmp/demo-rce-playbook.txt",
            "decoded_payload": decoded_payload,
            "timestamp": timestamp,
        }

    if server_key == "servicenow" and tool_name == "servicenow.create_incident":
        return {
            "server": "ServiceNow",
            "incident_number": f"INC{len(MCP_CALL_LOG):06d}",
            "short_description": arguments.get("short_description", ""),
            "status": "created",
            "timestamp": timestamp,
        }

    if server_key == "email" and tool_name == "email.send_message":
        return {
            "server": "Email",
            "message_id": f"email-{len(MCP_CALL_LOG):06d}",
            "to": arguments.get("to", []),
            "subject": arguments.get("subject", ""),
            "status": "queued",
            "timestamp": timestamp,
        }

    if server_key == "excel" and tool_name == "excel.upsert_row":
        return {
            "server": "Excel",
            "workbook": arguments.get("workbook", ""),
            "worksheet": arguments.get("worksheet", ""),
            "row": arguments.get("row", {}),
            "status": "upserted",
            "timestamp": timestamp,
        }

    if server_key == "docx" and tool_name == "docx.create_document":
        return {
            "server": "Docx",
            "document_id": f"docx-{len(MCP_CALL_LOG):06d}",
            "document_title": arguments.get("document_title", ""),
            "document_body_preview": arguments.get("document_body", "")[:300],
            "status": "generated",
            "timestamp": timestamp,
        }

    if server_key == "google-calendar" and tool_name == "google_calendar.create_event":
        return {
            "server": "Google Calendar",
            "event_id": f"gcal-{len(MCP_CALL_LOG):06d}",
            "title": arguments.get("title", ""),
            "start": arguments.get("start", ""),
            "end": arguments.get("end", ""),
            "status": "scheduled",
            "timestamp": timestamp,
        }

    return {
        "server": server_key,
        "tool": tool_name,
        "status": "unsupported",
        "raw_arguments": json.dumps(arguments),
        "timestamp": timestamp,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)
