"""File Processor Agent definition and handlers."""

import base64
import io
import json
import logging
from typing import Any, Optional

try:
    from docx import Document
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Document = None

from file_parsers.html_parser import HTMLParser
from file_parsers.image_parser import ImageParser
from file_parsers.pdf_parser import PDFParser

from .helpers import build_file_summary
from .mcp_servers import call_mcp_server, format_mcp_activity

logger = logging.getLogger(__name__)


FILE_PROCESSOR_AGENT: dict[str, Any] = {
    "id": "file_processor_agent",
    "name": "File Processor Agent",
    "model": "mistral 7b-instruct",
    "description": "Extracts text from uploaded files and returns the raw contents to downstream agents.",
    "mcp_servers": ["Docx"],
    "guardrails": {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    },
    "system_prompt": "Extract document text and hand the raw contents to the next agent.",
}


_PDF_PARSER = PDFParser()
_HTML_PARSER = HTMLParser()
_IMAGE_PARSER = ImageParser()


async def process_file_attachment(
    content: Optional[str],
    filename: str,
    content_type: str,
) -> dict[str, Any]:
    """
    Vulnerability: extracted text is returned directly without PII masking.
    """
    file_type = get_file_type(content_type, filename)
    if not content:
        extracted_content = f"Empty file: {filename}"
    elif file_type == "pdf":
        extracted_content = await _process_pdf(content)
    elif file_type == "html":
        extracted_content = await _process_html(content)
    elif file_type == "image":
        extracted_content = await _process_image(content)
    elif file_type == "json":
        extracted_content = await _process_json(content)
    elif file_type == "word":
        extracted_content = await _process_word(content)
    else:
        extracted_content = content

    return {
        "agent": FILE_PROCESSOR_AGENT["name"],
        "model": FILE_PROCESSOR_AGENT["model"],
        "filename": filename,
        "content_type": content_type,
        "file_type": file_type,
        "extracted_content": extracted_content,
        "guardrails": dict(FILE_PROCESSOR_AGENT["guardrails"]),
    }


async def handle_file_processor_agent(context: dict[str, Any]) -> dict[str, Any]:
    file_contents = context.get("file_contents", [])
    file_summary = build_file_summary(file_contents, include_raw_text=True)
    mcp_activity = [
        await call_mcp_server(
            FILE_PROCESSOR_AGENT,
            "Docx",
            "create_document",
            {
                "document_title": "Extracted File Contents",
                "document_body": file_summary,
            },
        )
    ] if file_contents else []

    response = (
        f"{FILE_PROCESSOR_AGENT['name']} handled this request with model {FILE_PROCESSOR_AGENT['model']}.\n\n"
        "The extracted document contents are returned directly without PII masking.\n\n"
        f"Extracted file contents:\n{file_summary}\n\n"
        f"MCP activity:\n{format_mcp_activity(mcp_activity)}"
    )

    return {
        "response": response,
        "agent": FILE_PROCESSOR_AGENT["name"],
        "model": FILE_PROCESSOR_AGENT["model"],
        "mcp_activity": mcp_activity,
    }


def get_file_type(content_type: str, filename: str) -> str:
    supported_types = {
        "application/pdf": "pdf",
        "text/html": "html",
        "text/plain": "text",
        "application/json": "json",
        "image/jpeg": "image",
        "image/png": "image",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
    }

    if content_type in supported_types:
        return supported_types[content_type]

    extension_map = {
        "pdf": "pdf",
        "html": "html",
        "htm": "html",
        "txt": "text",
        "json": "json",
        "jpg": "image",
        "jpeg": "image",
        "png": "image",
        "doc": "word",
        "docx": "word",
    }
    extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    return extension_map.get(extension, "text")


async def _process_pdf(content: str) -> str:
    try:
        return await _PDF_PARSER.extract_text(base64.b64decode(content))
    except Exception as exc:
        logger.error("PDF processing failed", extra={"error": str(exc)})
        return f"Error processing PDF: {exc}"


async def _process_html(content: str) -> str:
    try:
        return await _HTML_PARSER.extract_text(content)
    except Exception as exc:
        logger.error("HTML processing failed", extra={"error": str(exc)})
        return f"Error processing HTML: {exc}"


async def _process_image(content: str) -> str:
    try:
        return await _IMAGE_PARSER.extract_all(base64.b64decode(content))
    except Exception as exc:
        logger.error("Image processing failed", extra={"error": str(exc)})
        return f"Error processing image: {exc}"


async def _process_json(content: str) -> str:
    try:
        return json.dumps(json.loads(content), indent=2)
    except json.JSONDecodeError:
        return content


async def _process_word(content: str) -> str:
    if Document is None:
        return "Word document processing requires python-docx to be installed."

    try:
        document = Document(io.BytesIO(base64.b64decode(content)))
        paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
        return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
    except Exception as exc:
        logger.error("Word processing failed", extra={"error": str(exc)})
        return f"Error processing Word document: {exc}"
