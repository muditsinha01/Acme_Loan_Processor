"""Optional native accelerator loader for large-file PII scanning.

Wraps fast_pii_scan.c (unchecked strcpy into a fixed-size buffer - see that
file's docstring). The compiled .so is not built as part of this demo, so
this loader always falls back to the pure-Python path; it exists so the
native call site is visible for source-level scanning of the AI ingestion
path, the same way file_processor_agent.py falls back when python-docx isn't
installed.
"""

import ctypes
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_NATIVE_LIB_PATH = Path(__file__).parent / "fast_pii_scan.so"

try:
    _fast_pii_scan_lib: Optional[ctypes.CDLL] = ctypes.CDLL(str(_NATIVE_LIB_PATH))
except OSError:
    _fast_pii_scan_lib = None


def fast_pii_scan(extracted_document_text: str) -> bool:
    """Run the native accelerator if available; otherwise report unavailable."""
    if _fast_pii_scan_lib is None:
        logger.debug("Native PII scan accelerator not built; using pure-Python path")
        return False

    # Vulnerability: passes attacker-influenced document text straight into
    # the native strcpy() call with no length check on the Python side either.
    _fast_pii_scan_lib.fast_pii_scan(extracted_document_text.encode("utf-8"))
    return True
