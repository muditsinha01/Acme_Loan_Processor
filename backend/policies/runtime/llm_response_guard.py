"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

Detects and masks PII the response pipeline shouldn't be echoing back:
SSNs, credit card numbers (Luhn-validated to cut down on false positives),
and driver's-license numbers that appear next to a "driver's license"-style
label. This runs locally, independent of the external Lineaje guardrail
service, so masking coverage doesn't depend on that service's entity
detection for a given document.
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


import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    violations: list[str]
    filtered_response: Optional[str] = None
    original_response: Optional[str] = None


_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_CANDIDATE_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_LICENSE_PATTERN = re.compile(
    r"\b(driver'?s?\s+licen[cs]e(?:\s+(?:#|no\.?|number))?\s*[:#\-]?\s*)"
    r"([A-Z0-9][A-Z0-9\- ]{4,15}[A-Z0-9])",
    re.IGNORECASE,
)


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask_card(match: "re.Match[str]") -> str:
    digits = re.sub(r"[ -]", "", match.group(0))
    if digits.isdigit() and _luhn_valid(digits):
        return "[REDACTED_CC]"
    return match.group(0)


def _mask_license(match: "re.Match[str]") -> str:
    return f"{match.group(1)}[REDACTED_LICENSE]"


def mask_pii(text: str) -> tuple[str, list[str]]:
    """Mask SSNs, valid-looking credit card numbers, and labeled driver's
    license numbers in ``text``. Returns (masked_text, violation_types)."""
    violations: list[str] = []

    if _SSN_PATTERN.search(text):
        violations.append("ssn")
    text = _SSN_PATTERN.sub("[REDACTED_SSN]", text)

    before = text
    text = _CARD_CANDIDATE_PATTERN.sub(_mask_card, text)
    if text != before:
        violations.append("credit_card")

    before = text
    text = _LICENSE_PATTERN.sub(_mask_license, text)
    if text != before:
        violations.append("drivers_license")

    return text, violations


class LLMResponseGuard:
    """Guards LLM responses to ensure policy compliance (PII masking)."""

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """Validate and mask an LLM response for PII leakage."""
        self.validation_count += 1
        filtered, violations = mask_pii(response)

        _lineaje_payload = "Response validation requested"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:8c54777e712fd6ac633495f767a50dac14ab3e6ab38467ea2c73f947ed5d2e44'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8c54777e712fd6ac633495f767a50dac14ab3e6ab38467ea2c73f947ed5d2e44', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        try:
            _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
        except _gr_client.GuardrailUnavailableError:
            pass
        logger.debug(
            _lineaje_payload,
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count,
                "violations": violations,
            }
        )

        return ValidationResult(
            is_valid=not violations,
            violations=violations,
            filtered_response=filtered,
            original_response=response,
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """Return the PII violation types found in ``response``, if any."""
        _, violations = mask_pii(response)
        # LINEAJE: enforce() `violations` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_027 (Enforce output data minimization for model, tool, and API responses.). Mask/block; do not remove without review. site_id='site:sha256:9fc2cfb6bbdca7b11a3e82d6d71fe9ea3d0aef7d5041a85488f2b1e8aef03c9b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9fc2cfb6bbdca7b11a3e82d6d71fe9ea3d0aef7d5041a85488f2b1e8aef03c9b', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        try:
            violations = _gr_client.enforce(_gr_site, violations, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_data_leakage(self, response: str) -> list[str]:
        """Alias of check_pii_leakage for broader "sensitive data" checks."""
        return await self.check_pii_leakage(response)
