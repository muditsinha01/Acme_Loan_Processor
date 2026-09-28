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

        logger.debug(
            "Response validation requested",
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
