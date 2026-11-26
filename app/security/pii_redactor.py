"""Active PII redaction pipeline with Google Cloud DLP and deterministic fallback.

Every log record, persistent memory write, outbound prompt check, and external
scam report passes through `PIIRedactor` so sensitive senior-citizen data (SSN,
Medicare numbers, bank/card numbers, PINs/passwords, phone numbers, emails) is
scrubbed before leaving memory or reaching persistent storage.
"""

from __future__ import annotations

import copy
import importlib
import re
from dataclasses import dataclass, field
from typing import Any

# Ordered from most specific/high-risk patterns to broader contact patterns.
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b")
_MEDICARE_MBI_RE = re.compile(
    r"\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[-\s]?[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[-\s]?[AC-HJKMNP-RT-Y]{2}\d{2}\b"
)
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_BANK_ACCOUNT_RE = re.compile(
    r"(?i)\b(account(?:\s+number|\s*#)?|routing(?:\s+number|\s*#)?|iban)\s*[:=#-]?\s*([A-Z]{2}\d{2}[A-Z0-9]{10,30}|\d{8,17})\b"
)
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(password|passcode|pin(?:\s+code|\s+number)?|one[- ]time\s+code|otp|verification\s+code|security\s+code)\s*(?:is|=|:|-)?\s*([A-Za-z0-9!@#$%^&*_.-]{4,32})\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}(?!\w)"
)
_DOB_RE = re.compile(
    r"(?i)\b(dob|date\s+of\s+birth|born\s+on)\s*[:=-]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2},?\s+\d{4})"
)
_STREET_ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9.\s]{2,40}\s(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Lane|Ln\.?|Court|Ct\.?|Way)\b",
    re.IGNORECASE,
)

# Standard Cloud DLP info types for senior financial and identity protection.
DEFAULT_DLP_INFO_TYPES: tuple[str, ...] = (
    "US_SOCIAL_SECURITY_NUMBER",
    "CREDIT_CARD_NUMBER",
    "US_BANK_ROUTING_MICR",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "STREET_ADDRESS",
    "DATE_OF_BIRTH",
    "US_HEALTHCARE_NPI",
)


def _passes_luhn(digits: str) -> bool:
    """Validate candidate payment card digits with the Luhn checksum."""
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass(frozen=True)
class PIIRedactionReport:
    """Result of scrubbing a string for personally identifiable information."""

    redacted_text: str
    entities_detected: list[str] = field(default_factory=list)
    used_cloud_dlp: bool = False

    @property
    def had_pii(self) -> bool:
        """Return True if one or more PII entities were scrubbed."""
        return bool(self.entities_detected)


class PIIRedactor:
    """Scrubs sensitive PII via Google Cloud DLP and deterministic local rules.

    When `enable_cloud_dlp` is True and `project_id` is configured, text is first
    de-identified via Google Cloud Sensitive Data Protection (Cloud DLP)
    `DlpServiceClient.deidentify_content`. Deterministic local redaction always
    runs afterwards (and acts as the primary offline engine) as defense-in-depth
    so sensitive credentials, SSNs, Medicare IDs, and payment cards never leak.
    """

    def __init__(
        self,
        *,
        enable_cloud_dlp: bool = False,
        project_id: str | None = None,
        dlp_client: Any | None = None,
    ) -> None:
        self._enable_cloud_dlp = enable_cloud_dlp and bool(project_id)
        self._project_id = project_id
        self._dlp_client = dlp_client

    def _get_dlp_client(self) -> Any | None:
        if not self._enable_cloud_dlp:
            return None
        if self._dlp_client is not None:
            return self._dlp_client
        try:
            dlp_v2: Any = importlib.import_module("google.cloud.dlp_v2")
            self._dlp_client = dlp_v2.DlpServiceClient()
            return self._dlp_client
        except Exception:
            # Fail safe to local deterministic scrubbing without breaking availability.
            return None

    def _scrub_with_cloud_dlp(self, text: str) -> tuple[str, bool]:
        """De-identify text using Google Cloud DLP when enabled and available."""
        client = self._get_dlp_client()
        if client is None or not self._project_id:
            return text, False

        parent = f"projects/{self._project_id}"
        inspect_config: dict[str, Any] = {
            "info_types": [{"name": info_type} for info_type in DEFAULT_DLP_INFO_TYPES]
        }
        deidentify_config: dict[str, Any] = {
            "info_type_transformations": {
                "transformations": [
                    {
                        "primitive_transformation": {
                            "replace_with_info_type_config": {}
                        }
                    }
                ]
            }
        }
        try:
            response = client.deidentify_content(
                request={
                    "parent": parent,
                    "inspect_config": inspect_config,
                    "deidentify_config": deidentify_config,
                    "item": {"value": text},
                }
            )
            return str(response.item.value), True
        except Exception:
            return text, False

    def redact_text(self, text: str) -> PIIRedactionReport:
        """Redact PII from a single string and return a structured report."""
        if not text:
            return PIIRedactionReport(redacted_text=text)

        detected: list[str] = []
        working, used_dlp = self._scrub_with_cloud_dlp(text)
        if used_dlp and working != text:
            detected.append("CLOUD_DLP_MATCH")

        # 1. Credentials / PINs / OTPs
        def _replace_credential(match: re.Match[str]) -> str:
            detected.append("CREDENTIAL_OR_PIN")
            return f"{match.group(1)}: [REDACTED_CREDENTIAL]"

        working = _CREDENTIAL_RE.sub(_replace_credential, working)

        # 2. Bank account / routing / IBAN numbers
        def _replace_bank(match: re.Match[str]) -> str:
            detected.append("BANK_ACCOUNT")
            return f"{match.group(1)}: [REDACTED_BANK_ACCOUNT]"

        working = _BANK_ACCOUNT_RE.sub(_replace_bank, working)

        # 3. Payment card numbers (Luhn validated)
        def _replace_card(match: re.Match[str]) -> str:
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if _passes_luhn(digits):
                detected.append("CREDIT_CARD_NUMBER")
                return "[REDACTED_CARD]"
            return raw

        working = _CARD_CANDIDATE_RE.sub(_replace_card, working)

        # 4. US Social Security Numbers
        if _SSN_RE.search(working):
            detected.append("US_SOCIAL_SECURITY_NUMBER")
            working = _SSN_RE.sub("[REDACTED_SSN]", working)

        # 5. Medicare Beneficiary Identifiers (MBI)
        if _MEDICARE_MBI_RE.search(working):
            detected.append("MEDICARE_ID")
            working = _MEDICARE_MBI_RE.sub("[REDACTED_MEDICARE_ID]", working)

        # 6. Email addresses
        if _EMAIL_RE.search(working):
            detected.append("EMAIL_ADDRESS")
            working = _EMAIL_RE.sub("[REDACTED_EMAIL]", working)

        # 7. Phone numbers
        if _PHONE_RE.search(working):
            detected.append("PHONE_NUMBER")
            working = _PHONE_RE.sub("[REDACTED_PHONE]", working)

        # 8. Dates of birth
        def _replace_dob(match: re.Match[str]) -> str:
            detected.append("DATE_OF_BIRTH")
            return f"{match.group(1)}: [REDACTED_DOB]"

        working = _DOB_RE.sub(_replace_dob, working)

        # 9. Street addresses
        if _STREET_ADDRESS_RE.search(working):
            detected.append("STREET_ADDRESS")
            working = _STREET_ADDRESS_RE.sub("[REDACTED_ADDRESS]", working)

        # Deduplicate while preserving discovery order.
        unique_detected = list(dict.fromkeys(detected))
        return PIIRedactionReport(
            redacted_text=working,
            entities_detected=unique_detected,
            used_cloud_dlp=used_dlp,
        )

    def redact_structure(self, payload: Any) -> Any:
        """Recursively scrub PII from strings inside dicts, lists, and tuples."""
        if isinstance(payload, str):
            return self.redact_text(payload).redacted_text
        if isinstance(payload, dict):
            return {
                key: self.redact_structure(val)
                for key, val in payload.items()
            }
        if isinstance(payload, list):
            return [self.redact_structure(item) for item in payload]
        if isinstance(payload, tuple):
            return tuple(self.redact_structure(item) for item in payload)
        return copy.deepcopy(payload) if isinstance(payload, set) else payload


_DEFAULT_REDACTOR: PIIRedactor | None = None


def get_pii_redactor(
    *,
    enable_cloud_dlp: bool | None = None,
    project_id: str | None = None,
) -> PIIRedactor:
    """Return a singleton `PIIRedactor` (or a configured instance when overrides given)."""
    global _DEFAULT_REDACTOR
    if enable_cloud_dlp is not None or project_id is not None:
        return PIIRedactor(
            enable_cloud_dlp=bool(enable_cloud_dlp),
            project_id=project_id,
        )
    if _DEFAULT_REDACTOR is None:
        import os

        _DEFAULT_REDACTOR = PIIRedactor(
            enable_cloud_dlp=os.getenv("ENABLE_CLOUD_DLP", "false").lower() == "true",
            project_id=os.getenv("GOOGLE_CLOUD_PROJECT") or None,
        )
    return _DEFAULT_REDACTOR
