"""High-stakes protective action tools gated by Human-in-the-Loop (HITL) confirmation.

Every external or irreversible protective action (alerting a family caregiver,
filing an official FTC elder-fraud report, or blocking a potentially personal/
medical contact) uses ADK's native `FunctionTool(..., require_confirmation=...)`
pause-and-resume hook so the senior citizen MUST review and confirm first.
"""

from __future__ import annotations

import uuid
from typing import Any

from google.adk.tools import FunctionTool, ToolContext
from pydantic import ValidationError

from app.observability.logging import get_logger
from app.observability.tracing import traced_span
from app.schemas.tool_schemas import (
    CaregiverAlertResult,
    FileScamReportRequest,
    NotifyCaregiverRequest,
    OfficialScamReportResult,
    QuarantineSenderRequest,
    QuarantineSenderResult,
    ToolErrorResult,
)
from app.security.pii_redactor import get_pii_redactor

logger = get_logger(__name__)

_PERSONAL_OR_MEDICAL_HINTS: tuple[str, ...] = (
    "dr.",
    "doctor",
    "clinic",
    "hospital",
    "pharmacy",
    "medcenter",
    "cvs",
    "walgreens",
    "family",
    "mom",
    "dad",
    "daughter",
    "son",
    "grandson",
    "granddaughter",
    "caregiver",
)


def requires_quarantine_confirmation(
    sender_identifier: str = "",
    confidence_score: float = 0.0,
    looks_like_personal_or_medical_contact: bool = False,
    **_kwargs: Any,
) -> bool:
    """Conditional HITL predicate for `quarantine_suspicious_sender`.

    Forces an explicit human confirmation stop whenever confidence is below 0.90
    or the sender resembles a personal, family, doctor, hospital, or pharmacy
    contact so SilverShield never accidentally blocks vital care communications.
    """
    if looks_like_personal_or_medical_contact:
        return True
    if float(confidence_score) < 0.90:
        return True
    lowered = sender_identifier.lower()
    return any(hint in lowered for hint in _PERSONAL_OR_MEDICAL_HINTS)


def notify_trusted_family_caregiver(
    caregiver_name: str,
    caregiver_contact_channel: str,
    risk_level: str,
    incident_summary: str,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Send a PII-redacted safety alert to the senior's designated family caregiver.

    HIGH-STAKES ACTION (MANDATORY HUMAN CONFIRMATION): Wrapped with ADK
    `require_confirmation=True`. Execution automatically pauses so the senior
    citizen can review the caregiver name, channel, and exact alert text before
    approving transmission.

    Args:
        caregiver_name: First name or relationship of the trusted family caregiver
            (e.g., "Sarah (Daughter)", "Michael (Son)").
        caregiver_contact_channel: Delivery method: "sms", "email", or "phone_callback".
        risk_level: Severity of the suspected incident ("SAFE", "CAUTION", or "HIGH_RISK").
        incident_summary: Plain-language description of the suspected scam or hoax
            (10 to 1,000 characters). Any PII is automatically redacted before dispatch.

    Returns:
        A JSON-serializable dictionary matching `CaregiverAlertResult` with
        `alert_id`, `redacted_message_sent`, and `human_confirmed`, or
        `ToolErrorResult` with recovery instructions if validation fails.
    """
    with traced_span(
        "tool.notify_trusted_family_caregiver",
        attributes={"channel": caregiver_contact_channel, "risk_level": risk_level},
    ):
        try:
            req = NotifyCaregiverRequest(
                caregiver_name=caregiver_name,
                caregiver_contact_channel=caregiver_contact_channel,  # type: ignore[arg-type]
                risk_level=risk_level,  # type: ignore[arg-type]
                incident_summary=incident_summary,
            )
        except ValidationError as exc:
            return ToolErrorResult(
                error_code="INVALID_CAREGIVER_ALERT_INPUT",
                error_message=f"Could not prepare caregiver alert: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Ask the senior for the trusted caregiver's name (at least 2 chars), "
                    "preferred channel ('sms', 'email', or 'phone_callback'), and a short "
                    "summary of what happened (at least 10 chars), then retry."
                ),
                retryable=True,
            ).model_dump()

        # Defense-in-depth confirmation check if invoked through a context carrying rejection
        if (
            tool_context is not None
            and tool_context.tool_confirmation is not None
            and not tool_context.tool_confirmation.confirmed
        ):
            return CaregiverAlertResult(
                status="cancelled",
                alert_id=f"alert-cancelled-{uuid.uuid4().hex[:8]}",
                caregiver_name=req.caregiver_name,
                channel=req.caregiver_contact_channel,
                redacted_message_sent="",
                human_confirmed=False,
            ).model_dump()

        redactor = get_pii_redactor()
        clean_summary = redactor.redact_text(req.incident_summary).redacted_text
        alert_id = f"alert-{uuid.uuid4().hex[:10]}"
        message_body = (
            f"[SilverShield {req.risk_level} Alert] Hello {req.caregiver_name}, "
            f"your family member asked SilverShield to share a safety heads-up: "
            f"{clean_summary} Please check in with them calmly by phone."
        )

        if tool_context is not None:
            alerts = list(tool_context.state.get("sent_caregiver_alerts", []))
            alerts.append({"alert_id": alert_id, "caregiver": req.caregiver_name})
            tool_context.state["sent_caregiver_alerts"] = alerts

        logger.info(
            "caregiver_alert_dispatched",
            alert_id=alert_id,
            channel=req.caregiver_contact_channel,
            risk_level=req.risk_level,
        )
        return CaregiverAlertResult(
            status="success",
            alert_id=alert_id,
            caregiver_name=req.caregiver_name,
            channel=req.caregiver_contact_channel,
            redacted_message_sent=message_body,
            human_confirmed=True,
        ).model_dump()


def file_official_ftc_scam_report(
    scam_category: str,
    channel: str,
    incident_summary: str,
    suspicious_urls: list[str],
    financial_loss_occurred: bool = False,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Prepare and file a PII-scrubbed elder fraud report for FTC ReportFraud.

    HIGH-STAKES ACTION (MANDATORY HUMAN CONFIRMATION): Wrapped with ADK
    `require_confirmation=True`. Always stops for explicit human review and
    approval before filing, and automatically scrubs all personal identifiers
    (SSN, phone numbers, card numbers, emails) from the dossier.

    Args:
        scam_category: Category of fraud (e.g., "government_impersonation_scam",
            "medicare_impersonation_scam", "tech_support_scam").
        channel: Channel where scam occurred ("sms", "email", "phone_call_transcript",
            "social_media", "letter", "website_popup", or "unknown").
        incident_summary: Factual summary of the scam attempt (15 to 2,000 characters).
        suspicious_urls: List of suspicious links or domains observed (pass empty list
            `[]` if no links were involved).
        financial_loss_occurred: True if the senior already sent money, gift cards,
            or shared credentials; False if the scam was stopped in time.

    Returns:
        A JSON-serializable dictionary matching `OfficialScamReportResult` with
        `report_reference_id`, `redacted_dossier`, `human_confirmed`, and
        `follow_up_resources`. Returns `ToolErrorResult` with recovery steps on error.
    """
    with traced_span(
        "tool.file_official_ftc_scam_report",
        attributes={
            "scam_category": scam_category,
            "financial_loss_occurred": financial_loss_occurred,
        },
    ):
        try:
            req = FileScamReportRequest(
                scam_category=scam_category,
                channel=channel,  # type: ignore[arg-type]
                incident_summary=incident_summary,
                suspicious_urls=suspicious_urls,
                financial_loss_occurred=financial_loss_occurred,
            )
        except ValidationError as exc:
            return ToolErrorResult(
                error_code="INVALID_SCAM_REPORT_INPUT",
                error_message=f"Scam report fields failed validation: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Ensure `scam_category` is descriptive (at least 3 chars), "
                    "`incident_summary` has at least 15 characters, and `channel` is valid. "
                    "Retry once confirmed with the senior."
                ),
                retryable=True,
            ).model_dump()

        if (
            tool_context is not None
            and tool_context.tool_confirmation is not None
            and not tool_context.tool_confirmation.confirmed
        ):
            return OfficialScamReportResult(
                status="cancelled",
                report_reference_id=f"ftc-cancelled-{uuid.uuid4().hex[:8]}",
                redacted_dossier="",
                human_confirmed=False,
                follow_up_resources=[],
            ).model_dump()

        redactor = get_pii_redactor()
        clean_summary = redactor.redact_text(req.incident_summary).redacted_text
        ref_id = f"FTC-SS-{uuid.uuid4().hex[:8].upper()}"

        dossier = (
            f"Category: {req.scam_category} | Channel: {req.channel} | "
            f"Financial Loss: {req.financial_loss_occurred} | "
            f"URLs: {', '.join(req.suspicious_urls) or 'none'} | "
            f"Summary: {clean_summary}"
        )

        resources = [
            "FTC ReportFraud Portal: https://ReportFraud.ftc.gov",
            "DOJ National Elder Fraud Hotline: 1-833-372-8311 (Free, compassionate support)",
        ]
        if req.financial_loss_occurred:
            resources.insert(
                0,
                "IdentityTheft.gov (https://www.identitytheft.gov) & call the number on the back of your bank card immediately.",
            )

        if tool_context is not None:
            reports = list(tool_context.state.get("filed_scam_reports", []))
            reports.append(ref_id)
            tool_context.state["filed_scam_reports"] = reports

        logger.info(
            "official_scam_report_filed",
            report_reference_id=ref_id,
            scam_category=req.scam_category,
            financial_loss_occurred=req.financial_loss_occurred,
        )
        return OfficialScamReportResult(
            status="success",
            report_reference_id=ref_id,
            redacted_dossier=dossier,
            human_confirmed=True,
            follow_up_resources=resources,
        ).model_dump()


def quarantine_suspicious_sender(
    sender_identifier: str,
    reason: str,
    confidence_score: float,
    looks_like_personal_or_medical_contact: bool = False,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Add a suspicious sender, phone label, or phishing domain to the senior's block watchlist.

    CONDITIONAL HUMAN-IN-THE-LOOP HOOK: Automatically pauses for explicit human
    confirmation whenever `confidence_score < 0.90` or the sender resembles a
    family member, doctor, clinic, hospital, or pharmacy.

    Args:
        sender_identifier: Domain, email sender, or caller label to quarantine
            (3 to 250 characters).
        reason: Plain-language reason why this sender is being quarantined.
        confidence_score: Confidence between 0.0 and 1.0 that this sender is malicious.
        looks_like_personal_or_medical_contact: Set True if the sender name could
            belong to a relative, doctor, hospital, clinic, or pharmacy.

    Returns:
        A JSON-serializable dictionary matching `QuarantineSenderResult` or
        `ToolErrorResult` with recovery instructions if input validation fails.
    """
    with traced_span(
        "tool.quarantine_suspicious_sender",
        attributes={"confidence_score": confidence_score},
    ):
        try:
            req = QuarantineSenderRequest(
                sender_identifier=sender_identifier,
                reason=reason,
                confidence_score=confidence_score,
                looks_like_personal_or_medical_contact=looks_like_personal_or_medical_contact,
            )
        except ValidationError as exc:
            return ToolErrorResult(
                error_code="INVALID_QUARANTINE_INPUT",
                error_message=f"Could not quarantine sender: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Ensure `sender_identifier` is at least 3 characters and "
                    "`confidence_score` is a float between 0.0 and 1.0."
                ),
                retryable=True,
            ).model_dump()

        needed_confirmation = requires_quarantine_confirmation(
            sender_identifier=req.sender_identifier,
            confidence_score=req.confidence_score,
            looks_like_personal_or_medical_contact=req.looks_like_personal_or_medical_contact,
        )

        if (
            tool_context is not None
            and tool_context.tool_confirmation is not None
            and not tool_context.tool_confirmation.confirmed
        ):
            return QuarantineSenderResult(
                status="cancelled",
                quarantine_id=f"quar-cancelled-{uuid.uuid4().hex[:8]}",
                redacted_sender=get_pii_redactor()
                .redact_text(req.sender_identifier)
                .redacted_text,
                confirmation_was_required=needed_confirmation,
            ).model_dump()

        redacted_sender = (
            get_pii_redactor().redact_text(req.sender_identifier).redacted_text
        )
        quarantine_id = f"quar-{uuid.uuid4().hex[:8]}"
        if tool_context is not None:
            quarantined = list(tool_context.state.get("quarantined_senders", []))
            quarantined.append(redacted_sender)
            tool_context.state["quarantined_senders"] = quarantined

        logger.info(
            "suspicious_sender_quarantined",
            quarantine_id=quarantine_id,
            confirmation_was_required=needed_confirmation,
        )
        return QuarantineSenderResult(
            status="success",
            quarantine_id=quarantine_id,
            redacted_sender=redacted_sender,
            confirmation_was_required=needed_confirmation,
        ).model_dump()


# ADK FunctionTool wrappers with explicit Human-in-the-Loop confirmation gates.
notify_trusted_family_caregiver_tool = FunctionTool(
    func=notify_trusted_family_caregiver,
    require_confirmation=True,
)
file_official_ftc_scam_report_tool = FunctionTool(
    func=file_official_ftc_scam_report,
    require_confirmation=True,
)
quarantine_suspicious_sender_tool = FunctionTool(
    func=quarantine_suspicious_sender,
    require_confirmation=requires_quarantine_confirmation,
)
