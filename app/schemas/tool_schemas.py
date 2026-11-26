"""Strict Pydantic v2 input/output JSON schemas for all SilverShield tools.

Every tool validates incoming LLM arguments against a `ConfigDict(extra="forbid")`
Request model and emits a validated Response model (or `ToolErrorResult` with
explicit `recovery_instructions` for guided LLM recovery).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ChannelType = Literal[
    "sms",
    "email",
    "phone_call_transcript",
    "social_media",
    "letter",
    "website_popup",
    "unknown",
]
RiskLevel = Literal["SAFE", "CAUTION", "HIGH_RISK"]
FactVerdict = Literal[
    "VERIFIED_ACCURATE",
    "LIKELY_TRUE",
    "UNVERIFIED_USE_CAUTION",
    "MISLEADING_OR_OUT_OF_CONTEXT",
    "LIKELY_FAKE_NEWS",
]


class StrictSchemaModel(BaseModel):
    """Base schema rejecting unknown keys so tool contracts remain strict."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ToolErrorResult(StrictSchemaModel):
    """Structured error payload with explicit recovery instructions for the LLM."""

    status: Literal["error"] = "error"
    error_code: str = Field(
        description="Machine-readable error identifier (e.g., INVALID_URL_FORMAT)."
    )
    error_message: str = Field(
        description="Plain-language description of what failed."
    )
    recovery_instructions: str = Field(
        description="Concrete step-by-step instructions telling the LLM how to recover."
    )
    suggested_next_tool: str | None = Field(
        default=None,
        description="Optional alternative tool name the LLM can invoke instead.",
    )
    retryable: bool = Field(
        default=True,
        description="Whether retrying with corrected arguments is expected to succeed.",
    )


# ---------------------------------------------------------------------------
# 1. Scam Indicator Analysis Schemas
# ---------------------------------------------------------------------------


class AnalyzeMessageScamRequest(StrictSchemaModel):
    """Validated input schema for `analyze_message_scam_indicators`."""

    message_text: str = Field(
        min_length=5,
        max_length=10000,
        description="Exact text or transcript of the suspicious message, email, or call.",
    )
    channel: ChannelType = Field(
        default="unknown",
        description="Delivery channel where the senior received the message.",
    )
    claimed_sender: str = Field(
        default="",
        max_length=200,
        description="Who the message claims to be from (e.g., 'IRS', 'Medicare', 'Grandson').",
    )


class DetectedRedFlag(StrictSchemaModel):
    """A single forensic scam signal detected in a message."""

    category: str = Field(description="Red-flag category (e.g., payment_coercion).")
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="Severity weight of this red flag."
    )
    evidence_excerpt: str = Field(
        description="Short PII-redacted snippet triggering the finding."
    )
    plain_language_explanation: str = Field(
        description="Senior-friendly explanation of why this is a warning sign."
    )


class ScamIndicatorAnalysisResult(StrictSchemaModel):
    """Validated output schema for `analyze_message_scam_indicators`."""

    status: Literal["success"] = "success"
    risk_score: int = Field(ge=0, le=100, description="Composite scam risk score 0-100.")
    risk_level: RiskLevel = Field(description="Traffic-light risk verdict.")
    likely_scam_category: str = Field(
        description="Primary scam tactic identified (or 'none_detected')."
    )
    red_flags: list[DetectedRedFlag] = Field(
        default_factory=list,
        description="Detailed list of forensic red flags found.",
    )
    extracted_urls: list[str] = Field(
        default_factory=list,
        description="Suspicious or notable URLs extracted for follow-up inspection.",
    )
    pii_was_scrubbed: bool = Field(
        default=False,
        description="True if sensitive PII was redacted from the analyzed text.",
    )
    recommended_next_steps: list[str] = Field(
        default_factory=list,
        description="Calm, concrete protective actions tailored to senior citizens.",
    )


# ---------------------------------------------------------------------------
# 2. URL & Domain Reputation Schemas
# ---------------------------------------------------------------------------


class InspectUrlReputationRequest(StrictSchemaModel):
    """Validated input schema for `inspect_url_and_domain_reputation`."""

    url: str = Field(
        min_length=4,
        max_length=2048,
        description="Web address (URL) or domain name to inspect for phishing or spoofing.",
    )
    claimed_organization: str = Field(
        default="",
        max_length=150,
        description="Organization the link claims to belong to (e.g., 'Medicare', 'Chase Bank').",
    )

    @field_validator("url")
    @classmethod
    def _reject_whitespace_only(cls, value: str) -> str:
        if " " in value.strip():
            raise ValueError("URL must not contain spaces.")
        return value.strip()


class UrlReputationResult(StrictSchemaModel):
    """Validated output schema for `inspect_url_and_domain_reputation`."""

    status: Literal["success"] = "success"
    normalized_url: str = Field(description="Normalized URL analyzed.")
    hostname: str = Field(description="Extracted domain/hostname.")
    risk_score: int = Field(ge=0, le=100, description="URL phishing risk score 0-100.")
    risk_level: RiskLevel = Field(description="Traffic-light URL safety verdict.")
    is_official_trusted_domain: bool = Field(
        description="Whether hostname matches an official government or verified domain."
    )
    impersonated_brand: str | None = Field(
        default=None,
        description="Brand or agency the URL appears to spoof, if any.",
    )
    findings: list[str] = Field(
        default_factory=list,
        description="Human-readable technical and plain-language URL findings.",
    )
    safe_alternative_advice: str = Field(
        description="Safe way for a senior to reach the real organization."
    )


# ---------------------------------------------------------------------------
# 3. Persistent Scam Pattern Knowledge Base Schemas
# ---------------------------------------------------------------------------


class LookupScamPatternsRequest(StrictSchemaModel):
    """Validated input schema for `lookup_known_elder_scam_patterns`."""

    query_text: str = Field(
        min_length=3,
        max_length=2000,
        description="Summary of the suspicious script, claim, or situation to search.",
    )
    top_k: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of matching known scam or hoax patterns to return.",
    )


class KnownPatternHit(StrictSchemaModel):
    """Single semantic match from the persistent scam/hoax knowledge store."""

    pattern_id: str = Field(description="Stable identifier of the stored pattern.")
    title: str = Field(description="Human-readable scam or hoax title.")
    pattern_type: Literal["scam", "fake_news"] = Field(
        description="Whether the entry is a scam script or a debunked fake news hoax."
    )
    similarity_score: float = Field(
        ge=0.0, le=1.0, description="Cosine similarity match score (0.0 to 1.0)."
    )
    summary: str = Field(description="Brief plain-language description of the tactic.")
    official_guidance: str = Field(
        description="Trusted recovery or verification guidance for seniors."
    )


class ScamPatternMatchResult(StrictSchemaModel):
    """Validated output schema for `lookup_known_elder_scam_patterns`."""

    status: Literal["success"] = "success"
    datastore_backend: str = Field(
        description="Persistent backend queried (sqlite_vector or vertex_ai_search)."
    )
    matches: list[KnownPatternHit] = Field(
        default_factory=list,
        description="Top semantic matches ordered by descending similarity.",
    )


# ---------------------------------------------------------------------------
# 4. Fake News & Claim Fact-Check Schemas
# ---------------------------------------------------------------------------


class VerifyNewsClaimRequest(StrictSchemaModel):
    """Validated input schema for `verify_news_claim_credibility`."""

    claim_text: str = Field(
        min_length=8,
        max_length=5000,
        description="Headline, forwarded social post, or health/benefit claim to verify.",
    )
    source_name: str = Field(
        default="",
        max_length=200,
        description="Website, social channel, or forwarder where the senior saw the claim.",
    )
    topic_area: Literal[
        "health_medicine",
        "government_benefits",
        "finance_economy",
        "emergency_alert",
        "general_news",
    ] = Field(
        default="general_news",
        description="Broad subject area of the claim.",
    )


class FactCheckCredibilityResult(StrictSchemaModel):
    """Validated output schema for `verify_news_claim_credibility`."""

    status: Literal["success"] = "success"
    verdict: FactVerdict = Field(description="Structured credibility verdict.")
    credibility_score: int = Field(
        ge=0, le=100, description="Estimated credibility score (0=hoax, 100=verified)."
    )
    manipulation_indicators: list[str] = Field(
        default_factory=list,
        description="Propaganda, clickbait, or fear-mongering signals detected.",
    )
    matched_debunks: list[KnownPatternHit] = Field(
        default_factory=list,
        description="Related debunked viral hoaxes found in the persistent knowledge store.",
    )
    authoritative_sources_to_check: list[str] = Field(
        default_factory=list,
        description="Trusted official outlets seniors can check directly.",
    )
    plain_language_summary: str = Field(
        description="Calm, respectful summary explaining why the claim is trustworthy or false."
    )


# ---------------------------------------------------------------------------
# 5. Long-Term Safety History Schema
# ---------------------------------------------------------------------------


class RetrieveSafetyHistoryRequest(StrictSchemaModel):
    """Validated input schema for `retrieve_senior_safety_history`."""

    topic_query: str = Field(
        min_length=2,
        max_length=500,
        description="Topic or scam type to search in the senior's past safety memory.",
    )
    limit: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of past safety memory entries to retrieve.",
    )


class SafetyHistoryResult(StrictSchemaModel):
    """Validated output schema for `retrieve_senior_safety_history`."""

    status: Literal["success"] = "success"
    memory_backend: str = Field(description="Persistent memory backend queried.")
    entries: list[dict[str, Any]] = Field(
        default_factory=list,
        description="PII-redacted historical safety notes from prior conversations.",
    )


# ---------------------------------------------------------------------------
# 6. High-Stakes Human-in-the-Loop (HITL) Action Schemas
# ---------------------------------------------------------------------------


class NotifyCaregiverRequest(StrictSchemaModel):
    """Validated input schema for `notify_trusted_family_caregiver` (HITL-gated)."""

    caregiver_name: str = Field(
        min_length=2,
        max_length=100,
        description="First name or relationship of the trusted family caregiver (e.g., 'Sarah (Daughter)').",
    )
    caregiver_contact_channel: Literal["sms", "email", "phone_callback"] = Field(
        default="sms",
        description="Preferred notification channel for the caregiver.",
    )
    risk_level: RiskLevel = Field(description="Assessed risk level of the incident.")
    incident_summary: str = Field(
        min_length=10,
        max_length=1000,
        description="PII-redacted summary of the suspected scam to share with the caregiver.",
    )


class CaregiverAlertResult(StrictSchemaModel):
    """Validated output schema for `notify_trusted_family_caregiver`."""

    status: Literal["success", "awaiting_confirmation", "cancelled"] = Field(
        description="Execution status of the caregiver alert."
    )
    alert_id: str = Field(description="Unique audit identifier for this caregiver alert.")
    caregiver_name: str = Field(description="Caregiver notified.")
    channel: str = Field(description="Delivery channel used.")
    redacted_message_sent: str = Field(
        description="Exact PII-scrubbed alert message approved and dispatched."
    )
    human_confirmed: bool = Field(
        description="True when the human explicitly confirmed sending the alert."
    )


class FileScamReportRequest(StrictSchemaModel):
    """Validated input schema for `file_official_ftc_scam_report` (HITL-gated)."""

    scam_category: str = Field(
        min_length=3,
        max_length=120,
        description="Category of scam (e.g., 'irs_impersonation', 'medicare_phishing').",
    )
    channel: ChannelType = Field(
        description="Channel used by the scammer (sms, email, phone_call_transcript, etc.)."
    )
    incident_summary: str = Field(
        min_length=15,
        max_length=2000,
        description="Factual description of the scam attempt (PII will be scrubbed automatically).",
    )
    suspicious_urls: list[str] = Field(
        default_factory=list,
        description="List of suspicious URLs involved in the scam attempt.",
    )
    financial_loss_occurred: bool = Field(
        default=False,
        description="Whether money, gift cards, or credentials were already shared.",
    )


class OfficialScamReportResult(StrictSchemaModel):
    """Validated output schema for `file_official_ftc_scam_report`."""

    status: Literal["success", "awaiting_confirmation", "cancelled"] = Field(
        description="Execution status of the official scam report."
    )
    report_reference_id: str = Field(
        description="Reference number for the filed elder-fraud report."
    )
    redacted_dossier: str = Field(
        description="PII-scrubbed incident summary included in the report."
    )
    human_confirmed: bool = Field(
        description="True when the user explicitly approved submitting the report."
    )
    follow_up_resources: list[str] = Field(
        default_factory=list,
        description="Official elder-fraud hotlines (FTC ReportFraud.ftc.gov, DOJ Elder Fraud Hotline).",
    )


class QuarantineSenderRequest(StrictSchemaModel):
    """Validated input schema for `quarantine_suspicious_sender` (Conditional HITL)."""

    sender_identifier: str = Field(
        min_length=3,
        max_length=250,
        description="Suspicious email domain, website domain, or sender label to block/quarantine.",
    )
    reason: str = Field(
        min_length=5,
        max_length=500,
        description="Reason for quarantining this sender.",
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0-1.0) that this sender is malicious.",
    )
    looks_like_personal_or_medical_contact: bool = Field(
        default=False,
        description="True if sender name resembles family, doctor, hospital, or pharmacy.",
    )


class QuarantineSenderResult(StrictSchemaModel):
    """Validated output schema for `quarantine_suspicious_sender`."""

    status: Literal["success", "awaiting_confirmation", "cancelled"] = Field(
        description="Outcome status of the quarantine action."
    )
    quarantine_id: str = Field(description="Audit record ID for the quarantine rule.")
    redacted_sender: str = Field(
        description="PII-redacted representation of the quarantined sender."
    )
    confirmation_was_required: bool = Field(
        description="Whether conditional HITL confirmation was triggered."
    )


def get_all_tool_json_schemas() -> dict[str, dict[str, Any]]:
    """Export explicit JSON Schema definitions for all tool inputs and outputs."""
    return {
        "analyze_message_scam_indicators": {
            "input": AnalyzeMessageScamRequest.model_json_schema(),
            "output": ScamIndicatorAnalysisResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
        "inspect_url_and_domain_reputation": {
            "input": InspectUrlReputationRequest.model_json_schema(),
            "output": UrlReputationResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
        "lookup_known_elder_scam_patterns": {
            "input": LookupScamPatternsRequest.model_json_schema(),
            "output": ScamPatternMatchResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
        "verify_news_claim_credibility": {
            "input": VerifyNewsClaimRequest.model_json_schema(),
            "output": FactCheckCredibilityResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
        "retrieve_senior_safety_history": {
            "input": RetrieveSafetyHistoryRequest.model_json_schema(),
            "output": SafetyHistoryResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
        "notify_trusted_family_caregiver": {
            "input": NotifyCaregiverRequest.model_json_schema(),
            "output": CaregiverAlertResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
        "file_official_ftc_scam_report": {
            "input": FileScamReportRequest.model_json_schema(),
            "output": OfficialScamReportResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
        "quarantine_suspicious_sender": {
            "input": QuarantineSenderRequest.model_json_schema(),
            "output": QuarantineSenderResult.model_json_schema(),
            "error": ToolErrorResult.model_json_schema(),
        },
    }
