"""Structured Pydantic output schemas for ADK specialist and self-eval agents."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RiskVerdict(BaseModel):
    """Structured senior-friendly safety verdict summary."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["SAFE", "CAUTION", "HIGH_RISK"] = Field(
        description="Traffic-light safety classification."
    )
    headline: str = Field(
        description="Short, calm, plain-language headline understandable at a glance."
    )
    key_reasons: list[str] = Field(
        min_length=1,
        max_length=5,
        description="Up to 5 plain-language bullet reasons without technical jargon.",
    )
    immediate_safe_actions: list[str] = Field(
        min_length=1,
        max_length=5,
        description="Concrete step-by-step instructions the senior can follow right now.",
    )
    offer_caregiver_alert: bool = Field(
        default=False,
        description="Whether to offer (with explicit confirmation) notifying a family caregiver.",
    )


class SelfEvaluationVerdict(BaseModel):
    """Schema-constrained output for the self-evaluation guardrail critic agent."""

    model_config = ConfigDict(extra="forbid")

    grade: Literal["pass", "revise"] = Field(
        description="'pass' if the draft meets all senior-safety, clarity, and empathy rules; otherwise 'revise'."
    )
    empathy_and_respect_ok: bool = Field(
        description="True if tone is warm, calm, patient, and never condescending or shaming."
    )
    plain_language_ok: bool = Field(
        description="True if free of technical jargon and structured with short readable bullets."
    )
    no_credential_solicitation_ok: bool = Field(
        description="True if the response never asks for SSN, passwords, PINs, or bank/card numbers."
    )
    clear_verdict_and_steps_ok: bool = Field(
        description="True if a clear SAFE/CAUTION/HIGH RISK verdict and concrete safe next steps are present."
    )
    revision_feedback: str = Field(
        default="",
        description="Specific actionable instructions if grade is 'revise'; empty string if 'pass'.",
    )
