"""Unit tests verifying Tool Design: docstrings, descriptive names, JSON schemas & error recovery."""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from app.schemas.tool_schemas import (
    AnalyzeMessageScamRequest,
    InspectUrlReputationRequest,
    get_all_tool_json_schemas,
)
from app.tools import (
    analyze_message_scam_indicators,
    file_official_ftc_scam_report,
    inspect_url_and_domain_reputation,
    lookup_known_elder_scam_patterns,
    notify_trusted_family_caregiver,
    quarantine_suspicious_sender,
    retrieve_senior_safety_history,
    verify_news_claim_credibility,
)

ALL_TOOL_FUNCS = [
    analyze_message_scam_indicators,
    inspect_url_and_domain_reputation,
    lookup_known_elder_scam_patterns,
    verify_news_claim_credibility,
    retrieve_senior_safety_history,
    notify_trusted_family_caregiver,
    file_official_ftc_scam_report,
    quarantine_suspicious_sender,
]


def test_every_tool_has_comprehensive_docstring_and_descriptive_name() -> None:
    for fn in ALL_TOOL_FUNCS:
        assert len(fn.__name__) >= 20, f"Tool name too vague: {fn.__name__}"
        assert "_" in fn.__name__, f"Tool name should be verb_noun snake_case: {fn.__name__}"
        doc = inspect.getdoc(fn) or ""
        assert "Args:" in doc, f"Missing Args section in docstring of {fn.__name__}"
        assert "Returns:" in doc, f"Missing Returns section in docstring of {fn.__name__}"
        assert "tool_context" not in doc, f"Internal tool_context leaked into docstring of {fn.__name__}"


def test_explicit_json_schemas_enforce_strict_extra_forbid() -> None:
    schemas = get_all_tool_json_schemas()
    assert len(schemas) == len(ALL_TOOL_FUNCS)
    for name, contract in schemas.items():
        assert contract["input"]["type"] == "object", f"Invalid input schema for {name}"
        assert contract["input"].get("additionalProperties") is False
        assert contract["output"]["type"] == "object"
        assert "recovery_instructions" in contract["error"]["properties"]

    with pytest.raises(ValidationError):
        AnalyzeMessageScamRequest(
            message_text="Valid text",
            channel="sms",
            unexpected_extra_field="boom",  # type: ignore[call-arg]
        )

    with pytest.raises(ValidationError):
        InspectUrlReputationRequest(url="not a url with spaces")


def test_scam_indicator_analysis_detects_irs_gift_card_scam_and_scrubs_pii() -> None:
    res = analyze_message_scam_indicators(
        message_text=(
            "URGENT IRS Officer calling: There is a warrant for your arrest unless "
            "you buy Apple gift cards within 24 hours. Confirm SSN 123-45-6789."
        ),
        channel="phone_call_transcript",
        claimed_sender="IRS",
    )
    assert res["status"] == "success"
    assert res["risk_level"] == "HIGH_RISK"
    assert res["risk_score"] >= 70
    assert res["likely_scam_category"] == "government_impersonation_scam"
    assert res["pii_was_scrubbed"] is True
    assert "123-45-6789" not in str(res)


def test_scam_indicator_analysis_does_not_false_positive_benign_appointment() -> None:
    res = analyze_message_scam_indicators(
        message_text=(
            "Reminder from Oakridge Family Clinic: Your checkup with Dr. Patel is "
            "Tuesday at 10 AM. Reply C to confirm."
        ),
        channel="sms",
        claimed_sender="Oakridge Family Clinic",
    )
    assert res["status"] == "success"
    assert res["risk_level"] == "SAFE"
    assert res["risk_score"] < 25


def test_url_reputation_flags_medicare_spoof_and_accepts_official_gov() -> None:
    phish = inspect_url_and_domain_reputation(
        url="http://medicare-benefits-renew.xyz/login",
        claimed_organization="Medicare",
    )
    assert phish["status"] == "success"
    assert phish["risk_level"] == "HIGH_RISK"
    assert phish["impersonated_brand"] == "Medicare"
    assert phish["is_official_trusted_domain"] is False

    official = inspect_url_and_domain_reputation(
        url="https://www.medicare.gov/basics",
        claimed_organization="Medicare",
    )
    assert official["status"] == "success"
    assert official["risk_level"] == "SAFE"
    assert official["is_official_trusted_domain"] is True


def test_guided_error_handling_returns_recovery_instructions_instead_of_crashing() -> None:
    bad_msg = analyze_message_scam_indicators(message_text="hi", channel="sms")
    assert bad_msg["status"] == "error"
    assert bad_msg["error_code"] == "INVALID_SCAM_ANALYSIS_INPUT"
    assert len(bad_msg["recovery_instructions"]) > 20
    assert bad_msg["retryable"] is True

    bad_url = inspect_url_and_domain_reputation(url="not-a-domain")
    assert bad_url["status"] == "error"
    assert bad_url["error_code"] == "UNPARSEABLE_HOSTNAME"
    assert "analyze_message_scam_indicators" in bad_url["recovery_instructions"]

    bad_claim = verify_news_claim_credibility(claim_text="short")
    assert bad_claim["status"] == "error"
    assert bad_claim["error_code"] == "INVALID_CLAIM_INPUT"
    assert len(bad_claim["recovery_instructions"]) > 20


def test_fact_check_detects_miracle_cure_and_social_security_hoax() -> None:
    cure = verify_news_claim_credibility(
        claim_text=(
            "Secret kitchen spice miracle cure doctors don't want you to know "
            "reverses diabetes overnight — throw away your pills!"
        ),
        source_name="Facebook post",
        topic_area="health_medicine",
    )
    assert cure["status"] == "success"
    assert cure["verdict"] == "LIKELY_FAKE_NEWS"
    assert cure["credibility_score"] <= 30
    assert len(cure["authoritative_sources_to_check"]) >= 2

    official_info = verify_news_claim_credibility(
        claim_text=(
            "Annual flu vaccination is recommended for adults aged 65 and older "
            "during autumn; consult your doctor or local pharmacy."
        ),
        source_name="CDC.gov",
        topic_area="health_medicine",
    )
    assert official_info["status"] == "success"
    assert official_info["verdict"] == "VERIFIED_ACCURATE"
