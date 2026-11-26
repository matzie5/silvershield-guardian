"""Fake news and viral misinformation verification tool for senior citizens."""

from __future__ import annotations

from typing import Any

from google.adk.tools import ToolContext
from pydantic import ValidationError

from app.memory.knowledge_store import get_knowledge_store
from app.observability.tracing import traced_span
from app.schemas.tool_schemas import (
    FactCheckCredibilityResult,
    FactVerdict,
    KnownPatternHit,
    ToolErrorResult,
    VerifyNewsClaimRequest,
)
from app.security.pii_redactor import get_pii_redactor

_MANIPULATION_SIGNALS: tuple[tuple[str, int, tuple[str, ...], str], ...] = (
    (
        "miracle_medical_cure",
        38,
        (
            "miracle cure",
            "doctors don't want you to know",
            "doctors hate this",
            "big pharma is hiding",
            "reverses diabetes overnight",
            "cures cancer overnight",
            "throw away your pills",
            "stop taking your medication",
            "secret kitchen spice cures",
        ),
        "Promises an unproven 'miracle cure' or urges stopping prescribed medication — a dangerous health misinformation pattern.",
    ),
    (
        "viral_chain_panic",
        32,
        (
            "share before it gets deleted",
            "share before deleted",
            "forward to everyone you love",
            "forward immediately to all contacts",
            "media won't report this",
            "they are trying to hide this",
            "copy and paste this status",
        ),
        "Uses viral chain-letter urgency ('share before deleted') designed to spread panic before anyone fact-checks it.",
    ),
    (
        "fabricated_benefit_or_crisis_rumor",
        32,
        (
            "social security is being cancelled",
            "social security ending next month",
            "medicare shutting down next week",
            "banks freezing all accounts tonight",
            "withdraw all your cash tonight",
            "free $3,000 government flex card",
            "friend in the military warned",
        ),
        "Matches known false rumors claiming sudden government benefit cancellation, bank freezes, or universal cash cards.",
    ),
    (
        "clickbait_sensationalism",
        16,
        (
            "shocking truth",
            "you won't believe what happens next",
            "breaking!!!",
            "urgent warning to all seniors",
            "100% guaranteed secret",
        ),
        "Uses emotional clickbait headlines rather than calm, verifiable reporting.",
    ),
)

_AUTHORITATIVE_BY_TOPIC: dict[str, list[str]] = {
    "health_medicine": [
        "Your personal doctor or pharmacist",
        "CDC (cdc.gov) and National Institutes of Health (nih.gov)",
        "Mayo Clinic (mayoclinic.org)",
    ],
    "government_benefits": [
        "Social Security Administration (ssa.gov / 1-800-772-1213)",
        "Medicare Official Site (medicare.gov / 1-800-633-4227)",
        "USA.gov official government portal (usa.gov)",
    ],
    "finance_economy": [
        "Federal Trade Commission Consumer Advice (consumer.ftc.gov)",
        "Consumer Financial Protection Bureau (consumerfinance.gov)",
        "Associated Press (apnews.com) or Reuters (reuters.com)",
    ],
    "emergency_alert": [
        "Ready.gov official emergency alerts (ready.gov)",
        "National Weather Service (weather.gov)",
        "Your local city/county emergency management office",
    ],
    "general_news": [
        "Associated Press (apnews.com) and Reuters (reuters.com)",
        "Independent fact-checkers: FactCheck.org and Snopes.com",
        "AARP Fraud Watch Network (aarp.org/money/scams-fraud)",
    ],
}

_TRUSTED_SOURCES: frozenset[str] = frozenset(
    {
        "cdc",
        "cdc.gov",
        "nih",
        "nih.gov",
        "ssa.gov",
        "medicare.gov",
        "ftc.gov",
        "reuters",
        "associated press",
        "ap news",
        "npr",
        "bbc",
        "mayo clinic",
        "aarp",
        "who",
    }
)


def verify_news_claim_credibility(
    claim_text: str,
    source_name: str = "",
    topic_area: str = "general_news",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Verify a viral news headline, forwarded social post, or health/benefit claim.

    Use this tool when a senior citizen shares a news article, Facebook/WhatsApp
    forward, miracle health remedy, or alarming rumor about Social Security,
    Medicare, banking, or emergencies. It checks for disinformation tactics,
    cross-references debunked hoaxes in the persistent knowledge store, and returns
    a plain-language credibility verdict plus official sources to double-check.

    Args:
        claim_text: The exact headline, rumor, or forwarded post text to evaluate
            (8 to 5,000 characters).
        source_name: Where the senior saw or heard the claim (e.g., "Facebook post",
            "WhatsApp forward", "CDC.gov", "AP News"), or empty string if unknown.
        topic_area: Subject category. Must be one of: "health_medicine",
            "government_benefits", "finance_economy", "emergency_alert", "general_news".

    Returns:
        A JSON-serializable dictionary matching `FactCheckCredibilityResult` with
        `verdict`, `credibility_score` (0-100), `manipulation_indicators`,
        `matched_debunks`, `authoritative_sources_to_check`, and
        `plain_language_summary`. On invalid input, returns `ToolErrorResult` with
        recovery instructions.
    """
    with traced_span(
        "tool.verify_news_claim_credibility",
        attributes={"topic_area": topic_area, "source_name": source_name[:60]},
    ) as span:
        try:
            req = VerifyNewsClaimRequest(
                claim_text=claim_text,
                source_name=source_name,
                topic_area=topic_area,  # type: ignore[arg-type]
            )
        except ValidationError as exc:
            return ToolErrorResult(
                error_code="INVALID_CLAIM_INPUT",
                error_message=f"Could not validate claim input: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Ask the user to share the headline or main sentence of the claim "
                    "(at least 8 characters), and set `topic_area` to one of: "
                    "health_medicine, government_benefits, finance_economy, "
                    "emergency_alert, general_news."
                ),
                suggested_next_tool="lookup_known_elder_scam_patterns",
                retryable=True,
            ).model_dump()

        clean_claim = get_pii_redactor().redact_text(req.claim_text).redacted_text
        lowered = clean_claim.lower()
        source_lower = req.source_name.lower().strip()

        penalty = 0
        manipulation_indicators: list[str] = []

        for _code, weight, phrases, explanation in _MANIPULATION_SIGNALS:
            if any(p in lowered for p in phrases):
                penalty += weight
                manipulation_indicators.append(explanation)

        # Excessively loud ALL-CAPS shouting ratio
        alpha_chars = [c for c in clean_claim if c.isalpha()]
        if len(alpha_chars) >= 20:
            upper_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
            if upper_ratio > 0.55:
                penalty += 12
                manipulation_indicators.append(
                    "Uses heavy ALL-CAPS shouting, a common tactic in sensationalized clickbait."
                )

        # Cross-reference persistent vector knowledge store for known fake-news debunks
        store = get_knowledge_store()
        debunk_hits_raw = store.search(
            clean_claim,
            top_k=3,
            pattern_type="fake_news",
            min_similarity=0.18,
        )
        matched_debunks = [
            KnownPatternHit(
                pattern_id=rec.pattern_id,
                title=rec.title,
                pattern_type=rec.pattern_type,
                similarity_score=score,
                summary=rec.summary,
                official_guidance=rec.official_guidance,
            )
            for rec, score in debunk_hits_raw
        ]

        if matched_debunks and matched_debunks[0].similarity_score >= 0.28:
            penalty += 35
            manipulation_indicators.append(
                f"Closely matches a known debunked hoax: '{matched_debunks[0].title}'."
            )

        # Credible source boost when no strong hoax indicators present
        from_trusted_source = bool(
            source_lower and any(ts in source_lower for ts in _TRUSTED_SOURCES)
        )
        base_score = 78 if from_trusted_source else 62
        if any(
            u in lowered for u in ("forward", "whatsapp", "facebook", "chain message")
        ) and not from_trusted_source:
            penalty += 10
            manipulation_indicators.append(
                "Originates from an unverified social media or forwarded message chain."
            )

        credibility_score = max(0, min(100, base_score - penalty))

        verdict: FactVerdict
        if credibility_score <= 30:
            verdict = "LIKELY_FAKE_NEWS"
            summary = (
                "This claim shows strong signs of fake news or a known viral hoax. "
                "Please do not share it or act on its advice before checking official sources."
            )
        elif credibility_score <= 52:
            verdict = "MISLEADING_OR_OUT_OF_CONTEXT"
            summary = (
                "Parts of this claim appear exaggerated, misleading, or unverified. "
                "Double-check with trusted official sources before believing or forwarding it."
            )
        elif credibility_score <= 70:
            verdict = "UNVERIFIED_USE_CAUTION"
            summary = (
                "We did not find an exact match to a known hoax, but the claim has not "
                "been independently confirmed by an official source yet."
            )
        elif from_trusted_source:
            verdict = "VERIFIED_ACCURATE"
            summary = (
                "This information appears consistent with calm, official guidance and "
                "shows no fake-news manipulation warning signs."
            )
        else:
            verdict = "LIKELY_TRUE"
            summary = (
                "No fake-news or panic-hoax indicators were detected, though confirming "
                "directly with an official organization is always good practice."
            )

        result = FactCheckCredibilityResult(
            verdict=verdict,
            credibility_score=credibility_score,
            manipulation_indicators=manipulation_indicators,
            matched_debunks=matched_debunks,
            authoritative_sources_to_check=_AUTHORITATIVE_BY_TOPIC[req.topic_area],
            plain_language_summary=summary,
        )

        if tool_context is not None:
            tool_context.state["last_fact_check_verdict"] = verdict

        span.set_attribute("fact_check.verdict", verdict)
        span.set_attribute("fact_check.score", credibility_score)
        return result.model_dump()
