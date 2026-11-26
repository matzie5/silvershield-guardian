"""Scam forensics and URL/domain reputation tools with strict schemas and guided recovery."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from google.adk.tools import ToolContext
from pydantic import ValidationError

from app.observability.logging import get_logger
from app.observability.tracing import traced_span
from app.schemas.tool_schemas import (
    AnalyzeMessageScamRequest,
    DetectedRedFlag,
    InspectUrlReputationRequest,
    RiskLevel,
    ScamIndicatorAnalysisResult,
    ToolErrorResult,
    UrlReputationResult,
)
from app.security.pii_redactor import get_pii_redactor

logger = get_logger(__name__)

_URL_EXTRACT_RE = re.compile(
    r"(?:https?://[^\s<>\"']+|www\.[^\s<>\"']+|\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:com|org|net|gov|edu|xyz|top|click|info|biz|co|us|tk|ml|ga|cf|gq|vip|icu|buzz|online|site|link|support)(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)

_OFFICIAL_TRUSTED_DOMAINS: frozenset[str] = frozenset(
    {
        "ssa.gov",
        "medicare.gov",
        "irs.gov",
        "ftc.gov",
        "reportfraud.ftc.gov",
        "cdc.gov",
        "nih.gov",
        "usa.gov",
        "va.gov",
        "ready.gov",
        "consumer.ftc.gov",
        "who.int",
        "aarp.org",
        "apnews.com",
        "reuters.com",
        "snopes.com",
        "factcheck.org",
        "mayoclinic.org",
    }
)

_PROTECTED_BRANDS: dict[str, tuple[str, ...]] = {
    "Medicare": ("medicare.gov",),
    "Social Security Administration": ("ssa.gov",),
    "IRS": ("irs.gov",),
    "FTC": ("ftc.gov",),
    "Amazon": ("amazon.com",),
    "Apple": ("apple.com", "icloud.com"),
    "Microsoft": ("microsoft.com", "live.com"),
    "PayPal": ("paypal.com",),
    "Chase Bank": ("chase.com",),
    "Bank of America": ("bankofamerica.com",),
    "Wells Fargo": ("wellsfargo.com",),
    "USPS": ("usps.com",),
}

_BRAND_KEYWORDS: dict[str, tuple[str, ...]] = {
    "Medicare": ("medicare",),
    "Social Security Administration": ("ssa", "socialsecurity", "social-security"),
    "IRS": ("irs-", "-irs", "irsverify", "irstax", "internalrevenue"),
    "FTC": ("ftc-", "reportfraud"),
    "Amazon": ("amazon", "amaz0n", "arnazon"),
    "Apple": ("apple", "icloud", "app1e"),
    "Microsoft": ("microsoft", "micros0ft", "windows-support"),
    "PayPal": ("paypal", "paypa1"),
    "Chase Bank": ("chase",),
    "Bank of America": ("bankofamerica", "bofa"),
    "Wells Fargo": ("wellsfargo",),
    "USPS": ("usps",),
}

_HIGH_RISK_TLDS: frozenset[str] = frozenset(
    {
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".buzz",
        ".icu",
        ".vip",
        ".work",
        ".loan",
        ".support",
        ".site",
        ".online",
    }
)

_URL_SHORTENERS: frozenset[str] = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "ow.ly", "is.gd", "cutt.ly"}
)

_SCAM_RULES: tuple[tuple[str, str, int, tuple[str, ...], str], ...] = (
    (
        "payment_coercion",
        "critical",
        40,
        (
            "gift card",
            "apple card",
            "google play card",
            "target card",
            "bitcoin",
            "crypto",
            "wire transfer",
            "western union",
            "cash courier",
            "gold bars",
            "safe account",
            "zelle to protect",
            "prepaid card",
        ),
        "Demands payment via gift cards, wire transfer, cryptocurrency, or cash couriers — a hallmark of scams. Legitimate agencies and banks never request these.",
    ),
    (
        "credential_or_remote_access_harvesting",
        "critical",
        35,
        (
            "social security number",
            "confirm your ssn",
            "medicare number",
            "verify your medicare",
            "one-time code",
            "6-digit code",
            "read back the code",
            "pin number",
            "bank password",
            "routing number",
            "anydesk",
            "teamviewer",
            "ultraviewer",
            "remote access",
            "install this app to fix",
        ),
        "Asks for sensitive personal numbers, passcodes, or remote computer access that scammers use to steal identities or empty bank accounts.",
    ),
    (
        "government_or_legal_intimidation",
        "high",
        30,
        (
            "warrant for your arrest",
            "arrested immediately",
            "police will arrive",
            "social security suspended",
            "ssn suspended",
            "irs officer",
            "federal agent",
            "benefits will be cancelled",
            "medicare card expiring",
            "power shutoff in 30",
            "electricity disconnected in",
            "legal action within",
        ),
        "Uses threats of arrest, suspended government benefits, or instant utility shutoff to trigger panic.",
    ),
    (
        "secrecy_or_grandparent_isolation",
        "high",
        30,
        (
            "don't tell mom",
            "do not tell mom",
            "don't tell dad",
            "keep this between us",
            "keep this secret",
            "i'm in jail",
            "need bail money",
            "car accident and arrested",
            "please don't tell anyone",
            "grandma it's me",
            "grandpa it's me",
            "public defender needs cash",
        ),
        "Pressures you to keep a supposed family emergency secret and send urgent cash or bail — classic grandparent scam behavior.",
    ),
    (
        "tech_support_scareware",
        "high",
        30,
        (
            "virus detected",
            "computer is infected",
            "windows defender alert",
            "apple security alert",
            "call microsoft support immediately",
            "device will be permanently locked",
            "trojan spyware found",
        ),
        "Mimics scary fake virus alerts to trick you into calling a fraudulent tech-support hotline.",
    ),
    (
        "artificial_urgency",
        "medium",
        18,
        (
            "act immediately",
            "within 24 hours",
            "within 30 minutes",
            "expires tonight",
            "final notice",
            "urgent action required",
            "suspended today",
            "click immediately",
            "respond right now",
        ),
        "Creates artificial time pressure so you act quickly before double-checking with family or official sources.",
    ),
    (
        "prize_or_guaranteed_money_lure",
        "high",
        28,
        (
            "you have won",
            "publishers clearing house",
            "processing fee to claim",
            "pay taxes to release your prize",
            "guaranteed profit",
            "free $3,000 flex card",
            "unclaimed inheritance",
        ),
        "Promises an unexpected prize or guaranteed windfall while asking for upfront fees or personal details.",
    ),
)


def _classify_scam_category(matched_categories: set[str], lowered_text: str) -> str:
    if "secrecy_or_grandparent_isolation" in matched_categories:
        return "grandparent_or_family_impersonation_scam"
    if "tech_support_scareware" in matched_categories:
        return "tech_support_scam"
    if "prize_or_guaranteed_money_lure" in matched_categories:
        return "sweepstakes_or_investment_scam"
    if "medicare" in lowered_text and (
        "credential_or_remote_access_harvesting" in matched_categories
        or "government_or_legal_intimidation" in matched_categories
    ):
        return "medicare_impersonation_scam"
    if any(k in lowered_text for k in ("irs", "social security", "ssa")) and (
        "payment_coercion" in matched_categories
        or "government_or_legal_intimidation" in matched_categories
    ):
        return "government_impersonation_scam"
    if "credential_or_remote_access_harvesting" in matched_categories:
        return "phishing_or_credential_theft"
    if "payment_coercion" in matched_categories:
        return "financial_extortion_scam"
    if matched_categories:
        return "suspicious_social_engineering"
    return "none_detected"


def _score_to_risk_level(score: int) -> RiskLevel:
    if score >= 55:
        return "HIGH_RISK"
    if score >= 25:
        return "CAUTION"
    return "SAFE"


def analyze_message_scam_indicators(
    message_text: str,
    channel: str = "unknown",
    claimed_sender: str = "",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Analyze a suspicious text, email, letter, or call transcript for elder-scam tactics.

    Use this tool whenever a senior citizen shares a message, phone script, pop-up
    text, or email and asks whether it is legitimate or a scam. It evaluates urgency,
    government/family impersonation, gift-card/wire/crypto coercion, credential
    harvesting, and extracts embedded URLs while scrubbing any accidentally pasted PII.

    Args:
        message_text: The full text or transcript of the suspicious message (5 to 10,000
            characters). Example: "URGENT: Your Medicare card expires today. Click
            http://medicare-renew.xyz to confirm your SSN."
        channel: Where the message arrived. Must be one of: "sms", "email",
            "phone_call_transcript", "social_media", "letter", "website_popup", or "unknown".
        claimed_sender: Who the message claims to be from (e.g., "IRS", "Medicare",
            "Grandson", "Chase Bank"), or an empty string if unspecified.

    Returns:
        A JSON-serializable dictionary matching `ScamIndicatorAnalysisResult` with
        `risk_score` (0-100), `risk_level` ("SAFE" | "CAUTION" | "HIGH_RISK"),
        `likely_scam_category`, `red_flags`, `extracted_urls`, `pii_was_scrubbed`,
        and `recommended_next_steps`. On invalid input, returns `ToolErrorResult`
        with actionable `recovery_instructions`.
    """
    with traced_span(
        "tool.analyze_message_scam_indicators",
        attributes={"channel": channel, "claimed_sender": claimed_sender[:60]},
    ) as span:
        try:
            req = AnalyzeMessageScamRequest(
                message_text=message_text,
                channel=channel,  # type: ignore[arg-type]
                claimed_sender=claimed_sender,
            )
        except ValidationError as exc:
            error_payload = ToolErrorResult(
                error_code="INVALID_SCAM_ANALYSIS_INPUT",
                error_message=f"Could not validate message input: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Ask the user gently to share at least one full sentence of the "
                    "suspicious message, and ensure `channel` is one of: sms, email, "
                    "phone_call_transcript, social_media, letter, website_popup, unknown."
                ),
                suggested_next_tool="lookup_known_elder_scam_patterns",
                retryable=True,
            )
            logger.warning(
                "tool_validation_error",
                tool="analyze_message_scam_indicators",
                error_code=error_payload.error_code,
            )
            return error_payload.model_dump()

        redactor = get_pii_redactor()
        redaction = redactor.redact_text(req.message_text)
        clean_text = redaction.redacted_text
        lowered = f"{req.claimed_sender} {clean_text}".lower()

        extracted_urls = list(dict.fromkeys(_URL_EXTRACT_RE.findall(req.message_text)))
        red_flags: list[DetectedRedFlag] = []
        matched_categories: set[str] = set()
        score = 0

        for category, severity, weight, phrases, explanation in _SCAM_RULES:
            hit = next((p for p in phrases if p in lowered), None)
            if hit is not None:
                matched_categories.add(category)
                score += weight
                red_flags.append(
                    DetectedRedFlag(
                        category=category,
                        severity=severity,  # type: ignore[arg-type]
                        evidence_excerpt=f"Matched indicator phrase: '{hit}'",
                        plain_language_explanation=explanation,
                    )
                )

        # Evaluate embedded links as an additional signal
        if extracted_urls:
            non_official_urls = [
                u
                for u in extracted_urls
                if not any(
                    host in u.lower() for host in _OFFICIAL_TRUSTED_DOMAINS
                )
            ]
            if non_official_urls and (matched_categories or req.channel == "sms"):
                score += 20
                red_flags.append(
                    DetectedRedFlag(
                        category="unverified_embedded_link",
                        severity="high",
                        evidence_excerpt=f"Contains unverified link: {non_official_urls[0]}",
                        plain_language_explanation=(
                            "Includes a web link that does not belong to an official "
                            "government or verified organization website."
                        ),
                    )
                )

        # Bonus penalty if sender claims official government/bank agency via SMS with urgency
        if (
            req.channel == "sms"
            and any(
                agency in lowered
                for agency in ("irs", "medicare", "social security", "bank", "usps")
            )
            and (extracted_urls or "artificial_urgency" in matched_categories)
        ):
            score += 15

        score = min(100, score)
        risk_level = _score_to_risk_level(score)
        scam_category = _classify_scam_category(matched_categories, lowered)

        if risk_level == "HIGH_RISK":
            next_steps = [
                "Do NOT click any links, reply, call numbers in the message, or send money/gift cards.",
                "If this claims to be your bank, Medicare, or a relative, hang up and call the real phone number you already know or the number on the back of your card.",
                "If you already shared a password, card number, or money, call your bank immediately and the DOJ National Elder Fraud Hotline at 1-833-372-8311.",
            ]
        elif risk_level == "CAUTION":
            next_steps = [
                "Pause before replying or clicking anything — scammers rely on rushing you.",
                "Independently verify by calling the organization's official phone number from a paper bill or physical card.",
                "Ask a trusted family member or caregiver to look at the message with you.",
            ]
        else:
            next_steps = [
                "No strong scam warning signs were found in this text.",
                "Still avoid sharing passwords, PINs, or Social Security numbers by text or email.",
                "If anything feels unusual, confirm directly using a phone number you already trust.",
            ]

        result = ScamIndicatorAnalysisResult(
            risk_score=score,
            risk_level=risk_level,
            likely_scam_category=scam_category,
            red_flags=red_flags,
            extracted_urls=extracted_urls,
            pii_was_scrubbed=redaction.had_pii,
            recommended_next_steps=next_steps,
        )

        if tool_context is not None:
            tool_context.state["last_scam_risk_level"] = risk_level
            tool_context.state["last_scam_category"] = scam_category

        span.set_attribute("scam.risk_score", score)
        span.set_attribute("scam.risk_level", risk_level)
        span.set_attribute("scam.pii_scrubbed", redaction.had_pii)
        return result.model_dump()


def _matches_domain(hostname: str, trusted_domain: str) -> bool:
    return hostname == trusted_domain or hostname.endswith(f".{trusted_domain}")


def inspect_url_and_domain_reputation(
    url: str,
    claimed_organization: str = "",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Inspect a web URL or domain name for phishing, lookalike spoofing, and unsafe traits.

    Use this tool whenever a suspicious link or website domain appears in an email,
    SMS, social post, or browser pop-up. Checks for official government/trusted
    domains, brand typosquatting (e.g., `medicare-benefits-verify.xyz`), raw IP
    addresses, punycode homoglyphs, URL shorteners, and insecure credential paths.

    Args:
        url: The web link or domain name to check (e.g., "https://medicare-renew.xyz/login"
            or "ssa.gov"). Must not contain spaces.
        claimed_organization: Name of the agency or company the link pretends to be
            (e.g., "Medicare", "IRS", "Chase Bank"), or an empty string if unknown.

    Returns:
        A JSON-serializable dictionary matching `UrlReputationResult` containing
        `normalized_url`, `hostname`, `risk_score` (0-100), `risk_level`,
        `is_official_trusted_domain`, `impersonated_brand`, `findings`, and
        `safe_alternative_advice`. Returns `ToolErrorResult` with recovery steps
        if the URL is malformed.
    """
    with traced_span(
        "tool.inspect_url_and_domain_reputation",
        attributes={"claimed_organization": claimed_organization[:60]},
    ) as span:
        try:
            req = InspectUrlReputationRequest(
                url=url, claimed_organization=claimed_organization
            )
        except ValidationError as exc:
            return ToolErrorResult(
                error_code="INVALID_URL_FORMAT",
                error_message=f"The provided link is not a valid URL: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Remove spaces or surrounding punctuation from the URL and retry "
                    "`inspect_url_and_domain_reputation`. If the user did not include "
                    "a complete web address, analyze the message text instead using "
                    "`analyze_message_scam_indicators`."
                ),
                suggested_next_tool="analyze_message_scam_indicators",
                retryable=True,
            ).model_dump()

        raw_url = req.url
        normalized = (
            raw_url if "://" in raw_url else f"https://{raw_url.lstrip('/')}"
        )
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower().strip(".")

        if not hostname or "." not in hostname:
            return ToolErrorResult(
                error_code="UNPARSEABLE_HOSTNAME",
                error_message=f"Could not extract a valid website domain from '{raw_url}'.",
                recovery_instructions=(
                    "Gently ask the senior to read or copy the full website address "
                    "(for example, something ending in .com, .gov, or .org), or proceed "
                    "by checking the message wording with `analyze_message_scam_indicators`."
                ),
                suggested_next_tool="analyze_message_scam_indicators",
                retryable=True,
            ).model_dump()

        findings: list[str] = []
        risk_score = 0
        impersonated_brand: str | None = None

        is_official = any(
            _matches_domain(hostname, domain)
            for domain in _OFFICIAL_TRUSTED_DOMAINS
        )

        # 1. Raw IP address host
        try:
            ipaddress.ip_address(hostname)
            risk_score += 55
            findings.append(
                "Uses a raw numerical IP address instead of a real organization website name."
            )
        except ValueError:
            pass

        # 2. Punycode / IDN homograph indicator
        if "xn--" in hostname:
            risk_score += 45
            findings.append(
                "Uses hidden internationalized 'punycode' characters often abused to mimic real websites."
            )

        # 3. '@' credential/redirect trick
        if "@" in parsed.netloc:
            risk_score += 45
            findings.append(
                "Contains an '@' symbol in the address, a trick used to hide the true destination website."
            )

        # 4. URL shortener
        if hostname in _URL_SHORTENERS:
            risk_score += 35
            findings.append(
                f"Uses link shortener '{hostname}', which hides the real destination website."
            )

        # 5. High-risk TLD
        if any(hostname.endswith(tld) for tld in _HIGH_RISK_TLDS):
            risk_score += 35
            findings.append(
                "Ends in a low-trust web extension frequently abused for disposable scam websites."
            )

        # 6. Brand or government agency lookalike spoofing
        for brand, keywords in _BRAND_KEYWORDS.items():
            official_domains = _PROTECTED_BRANDS[brand]
            matches_official = any(
                _matches_domain(hostname, d) for d in official_domains
            )
            claimed_match = (
                req.claimed_organization
                and brand.lower() in req.claimed_organization.lower()
            )
            keyword_in_host = any(kw in hostname for kw in keywords)
            if (keyword_in_host or claimed_match) and not matches_official:
                impersonated_brand = brand
                risk_score += 50
                findings.append(
                    f"Appears to impersonate {brand}, but '{hostname}' is NOT an official "
                    f"{brand} domain ({', '.join(official_domains)})."
                )
                break

        # 7. Excessive hyphens or subdomains
        if hostname.count("-") >= 2 and not is_official:
            risk_score += 15
            findings.append(
                "Domain uses multiple hyphens, a common pattern in hastily created phishing sites."
            )
        if len(hostname.split(".")) >= 4 and not is_official:
            risk_score += 15
            findings.append(
                "Contains unusually many nested subdomains designed to look official at first glance."
            )

        # 8. Insecure HTTP + sensitive path
        path_lower = f"{parsed.path}?{parsed.query}".lower()
        if raw_url.lower().startswith("http://") and any(
            w in path_lower for w in ("login", "verify", "account", "bank", "ssn", "medicare")
        ):
            risk_score += 25
            findings.append(
                "Uses an unencrypted 'http://' link asking to log in or verify account details."
            )

        if is_official and risk_score == 0:
            findings.append(
                f"'{hostname}' is a recognized official trusted domain."
            )

        risk_score = min(100, risk_score)
        risk_level = _score_to_risk_level(risk_score)

        if impersonated_brand:
            official_list = ", ".join(_PROTECTED_BRANDS[impersonated_brand])
            safe_advice = (
                f"Do not click this link. Instead, open a new browser window and type "
                f"the official address yourself ({official_list}) or call the official "
                f"number on the back of your card."
            )
        elif is_official:
            safe_advice = (
                f"'{hostname}' is an official website, though it is always safest to type "
                f"the address yourself rather than clicking links from unexpected messages."
            )
        else:
            safe_advice = (
                "Avoid entering personal details on unfamiliar websites. Navigate directly "
                "to the organization's official website or ask a trusted family member first."
            )

        result = UrlReputationResult(
            normalized_url=normalized,
            hostname=hostname,
            risk_score=risk_score,
            risk_level=risk_level,
            is_official_trusted_domain=is_official,
            impersonated_brand=impersonated_brand,
            findings=findings,
            safe_alternative_advice=safe_advice,
        )
        if tool_context is not None:
            tool_context.state["last_inspected_hostname"] = hostname
            tool_context.state["last_url_risk_level"] = risk_level

        span.set_attribute("url.hostname", hostname)
        span.set_attribute("url.risk_score", risk_score)
        return result.model_dump()
