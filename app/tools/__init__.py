"""SilverShield domain tools for scam forensics, fact-checking, memory, and HITL actions."""

from app.tools.fact_check import verify_news_claim_credibility
from app.tools.high_stakes_actions import (
    file_official_ftc_scam_report,
    file_official_ftc_scam_report_tool,
    notify_trusted_family_caregiver,
    notify_trusted_family_caregiver_tool,
    quarantine_suspicious_sender,
    quarantine_suspicious_sender_tool,
    requires_quarantine_confirmation,
)
from app.tools.knowledge_base import lookup_known_elder_scam_patterns
from app.tools.memory_tools import retrieve_senior_safety_history
from app.tools.scam_analysis import (
    analyze_message_scam_indicators,
    inspect_url_and_domain_reputation,
)

__all__ = [
    "analyze_message_scam_indicators",
    "file_official_ftc_scam_report",
    "file_official_ftc_scam_report_tool",
    "inspect_url_and_domain_reputation",
    "lookup_known_elder_scam_patterns",
    "notify_trusted_family_caregiver",
    "notify_trusted_family_caregiver_tool",
    "quarantine_suspicious_sender",
    "quarantine_suspicious_sender_tool",
    "requires_quarantine_confirmation",
    "retrieve_senior_safety_history",
    "verify_news_claim_credibility",
]
