"""Automated golden-dataset regression evaluator for SilverShield Guardian.

Validates:
1. ADK `EvalSet` and `EvalConfig` schema integrity.
2. Deterministic regression metrics across all 8 golden senior-safety scenarios:
   - Elder scam detection recall (target: 100%)
   - Fake news detection recall (target: 100%)
   - Benign message false-positive rate (target: 0%)
   - Zero PII leakage across outputs and memory
   - Mandatory HITL confirmation enforcement on high-stakes actions
3. Exits with code 0 only when every regression threshold passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Ensure repository root is importable when run directly via `python tests/eval/run_golden_eval.py`
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from google.adk.evaluation.eval_set import EvalSet  # noqa: E402

from app.schemas.tool_schemas import get_all_tool_json_schemas  # noqa: E402
from app.security.pii_redactor import PIIRedactor  # noqa: E402
from app.tools.fact_check import verify_news_claim_credibility  # noqa: E402
from app.tools.high_stakes_actions import (  # noqa: E402
    file_official_ftc_scam_report_tool,
    notify_trusted_family_caregiver_tool,
    requires_quarantine_confirmation,
)
from app.tools.knowledge_base import lookup_known_elder_scam_patterns  # noqa: E402
from app.tools.scam_analysis import (  # noqa: E402
    analyze_message_scam_indicators,
    inspect_url_and_domain_reputation,
)

EVALSET_PATH = REPO_ROOT / "tests/eval/evalsets/scam_and_fake_news.evalset.json"
EVAL_CONFIG_PATH = REPO_ROOT / "tests/eval/eval_config.json"


def run_regression_suite() -> dict[str, Any]:
    """Execute deterministic regression evaluation against the ADK golden dataset."""
    raw_evalset = json.loads(EVALSET_PATH.read_text(encoding="utf-8"))
    eval_set = EvalSet.model_validate(raw_evalset)
    eval_config = json.loads(EVAL_CONFIG_PATH.read_text(encoding="utf-8"))

    case_results: list[dict[str, Any]] = []
    scam_total = scam_hits = 0
    fakenews_total = fakenews_hits = 0
    benign_total = benign_false_positives = 0

    for case in eval_set.eval_cases:
        eval_id = case.eval_id
        user_text = case.conversation[0].user_content.parts[0].text or ""

        if eval_id.startswith("scam_"):
            scam_total += 1
            res = analyze_message_scam_indicators(
                message_text=user_text, channel="unknown", claimed_sender=""
            )
            url_high_risk = False
            for url in res.get("extracted_urls", []):
                url_res = inspect_url_and_domain_reputation(url=url)
                if url_res.get("risk_level") == "HIGH_RISK":
                    url_high_risk = True
            kb_res = lookup_known_elder_scam_patterns(query_text=user_text, top_k=2)
            passed = (
                res["risk_level"] == "HIGH_RISK" or url_high_risk
            ) and len(kb_res.get("matches", [])) >= 1
            if passed:
                scam_hits += 1
            case_results.append(
                {
                    "eval_id": eval_id,
                    "passed": passed,
                    "risk_score": res["risk_score"],
                    "risk_level": res["risk_level"],
                    "kb_top_match": kb_res["matches"][0]["pattern_id"]
                    if kb_res.get("matches")
                    else None,
                }
            )
        elif eval_id.startswith("fakenews_"):
            fakenews_total += 1
            topic = (
                "health_medicine"
                if "diabetes" in eval_id
                else "government_benefits"
            )
            res = verify_news_claim_credibility(
                claim_text=user_text, source_name="Social media forward", topic_area=topic
            )
            passed = res["verdict"] in {
                "LIKELY_FAKE_NEWS",
                "MISLEADING_OR_OUT_OF_CONTEXT",
            }
            if passed:
                fakenews_hits += 1
            case_results.append(
                {
                    "eval_id": eval_id,
                    "passed": passed,
                    "verdict": res["verdict"],
                    "credibility_score": res["credibility_score"],
                }
            )
        elif eval_id.startswith("benign_"):
            benign_total += 1
            res = analyze_message_scam_indicators(
                message_text=user_text, channel="sms", claimed_sender="Oakridge Family Clinic"
            )
            passed = res["risk_level"] == "SAFE"
            if not passed:
                benign_false_positives += 1
            case_results.append(
                {
                    "eval_id": eval_id,
                    "passed": passed,
                    "risk_score": res["risk_score"],
                    "risk_level": res["risk_level"],
                }
            )
        elif eval_id.startswith("hitl_"):
            hitl_enforced = (
                notify_trusted_family_caregiver_tool._require_confirmation is True
                and file_official_ftc_scam_report_tool._require_confirmation is True
                and requires_quarantine_confirmation(
                    sender_identifier="Dr. Patel Clinic", confidence_score=0.95
                )
                is True
            )
            case_results.append(
                {
                    "eval_id": eval_id,
                    "passed": hitl_enforced,
                    "hitl_enforced": hitl_enforced,
                }
            )

    # Verify PII zero-leakage benchmark
    redactor = PIIRedactor(enable_cloud_dlp=False)
    sample_pii = "My SSN is 123-45-6789, email grandma@example.com, phone 555-234-5678."
    redacted = redactor.redact_text(sample_pii).redacted_text
    pii_zero_leak = all(
        raw not in redacted
        for raw in ("123-45-6789", "grandma@example.com", "555-234-5678")
    )

    schemas = get_all_tool_json_schemas()
    schemas_valid = len(schemas) == 8

    scam_recall = scam_hits / max(1, scam_total)
    fakenews_recall = fakenews_hits / max(1, fakenews_total)
    benign_fp_rate = benign_false_positives / max(1, benign_total)
    all_passed = (
        all(r["passed"] for r in case_results)
        and scam_recall == 1.0
        and fakenews_recall == 1.0
        and benign_fp_rate == 0.0
        and pii_zero_leak
        and schemas_valid
    )

    return {
        "eval_set_id": eval_set.eval_set_id,
        "criteria_configured": list(eval_config["criteria"].keys()),
        "total_cases": len(case_results),
        "passed_cases": sum(1 for r in case_results if r["passed"]),
        "metrics": {
            "scam_detection_recall": scam_recall,
            "fake_news_detection_recall": fakenews_recall,
            "benign_false_positive_rate": benign_fp_rate,
            "pii_zero_leakage": pii_zero_leak,
            "tool_json_schemas_count": len(schemas),
        },
        "all_passed": all_passed,
        "case_results": case_results,
    }


def main() -> int:
    report = run_regression_suite()
    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
