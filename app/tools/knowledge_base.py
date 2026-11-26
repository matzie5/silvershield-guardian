"""Persistent vector knowledge-base lookup tool for known elder scam patterns."""

from __future__ import annotations

from typing import Any

from google.adk.tools import ToolContext
from pydantic import ValidationError

from app.memory.knowledge_store import get_knowledge_store
from app.observability.tracing import traced_span
from app.schemas.tool_schemas import (
    KnownPatternHit,
    LookupScamPatternsRequest,
    ScamPatternMatchResult,
    ToolErrorResult,
)


def lookup_known_elder_scam_patterns(
    query_text: str,
    top_k: int = 3,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Search the persistent vector knowledge base for known elder scam and hoax scripts.

    Use this tool to cross-reference a suspicious phone call, text message, email,
    or viral post against documented elder-fraud schemes (such as grandparent scams,
    Medicare phishing, IRS gift-card demands, tech-support pop-ups, and debunked
    health or Social Security hoaxes).

    Args:
        query_text: Short summary or excerpt of the suspicious message or claim
            (3 to 2,000 characters). Example: "caller says my grandson is in jail and
            needs bail money without telling mom".
        top_k: Maximum number of matching known scam/hoax patterns to return (1 to 10).

    Returns:
        A JSON-serializable dictionary matching `ScamPatternMatchResult` containing
        `datastore_backend` and `matches` (each with `pattern_id`, `title`,
        `pattern_type`, `similarity_score`, `summary`, and `official_guidance`).
        Returns `ToolErrorResult` with `recovery_instructions` if validation fails.
    """
    with traced_span("tool.lookup_known_elder_scam_patterns", attributes={"top_k": top_k}):
        try:
            req = LookupScamPatternsRequest(query_text=query_text, top_k=top_k)
        except ValidationError as exc:
            return ToolErrorResult(
                error_code="INVALID_KNOWLEDGE_QUERY",
                error_message=f"Invalid pattern lookup query: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Provide a `query_text` of at least 3 characters summarizing the "
                    "suspected scam or claim, and set `top_k` between 1 and 10."
                ),
                retryable=True,
            ).model_dump()

        store = get_knowledge_store()
        raw_hits = store.search(req.query_text, top_k=req.top_k)
        hits = [
            KnownPatternHit(
                pattern_id=record.pattern_id,
                title=record.title,
                pattern_type=record.pattern_type,
                similarity_score=score,
                summary=record.summary,
                official_guidance=record.official_guidance,
            )
            for record, score in raw_hits
        ]

        if tool_context is not None and hits:
            tool_context.state["top_matched_pattern_id"] = hits[0].pattern_id

        return ScamPatternMatchResult(
            datastore_backend=store.backend_name,
            matches=hits,
        ).model_dump()
