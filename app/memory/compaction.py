"""Context bloat management: ADK EventsCompactionConfig, ContextCacheConfig, and PII-safe windowing.

Prevents unbounded context growth across long senior-citizen conversations by:
1. Configuring ADK `EventsCompactionConfig` with both sliding-window and
   token-threshold summarization backed by a fast Gemini Flash summarizer.
2. Enabling Gemini `ContextCacheConfig` to cache the static Senior Constitution
   and scam taxonomy prefix.
3. Providing a deterministic, PII-scrubbed `PIISafeHistoryCompactor` utility for
   local compaction and regression verification.
"""

from __future__ import annotations

from dataclasses import dataclass

from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.apps.app import EventsCompactionConfig
from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
from google.adk.models import Gemini

from app.config.model_router import ModelRouter, TaskKind
from app.config.settings import Settings, get_settings
from app.security.pii_redactor import PIIRedactor, get_pii_redactor

COMPACTION_SUMMARY_PROMPT = (
    "You are summarizing an earlier part of a digital-safety conversation with a "
    "senior citizen. Preserve: (1) any scam tactics, suspicious domains, or fake "
    "news claims already evaluated and their SAFE/CAUTION/HIGH RISK verdicts, "
    "(2) exact tool names called, and (3) any open follow-up actions requested by "
    "the user. NEVER copy any personal identifiers (SSN, phone numbers, emails, "
    "card numbers, passwords) into the summary.\n\n{conversation_history}"
)


def build_events_compaction_config(
    settings: Settings | None = None,
    router: ModelRouter | None = None,
) -> EventsCompactionConfig:
    """Build ADK `EventsCompactionConfig` using Gemini Flash for low-cost compaction."""
    cfg = settings or get_settings()
    model_router = router or ModelRouter(cfg)
    route_decision = model_router.route(TaskKind.COMPACTION_SUMMARY)

    summarizer = LlmEventSummarizer(
        llm=Gemini(model=route_decision.model_name),
        prompt_template=COMPACTION_SUMMARY_PROMPT,
    )
    return EventsCompactionConfig(
        compaction_interval=cfg.compaction_interval,
        overlap_size=cfg.compaction_overlap_size,
        token_threshold=cfg.compaction_token_threshold,
        event_retention_size=cfg.compaction_event_retention_size,
        summarizer=summarizer,
    )


def build_context_cache_config(
    settings: Settings | None = None,
) -> ContextCacheConfig | None:
    """Build ADK `ContextCacheConfig` when context caching is enabled."""
    cfg = settings or get_settings()
    if not cfg.enable_context_caching:
        return None
    return ContextCacheConfig(
        min_tokens=2048,
        ttl_seconds=1800,
        cache_intervals=10,
    )


@dataclass(frozen=True)
class CompactedWindow:
    """Result of PII-safe token-budget sliding-window compaction."""

    summary: str
    retained_turns: list[dict[str, str]]
    compacted_turn_count: int
    estimated_tokens_before: int
    estimated_tokens_after: int


class PIISafeHistoryCompactor:
    """Token-aware sliding-window history compactor with built-in PII scrubbing."""

    def __init__(
        self,
        *,
        max_token_budget: int = 2000,
        retain_recent_turns: int = 4,
        redactor: PIIRedactor | None = None,
    ) -> None:
        self._max_token_budget = max(200, max_token_budget)
        self._retain_recent_turns = max(1, retain_recent_turns)
        self._redactor = redactor or get_pii_redactor()

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Approximate token count (~4 characters per token)."""
        return max(1, (len(text) + 3) // 4) if text else 0

    def compact_turns(self, turns: list[dict[str, str]]) -> CompactedWindow:
        """Compact older turns into a PII-scrubbed digest when over token budget."""
        total_before = sum(
            self.estimate_tokens(t.get("content", "")) for t in turns
        )
        if total_before <= self._max_token_budget or len(turns) <= self._retain_recent_turns:
            scrubbed_recent = [
                {
                    "role": t.get("role", "user"),
                    "content": self._redactor.redact_text(
                        t.get("content", "")
                    ).redacted_text,
                }
                for t in turns
            ]
            return CompactedWindow(
                summary="",
                retained_turns=scrubbed_recent,
                compacted_turn_count=0,
                estimated_tokens_before=total_before,
                estimated_tokens_after=sum(
                    self.estimate_tokens(t["content"]) for t in scrubbed_recent
                ),
            )

        older = turns[: -self._retain_recent_turns]
        recent = turns[-self._retain_recent_turns :]

        digest_lines: list[str] = []
        for idx, turn in enumerate(older, start=1):
            role = turn.get("role", "user")
            clean_text = self._redactor.redact_text(
                turn.get("content", "")
            ).redacted_text
            excerpt = clean_text[:180].replace("\n", " ").strip()
            digest_lines.append(f"- Turn {idx} ({role}): {excerpt}")

        summary = "Earlier conversation summary (PII redacted):\n" + "\n".join(
            digest_lines
        )
        retained = [
            {
                "role": t.get("role", "user"),
                "content": self._redactor.redact_text(
                    t.get("content", "")
                ).redacted_text,
            }
            for t in recent
        ]
        tokens_after = self.estimate_tokens(summary) + sum(
            self.estimate_tokens(t["content"]) for t in retained
        )
        return CompactedWindow(
            summary=summary,
            retained_turns=retained,
            compacted_turn_count=len(older),
            estimated_tokens_before=total_before,
            estimated_tokens_after=tokens_after,
        )
