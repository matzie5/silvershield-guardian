"""Non-blocking ADK plugin dispatching background memory consolidation tasks."""

from __future__ import annotations

from typing import Any

from google.adk.plugins.base_plugin import BasePlugin

from app.memory.async_memory_manager import (
    AsyncMemoryConsolidator,
    get_memory_consolidator,
)
from app.observability.logging import get_logger

logger = get_logger(__name__)


class AsyncMemoryPlugin(BasePlugin):
    """Triggers non-blocking background memory consolidation after every runner turn."""

    def __init__(
        self,
        *,
        consolidator: AsyncMemoryConsolidator | None = None,
        name: str = "async_memory_consolidation",
    ) -> None:
        super().__init__(name=name)
        self._consolidator = consolidator

    def _get_consolidator(self) -> AsyncMemoryConsolidator:
        if self._consolidator is None:
            self._consolidator = get_memory_consolidator()
        return self._consolidator

    async def after_run_callback(self, *, invocation_context: Any) -> None:
        """Schedule PII-scrubbed background memory consolidation without blocking response."""
        session = getattr(invocation_context, "session", None)
        if session is None:
            return

        events = getattr(session, "events", None) or []
        snippets: list[str] = []
        for event in events[-4:]:
            content = getattr(event, "content", None)
            parts = getattr(content, "parts", None) if content is not None else None
            if not parts:
                continue
            text = " ".join(
                str(p.text) for p in parts if getattr(p, "text", None)
            ).strip()
            if text:
                author = getattr(event, "author", "unknown") or "unknown"
                snippets.append(f"{author}: {text[:300]}")

        if not snippets:
            return

        state = getattr(session, "state", {}) or {}
        summary = " | ".join(snippets)
        metadata = {
            "last_scam_risk_level": state.get("last_scam_risk_level", "unknown"),
            "last_scam_category": state.get("last_scam_category", "none"),
            "last_fact_check_verdict": state.get("last_fact_check_verdict", "none"),
        }

        consolidator = self._get_consolidator()
        consolidator.schedule_consolidation(
            app_name=session.app_name,
            user_id=session.user_id,
            session_id=session.id,
            summary_text=summary,
            metadata=metadata,
        )

    async def close(self) -> None:
        """Drain pending background memory tasks gracefully on runner shutdown."""
        if self._consolidator is not None:
            try:
                await self._consolidator.wait_for_pending(timeout_seconds=5.0)
            except Exception as exc:
                logger.warning("async_memory_drain_timeout", error=str(exc))
