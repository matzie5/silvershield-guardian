"""Persistent cross-session memory service and non-blocking async consolidation.

Implements:
1. `PersistentSqliteMemoryService(BaseMemoryService)`: A real persistent ADK
   memory service that scrubs PII before storage and supports cross-session
   semantic/keyword recall.
2. `build_memory_service`: Selects Vertex AI Memory Bank (`VertexAiMemoryBankService`)
   when deployed to Agent Runtime, or `PersistentSqliteMemoryService` locally/Cloud Run.
3. `AsyncMemoryConsolidator`: Schedules expensive memory extraction, PII scrubbing,
   and persistence as non-blocking background `asyncio.Task`s so the user-facing
   conversation UI never blocks.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from google.adk.events.event import Event
from google.adk.memory import BaseMemoryService, InMemoryMemoryService
from google.adk.memory.base_memory_service import SearchMemoryResponse
from google.adk.memory.memory_entry import MemoryEntry
from google.adk.sessions.session import Session
from google.genai import types

from app.config.settings import Settings, get_settings
from app.memory.knowledge_store import compute_text_embedding, cosine_similarity
from app.observability.logging import get_logger
from app.observability.tracing import traced_span
from app.security.pii_redactor import PIIRedactor, get_pii_redactor

logger = get_logger(__name__)


def _extract_event_text(event: Event) -> str:
    """Safely extract concatenated text parts from an ADK Event."""
    content = getattr(event, "content", None)
    parts = getattr(content, "parts", None) if content is not None else None
    if not parts:
        return ""
    texts: list[str] = []
    for part in parts:
        text = getattr(part, "text", None)
        if text:
            texts.append(str(text))
    return " ".join(texts).strip()


class PersistentSqliteMemoryService(BaseMemoryService):
    """ADK `BaseMemoryService` backed by SQLite with active PII scrubbing & vector recall."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        redactor: PIIRedactor | None = None,
    ) -> None:
        self._db_path = Path(db_path).expanduser()
        self._redactor = redactor or get_pii_redactor()
        if str(self._db_path) != ":memory:":
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_memories (
                    memory_id TEXT PRIMARY KEY,
                    app_name TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    session_id TEXT,
                    author TEXT NOT NULL,
                    text_content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memories_app_user
                ON user_memories (app_name, user_id)
                """
            )
            conn.commit()

    def _insert_entries_sync(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str | None,
        entries: list[tuple[str, str, dict[str, Any]]],
    ) -> int:
        if not entries:
            return 0
        now_iso = datetime.now(UTC).isoformat()
        inserted = 0
        with self._connect() as conn:
            for author, raw_text, metadata in entries:
                redaction = self._redactor.redact_text(raw_text)
                clean_text = redaction.redacted_text.strip()
                if not clean_text:
                    continue
                safe_metadata = self._redactor.redact_structure(dict(metadata))
                safe_metadata["pii_scrubbed"] = redaction.had_pii
                embedding = compute_text_embedding(clean_text)
                conn.execute(
                    """
                    INSERT INTO user_memories (
                        memory_id, app_name, user_id, session_id, author,
                        text_content, metadata_json, embedding_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        app_name,
                        user_id,
                        session_id,
                        author,
                        clean_text,
                        json.dumps(safe_metadata),
                        json.dumps(embedding),
                        now_iso,
                    ),
                )
                inserted += 1
            conn.commit()
        return inserted

    async def add_session_to_memory(self, session: Session) -> None:
        """Persist PII-scrubbed textual highlights from a full ADK session."""
        extracted: list[tuple[str, str, dict[str, Any]]] = []
        for event in getattr(session, "events", []) or []:
            text = _extract_event_text(event)
            if text:
                extracted.append(
                    (
                        getattr(event, "author", "unknown") or "unknown",
                        text,
                        {"source": "session_consolidation"},
                    )
                )
        inserted = await asyncio.to_thread(
            self._insert_entries_sync,
            app_name=session.app_name,
            user_id=session.user_id,
            session_id=session.id,
            entries=extracted,
        )
        logger.info(
            "memory_session_persisted",
            app_name=session.app_name,
            session_id=session.id,
            entries_persisted=inserted,
        )

    async def add_events_to_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        events: Sequence[Event],
        session_id: str | None = None,
        custom_metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Incrementally persist PII-scrubbed event deltas."""
        meta = dict(custom_metadata or {})
        extracted = [
            (
                getattr(event, "author", "unknown") or "unknown",
                text,
                meta,
            )
            for event in events
            if (text := _extract_event_text(event))
        ]
        await asyncio.to_thread(
            self._insert_entries_sync,
            app_name=app_name,
            user_id=user_id,
            session_id=session_id,
            entries=extracted,
        )

    async def add_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        memories: Sequence[MemoryEntry],
        custom_metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Persist explicit `MemoryEntry` items after mandatory PII redaction."""
        base_meta = dict(custom_metadata or {})
        extracted: list[tuple[str, str, dict[str, Any]]] = []
        for entry in memories:
            parts = entry.content.parts or []
            text = " ".join(
                str(p.text) for p in parts if getattr(p, "text", None)
            ).strip()
            if text:
                merged_meta = {**base_meta, **(entry.custom_metadata or {})}
                extracted.append((entry.author or "silvershield", text, merged_meta))
        await asyncio.to_thread(
            self._insert_entries_sync,
            app_name=app_name,
            user_id=user_id,
            session_id=None,
            entries=extracted,
        )

    def _search_sync(
        self, *, app_name: str, user_id: str, query: str, limit: int = 8
    ) -> list[MemoryEntry]:
        clean_query = self._redactor.redact_text(query).redacted_text
        query_vec = compute_text_embedding(clean_query)
        scored: list[tuple[float, MemoryEntry]] = []

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT memory_id, author, text_content, metadata_json, embedding_json, created_at
                FROM user_memories
                WHERE app_name = ? AND user_id = ?
                ORDER BY created_at DESC
                LIMIT 200
                """,
                (app_name, user_id),
            ).fetchall()

            for row in rows:
                vec = json.loads(row["embedding_json"])
                sim = cosine_similarity(query_vec, vec)
                # Keyword boost for direct safety-topic recall
                if clean_query.lower() in row["text_content"].lower():
                    sim = min(1.0, sim + 0.25)
                if sim >= 0.08 or not clean_query.strip():
                    entry = MemoryEntry(
                        id=row["memory_id"],
                        author=row["author"],
                        timestamp=row["created_at"],
                        custom_metadata=json.loads(row["metadata_json"]),
                        content=types.Content(
                            role="model" if row["author"] != "user" else "user",
                            parts=[types.Part.from_text(text=row["text_content"])],
                        ),
                    )
                    scored.append((sim, entry))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [entry for _, entry in scored[:limit]]

    async def search_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        query: str,
    ) -> SearchMemoryResponse:
        """Retrieve relevant PII-scrubbed memories across prior sessions."""
        with traced_span(
            "memory_service.search_memory",
            attributes={"app_name": app_name, "backend": "sqlite"},
        ):
            entries = await asyncio.to_thread(
                self._search_sync, app_name=app_name, user_id=user_id, query=query
            )
            return SearchMemoryResponse(memories=entries)


def build_memory_service(settings: Settings | None = None) -> BaseMemoryService:
    """Create the configured cross-session ADK Memory Service."""
    cfg = settings or get_settings()

    if (
        cfg.memory_backend == "vertex_ai"
        and cfg.google_cloud_project
        and cfg.vertex_agent_engine_id
    ):
        try:
            from google.adk.memory import VertexAiMemoryBankService

            service = VertexAiMemoryBankService(
                project=cfg.google_cloud_project,
                location=cfg.google_cloud_location,
                agent_engine_id=cfg.vertex_agent_engine_id,
            )
            logger.info("memory_service_initialized", backend="vertex_ai_memory_bank")
            return service
        except Exception as exc:
            logger.warning(
                "vertex_ai_memory_init_failed",
                error=str(exc),
                fallback="persistent_sqlite",
            )

    if cfg.memory_backend == "memory":
        logger.info("memory_service_initialized", backend="in_memory")
        return InMemoryMemoryService()

    logger.info("memory_service_initialized", backend="persistent_sqlite")
    return PersistentSqliteMemoryService(db_path=cfg.memory_db_path)


class AsyncMemoryConsolidator:
    """Schedules expensive PII-scrubbed memory consolidation on background tasks.

    Keeps the senior citizen's interactive chat turn fast and non-blocking by
    offloading consolidation to bounded `asyncio.Task`s with full OpenTelemetry
    tracing, error capture, and graceful shutdown draining.
    """

    def __init__(
        self,
        memory_service: BaseMemoryService,
        *,
        redactor: PIIRedactor | None = None,
        max_concurrency: int = 4,
    ) -> None:
        self._memory_service = memory_service
        self._redactor = redactor or get_pii_redactor()
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._pending_tasks: set[asyncio.Task[None]] = set()
        self.completed_count: int = 0
        self.failed_count: int = 0

    @property
    def memory_service(self) -> BaseMemoryService:
        """Expose underlying persistent memory service for queries."""
        return self._memory_service

    @property
    def pending_count(self) -> int:
        """Number of background consolidation tasks currently in flight."""
        return len(self._pending_tasks)

    def schedule_consolidation(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
        summary_text: str,
        metadata: dict[str, Any] | None = None,
    ) -> asyncio.Task[None]:
        """Dispatch a non-blocking background task to scrub and consolidate memory."""
        task = asyncio.create_task(
            self._run_consolidation(
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
                summary_text=summary_text,
                metadata=metadata or {},
            ),
            name=f"silvershield-memory-{session_id}",
        )
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)
        logger.info(
            "async_memory_task_scheduled",
            session_id=session_id,
            pending_tasks=len(self._pending_tasks),
        )
        return task

    async def _run_consolidation(
        self,
        *,
        app_name: str,
        user_id: str,
        session_id: str,
        summary_text: str,
        metadata: dict[str, Any],
    ) -> None:
        async with self._semaphore:
            with traced_span(
                "memory.async_consolidation",
                attributes={"app_name": app_name, "session_id": session_id},
            ):
                try:
                    redaction = self._redactor.redact_text(summary_text)
                    safe_meta = self._redactor.redact_structure(
                        {
                            **metadata,
                            "session_id": session_id,
                            "pii_entities_scrubbed": redaction.entities_detected,
                        }
                    )
                    entry = MemoryEntry(
                        author="silvershield_memory_consolidator",
                        timestamp=datetime.now(UTC).isoformat(),
                        custom_metadata=safe_meta if isinstance(safe_meta, dict) else {},
                        content=types.Content(
                            role="model",
                            parts=[types.Part.from_text(text=redaction.redacted_text)],
                        ),
                    )
                    await self._memory_service.add_memory(
                        app_name=app_name,
                        user_id=user_id,
                        memories=[entry],
                        custom_metadata={"session_id": session_id},
                    )
                    self.completed_count += 1
                    logger.info(
                        "async_memory_consolidation_completed",
                        session_id=session_id,
                        pii_scrubbed=redaction.had_pii,
                        completed_count=self.completed_count,
                    )
                except Exception as exc:
                    self.failed_count += 1
                    logger.error(
                        "async_memory_consolidation_failed",
                        session_id=session_id,
                        error=str(exc),
                    )

    async def wait_for_pending(self, timeout_seconds: float = 10.0) -> None:
        """Await all in-flight background memory consolidation tasks cleanly."""
        if not self._pending_tasks:
            return
        tasks = list(self._pending_tasks)
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout_seconds,
        )


_DEFAULT_CONSOLIDATOR: AsyncMemoryConsolidator | None = None


def get_memory_consolidator(
    settings: Settings | None = None,
) -> AsyncMemoryConsolidator:
    """Return the process-wide `AsyncMemoryConsolidator`."""
    global _DEFAULT_CONSOLIDATOR
    if settings is not None:
        return AsyncMemoryConsolidator(build_memory_service(settings))
    if _DEFAULT_CONSOLIDATOR is None:
        _DEFAULT_CONSOLIDATOR = AsyncMemoryConsolidator(build_memory_service())
    return _DEFAULT_CONSOLIDATOR
