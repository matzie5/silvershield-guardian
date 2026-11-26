"""Persistent ADK Session Service factory (SQLite, Cloud SQL PostgreSQL, Vertex AI).

Ensures conversational history and risk state survive restarts and multi-turn
sessions using `DatabaseSessionService` locally/on Cloud SQL or
`VertexAiSessionService` on Vertex AI Agent Runtime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from google.adk.sessions import BaseSessionService, InMemorySessionService

from app.config.settings import Settings, get_settings
from app.observability.logging import get_logger

logger = get_logger(__name__)


def _ensure_sqlite_parent_dir(db_url: str) -> None:
    """Create parent directory for local SQLite file URLs if needed."""
    prefixes = ("sqlite+aiosqlite:///", "sqlite:///")
    for prefix in prefixes:
        if db_url.startswith(prefix):
            path_part = db_url[len(prefix) :]
            if path_part and path_part != ":memory:":
                Path(path_part).expanduser().resolve().parent.mkdir(
                    parents=True, exist_ok=True
                )
            break


def build_session_service_uri(settings: Settings | None = None) -> str:
    """Return the session service URI suitable for ADK FastAPI / Runner config."""
    cfg = settings or get_settings()
    if cfg.session_backend == "memory":
        return "memory://"
    if cfg.session_backend == "vertex_ai":
        if cfg.google_cloud_project and cfg.vertex_agent_engine_id:
            return (
                f"agentengine://projects/{cfg.google_cloud_project}/"
                f"locations/{cfg.google_cloud_location}/"
                f"reasoningEngines/{cfg.vertex_agent_engine_id}"
            )
        logger.warning(
            "vertex_ai_session_fallback",
            reason="Missing project or agent_engine_id; falling back to persistent SQLite.",
        )
    db_url = cfg.resolve_session_db_url()
    _ensure_sqlite_parent_dir(db_url)
    return db_url


def build_session_service(settings: Settings | None = None) -> BaseSessionService:
    """Instantiate the configured persistent ADK session service."""
    cfg = settings or get_settings()

    if cfg.session_backend == "memory":
        logger.info("session_service_initialized", backend="in_memory")
        return InMemorySessionService()

    if cfg.session_backend == "vertex_ai" and cfg.google_cloud_project:
        try:
            from google.adk.sessions import VertexAiSessionService

            kwargs: dict[str, Any] = {
                "project": cfg.google_cloud_project,
                "location": cfg.google_cloud_location,
            }
            if cfg.vertex_agent_engine_id:
                kwargs["agent_engine_id"] = cfg.vertex_agent_engine_id
            service = VertexAiSessionService(**kwargs)
            logger.info(
                "session_service_initialized",
                backend="vertex_ai",
                location=cfg.google_cloud_location,
            )
            return service
        except Exception as exc:
            logger.warning(
                "vertex_ai_session_init_failed",
                error=str(exc),
                fallback="database_sqlite",
            )

    from google.adk.sessions import DatabaseSessionService

    db_url = cfg.resolve_session_db_url()
    _ensure_sqlite_parent_dir(db_url)
    logger.info(
        "session_service_initialized",
        backend=cfg.session_backend,
        scheme=db_url.split("://", maxsplit=1)[0],
    )
    return DatabaseSessionService(db_url=db_url)
