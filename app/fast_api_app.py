"""Production FastAPI server for Cloud Run / GKE deployment via ADK `get_fast_api_app`.

Configures:
- Persistent ADK session backend (SQLite locally, Cloud SQL PostgreSQL in prod)
- OpenTelemetry Cloud Trace export (`otel_to_cloud=True` in cloud environments)
- Structured JSON health and JSON-schema inspection endpoints
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from google.adk.cli.fast_api import get_fast_api_app

from app.config.settings import Settings, get_settings
from app.memory.session_store import build_session_service_uri
from app.observability.logging import configure_logging, get_logger
from app.observability.tracing import configure_tracing
from app.schemas.tool_schemas import get_all_tool_json_schemas

logger = get_logger(__name__)


def create_web_app(settings: Settings | None = None) -> FastAPI:
    """Create the production FastAPI app serving SilverShield Guardian."""
    cfg = settings or get_settings()
    configure_tracing(cfg)
    configure_logging(cfg)

    agents_dir = str(Path(__file__).resolve().parent.parent)
    session_uri = build_session_service_uri(cfg)
    export_to_cloud = cfg.otel_traces_exporter == "google_cloud_trace"

    web_app = get_fast_api_app(
        agents_dir=agents_dir,
        session_service_uri=session_uri,
        web=(cfg.app_env == "local"),
        otel_to_cloud=export_to_cloud,
        trace_to_cloud=export_to_cloud,
    )
    web_app.title = "SilverShield Guardian — Senior Scam & Fake News Protection Agent"
    web_app.version = "1.0.0"

    @web_app.get("/healthz", tags=["operations"])
    async def health_check() -> dict[str, Any]:
        """Liveness & readiness probe endpoint (never exposes secrets)."""
        return {
            "status": "ok",
            "service": cfg.otel_service_name,
            "environment": cfg.app_env,
            "session_backend": cfg.session_backend,
            "memory_backend": cfg.memory_backend,
            "fast_model": cfg.fast_model_name,
            "reasoning_model": cfg.reasoning_model_name,
        }

    @web_app.get("/api/tool-schemas", tags=["contracts"])
    async def tool_schemas() -> dict[str, Any]:
        """Expose explicit Pydantic JSON Schemas for all registered SilverShield tools."""
        return get_all_tool_json_schemas()

    logger.info(
        "fastapi_server_initialized",
        environment=cfg.app_env,
        otel_to_cloud=export_to_cloud,
        session_backend=cfg.session_backend,
    )
    return web_app


fast_api_app = create_web_app()
