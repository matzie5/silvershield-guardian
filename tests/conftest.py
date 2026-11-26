"""Shared pytest fixtures for SilverShield Guardian test isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config.settings import Settings
from app.observability.logging import configure_logging
from app.observability.tracing import configure_tracing


@pytest.fixture
def isolated_settings(tmp_path: Path) -> Settings:
    """Create isolated per-test settings pointing SQLite stores to tmp_path."""
    settings = Settings(
        app_env="local",
        log_format="json",
        session_backend="sqlite",
        session_db_url=f"sqlite+aiosqlite:///{tmp_path / 'sessions.db'}",
        knowledge_db_path=str(tmp_path / "knowledge.db"),
        memory_backend="sqlite",
        memory_db_path=str(tmp_path / "memory.db"),
        otel_traces_exporter="in_memory",
        enable_cloud_dlp=False,
        enable_model_armor=False,
    )
    configure_tracing(settings, force=True)
    configure_logging(settings, force=True)
    return settings
