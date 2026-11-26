"""Application settings backed by environment variables and GCP Secret Manager."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.security.secrets import SecretManagerResolver

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"


class Settings(BaseSettings):
    """Strongly typed runtime configuration for SilverShield Guardian."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # Environment & Logging
    app_env: Literal["local", "dev", "staging", "prod"] = Field(
        default="local", alias="APP_ENV"
    )
    app_name: str = Field(default="app", alias="APP_NAME")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: Literal["json", "console"] = Field(default="json", alias="LOG_FORMAT")

    # Google Cloud & GenAI
    google_genai_use_vertexai: bool = Field(
        default=False, alias="GOOGLE_GENAI_USE_VERTEXAI"
    )
    google_cloud_project: str | None = Field(
        default=None, alias="GOOGLE_CLOUD_PROJECT"
    )
    google_cloud_location: str = Field(
        default="us-central1", alias="GOOGLE_CLOUD_LOCATION"
    )

    # Secret Manager (no hardcoded API keys!)
    use_secret_manager: bool = Field(default=False, alias="USE_SECRET_MANAGER")
    gemini_api_key_secret_name: str = Field(
        default="silvershield-gemini-api-key", alias="GEMINI_API_KEY_SECRET_NAME"
    )
    session_db_secret_name: str = Field(
        default="silvershield-session-db-url", alias="SESSION_DB_SECRET_NAME"
    )

    # Strategic Model Routing
    fast_model_name: str = Field(
        default="gemini-2.5-flash", alias="SILVERSHIELD_FAST_MODEL"
    )
    reasoning_model_name: str = Field(
        default="gemini-2.5-pro", alias="SILVERSHIELD_REASONING_MODEL"
    )

    # Persistent Session, Knowledge Store & Memory Bank
    session_backend: Literal["sqlite", "postgres", "vertex_ai", "memory"] = Field(
        default="sqlite", alias="SESSION_BACKEND"
    )
    session_db_url: str = Field(
        default=f"sqlite+aiosqlite:///{_DEFAULT_DATA_DIR / 'silvershield_sessions.db'}",
        alias="SESSION_DB_URL",
    )
    knowledge_db_path: str = Field(
        default=str(_DEFAULT_DATA_DIR / "silvershield_knowledge.db"),
        alias="KNOWLEDGE_DB_PATH",
    )
    vertex_ai_search_datastore_id: str | None = Field(
        default=None, alias="VERTEX_AI_SEARCH_DATASTORE_ID"
    )
    memory_backend: Literal["sqlite", "vertex_ai", "memory"] = Field(
        default="sqlite", alias="MEMORY_BACKEND"
    )
    memory_db_path: str = Field(
        default=str(_DEFAULT_DATA_DIR / "silvershield_memory.db"),
        alias="MEMORY_DB_PATH",
    )
    vertex_agent_engine_id: str | None = Field(
        default=None, alias="VERTEX_AGENT_ENGINE_ID"
    )

    # Context Compaction & Caching
    compaction_interval: int = Field(default=8, ge=1, alias="COMPACTION_INTERVAL")
    compaction_overlap_size: int = Field(
        default=2, ge=0, alias="COMPACTION_OVERLAP_SIZE"
    )
    compaction_token_threshold: int = Field(
        default=12000, ge=512, alias="COMPACTION_TOKEN_THRESHOLD"
    )
    compaction_event_retention_size: int = Field(
        default=6, ge=1, alias="COMPACTION_EVENT_RETENTION_SIZE"
    )
    enable_context_caching: bool = Field(
        default=True, alias="ENABLE_CONTEXT_CACHING"
    )

    # Security & Guardrails
    enable_cloud_dlp: bool = Field(default=False, alias="ENABLE_CLOUD_DLP")
    enable_model_armor: bool = Field(default=False, alias="ENABLE_MODEL_ARMOR")
    model_armor_template_id: str | None = Field(
        default=None, alias="MODEL_ARMOR_TEMPLATE_ID"
    )

    # Observability & Distributed Tracing
    otel_sdk_disabled: bool = Field(default=False, alias="OTEL_SDK_DISABLED")
    otel_service_name: str = Field(
        default="silvershield-guardian", alias="OTEL_SERVICE_NAME"
    )
    otel_traces_exporter: Literal[
        "none", "console", "otlp", "google_cloud_trace", "in_memory"
    ] = Field(default="none", alias="OTEL_TRACES_EXPORTER")
    otel_exporter_otlp_endpoint: str | None = Field(
        default=None, alias="OTEL_EXPORTER_OTLP_ENDPOINT"
    )

    def build_secret_resolver(self) -> SecretManagerResolver:
        """Create a SecretManagerResolver configured from these settings."""
        return SecretManagerResolver(
            project_id=self.google_cloud_project,
            use_secret_manager=self.use_secret_manager,
        )

    def resolve_gemini_api_key(self, *, required: bool = False) -> str | None:
        """Resolve the Gemini API key via Secret Manager or environment (never hardcoded)."""
        if self.google_genai_use_vertexai:
            return None
        resolver = self.build_secret_resolver()
        return resolver.get_secret(
            env_var="GOOGLE_API_KEY",
            secret_name=self.gemini_api_key_secret_name,
            required=required,
            app_env=self.app_env,
        )

    def resolve_session_db_url(self) -> str:
        """Resolve the database connection URI securely via Secret Manager when using Cloud SQL."""
        if self.session_backend == "postgres":
            resolver = self.build_secret_resolver()
            secret_url = resolver.get_secret(
                env_var="SESSION_DB_URL",
                secret_name=self.session_db_secret_name,
                required=self.app_env in {"staging", "prod"},
                app_env=self.app_env,
            )
            if secret_url:
                return secret_url
        return self.session_db_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached process-wide application settings."""
    return Settings()
