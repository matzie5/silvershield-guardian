"""Top-level ADK App and root_agent assembly for SilverShield Guardian.

Wires together:
- Multi-agent coordinator & specialist workflows (`app/agents/hierarchy.py`)
- Constitutional GlobalInstructionPlugin + SeniorSafetyGuardrailPlugin +
  AuditObservabilityPlugin + SilverShieldRetryPlugin + AsyncMemoryPlugin
- ADK `EventsCompactionConfig` + `ContextCacheConfig` + `ResumabilityConfig(is_resumable=True)`
- Structured JSON logging and OpenTelemetry distributed tracing
"""

from __future__ import annotations

from typing import Any

from google.adk.apps import App, ResumabilityConfig
from google.adk.plugins.global_instruction_plugin import GlobalInstructionPlugin

from app.agents.hierarchy import create_root_coordinator
from app.config.model_router import ModelRouter
from app.config.settings import Settings, get_settings
from app.memory.async_memory_manager import (
    AsyncMemoryConsolidator,
    get_memory_consolidator,
)
from app.memory.compaction import (
    build_context_cache_config,
    build_events_compaction_config,
)
from app.observability.logging import configure_logging
from app.observability.tracing import configure_tracing
from app.plugins.async_memory_plugin import AsyncMemoryPlugin
from app.plugins.audit_observability_plugin import AuditObservabilityPlugin
from app.plugins.safety_guardrail_plugin import (
    SeniorSafetyGuardrailPlugin,
    SilverShieldRetryPlugin,
)
from app.prompts.constitution import GLOBAL_SENIOR_CONSTITUTION
from app.security.pii_redactor import get_pii_redactor


def create_silvershield_app(
    *,
    settings: Settings | None = None,
    app_name: str | None = None,
    consolidator: AsyncMemoryConsolidator | None = None,
    model_override: Any | None = None,
    enable_web_grounding: bool = False,
) -> App:
    """Factory creating a fully wired SilverShield ADK `App`."""
    cfg = settings or get_settings()
    configure_tracing(cfg)
    configure_logging(cfg)

    router = ModelRouter(cfg)
    redactor = get_pii_redactor(
        enable_cloud_dlp=cfg.enable_cloud_dlp,
        project_id=cfg.google_cloud_project,
    )
    active_consolidator = consolidator or get_memory_consolidator(cfg)

    coordinator = create_root_coordinator(
        router=router,
        settings=cfg,
        enable_web_grounding=enable_web_grounding,
        model_override=model_override,
    )

    plugins = [
        GlobalInstructionPlugin(
            global_instruction=GLOBAL_SENIOR_CONSTITUTION,
            name="silvershield_constitution",
        ),
        SeniorSafetyGuardrailPlugin(
            enable_model_armor=cfg.enable_model_armor,
            model_armor_template_id=cfg.model_armor_template_id,
            redactor=redactor,
        ),
        AuditObservabilityPlugin(redactor=redactor),
        SilverShieldRetryPlugin(max_retries=2),
        AsyncMemoryPlugin(consolidator=active_consolidator),
    ]

    return App(
        name=app_name or cfg.app_name,
        root_agent=coordinator,
        plugins=plugins,
        events_compaction_config=build_events_compaction_config(cfg, router),
        context_cache_config=build_context_cache_config(cfg),
        resumability_config=ResumabilityConfig(is_resumable=True),
    )


app = create_silvershield_app()
root_agent = app.root_agent
