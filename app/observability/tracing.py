"""Distributed OpenTelemetry tracing for SilverShield Guardian.

Links spans across FastAPI HTTP entrypoints, ADK multi-agent orchestration,
tool executions, guardrail evaluations, PII redaction, and background memory
consolidation. Supports Google Cloud Trace, OTLP, console, and in-memory export.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Span, Status, StatusCode, Tracer

from app.config.settings import Settings, get_settings

_CONFIGURED = False
_IN_MEMORY_EXPORTER: InMemorySpanExporter | None = None


def _build_exporter(settings: Settings) -> SpanExporter | None:
    global _IN_MEMORY_EXPORTER
    mode = settings.otel_traces_exporter

    if mode == "none" or settings.otel_sdk_disabled:
        return None
    if mode == "console":
        return ConsoleSpanExporter()
    if mode == "in_memory":
        _IN_MEMORY_EXPORTER = InMemorySpanExporter()
        return _IN_MEMORY_EXPORTER
    if mode == "google_cloud_trace":
        try:
            cloud_trace_mod: Any = importlib.import_module(
                "opentelemetry.exporter.cloud_trace"
            )
            return cast(
                SpanExporter,
                cloud_trace_mod.CloudTraceSpanExporter(
                    project_id=settings.google_cloud_project
                ),
            )
        except Exception:
            return None
    if mode == "otlp":
        try:
            otlp_mod: Any = importlib.import_module(
                "opentelemetry.exporter.otlp.proto.http.trace_exporter"
            )
            return cast(
                SpanExporter,
                otlp_mod.OTLPSpanExporter(
                    endpoint=settings.otel_exporter_otlp_endpoint
                ),
            )
        except Exception:
            return None
    return None


def configure_tracing(
    settings: Settings | None = None,
    *,
    exporter: SpanExporter | None = None,
    force: bool = False,
) -> TracerProvider:
    """Configure the global OpenTelemetry TracerProvider with the chosen exporter."""
    global _CONFIGURED
    cfg = settings or get_settings()

    existing = trace.get_tracer_provider()
    if _CONFIGURED and not force and isinstance(existing, TracerProvider):
        return existing

    active_exporter = exporter if exporter is not None else _build_exporter(cfg)
    processor = (
        SimpleSpanProcessor(active_exporter)
        if isinstance(active_exporter, (InMemorySpanExporter, ConsoleSpanExporter))
        else (BatchSpanProcessor(active_exporter) if active_exporter is not None else None)
    )

    # OpenTelemetry allows setting the global TracerProvider only once per process;
    # when reconfiguring (e.g., attaching an in-memory exporter in tests), attach the
    # processor to the existing SDK TracerProvider.
    if isinstance(existing, TracerProvider):
        if processor is not None:
            existing.add_span_processor(processor)
        _CONFIGURED = True
        return existing

    resource = Resource.create(
        {
            "service.name": cfg.otel_service_name,
            "service.namespace": "silvershield",
            "deployment.environment": cfg.app_env,
        }
    )
    provider = TracerProvider(resource=resource)
    if processor is not None:
        provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)
    _CONFIGURED = True
    return provider


def get_in_memory_exporter() -> InMemorySpanExporter | None:
    """Return the active in-memory span exporter if configured (useful in tests)."""
    return _IN_MEMORY_EXPORTER


def get_tracer(name: str = "silvershield") -> Tracer:
    """Return an OpenTelemetry Tracer bound to the active provider."""
    return trace.get_tracer(name)


def get_current_trace_context(project_id: str | None = None) -> dict[str, str]:
    """Extract trace_id and span_id from the active OTel span for log correlation."""
    span = trace.get_current_span()
    span_ctx = span.get_span_context() if span is not None else None
    if span_ctx is None or not span_ctx.is_valid:
        return {}

    trace_id_hex = f"{span_ctx.trace_id:032x}"
    span_id_hex = f"{span_ctx.span_id:016x}"
    context: dict[str, str] = {
        "trace_id": trace_id_hex,
        "span_id": span_id_hex,
    }
    if project_id:
        context["logging.googleapis.com/trace"] = (
            f"projects/{project_id}/traces/{trace_id_hex}"
        )
        context["logging.googleapis.com/spanId"] = span_id_hex
    return context


@contextmanager
def traced_span(
    span_name: str,
    *,
    attributes: dict[str, Any] | None = None,
    tracer_name: str = "silvershield",
) -> Iterator[Span]:
    """Context manager creating a linked OpenTelemetry span with safe attributes."""
    tracer = get_tracer(tracer_name)
    with tracer.start_as_current_span(span_name) as span:
        if attributes:
            for key, value in attributes.items():
                if value is not None:
                    span.set_attribute(
                        key,
                        value
                        if isinstance(value, (bool, int, float, str))
                        else str(value),
                    )
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
