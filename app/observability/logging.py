"""Structured JSON logging with automatic PII scrubbing and Cloud Trace correlation.

Uses `structlog` emitting JSON records compatible with Google Cloud Logging
(`severity`, `timestamp`, `logging.googleapis.com/trace`, `logging.googleapis.com/spanId`).
Every log event automatically passes through `PIIRedactor` before serialization.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

from app.config.settings import Settings, get_settings
from app.observability.tracing import get_current_trace_context
from app.security.pii_redactor import PIIRedactor, get_pii_redactor

_LOGGING_CONFIGURED = False


def _add_cloud_logging_severity(
    _logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Map log levels to Google Cloud Logging `severity` field."""
    level_map = {
        "debug": "DEBUG",
        "info": "INFO",
        "warning": "WARNING",
        "warn": "WARNING",
        "error": "ERROR",
        "critical": "CRITICAL",
        "exception": "ERROR",
    }
    event_dict["severity"] = level_map.get(method_name.lower(), "INFO")
    return event_dict


def _inject_trace_context_processor(project_id: str | None) -> Any:
    def _processor(
        _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        trace_ctx = get_current_trace_context(project_id=project_id)
        for key, value in trace_ctx.items():
            event_dict.setdefault(key, value)
        return event_dict

    return _processor


def _pii_redaction_processor(redactor: PIIRedactor) -> Any:
    """Scrub PII from every field in a structured log event before emission."""

    def _processor(
        _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        redacted = redactor.redact_structure(dict(event_dict))
        return redacted if isinstance(redacted, dict) else event_dict

    return _processor


def configure_logging(
    settings: Settings | None = None,
    *,
    redactor: PIIRedactor | None = None,
    force: bool = False,
) -> None:
    """Configure process-wide structured JSON logging with PII scrubbing."""
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED and not force:
        return

    cfg = settings or get_settings()
    active_redactor = redactor or get_pii_redactor(
        enable_cloud_dlp=cfg.enable_cloud_dlp,
        project_id=cfg.google_cloud_project,
    )

    log_level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,
    )

    renderer: Any = (
        structlog.processors.JSONRenderer(sort_keys=True)
        if cfg.log_format == "json"
        else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            _add_cloud_logging_severity,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _inject_trace_context_processor(cfg.google_cloud_project),
            _pii_redaction_processor(active_redactor),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )
    _LOGGING_CONFIGURED = True


def get_logger(name: str) -> Any:
    """Return a structured logger bound with component metadata."""
    if not _LOGGING_CONFIGURED:
        configure_logging()
    return structlog.get_logger(name)
