"""Intent-vs-Outcome structured audit & OpenTelemetry observability ADK plugin.

Explicitly captures paired `INTENT` (before execution) and `OUTCOME` (after
execution or error) records for every agent run and tool invocation, linked by
a correlation `action_id` and active OpenTelemetry `trace_id`/`span_id`, with
automatic PII redaction on all arguments and results.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from typing import Any

from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from app.observability.logging import get_logger
from app.observability.tracing import get_current_trace_context, get_tracer
from app.security.pii_redactor import PIIRedactor, get_pii_redactor

logger = get_logger(__name__)


class AuditObservabilityPlugin(BasePlugin):
    """Logs paired Intent vs. Outcome structured audit events and OTel spans."""

    def __init__(
        self,
        *,
        name: str = "audit_observability",
        redactor: PIIRedactor | None = None,
        max_buffer_size: int = 500,
    ) -> None:
        super().__init__(name=name)
        self._redactor = redactor or get_pii_redactor()
        self._agent_timers: dict[str, tuple[str, float]] = {}
        self._tool_timers: dict[str, tuple[str, float, str]] = {}
        self._audit_records: deque[dict[str, Any]] = deque(maxlen=max_buffer_size)

    @property
    def audit_records(self) -> list[dict[str, Any]]:
        """Return a snapshot of captured PII-redacted Intent/Outcome audit records."""
        return list(self._audit_records)

    def clear_records(self) -> None:
        """Reset the in-memory audit buffer (useful in test isolation)."""
        self._audit_records.clear()

    def _record(self, event_name: str, payload: dict[str, Any]) -> None:
        safe_payload = self._redactor.redact_structure(payload)
        if not isinstance(safe_payload, dict):
            safe_payload = {"detail": str(safe_payload)}
        trace_ctx = get_current_trace_context()
        entry = {
            "event": event_name,
            **trace_ctx,
            **safe_payload,
        }
        self._audit_records.append(entry)
        logger.info(event_name, **safe_payload)

    @staticmethod
    def _agent_key(agent: BaseAgent, callback_context: CallbackContext) -> str:
        inv_id = getattr(callback_context, "invocation_id", "inv")
        return f"{inv_id}:{agent.name}"

    @staticmethod
    def _tool_key(tool: BaseTool, tool_context: ToolContext) -> str:
        inv_id = getattr(tool_context, "invocation_id", "inv")
        fc_id = getattr(tool_context, "function_call_id", None) or tool.name
        return f"{inv_id}:{tool.name}:{fc_id}"

    async def before_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> types.Content | None:
        """Log agent INTENT prior to agent execution."""
        action_id = f"agt-{uuid.uuid4().hex[:10]}"
        self._agent_timers[self._agent_key(agent, callback_context)] = (
            action_id,
            time.monotonic(),
        )
        self._record(
            "agent_intent",
            {
                "phase": "INTENT",
                "action_id": action_id,
                "invocation_id": getattr(callback_context, "invocation_id", ""),
                "agent_name": agent.name,
                "intended_action": f"execute_agent:{agent.name}",
                "agent_description": getattr(agent, "description", "") or "",
            },
        )
        return None

    async def after_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> types.Content | None:
        """Log agent OUTCOME paired with the recorded INTENT."""
        key = self._agent_key(agent, callback_context)
        action_id, start = self._agent_timers.pop(
            key, (f"agt-{uuid.uuid4().hex[:10]}", time.monotonic())
        )
        latency_ms = round((time.monotonic() - start) * 1000.0, 2)
        self._record(
            "agent_outcome",
            {
                "phase": "OUTCOME",
                "action_id": action_id,
                "invocation_id": getattr(callback_context, "invocation_id", ""),
                "agent_name": agent.name,
                "outcome_status": "completed",
                "intent_outcome_match": True,
                "latency_ms": latency_ms,
            },
        )
        return None

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        """Log tool INTENT with PII-redacted arguments before execution."""
        action_id = f"tol-{uuid.uuid4().hex[:10]}"
        intended_goal = f"invoke_tool:{tool.name}"
        self._tool_timers[self._tool_key(tool, tool_context)] = (
            action_id,
            time.monotonic(),
            intended_goal,
        )
        tracer = get_tracer("silvershield.audit")
        with tracer.start_as_current_span(f"audit.intent.{tool.name}") as span:
            span.set_attribute("audit.phase", "INTENT")
            span.set_attribute("audit.action_id", action_id)
            span.set_attribute("tool.name", tool.name)
            self._record(
                "tool_intent",
                {
                    "phase": "INTENT",
                    "action_id": action_id,
                    "invocation_id": getattr(tool_context, "invocation_id", ""),
                    "tool_name": tool.name,
                    "intended_action": intended_goal,
                    "tool_args": tool_args,
                },
            )
        return None

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Log tool OUTCOME paired with the original INTENT and check divergence."""
        del tool_args
        key = self._tool_key(tool, tool_context)
        action_id, start, intended_goal = self._tool_timers.pop(
            key, (f"tol-{uuid.uuid4().hex[:10]}", time.monotonic(), f"invoke_tool:{tool.name}")
        )
        latency_ms = round((time.monotonic() - start) * 1000.0, 2)
        status = (
            str(result.get("status", "success"))
            if isinstance(result, dict)
            else "success"
        )
        matched = status not in {"error", "cancelled"}
        tracer = get_tracer("silvershield.audit")
        with tracer.start_as_current_span(f"audit.outcome.{tool.name}") as span:
            span.set_attribute("audit.phase", "OUTCOME")
            span.set_attribute("audit.action_id", action_id)
            span.set_attribute("audit.intent_outcome_match", matched)
            span.set_attribute("audit.latency_ms", latency_ms)
            self._record(
                "tool_outcome",
                {
                    "phase": "OUTCOME",
                    "action_id": action_id,
                    "invocation_id": getattr(tool_context, "invocation_id", ""),
                    "tool_name": tool.name,
                    "intended_action": intended_goal,
                    "outcome_status": status,
                    "intent_outcome_match": matched,
                    "latency_ms": latency_ms,
                    "outcome_keys": sorted(result.keys())
                    if isinstance(result, dict)
                    else [],
                },
            )
        return None

    async def on_tool_error_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        error: Exception,
    ) -> dict[str, Any] | None:
        """Log failed tool OUTCOME diverging from recorded INTENT."""
        del tool_args
        key = self._tool_key(tool, tool_context)
        action_id, start, intended_goal = self._tool_timers.pop(
            key, (f"tol-{uuid.uuid4().hex[:10]}", time.monotonic(), f"invoke_tool:{tool.name}")
        )
        latency_ms = round((time.monotonic() - start) * 1000.0, 2)
        self._record(
            "tool_outcome",
            {
                "phase": "OUTCOME",
                "action_id": action_id,
                "invocation_id": getattr(tool_context, "invocation_id", ""),
                "tool_name": tool.name,
                "intended_action": intended_goal,
                "outcome_status": "exception",
                "intent_outcome_match": False,
                "error_type": type(error).__name__,
                "error_message": str(error),
                "latency_ms": latency_ms,
            },
        )
        return None
