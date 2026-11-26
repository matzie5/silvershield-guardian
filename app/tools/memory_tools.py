"""Long-term cross-session safety memory retrieval tool."""

from __future__ import annotations

from typing import Any

from google.adk.tools import ToolContext
from pydantic import ValidationError

from app.memory.async_memory_manager import get_memory_consolidator
from app.observability.tracing import traced_span
from app.schemas.tool_schemas import (
    RetrieveSafetyHistoryRequest,
    SafetyHistoryResult,
    ToolErrorResult,
)


async def retrieve_senior_safety_history(
    topic_query: str,
    limit: int = 5,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Retrieve PII-redacted safety history from the senior's past conversations.

    Use this tool when the user mentions an earlier scam attempt, recurring phone
    calls, previously discussed caregiver contacts, or asks "didn't we check something
    like this last week?". Searches cross-session persistent memory safely.

    Args:
        topic_query: Keywords describing what to look up in past safety sessions
            (2 to 500 characters). Example: "Medicare phone calls" or "caregiver".
        limit: Maximum number of historical memory notes to return (1 to 20).

    Returns:
        A JSON-serializable dictionary matching `SafetyHistoryResult` containing
        `memory_backend` and `entries` (all PII-scrubbed). Returns `ToolErrorResult`
        with recovery steps on invalid arguments.
    """
    with traced_span("tool.retrieve_senior_safety_history", attributes={"limit": limit}):
        try:
            req = RetrieveSafetyHistoryRequest(topic_query=topic_query, limit=limit)
        except ValidationError as exc:
            return ToolErrorResult(
                error_code="INVALID_HISTORY_QUERY",
                error_message=f"Invalid memory search query: {exc.errors()[0]['msg']}",
                recovery_instructions=(
                    "Provide a `topic_query` of at least 2 characters (e.g., 'scam calls' "
                    "or 'Medicare') and a `limit` between 1 and 20."
                ),
                retryable=True,
            ).model_dump()

        entries: list[dict[str, Any]] = []
        backend = "persistent_sqlite"

        # Prefer ADK ToolContext.search_memory when attached to an active Runner
        if tool_context is not None:
            try:
                response = await tool_context.search_memory(req.topic_query)
                backend = "adk_memory_service"
                for mem in response.memories[: req.limit]:
                    parts = mem.content.parts or []
                    text = " ".join(
                        str(p.text) for p in parts if getattr(p, "text", None)
                    )
                    entries.append(
                        {
                            "author": mem.author or "silvershield",
                            "timestamp": mem.timestamp or "",
                            "summary": text,
                            "metadata": mem.custom_metadata or {},
                        }
                    )
            except ValueError:
                # Runner initialized without memory_service; fall back to persistent store.
                pass

        if not entries:
            consolidator = get_memory_consolidator()
            user_id = (
                getattr(
                    getattr(tool_context, "_invocation_context", None),
                    "user_id",
                    "default_senior",
                )
                if tool_context is not None
                else "default_senior"
            )
            app_name = (
                getattr(
                    getattr(tool_context, "_invocation_context", None),
                    "app_name",
                    "app",
                )
                if tool_context is not None
                else "app"
            )
            response = await consolidator.memory_service.search_memory(
                app_name=app_name,
                user_id=user_id,
                query=req.topic_query,
            )
            for mem in response.memories[: req.limit]:
                parts = mem.content.parts or []
                text = " ".join(
                    str(p.text) for p in parts if getattr(p, "text", None)
                )
                entries.append(
                    {
                        "author": mem.author or "silvershield",
                        "timestamp": mem.timestamp or "",
                        "summary": text,
                        "metadata": mem.custom_metadata or {},
                    }
                )

        return SafetyHistoryResult(
            memory_backend=backend,
            entries=entries,
        ).model_dump()
