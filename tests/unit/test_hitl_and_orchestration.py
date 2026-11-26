"""Unit & orchestration tests for ADK multi-agent hierarchy, HITL pause/resume, and FastAPI."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from fastapi.testclient import TestClient
from google.adk.agents import LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
from google.adk.apps import App, ResumabilityConfig
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import PrivateAttr

from app.agent import create_silvershield_app
from app.agents.hierarchy import QualityEscalationChecker
from app.config.settings import Settings
from app.fast_api_app import create_web_app
from app.tools.high_stakes_actions import (
    notify_trusted_family_caregiver_tool,
    quarantine_suspicious_sender_tool,
    requires_quarantine_confirmation,
)


class ScriptedFakeLlm(BaseLlm):
    """Deterministic fake BaseLlm for offline ADK Runner & HITL tests."""

    _responses: list[LlmResponse] = PrivateAttr(default_factory=list)

    def __init__(self, responses: list[LlmResponse]) -> None:
        super().__init__(model="fake-gemini")
        self._responses = list(responses)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        del llm_request, stream
        if not self._responses:
            yield LlmResponse(
                content=types.Content(
                    role="model", parts=[types.Part.from_text(text="Done.")]
                )
            )
            return
        yield self._responses.pop(0)


def test_silvershield_app_wires_multi_agent_hierarchy_compaction_and_plugins(
    isolated_settings: Settings,
) -> None:
    adk_app = create_silvershield_app(settings=isolated_settings)
    assert adk_app.name == "app"
    assert adk_app.resumability_config is not None
    assert adk_app.resumability_config.is_resumable is True
    assert adk_app.events_compaction_config is not None
    assert adk_app.context_cache_config is not None

    plugin_names = {p.name for p in adk_app.plugins}
    assert {
        "silvershield_constitution",
        "senior_safety_guardrail",
        "audit_observability",
        "silvershield_reflect_retry",
        "async_memory_consolidation",
    }.issubset(plugin_names)

    coordinator = adk_app.root_agent
    assert isinstance(coordinator, LlmAgent)
    assert coordinator.name == "senior_guardian_coordinator"

    sub_names = {a.name: a for a in coordinator.sub_agents}
    assert "scam_and_news_investigation_pipeline" in sub_names
    assert "protective_action_agent" in sub_names

    pipeline = sub_names["scam_and_news_investigation_pipeline"]
    assert isinstance(pipeline, SequentialAgent)
    assert isinstance(pipeline.sub_agents[0], ParallelAgent)
    assert isinstance(pipeline.sub_agents[1], LlmAgent)
    assert pipeline.sub_agents[1].model == isolated_settings.reasoning_model_name
    assert isinstance(pipeline.sub_agents[2], LoopAgent)


def test_conditional_hitl_predicate_protects_medical_and_uncertain_contacts() -> None:
    assert (
        requires_quarantine_confirmation(
            sender_identifier="dr.patel@oakridgeclinic.org",
            confidence_score=0.98,
        )
        is True
    )
    assert (
        requires_quarantine_confirmation(
            sender_identifier="unknown-sender@example.com",
            confidence_score=0.75,
        )
        is True
    )
    assert (
        requires_quarantine_confirmation(
            sender_identifier="scam@medicare-fake-benefits.xyz",
            confidence_score=0.96,
            looks_like_personal_or_medical_contact=False,
        )
        is False
    )


async def test_hitl_require_confirmation_pauses_and_resumes_caregiver_alert() -> None:
    """Verify native ADK HITL pause (`adk_request_confirmation`) and human-approved resume."""
    tool_call_resp = LlmResponse(
        content=types.Content(
            role="model",
            parts=[
                types.Part(
                    function_call=types.FunctionCall(
                        id="fc-alert-1",
                        name="notify_trusted_family_caregiver",
                        args={
                            "caregiver_name": "Sarah (Daughter)",
                            "caregiver_contact_channel": "sms",
                            "risk_level": "HIGH_RISK",
                            "incident_summary": "IRS gift card call asking for SSN 123-45-6789.",
                        },
                    )
                )
            ],
        )
    )
    final_resp = LlmResponse(
        content=types.Content(
            role="model",
            parts=[
                types.Part.from_text(
                    text="Your daughter Sarah has been notified with all personal numbers removed."
                )
            ],
        )
    )

    hitl_agent = LlmAgent(
        name="hitl_test_agent",
        model=ScriptedFakeLlm([tool_call_resp, final_resp]),
        instruction="Notify caregiver when asked.",
        tools=[notify_trusted_family_caregiver_tool, quarantine_suspicious_sender_tool],
    )
    hitl_app = App(
        name="hitl_test_app",
        root_agent=hitl_agent,
        resumability_config=ResumabilityConfig(is_resumable=True),
    )

    runner = InMemoryRunner(app=hitl_app)
    session = await runner.session_service.create_session(
        app_name="hitl_test_app", user_id="senior-hitl"
    )

    # Turn 1: Agent attempts high-stakes action -> ADK MUST pause with adk_request_confirmation
    paused_events = [
        event
        async for event in runner.run_async(
            user_id="senior-hitl",
            session_id=session.id,
            new_message=types.Content(
                role="user",
                parts=[types.Part.from_text(text="Alert my daughter Sarah.")],
            ),
        )
    ]

    confirmation_calls = [
        fc
        for ev in paused_events
        for fc in ev.get_function_calls()
        if fc.name == "adk_request_confirmation"
    ]
    assert confirmation_calls, "Expected ADK HITL confirmation pause before executing caregiver alert"
    confirm_fc = confirmation_calls[-1]

    # Turn 2: Human explicitly approves -> tool executes with PII scrubbed
    resumed_events = [
        event
        async for event in runner.run_async(
            user_id="senior-hitl",
            session_id=session.id,
            new_message=types.Content(
                role="user",
                parts=[
                    types.Part(
                        function_response=types.FunctionResponse(
                            id=confirm_fc.id,
                            name=confirm_fc.name,
                            response={"confirmed": True},
                        )
                    )
                ],
            ),
        )
    ]

    tool_responses = [
        fr
        for ev in resumed_events
        for fr in ev.get_function_responses()
        if fr.name == "notify_trusted_family_caregiver"
    ]
    assert tool_responses, "Expected caregiver tool to execute after human approval"
    payload: dict[str, Any] = tool_responses[-1].response or {}
    assert payload["status"] == "success"
    assert payload["human_confirmed"] is True
    assert "123-45-6789" not in payload["redacted_message_sent"]
    assert "[REDACTED_SSN]" in payload["redacted_message_sent"]


async def test_quality_escalation_checker_exits_self_eval_loop_on_pass() -> None:
    checker = QualityEscalationChecker(name="quality_escalation_checker")
    runner = InMemoryRunner(agent=checker, app_name="escalation_test")
    session = await runner.session_service.create_session(
        app_name="escalation_test",
        user_id="u1",
        state={"self_eval_verdict": {"grade": "pass"}},
    )
    events = [
        ev
        async for ev in runner.run_async(
            user_id="u1",
            session_id=session.id,
            new_message=types.Content(
                role="user", parts=[types.Part.from_text(text="check")]
            ),
        )
    ]
    assert any(ev.actions and ev.actions.escalate for ev in events)


def test_fastapi_health_and_tool_schemas_endpoints(isolated_settings: Settings) -> None:
    web_app = create_web_app(isolated_settings)
    client = TestClient(web_app)

    health = client.get("/healthz")
    assert health.status_code == 200
    body = health.json()
    assert body["status"] == "ok"
    assert body["fast_model"] == "gemini-2.5-flash"
    assert body["reasoning_model"] == "gemini-2.5-pro"

    schemas = client.get("/api/tool-schemas")
    assert schemas.status_code == 200
    assert "analyze_message_scam_indicators" in schemas.json()
    assert "notify_trusted_family_caregiver" in schemas.json()
