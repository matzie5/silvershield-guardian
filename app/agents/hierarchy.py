"""Multi-agent ADK architecture for SilverShield Guardian.

Implements proven ADK orchestration patterns instead of a monolithic prompt:
- Coordinator (`LlmAgent` / Flash): Warm senior triage, memory recall, delegation.
- Investigation Pipeline (`SequentialAgent`):
  1. Parallel Verification (`ParallelAgent`):
     - `scam_forensics_agent` (Flash): Scam indicator forensics, URL spoofing,
       and persistent vector scam-pattern lookup.
     - `fake_news_fact_checker_agent` (Flash): Misinformation verification and
       isolated optional web-grounding sub-agent (`AgentTool`).
  2. Risk Synthesis (`LlmAgent` / Pro): Reconciles parallel evidence into a
     compassionate, plain-language Senior Safety Briefing.
  3. Self-Evaluation Refinement Loop (`LoopAgent`, `max_iterations=2`):
     - `senior_quality_evaluator_agent` (Flash, `output_schema=SelfEvaluationVerdict`)
     - `quality_escalation_checker` (`BaseAgent` emitting `escalate=True` on pass)
     - `senior_guidance_refiner_agent` (Pro): Rewrites drafts failing self-eval.
- Protective Action Agent (`LlmAgent` / Flash): HITL confirmation-gated external
  actions (`notify_trusted_family_caregiver`, `file_official_ftc_scam_report`,
  `quarantine_suspicious_sender`).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

from google.adk.agents import (
    BaseAgent,
    LlmAgent,
    LoopAgent,
    ParallelAgent,
    SequentialAgent,
)
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.adk.tools import AgentTool, google_search
from google.genai import types as genai_types

from app.config.model_router import ModelRouter, TaskKind
from app.config.settings import Settings, get_settings
from app.observability.logging import get_logger
from app.prompts.constitution import (
    COORDINATOR_INSTRUCTION,
    FAKE_NEWS_FACT_CHECKER_INSTRUCTION,
    PROTECTIVE_ACTION_INSTRUCTION,
    RISK_SYNTHESIS_INSTRUCTION,
    SCAM_FORENSICS_INSTRUCTION,
    SELF_EVAL_CRITIC_INSTRUCTION,
    SENIOR_REFINER_INSTRUCTION,
    WEB_GROUNDING_INSTRUCTION,
)
from app.schemas.agent_schemas import SelfEvaluationVerdict
from app.tools.fact_check import verify_news_claim_credibility
from app.tools.high_stakes_actions import (
    file_official_ftc_scam_report_tool,
    notify_trusted_family_caregiver_tool,
    quarantine_suspicious_sender_tool,
)
from app.tools.knowledge_base import lookup_known_elder_scam_patterns
from app.tools.memory_tools import retrieve_senior_safety_history
from app.tools.scam_analysis import (
    analyze_message_scam_indicators,
    inspect_url_and_domain_reputation,
)

logger = get_logger(__name__)


def _resolve_model(
    router: ModelRouter,
    task_kind: TaskKind,
    *,
    model_override: Any | None = None,
) -> Any:
    """Resolve model via strategic router (or honor test double override)."""
    if model_override is not None:
        return model_override
    decision = router.route(task_kind)
    logger.info(
        "model_route_selected",
        task_kind=decision.task_kind.value,
        tier=decision.tier.value,
        model_name=decision.model_name,
        rationale=decision.rationale,
    )
    return decision.model_name


class QualityEscalationChecker(BaseAgent):
    """Custom ADK BaseAgent that exits the self-eval LoopAgent when grade == 'pass'."""

    async def _run_async_impl(
        self, ctx: InvocationContext
    ) -> AsyncGenerator[Event, None]:
        verdict = ctx.session.state.get("self_eval_verdict")
        passed = False
        if isinstance(verdict, dict):
            passed = verdict.get("grade") == "pass"
        elif isinstance(verdict, SelfEvaluationVerdict):
            passed = verdict.grade == "pass"
        elif isinstance(verdict, str) and '"grade": "pass"' in verdict.lower():
            passed = True

        if passed:
            logger.info("self_eval_quality_gate_passed", agent=self.name)
            yield Event(author=self.name, actions=EventActions(escalate=True))
        else:
            logger.info("self_eval_quality_gate_requesting_revision", agent=self.name)
            yield Event(author=self.name)


def create_web_grounding_agent(
    router: ModelRouter,
    *,
    model_override: Any | None = None,
) -> LlmAgent:
    """Isolated Google Search grounding agent (never mixes google_search with FunctionTools)."""
    return LlmAgent(
        name="web_grounding_specialist",
        model=_resolve_model(
            router, TaskKind.WEB_GROUNDING, model_override=model_override
        ),
        description="Searches authoritative public sources (.gov, FTC, CDC, AP, Reuters) for breaking scams and news.",
        instruction=WEB_GROUNDING_INSTRUCTION,
        tools=[google_search],
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.1),
    )


def create_scam_forensics_agent(
    router: ModelRouter,
    *,
    model_override: Any | None = None,
) -> LlmAgent:
    """Fast-tier specialist for scam indicators, URL spoofing, and known elder-fraud patterns."""
    return LlmAgent(
        name="scam_forensics_agent",
        model=_resolve_model(
            router, TaskKind.SCAM_FORENSICS, model_override=model_override
        ),
        description="Analyzes suspicious messages, phone scripts, and links for elder scam indicators.",
        instruction=SCAM_FORENSICS_INSTRUCTION,
        tools=[
            analyze_message_scam_indicators,
            inspect_url_and_domain_reputation,
            lookup_known_elder_scam_patterns,
        ],
        output_key="scam_forensics_report",
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.1),
    )


def create_fake_news_fact_checker_agent(
    router: ModelRouter,
    *,
    settings: Settings | None = None,
    enable_web_grounding: bool = False,
    model_override: Any | None = None,
) -> LlmAgent:
    """Fast-tier specialist verifying viral news claims, health remedies, and benefit rumors."""
    cfg = settings or get_settings()
    tools: list[Any] = [verify_news_claim_credibility]
    if enable_web_grounding:
        tools.append(
            AgentTool(
                agent=create_web_grounding_agent(router, model_override=model_override)
            )
        )
    if cfg.vertex_ai_search_datastore_id:
        from google.adk.tools import VertexAiSearchTool

        tools.append(
            VertexAiSearchTool(data_store_id=cfg.vertex_ai_search_datastore_id)
        )

    return LlmAgent(
        name="fake_news_fact_checker_agent",
        model=_resolve_model(
            router, TaskKind.FAKE_NEWS_FACT_CHECK, model_override=model_override
        ),
        description="Fact-checks viral news claims, miracle medical cures, and Social Security/Medicare rumors.",
        instruction=FAKE_NEWS_FACT_CHECKER_INSTRUCTION,
        tools=tools,
        output_key="fact_check_report",
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.1),
    )


def create_risk_synthesis_agent(
    router: ModelRouter,
    *,
    model_override: Any | None = None,
) -> LlmAgent:
    """Reasoning-tier (Gemini Pro) specialist synthesizing parallel findings into senior guidance."""
    return LlmAgent(
        name="senior_guidance_synthesis_agent",
        model=_resolve_model(
            router, TaskKind.RISK_SYNTHESIS, model_override=model_override
        ),
        description="Synthesizes forensic and fact-check findings into a calm, plain-language Senior Safety Briefing.",
        instruction=RISK_SYNTHESIS_INSTRUCTION,
        output_key="draft_senior_guidance",
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.2),
    )


def create_self_eval_critic_agent(
    router: ModelRouter,
    *,
    model_override: Any | None = None,
) -> LlmAgent:
    """Fast-tier schema-constrained self-evaluator checking empathy, readability, and safety."""
    return LlmAgent(
        name="senior_quality_evaluator_agent",
        model=_resolve_model(
            router, TaskKind.SELF_EVAL_CRITIQUE, model_override=model_override
        ),
        description="Self-evaluates draft guidance against senior clarity, empathy, and safety criteria.",
        instruction=SELF_EVAL_CRITIC_INSTRUCTION,
        output_schema=SelfEvaluationVerdict,
        output_key="self_eval_verdict",
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.0),
    )


def create_senior_refiner_agent(
    router: ModelRouter,
    *,
    model_override: Any | None = None,
) -> LlmAgent:
    """Reasoning-tier (Gemini Pro) refiner rewriting drafts that fail self-evaluation."""
    return LlmAgent(
        name="senior_guidance_refiner_agent",
        model=_resolve_model(
            router, TaskKind.GUIDANCE_REFINEMENT, model_override=model_override
        ),
        description="Revises draft senior safety briefings to fix any quality or empathy gaps.",
        instruction=SENIOR_REFINER_INSTRUCTION,
        output_key="draft_senior_guidance",
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.2),
    )


def create_investigation_pipeline(
    router: ModelRouter,
    *,
    settings: Settings | None = None,
    enable_web_grounding: bool = False,
    model_override: Any | None = None,
) -> SequentialAgent:
    """Sequential workflow combining Parallel verification, Pro synthesis, and Self-Eval loop."""
    parallel_verification = ParallelAgent(
        name="parallel_verification_stage",
        description="Runs Scam Forensics and Fake News Fact-Checking concurrently.",
        sub_agents=[
            create_scam_forensics_agent(router, model_override=model_override),
            create_fake_news_fact_checker_agent(
                router,
                settings=settings,
                enable_web_grounding=enable_web_grounding,
                model_override=model_override,
            ),
        ],
    )

    self_eval_loop = LoopAgent(
        name="self_eval_refinement_loop",
        description="Self-evaluates and refines guidance until senior-safety quality criteria pass.",
        sub_agents=[
            create_self_eval_critic_agent(router, model_override=model_override),
            QualityEscalationChecker(
                name="quality_escalation_checker",
                description="Exits refinement loop immediately once self-eval returns grade='pass'.",
            ),
            create_senior_refiner_agent(router, model_override=model_override),
        ],
        max_iterations=2,
    )

    return SequentialAgent(
        name="scam_and_news_investigation_pipeline",
        description=(
            "Full end-to-end investigation workflow for checking suspicious texts, "
            "emails, phone calls, URLs, or viral news/health/benefit claims."
        ),
        sub_agents=[
            parallel_verification,
            create_risk_synthesis_agent(router, model_override=model_override),
            self_eval_loop,
        ],
    )


def create_protective_action_agent(
    router: ModelRouter,
    *,
    model_override: Any | None = None,
) -> LlmAgent:
    """Specialist owning Human-in-the-Loop confirmation-gated external actions."""
    return LlmAgent(
        name="protective_action_agent",
        model=_resolve_model(
            router, TaskKind.PROTECTIVE_ACTION, model_override=model_override
        ),
        description=(
            "Executes human-confirmed protective actions: alerting a trusted family "
            "caregiver, filing a PII-redacted FTC scam report, or quarantining a sender."
        ),
        instruction=PROTECTIVE_ACTION_INSTRUCTION,
        tools=[
            notify_trusted_family_caregiver_tool,
            file_official_ftc_scam_report_tool,
            quarantine_suspicious_sender_tool,
        ],
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.1),
    )


def create_root_coordinator(
    router: ModelRouter | None = None,
    *,
    settings: Settings | None = None,
    enable_web_grounding: bool = False,
    model_override: Any | None = None,
) -> LlmAgent:
    """Build the top-level SilverShield Coordinator delegating to specialist sub-agents."""
    cfg = settings or get_settings()
    active_router = router or ModelRouter(cfg)

    return LlmAgent(
        name="senior_guardian_coordinator",
        model=_resolve_model(
            active_router, TaskKind.COORDINATOR_TRIAGE, model_override=model_override
        ),
        description=(
            "SilverShield Guardian coordinator protecting senior citizens from scams "
            "and fake news through compassionate triage and specialist orchestration."
        ),
        instruction=COORDINATOR_INSTRUCTION,
        tools=[retrieve_senior_safety_history],
        sub_agents=[
            create_investigation_pipeline(
                active_router,
                settings=cfg,
                enable_web_grounding=enable_web_grounding,
                model_override=model_override,
            ),
            create_protective_action_agent(
                active_router, model_override=model_override
            ),
        ],
        generate_content_config=genai_types.GenerateContentConfig(temperature=0.2),
    )
