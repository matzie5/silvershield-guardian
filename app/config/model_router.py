"""Strategic model routing for SilverShield Guardian.

Routes fast classification, tool invocation, compaction summarization, and
self-evaluation tasks to Gemini Flash while escalating nuanced social-engineering
risk synthesis and multi-signal senior guidance refinement to Gemini Pro.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.config.settings import Settings, get_settings


class ModelTier(StrEnum):
    """Logical model capability tiers."""

    FAST = "fast"
    REASONING = "reasoning"


class TaskKind(StrEnum):
    """Semantic agent task types used for strategic model selection."""

    COORDINATOR_TRIAGE = "coordinator_triage"
    SCAM_FORENSICS = "scam_forensics"
    FAKE_NEWS_FACT_CHECK = "fake_news_fact_check"
    WEB_GROUNDING = "web_grounding"
    PROTECTIVE_ACTION = "protective_action"
    COMPACTION_SUMMARY = "compaction_summary"
    SELF_EVAL_CRITIQUE = "self_eval_critique"
    RISK_SYNTHESIS = "risk_synthesis"
    GUIDANCE_REFINEMENT = "guidance_refinement"


@dataclass(frozen=True)
class ModelRouteDecision:
    """Audit record describing why a particular Gemini model was chosen."""

    task_kind: TaskKind
    tier: ModelTier
    model_name: str
    rationale: str


_DEFAULT_TASK_TIERS: dict[TaskKind, tuple[ModelTier, str]] = {
    TaskKind.COORDINATOR_TRIAGE: (
        ModelTier.FAST,
        "Low-latency conversational triage and sub-agent delegation.",
    ),
    TaskKind.SCAM_FORENSICS: (
        ModelTier.FAST,
        "Rapid structured tool invocation for scam indicator and URL forensics.",
    ),
    TaskKind.FAKE_NEWS_FACT_CHECK: (
        ModelTier.FAST,
        "Fast tool-driven claim extraction and knowledge base verification.",
    ),
    TaskKind.WEB_GROUNDING: (
        ModelTier.FAST,
        "Low-latency web search grounding for current scam alerts and news.",
    ),
    TaskKind.PROTECTIVE_ACTION: (
        ModelTier.FAST,
        "Deterministic execution of HITL-gated caregiver and reporting tools.",
    ),
    TaskKind.COMPACTION_SUMMARY: (
        ModelTier.FAST,
        "Cost-efficient rolling summarization of older conversation events.",
    ),
    TaskKind.SELF_EVAL_CRITIQUE: (
        ModelTier.FAST,
        "Rapid schema-constrained guardrail critique of draft senior guidance.",
    ),
    TaskKind.RISK_SYNTHESIS: (
        ModelTier.REASONING,
        "Deep multi-signal reasoning to reconcile scam forensics and fact-check evidence.",
    ),
    TaskKind.GUIDANCE_REFINEMENT: (
        ModelTier.REASONING,
        "Nuanced empathetic rewriting for high-stakes elder protection guidance.",
    ),
}


class ModelRouter:
    """Selects the optimal Gemini model tier for each agent and runtime task."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def fast_model(self) -> str:
        """Return the configured fast-tier model name (Gemini Flash)."""
        return self._settings.fast_model_name

    @property
    def reasoning_model(self) -> str:
        """Return the configured reasoning-tier model name (Gemini Pro)."""
        return self._settings.reasoning_model_name

    def get_model_for_tier(self, tier: ModelTier) -> str:
        """Resolve a `ModelTier` to its concrete Gemini model identifier."""
        if tier == ModelTier.REASONING:
            return self.reasoning_model
        return self.fast_model

    def route(
        self,
        task_kind: TaskKind,
        *,
        high_stakes: bool = False,
        conflicting_signals: bool = False,
        input_char_length: int = 0,
    ) -> ModelRouteDecision:
        """Determine the concrete Gemini model for a task with dynamic escalation.

        Fast tasks automatically escalate to the `REASONING` tier (Gemini Pro)
        when conflicting forensic signals are detected, the request is marked
        high-stakes, or the input exceeds complex multi-document length thresholds.
        """
        base_tier, base_rationale = _DEFAULT_TASK_TIERS[task_kind]
        selected_tier = base_tier
        rationale = base_rationale

        if base_tier == ModelTier.FAST and (
            conflicting_signals or (high_stakes and input_char_length > 1500)
        ):
            selected_tier = ModelTier.REASONING
            rationale = (
                f"Escalated {task_kind.value} from FAST to REASONING due to "
                f"conflicting_signals={conflicting_signals}, "
                f"high_stakes={high_stakes}, input_len={input_char_length}."
            )

        return ModelRouteDecision(
            task_kind=task_kind,
            tier=selected_tier,
            model_name=self.get_model_for_tier(selected_tier),
            rationale=rationale,
        )
