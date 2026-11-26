"""Safety, policy, Model Armor, and self-healing retry ADK plugins.

Implements:
1. `SeniorSafetyGuardrailPlugin(BasePlugin)`:
   - `before_model_callback`: Runs Google Cloud Model Armor (when enabled) +
     deterministic prompt-injection/jailbreak defense + automatic PII scrubbing
     of user prompts before sending content to the LLM.
   - `after_model_callback`: Runs Google Cloud Model Armor response checks +
     deterministic elder-safety policy enforcement (prevents the model from ever
     soliciting SSN/passwords/PINs/cards or endorsing gift-card/wire payments).
2. `SilverShieldRetryPlugin(ReflectAndRetryToolPlugin)`:
   - Detects structured `status == "error"` tool responses and supplies guided
     self-healing recovery instructions without crashing the session.
"""

from __future__ import annotations

import importlib
import re
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.plugins.reflect_retry_tool_plugin import ReflectAndRetryToolPlugin
from google.genai import types

from app.observability.logging import get_logger
from app.observability.tracing import traced_span
from app.security.pii_redactor import PIIRedactor, get_pii_redactor

logger = get_logger(__name__)

_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"),
    re.compile(r"(?i)disregard\s+(?:your\s+)?(?:constitution|safety\s+rules|system\s+prompt)"),
    re.compile(r"(?i)reveal\s+(?:your\s+)?system\s+prompt"),
    re.compile(r"(?i)(?:pretend|act)\s+you\s+are\s+(?:a\s+)?scammer"),
    re.compile(r"(?i)convince\s+(?:the\s+)?(?:grandma|grandpa|senior|elder)\s+to\s+(?:send|wire|buy)"),
    re.compile(r"(?i)tell\s+(?:them|grandma|grandpa|the\s+user)\s+this\s+scam\s+is\s+safe"),
)

_UNSAFE_MODEL_OUTPUT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "credential_solicitation",
        re.compile(
            r"(?i)(?:please\s+(?:provide|share|type|send|enter)\s+your\s+"
            r"(?:social\s+security\s+number|ssn|password|pin\s+number|bank\s+account\s+number|credit\s+card\s+number|medicare\s+number))"
        ),
    ),
    (
        "unsafe_payment_endorsement",
        re.compile(
            r"(?i)(?:you\s+should\s+(?:buy|send|wire)\s+(?:gift\s+cards|apple\s+cards|bitcoin|wire\s+transfer))"
        ),
    ),
    (
        "unsafe_medical_directive",
        re.compile(
            r"(?i)(?:stop\s+taking\s+your\s+(?:prescribed\s+)?(?:medication|pills|insulin)\s+immediately)"
        ),
    ),
)

_SAFE_INJECTION_REFUSAL = (
    "**[CAUTION - SAFETY GUARDRAIL TRIGGERED]**\n\n"
    "I noticed instructions asking me to bypass my senior-safety rules. "
    "SilverShield is always here to protect you honestly and cannot pretend a "
    "scam is safe or ignore safety checks.\n\n"
    "If someone sent you a suspicious message or asked you to paste text here, "
    "please tell me in your own words what happened and I will gladly help you "
    "verify it safely."
)

_SAFE_OUTPUT_OVERRIDE = (
    "**[CAUTION - RESPONSE ADJUSTED FOR YOUR SAFETY]**\n\n"
    "SilverShield's safety check blocked part of a draft reply because it did not "
    "meet our strict protection standards. Please remember:\n"
    "1. Never share your Social Security Number, Medicare number, passwords, PINs, "
    "or bank/card numbers in any chat, text, or phone call.\n"
    "2. Never send gift cards, wire transfers, or cryptocurrency to strangers or "
    "urgent callers.\n"
    "3. For medical or financial questions, always check directly with your doctor "
    "or the official phone number on the back of your card."
)


class SeniorSafetyGuardrailPlugin(BasePlugin):
    """App-wide ADK guardrail plugin combining Model Armor, injection defense, and PII scrubbing."""

    def __init__(
        self,
        *,
        name: str = "senior_safety_guardrail",
        enable_model_armor: bool = False,
        model_armor_template_id: str | None = None,
        redactor: PIIRedactor | None = None,
        model_armor_client: Any | None = None,
    ) -> None:
        super().__init__(name=name)
        self._enable_model_armor = enable_model_armor and bool(model_armor_template_id)
        self._model_armor_template_id = model_armor_template_id
        self._redactor = redactor or get_pii_redactor()
        self._model_armor_client = model_armor_client
        self.blocked_inputs_count: int = 0
        self.blocked_outputs_count: int = 0
        self.redacted_prompts_count: int = 0

    def _get_model_armor_client(self) -> Any | None:
        if not self._enable_model_armor:
            return None
        if self._model_armor_client is not None:
            return self._model_armor_client
        try:
            modelarmor_v1: Any = importlib.import_module("google.cloud.modelarmor_v1")
            self._model_armor_client = modelarmor_v1.ModelArmorClient()
            return self._model_armor_client
        except Exception:
            return None

    def _check_model_armor_prompt(self, text: str) -> bool:
        """Return True if Google Cloud Model Armor flags the prompt as unsafe."""
        client = self._get_model_armor_client()
        if client is None or not self._model_armor_template_id:
            return False
        try:
            response = client.sanitize_user_prompt(
                request={
                    "name": self._model_armor_template_id,
                    "user_prompt_data": {"text": text},
                }
            )
            match_state = getattr(
                getattr(response, "sanitization_result", None),
                "filter_match_state",
                None,
            )
            return str(match_state).upper().endswith("MATCH_FOUND")
        except Exception as exc:
            logger.warning("model_armor_prompt_check_fallback", error=str(exc))
            return False

    def _check_model_armor_response(self, text: str) -> bool:
        """Return True if Google Cloud Model Armor flags the model response as unsafe."""
        client = self._get_model_armor_client()
        if client is None or not self._model_armor_template_id:
            return False
        try:
            response = client.sanitize_model_response(
                request={
                    "name": self._model_armor_template_id,
                    "model_response_data": {"text": text},
                }
            )
            match_state = getattr(
                getattr(response, "sanitization_result", None),
                "filter_match_state",
                None,
            )
            return str(match_state).upper().endswith("MATCH_FOUND")
        except Exception as exc:
            logger.warning("model_armor_response_check_fallback", error=str(exc))
            return False

    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request: LlmRequest
    ) -> LlmResponse | None:
        """Block prompt injection and scrub sensitive PII before calling Gemini."""
        with traced_span("guardrail.before_model") as span:
            contents = getattr(llm_request, "contents", None) or []
            user_texts: list[str] = []

            for content in contents:
                if getattr(content, "role", None) != "user":
                    continue
                for part in content.parts or []:
                    text = getattr(part, "text", None)
                    if not text:
                        continue
                    user_texts.append(text)
                    # Scrub PII in-place before sending to external model endpoints
                    report = self._redactor.redact_text(text)
                    if report.had_pii:
                        part.text = report.redacted_text
                        self.redacted_prompts_count += 1
                        callback_context.state["pii_redacted_in_prompt"] = True
                        logger.info(
                            "guardrail_prompt_pii_scrubbed",
                            entities=report.entities_detected,
                        )

            combined_user_text = "\n".join(user_texts)
            if not combined_user_text:
                return None

            is_injection = any(
                pattern.search(combined_user_text)
                for pattern in _PROMPT_INJECTION_PATTERNS
            )
            is_model_armor_flagged = (
                False if is_injection else self._check_model_armor_prompt(combined_user_text)
            )

            if is_injection or is_model_armor_flagged:
                self.blocked_inputs_count += 1
                reason = (
                    "prompt_injection_detected"
                    if is_injection
                    else "model_armor_prompt_blocked"
                )
                span.set_attribute("guardrail.blocked", True)
                span.set_attribute("guardrail.reason", reason)
                callback_context.state["last_guardrail_block_reason"] = reason
                logger.warning(
                    "guardrail_blocked_input",
                    reason=reason,
                    blocked_inputs_count=self.blocked_inputs_count,
                )
                return LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=_SAFE_INJECTION_REFUSAL)],
                    )
                )

            span.set_attribute("guardrail.blocked", False)
            return None

    async def after_model_callback(
        self, *, callback_context: CallbackContext, llm_response: LlmResponse
    ) -> LlmResponse | None:
        """Audit outbound model responses against senior-safety & Model Armor policies."""
        with traced_span("guardrail.after_model") as span:
            content = getattr(llm_response, "content", None)
            parts = getattr(content, "parts", None) if content is not None else None
            if not parts:
                return None

            response_text = "\n".join(
                p.text for p in parts if getattr(p, "text", None)
            )
            if not response_text:
                return None

            violated_rule: str | None = None
            for rule_name, pattern in _UNSAFE_MODEL_OUTPUT_PATTERNS:
                if pattern.search(response_text):
                    violated_rule = rule_name
                    break

            if violated_rule is None and self._check_model_armor_response(response_text):
                violated_rule = "model_armor_response_blocked"

            if violated_rule is not None:
                self.blocked_outputs_count += 1
                span.set_attribute("guardrail.output_blocked", True)
                span.set_attribute("guardrail.reason", violated_rule)
                callback_context.state["last_output_guardrail_intervention"] = violated_rule
                logger.warning(
                    "guardrail_blocked_output",
                    reason=violated_rule,
                    blocked_outputs_count=self.blocked_outputs_count,
                )
                return LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=_SAFE_OUTPUT_OVERRIDE)],
                    )
                )

            span.set_attribute("guardrail.output_blocked", False)
            return None


class SilverShieldRetryPlugin(ReflectAndRetryToolPlugin):
    """Self-healing tool retry plugin that inspects structured `ToolErrorResult` dicts."""

    def __init__(self, max_retries: int = 2) -> None:
        super().__init__(
            name="silvershield_reflect_retry",
            max_retries=max_retries,
            throw_exception_if_retry_exceeded=False,
        )

    async def extract_error_from_result(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
        result: Any,
    ) -> Any:
        """Recognize structured `status == 'error'` tool returns for guided reflection."""
        del tool, tool_args, tool_context
        if isinstance(result, dict) and result.get("status") == "error":
            return result
        return None
