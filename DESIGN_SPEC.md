# DESIGN_SPEC.md — SilverShield Guardian

## Overview

**SilverShield Guardian** is an **Agents for Good** multi-agent AI assistant built with Google's **Agent Development Kit (ADK)** to protect senior citizens and their family caregivers from:

1. **Elder-targeted scams**: Government/IRS/Medicare/Social Security impersonation, "grandparent" AI voice-clone emergencies, tech-support pop-ups, phishing/smishing links, gift-card/wire/crypto extortion, and romance/sweepstakes fraud.
2. **Viral fake news and misinformation**: Miracle medical cures, fabricated pension/Social Security cancellation rumors, doctored emergency warnings, and fear-mongering clickbait.

Older adults lose billions of dollars annually to social engineering and suffer serious health and emotional harm from viral misinformation. SilverShield serves as a patient, respectful, jargon-free digital companion that investigates suspicious messages, links, phone scripts, and viral news claims, delivers a clear traffic-light verdict (**SAFE**, **CAUTION**, **HIGH RISK**), and offers human-confirmed protective actions (alerting a trusted family caregiver, filing a PII-redacted FTC report, or quarantining a suspicious sender).

## Architecture & Multi-Agent Patterns

SilverShield uses proven ADK orchestration patterns rather than a monolithic agent:

- **Coordinator (`senior_guardian_coordinator`, `LlmAgent` / Flash)**: Greets the senior warmly, recalls prior safety context from persistent memory, answers everyday digital-safety questions, or delegates investigations and protective actions to specialist sub-agents.
- **Investigation Pipeline (`scam_and_news_investigation_pipeline`, `SequentialAgent`)**:
  1. **Parallel Verification Stage (`parallel_verification_stage`, `ParallelAgent`)**:
     - `scam_forensics_agent` (`LlmAgent` / Flash): Runs deterministic scam-indicator forensics, URL/domain reputation checks, and vector similarity search against the persistent elder-scam knowledge base.
     - `fake_news_fact_checker_agent` (`LlmAgent` / Flash): Verifies viral news and health/benefit claims against the curated fact-check store (plus an isolated optional web-grounding sub-agent via `AgentTool` so `google_search` is never mixed with custom `FunctionTool`s).
  2. **Risk Synthesis Stage (`senior_guidance_synthesis_agent`, `LlmAgent` / Pro)**: Uses Gemini Pro for nuanced social-engineering reasoning and compiles a calm, plain-language Senior Safety Briefing.
  3. **Self-Evaluation Refinement Loop (`self_eval_refinement_loop`, `LoopAgent`, `max_iterations=2`)**:
     - `senior_quality_evaluator_agent` (`LlmAgent` / Flash, `output_schema=SelfEvaluationVerdict`): Audits tone, empathy, 6th-grade readability, zero credential solicitation, and traffic-light clarity.
     - `quality_escalation_checker` (`BaseAgent`): Short-circuits the loop with `EventActions(escalate=True)` once the self-eval passes.
     - `senior_guidance_refiner_agent` (`LlmAgent` / Pro): Rewrites any response flagged by the self-evaluator.
- **Protective Action Agent (`protective_action_agent`, `LlmAgent` / Flash)**: Executes high-stakes external actions gated behind ADK Human-in-the-Loop (HITL) `FunctionTool(..., require_confirmation=...)` pauses.

## Strategic Model Routing

| Task / Agent | Model Tier | Default Model | Rationale |
| --- | --- | --- | --- |
| Coordinator triage & routing | `FAST` | `gemini-2.5-flash` | Low-latency conversational responsiveness |
| Scam Forensics & Fact-Checking tool callers | `FAST` | `gemini-2.5-flash` | Fast structured tool calling & schema handling |
| History compaction summarizer | `FAST` | `gemini-2.5-flash` | Cost-effective rolling event summarization |
| Self-evaluation quality critic | `FAST` | `gemini-2.5-flash` | Rapid rubric compliance checks |
| Risk synthesis & nuanced guidance refiner | `REASONING` | `gemini-2.5-pro` | Complex social-engineering synthesis & compassionate framing |

## Tools & Strict Schemas

All tools enforce strict Pydantic v2 input/output schemas (`ConfigDict(extra="forbid")`), descriptive verb-noun names, exhaustive docstrings, and guided error recovery (`ToolErrorResult` with `recovery_instructions`):

1. `analyze_message_scam_indicators` — Scores urgency, impersonation, payment coercion (gift cards/crypto/wire), secrecy, and credential-harvesting patterns.
2. `inspect_url_and_domain_reputation` — Inspects URLs for lookalike/typosquatted domains (e.g., `medicare-verify-benefits.xyz`), raw IPs, suspicious TLDs, punycode, URL shorteners, and insecure credential forms.
3. `lookup_known_elder_scam_patterns` — Queries the persistent SQLite vector store (and optional Vertex AI Search) for matching elder scam scripts and known misinformation hoaxes.
4. `verify_news_claim_credibility` — Evaluates viral news claims for sensationalist framing, miracle-cure markers, unverified conspiracy indicators, and matches against verified fact-checks.
5. `retrieve_senior_safety_history` — Retrieves PII-redacted long-term safety patterns for the user across sessions.
6. `notify_trusted_family_caregiver` *(HITL `require_confirmation=True`)* — Sends a scam alert to a designated family caregiver only after explicit human confirmation.
7. `file_official_ftc_scam_report` *(HITL `require_confirmation=True`)* — Submits a PII-scrubbed scam dossier to elder fraud reporting channels only after explicit human confirmation.
8. `quarantine_suspicious_sender` *(Conditional HITL `require_confirmation=predicate`)* — Quarantines a sender/domain; pauses for human confirmation whenever confidence is below 0.90 or the sender resembles a personal/medical contact.

## Context, Memory & Compaction

- **Constitution**: `app/prompts/constitution.py` enforced globally via `GlobalInstructionPlugin`.
- **Compaction & Caching**: ADK `EventsCompactionConfig` (sliding window + token threshold with `LlmEventSummarizer`) and `ContextCacheConfig` on `App`, complemented by a PII-safe sliding-window compactor.
- **Persistent State**: ADK `DatabaseSessionService` (SQLite locally, Cloud SQL PostgreSQL in Cloud Run, or `VertexAiSessionService` on Agent Runtime) + `PersistentScamKnowledgeStore` (SQLite vector store / Vertex AI Search).
- **Async Memory Consolidation**: `AsyncMemoryPlugin` triggers non-blocking background `asyncio.Task`s via `AsyncMemoryConsolidator`, scrubbing PII before writing consolidated user safety insights to `PersistentMemoryService` / Vertex AI Memory Bank.

## Security, Guardrails & Observability

- **PII Redaction**: `PIIRedactor` integrates Google Cloud DLP (`google-cloud-dlp`) with a deterministic local Luhn/regex engine (SSN, credit card, bank routing/account, Medicare MBI, phone, email, PIN/password, address). Applied to all structured logs, memory writes, outbound LLM requests, and scam reports.
- **Guardrails**: `SeniorSafetyGuardrailPlugin` (`BasePlugin`) integrates Google Cloud Model Armor (with local deterministic fallback) for prompt-injection blocking, PII prompt redaction, and output policy verification.
- **Observability**: Structured JSON logging via `structlog` (Cloud Logging schema), `AuditObservabilityPlugin` emitting paired `INTENT` and `OUTCOME` records linked by `action_id`, and OpenTelemetry distributed tracing (`CloudTraceSpanExporter` / OTLP / `otel_to_cloud=True`).
- **Secret Management**: `SecretManagerResolver` fetches runtime credentials from GCP Secret Manager (`google-cloud-secret-manager`) with ADC and TTL caching; local env fallback only in development; zero hardcoded secrets.

## Infrastructure, Evaluation & CI/CD

- **IaC**: Complete Terraform stack under `deployment/terraform/` (Cloud Run v2, Cloud SQL PostgreSQL, Secret Manager, least-privilege IAM, GCS/BigQuery telemetry, optional Agent Engine & Discovery Engine) + `Dockerfile` + `Makefile` + `[tool.agents-cli]` config.
- **Evaluation**: ADK golden `EvalSet` (`tests/eval/evalsets/scam_and_fake_news.evalset.json`), `eval_config.json`, offline deterministic regression runner (`tests/eval/run_golden_eval.py`), and comprehensive `pytest` suite.
- **CI/CD**: GitHub Actions workflows for linting, mypy, pytest, offline golden eval, `terraform validate`, secret scanning, and Workload Identity Federation deployment.
