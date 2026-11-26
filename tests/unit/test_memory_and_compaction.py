"""Unit tests for persistent sessions, vector knowledge store, compaction, and async memory."""

from __future__ import annotations

from pathlib import Path

from app.config.settings import Settings
from app.memory.async_memory_manager import (
    AsyncMemoryConsolidator,
    PersistentSqliteMemoryService,
)
from app.memory.compaction import (
    PIISafeHistoryCompactor,
    build_context_cache_config,
    build_events_compaction_config,
)
from app.memory.knowledge_store import KnowledgeRecord, PersistentScamKnowledgeStore
from app.memory.session_store import build_session_service


async def test_database_session_service_persists_state_across_instances(
    isolated_settings: Settings,
) -> None:
    svc1 = build_session_service(isolated_settings)
    created = await svc1.create_session(
        app_name="app",
        user_id="senior-001",
        state={"user:preferred_caregiver": "Sarah", "last_risk": "HIGH_RISK"},
    )

    # Open a brand-new DatabaseSessionService pointing to the same SQLite DB
    svc2 = build_session_service(isolated_settings)
    loaded = await svc2.get_session(
        app_name="app",
        user_id="senior-001",
        session_id=created.id,
    )
    assert loaded is not None
    assert loaded.state["user:preferred_caregiver"] == "Sarah"
    assert loaded.state["last_risk"] == "HIGH_RISK"


def test_persistent_vector_knowledge_store_retrieves_and_persists_patterns(
    tmp_path: Path,
) -> None:
    db_file = tmp_path / "scam_kb.db"
    store1 = PersistentScamKnowledgeStore(db_file)
    hits = store1.search("grandma I am in jail need bail wire transfer don't tell mom", top_k=3)
    assert hits
    assert hits[0][0].pattern_id == "scam-grandparent-ai-voice"

    # Upsert custom pattern containing PII and verify PII scrubbing + persistence across restart
    store1.upsert_pattern(
        KnowledgeRecord(
            pattern_id="scam-custom-roof-repair",
            title="Door-to-Door Storm Roof Cash Scam",
            pattern_type="scam",
            summary="Fake roofer calls 555-999-1234 demanding cash upfront.",
            indicators="roof storm damage cash upfront today only",
            official_guidance="Never pay upfront cash to unsolicited door-to-door contractors.",
        )
    )

    store2 = PersistentScamKnowledgeStore(db_file)
    custom_hits = store2.search("unsolicited roof storm damage cash upfront", top_k=2)
    assert any(rec.pattern_id == "scam-custom-roof-repair" for rec, _ in custom_hits)
    matched_custom = next(rec for rec, _ in custom_hits if rec.pattern_id == "scam-custom-roof-repair")
    assert "555-999-1234" not in matched_custom.summary
    assert "[REDACTED_PHONE]" in matched_custom.summary


def test_history_compaction_config_and_pii_safe_sliding_window(
    isolated_settings: Settings,
) -> None:
    adk_compaction = build_events_compaction_config(isolated_settings)
    assert adk_compaction.compaction_interval == isolated_settings.compaction_interval
    assert adk_compaction.overlap_size == isolated_settings.compaction_overlap_size
    assert adk_compaction.token_threshold == isolated_settings.compaction_token_threshold
    assert adk_compaction.summarizer is not None

    cache_cfg = build_context_cache_config(isolated_settings)
    assert cache_cfg is not None
    assert cache_cfg.min_tokens == 2048

    compactor = PIISafeHistoryCompactor(max_token_budget=220, retain_recent_turns=2)
    turns = [
        {
            "role": "user",
            "content": f"Turn {i}: Checking suspicious Medicare call asking for SSN 123-45-6789 " + ("x" * 200),
        }
        for i in range(6)
    ]
    window = compactor.compact_turns(turns)
    assert window.compacted_turn_count == 4
    assert len(window.retained_turns) == 2
    assert window.estimated_tokens_after < window.estimated_tokens_before
    assert "123-45-6789" not in window.summary
    assert "[REDACTED_SSN]" in window.summary


async def test_async_memory_consolidator_runs_non_blocking_and_scrubs_pii(
    tmp_path: Path,
) -> None:
    mem_db = tmp_path / "memory.db"
    memory_service = PersistentSqliteMemoryService(mem_db)
    consolidator = AsyncMemoryConsolidator(memory_service)

    task = consolidator.schedule_consolidation(
        app_name="app",
        user_id="senior-002",
        session_id="sess-99",
        summary_text=(
            "User reported repeated IRS gift card calls to 555-222-3333 asking "
            "for SSN 123-45-6789. Verdict was HIGH_RISK."
        ),
        metadata={"last_scam_category": "government_impersonation_scam"},
    )
    assert task is not None
    await consolidator.wait_for_pending(timeout_seconds=5.0)
    assert consolidator.completed_count == 1
    assert consolidator.failed_count == 0

    # Verify persistence across a new PersistentSqliteMemoryService instance and zero PII leak
    reopened = PersistentSqliteMemoryService(mem_db)
    res = await reopened.search_memory(
        app_name="app", user_id="senior-002", query="IRS gift card"
    )
    assert len(res.memories) == 1
    stored_text = res.memories[0].content.parts[0].text or ""
    assert "IRS gift card" in stored_text
    assert "123-45-6789" not in stored_text
    assert "555-222-3333" not in stored_text
    assert "[REDACTED_SSN]" in stored_text
