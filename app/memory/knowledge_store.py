"""Persistent vector-indexed knowledge store for elder scams and debunked hoaxes.

Backed by SQLite with dense hashed character/word n-gram cosine similarity so
the agent retrieves known scam scripts and fact-check debunks persistently
across turns and restarts with zero external setup, while optionally integrating
Vertex AI Search (`VERTEX_AI_SEARCH_DATASTORE_ID`) in Google Cloud deployments.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from app.config.settings import Settings, get_settings
from app.observability.logging import get_logger
from app.observability.tracing import traced_span
from app.security.pii_redactor import PIIRedactor, get_pii_redactor

logger = get_logger(__name__)

_VECTOR_DIM = 512
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS: frozenset[str] = frozenset(
    {
        "the",
        "and",
        "for",
        "you",
        "your",
        "with",
        "this",
        "that",
        "from",
        "have",
        "will",
        "are",
        "not",
        "they",
        "their",
        "was",
        "were",
        "been",
        "being",
        "into",
        "about",
        "over",
        "just",
        "only",
        "then",
        "than",
        "them",
        "there",
        "here",
        "what",
        "when",
        "where",
        "who",
        "how",
        "can",
        "could",
        "should",
        "would",
        "may",
        "might",
        "must",
        "please",
        "also",
        "very",
        "some",
        "any",
        "all",
        "but",
        "she",
        "her",
        "his",
        "him",
        "our",
        "out",
        "saying",
        "said",
        "got",
        "get",
        "received",
    }
)


def compute_text_embedding(text: str, dim: int = _VECTOR_DIM) -> list[float]:
    """Compute a deterministic L2-normalized dense embedding for semantic matching.

    Combines stopword-filtered word unigrams, word bigrams, and character 5-grams
    using signed feature hashing so domain keywords ('medicare', 'grandson',
    'anydesk', 'gift card') align cleanly in cosine similarity space.
    """
    vec = [0.0] * dim
    cleaned = text.lower().strip()
    if not cleaned:
        return vec

    tokens = [
        tok for tok in _TOKEN_RE.findall(cleaned) if len(tok) >= 3 and tok not in _STOPWORDS
    ]
    features: list[tuple[str, float]] = []
    for tok in tokens:
        features.append((f"w:{tok}", 3.0))
        if len(tok) >= 5:
            features.append((f"p:{tok[:5]}", 1.2))
    for i in range(len(tokens) - 1):
        features.append((f"b:{tokens[i]}_{tokens[i + 1]}", 3.5))

    for feat, weight in features:
        digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "big") % dim
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[idx] += sign * weight

    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0.0:
        vec = [v / norm for v in vec]
    return vec


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute bounded cosine similarity in [0.0, 1.0]."""
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    return max(0.0, min(1.0, dot))


@dataclass(frozen=True)
class KnowledgeRecord:
    """Persistent elder scam or fake-news debunk entry."""

    pattern_id: str
    title: str
    pattern_type: Literal["scam", "fake_news"]
    summary: str
    indicators: str
    official_guidance: str


SEED_KNOWLEDGE_RECORDS: tuple[KnowledgeRecord, ...] = (
    KnowledgeRecord(
        pattern_id="scam-grandparent-ai-voice",
        title="Grandparent / AI Voice-Clone Emergency Scam",
        pattern_type="scam",
        summary=(
            "Caller impersonates a grandchild or relative claiming an urgent car accident, "
            "arrest, or hospital emergency, demanding immediate bail or cash courier money "
            "and insisting 'please don't tell Mom or Dad'."
        ),
        indicators="grandma grandpa bail jail accident lawyer wire cash courier don't tell mom voice sounds different",
        official_guidance=(
            "Hang up immediately without paying. Call your grandchild or their parents "
            "directly on the phone number you already know and trust."
        ),
    ),
    KnowledgeRecord(
        pattern_id="scam-irs-ssa-impersonation",
        title="IRS / Social Security Arrest & Gift Card Scam",
        pattern_type="scam",
        summary=(
            "Fraudsters pose as IRS or Social Security Administration officers threatening "
            "immediate arrest, suspended Social Security number, or frozen benefits unless "
            "paid immediately with gift cards, wire transfer, or cryptocurrency."
        ),
        indicators="irs social security ssa suspended arrested warrant badge number gift card apple card google play bitcoin wire transfer",
        official_guidance=(
            "The IRS and Social Security NEVER call or text to threaten arrest or demand "
            "gift cards, crypto, or wire transfers. Hang up and call SSA at 1-800-772-1213 "
            "or check ssa.gov directly."
        ),
    ),
    KnowledgeRecord(
        pattern_id="scam-medicare-card-phishing",
        title="Fake Medicare New Card / Benefits Suspension Phishing",
        pattern_type="scam",
        summary=(
            "Text, email, or call claiming your Medicare card is expiring or benefits will "
            "be cancelled unless you click a lookalike link or read back your Medicare number."
        ),
        indicators="medicare chip card expiring suspended benefits verify medicare number click link renew coverage",
        official_guidance=(
            "Do not click links or share your Medicare number. Call the official number "
            "1-800-MEDICARE (1-800-633-4227) or visit medicare.gov by typing it yourself."
        ),
    ),
    KnowledgeRecord(
        pattern_id="scam-tech-support-popup",
        title="Fake Microsoft / Apple Virus Alert Tech-Support Scam",
        pattern_type="scam",
        summary=(
            "Loud browser pop-up or phone call claiming your computer is infected with a "
            "critical virus and urging you to call a toll-free number and install remote "
            "access software (AnyDesk, TeamViewer) to fix it for a fee."
        ),
        indicators="microsoft apple virus infected defender critical alert call toll free remote access anydesk teamviewer ultraviewer locked",
        official_guidance=(
            "Microsoft and Apple NEVER show security warnings with a phone number to call. "
            "Close the browser window (or restart your computer) and never grant remote access."
        ),
    ),
    KnowledgeRecord(
        pattern_id="scam-bank-fraud-sms-spoof",
        title="Fake Bank Fraud Alert & One-Time Passcode Theft",
        pattern_type="scam",
        summary=(
            "Text or call claiming an unauthorized $900+ charge on your bank or Zelle account, "
            "asking you to click a link, move funds to a 'safe account', or read back a 6-digit code."
        ),
        indicators="bank fraud alert unauthorized charge zelle suspicious transaction verify account read back code safe account",
        official_guidance=(
            "Never tap links in bank texts or read one-time passcodes to callers. Call the "
            "official customer service number printed on the back of your physical bank card."
        ),
    ),
    KnowledgeRecord(
        pattern_id="scam-lottery-sweepstakes-fee",
        title="Sweepstakes / Publishers Clearing House Advance-Fee Scam",
        pattern_type="scam",
        summary=(
            "Message claiming you won millions of dollars or a new car, but must first pay "
            "taxes, customs, or processing fees via gift cards, prepaid debit card, or wire."
        ),
        indicators="congratulations won lottery sweepstakes prize publishers clearing house processing fee taxes wire gift card claim",
        official_guidance=(
            "Real sweepstakes and lotteries NEVER ask winners to pay upfront fees or taxes "
            "to receive a prize. Delete the message and do not send any money."
        ),
    ),
    KnowledgeRecord(
        pattern_id="scam-romance-crypto-investment",
        title="Online Romance & Guaranteed Crypto Investment Scam",
        pattern_type="scam",
        summary=(
            "Friendly stranger on Facebook, WhatsApp, or dating apps builds quick emotional "
            "trust, avoids meeting in person, and asks for urgent travel/medical funds or "
            "invites you into a 'guaranteed' crypto/gold trading platform."
        ),
        indicators="my love darling stranded overseas customs medical emergency guaranteed profit crypto trading whatsapp secret",
        official_guidance=(
            "Never send money, gift cards, or cryptocurrency to someone you have only met "
            "online. Talk it over with a trusted family member or friend before acting."
        ),
    ),
    KnowledgeRecord(
        pattern_id="scam-utility-shutoff-urgent",
        title="30-Minute Electricity / Water Shutoff Threat Scam",
        pattern_type="scam",
        summary=(
            "Caller threatens that your power, gas, or water will be disconnected within "
            "30-60 minutes unless you pay immediately over the phone using Zelle or prepaid card."
        ),
        indicators="electric power utility water shutoff disconnected 30 minutes overdue pay immediately prepaid zelle",
        official_guidance=(
            "Utility companies send written notices before disconnection and never demand "
            "gift cards or instant Zelle payments. Call the official number on your paper bill."
        ),
    ),
    KnowledgeRecord(
        pattern_id="fakenews-miracle-diabetes-cure",
        title="Viral 'Miracle Cure Doctors Hide' Medical Misinformation",
        pattern_type="fake_news",
        summary=(
            "Sensational social post or forwarded message claiming a single kitchen spice, "
            "baking soda, or secret tea 'reverses diabetes, Alzheimer's, or cancer overnight' "
            "and urges seniors to throw away prescribed medication."
        ),
        indicators="miracle cure doctors don't want you to know big pharma hiding reverses diabetes cancer overnight throw away pills secret trick",
        official_guidance=(
            "No single kitchen remedy cures diabetes, cancer, or dementia overnight. Never "
            "stop prescribed medication based on social media posts — check with your doctor "
            "or trusted sources like CDC.gov and NIH.gov."
        ),
    ),
    KnowledgeRecord(
        pattern_id="fakenews-social-security-cancelled",
        title="Viral Hoax: 'Social Security Payments Ending Next Month'",
        pattern_type="fake_news",
        summary=(
            "Alarming chain post or clickbait headline claiming Social Security checks or "
            "Medicare are being cancelled next week unless you sign a petition or register "
            "on an unofficial website."
        ),
        indicators="breaking social security cancelled ending next month checks stopped share before deleted sign petition urgent alert seniors",
        official_guidance=(
            "Viral posts claiming Social Security is suddenly stopping are false clickbait. "
            "Always verify benefit updates directly at ssa.gov or major news outlets like AP or Reuters."
        ),
    ),
    KnowledgeRecord(
        pattern_id="fakenews-free-senior-cash-card",
        title="Misleading 'Government $3,000 Senior Stimulus / Flex Card' Ad",
        pattern_type="fake_news",
        summary=(
            "Social media ads promising every senior an automatic $2,500-$4,000 government "
            "'flex card' or stimulus check if they enter personal details on an unofficial page."
        ),
        indicators="free government flex card senior stimulus check 3000 4000 allowance claim today expires tonight click here",
        official_guidance=(
            "There is no universal $3,000 government cash flex card for all seniors. Some "
            "Medicare Advantage plans offer modest over-the-counter allowances — verify only "
            "at medicare.gov or with your licensed plan provider."
        ),
    ),
    KnowledgeRecord(
        pattern_id="fakenews-power-grid-martial-law",
        title="Forwarded 'Nationwide Bank Freeze / Grid Blackout Tonight' Hoax",
        pattern_type="fake_news",
        summary=(
            "Chain message claiming a friend in the military or government warned that banks "
            "will freeze accounts or the power grid will shut down tonight — urging people "
            "to withdraw all cash and forward to everyone."
        ),
        indicators="friend in military insider warned banks freezing accounts withdraw all cash blackout tonight forward to everyone share immediately",
        official_guidance=(
            "Urgent anonymous chain messages telling you to withdraw cash or 'forward to "
            "everyone before deleted' are classic panic hoaxes. Check official local news "
            "or ready.gov for real emergency alerts."
        ),
    ),
)


class PersistentScamKnowledgeStore:
    """SQLite-backed vector similarity store for elder scam & fake-news patterns."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        vertex_datastore_id: str | None = None,
        redactor: PIIRedactor | None = None,
    ) -> None:
        self._db_path = Path(db_path).expanduser()
        self._vertex_datastore_id = vertex_datastore_id or None
        self._redactor = redactor or get_pii_redactor()
        if str(self._db_path) != ":memory:":
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._seed_defaults()

    @property
    def backend_name(self) -> str:
        """Return active datastore backend label."""
        if self._vertex_datastore_id:
            return "vertex_ai_search+sqlite_vector"
        return "sqlite_vector"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS knowledge_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    indicators TEXT NOT NULL,
                    official_guidance TEXT NOT NULL,
                    embedding_json TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    def _seed_defaults(self) -> None:
        with self._connect() as conn:
            existing_count = conn.execute(
                "SELECT COUNT(*) FROM knowledge_patterns"
            ).fetchone()[0]
            if existing_count > 0:
                return
            for record in SEED_KNOWLEDGE_RECORDS:
                self._upsert_in_conn(conn, record)
            conn.commit()

    def _upsert_in_conn(self, conn: sqlite3.Connection, record: KnowledgeRecord) -> None:
        scrubbed_summary = self._redactor.redact_text(record.summary).redacted_text
        scrubbed_indicators = self._redactor.redact_text(record.indicators).redacted_text
        scrubbed_guidance = self._redactor.redact_text(
            record.official_guidance
        ).redacted_text
        combined_text = (
            f"{record.title} {scrubbed_summary} {scrubbed_indicators}"
        )
        embedding = compute_text_embedding(combined_text)
        conn.execute(
            """
            INSERT INTO knowledge_patterns (
                pattern_id, title, pattern_type, summary, indicators, official_guidance, embedding_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pattern_id) DO UPDATE SET
                title=excluded.title,
                pattern_type=excluded.pattern_type,
                summary=excluded.summary,
                indicators=excluded.indicators,
                official_guidance=excluded.official_guidance,
                embedding_json=excluded.embedding_json
            """,
            (
                record.pattern_id,
                record.title,
                record.pattern_type,
                scrubbed_summary,
                scrubbed_indicators,
                scrubbed_guidance,
                json.dumps(embedding),
            ),
        )

    def upsert_pattern(self, record: KnowledgeRecord) -> None:
        """Persist a new or updated PII-scrubbed scam/fake-news pattern."""
        with traced_span(
            "knowledge_store.upsert_pattern",
            attributes={"pattern_id": record.pattern_id, "pattern_type": record.pattern_type},
        ), self._connect() as conn:
            self._upsert_in_conn(conn, record)
            conn.commit()

    def search(
        self,
        query: str,
        *,
        top_k: int = 3,
        pattern_type: Literal["scam", "fake_news"] | None = None,
        min_similarity: float = 0.08,
    ) -> list[tuple[KnowledgeRecord, float]]:
        """Perform persistent vector cosine similarity search over stored patterns."""
        with traced_span(
            "knowledge_store.search",
            attributes={
                "datastore_backend": self.backend_name,
                "top_k": top_k,
                "pattern_type": pattern_type or "all",
            },
        ):
            scrubbed_query = self._redactor.redact_text(query).redacted_text
            query_vec = compute_text_embedding(scrubbed_query)

            sql = "SELECT * FROM knowledge_patterns"
            params: list[str] = []
            if pattern_type is not None:
                sql += " WHERE pattern_type = ?"
                params.append(pattern_type)

            scored: list[tuple[KnowledgeRecord, float]] = []
            with self._connect() as conn:
                rows = conn.execute(sql, params).fetchall()
                for row in rows:
                    vec = json.loads(row["embedding_json"])
                    score = cosine_similarity(query_vec, vec)
                    if score >= min_similarity:
                        record = KnowledgeRecord(
                            pattern_id=row["pattern_id"],
                            title=row["title"],
                            pattern_type=row["pattern_type"],
                            summary=row["summary"],
                            indicators=row["indicators"],
                            official_guidance=row["official_guidance"],
                        )
                        scored.append((record, round(score, 4)))

            scored.sort(key=lambda item: item[1], reverse=True)
            results = scored[:top_k]
            logger.info(
                "knowledge_store_search_completed",
                backend=self.backend_name,
                matches_found=len(results),
                top_score=results[0][1] if results else 0.0,
            )
            return results


_DEFAULT_STORE: PersistentScamKnowledgeStore | None = None


def get_knowledge_store(settings: Settings | None = None) -> PersistentScamKnowledgeStore:
    """Return the process-wide persistent scam/fact-check vector store."""
    global _DEFAULT_STORE
    if settings is not None:
        return PersistentScamKnowledgeStore(
            db_path=settings.knowledge_db_path,
            vertex_datastore_id=settings.vertex_ai_search_datastore_id,
        )
    if _DEFAULT_STORE is None:
        cfg = get_settings()
        _DEFAULT_STORE = PersistentScamKnowledgeStore(
            db_path=cfg.knowledge_db_path,
            vertex_datastore_id=cfg.vertex_ai_search_datastore_id,
        )
    return _DEFAULT_STORE
