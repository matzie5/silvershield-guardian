"""Unit tests for PII redaction (local + Cloud DLP mock) and Secret Manager hygiene."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.security.pii_redactor import PIIRedactor
from app.security.secrets import SecretManagerResolver, SecretResolutionError


def test_pii_redactor_scrubs_all_senior_sensitive_entities() -> None:
    redactor = PIIRedactor(enable_cloud_dlp=False)
    sensitive = (
        "SSN 123-45-6789, Medicare 1EG4-TE5-MK72, phone (555) 867-5309, "
        "email evelyn.smith@example.com, PIN: 4829, account number 987654321012, "
        "lives at 742 Evergreen Terrace Street."
    )
    report = redactor.redact_text(sensitive)

    assert report.had_pii is True
    for leaked in (
        "123-45-6789",
        "1EG4-TE5-MK72",
        "867-5309",
        "evelyn.smith@example.com",
        "4829",
        "987654321012",
        "742 Evergreen Terrace Street",
    ):
        assert leaked not in report.redacted_text
    assert "[REDACTED_SSN]" in report.redacted_text
    assert "[REDACTED_MEDICARE_ID]" in report.redacted_text
    assert "[REDACTED_EMAIL]" in report.redacted_text
    assert "[REDACTED_PHONE]" in report.redacted_text
    assert "[REDACTED_CREDENTIAL]" in report.redacted_text
    assert "[REDACTED_BANK_ACCOUNT]" in report.redacted_text
    assert "[REDACTED_ADDRESS]" in report.redacted_text


def test_pii_redactor_integrates_cloud_dlp_client_when_enabled() -> None:
    class FakeDlpClient:
        def __init__(self) -> None:
            self.called = False

        def deidentify_content(self, request: dict) -> SimpleNamespace:
            self.called = True
            text = request["item"]["value"].replace("123-45-6789", "[US_SOCIAL_SECURITY_NUMBER]")
            return SimpleNamespace(item=SimpleNamespace(value=text))

    fake_dlp = FakeDlpClient()
    redactor = PIIRedactor(
        enable_cloud_dlp=True,
        project_id="test-gcp-project",
        dlp_client=fake_dlp,
    )
    report = redactor.redact_text("Caller asked for SSN 123-45-6789")
    assert fake_dlp.called is True
    assert report.used_cloud_dlp is True
    assert "123-45-6789" not in report.redacted_text


def test_secret_manager_resolver_fetches_caches_and_rejects_prod_placeholders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    class FakeSecretManagerClient:
        def access_secret_version(self, request: dict) -> SimpleNamespace:
            nonlocal calls
            calls += 1
            assert request["name"] == (
                "projects/demo-proj/secrets/silvershield-gemini-api-key/versions/latest"
            )
            return SimpleNamespace(
                payload=SimpleNamespace(data=b"resolved-from-gsm-value")
            )

    resolver = SecretManagerResolver(
        project_id="demo-proj",
        use_secret_manager=True,
        cache_ttl_seconds=60,
        client=FakeSecretManagerClient(),
    )

    first = resolver.get_secret(
        env_var="GOOGLE_API_KEY",
        secret_name="silvershield-gemini-api-key",
        required=True,
        app_env="prod",
    )
    second = resolver.get_secret(
        env_var="GOOGLE_API_KEY",
        secret_name="silvershield-gemini-api-key",
        required=True,
        app_env="prod",
    )
    assert first == "resolved-from-gsm-value"
    assert second == "resolved-from-gsm-value"
    assert calls == 1  # Served from TTL cache on second call
    assert "resolved-from-gsm-value" not in resolver.mask_for_diagnostics(first)

    # Verify production rejects placeholder secrets
    monkeypatch.setenv("FAKE_PROD_KEY", "your-api-key-here")
    local_resolver = SecretManagerResolver(use_secret_manager=False)
    with pytest.raises(SecretResolutionError):
        local_resolver.get_secret(
            env_var="FAKE_PROD_KEY", required=True, app_env="prod"
        )


def test_repository_contains_no_hardcoded_api_keys_or_raw_prints() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    secret_re = re.compile(
        r"(AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9]{20,}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)"
    )
    bare_print_re = re.compile(r"^\s*print\(", re.MULTILINE)

    for py_file in (repo_root / "app").rglob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        assert not secret_re.search(source), f"Potential secret found in {py_file}"
        assert not bare_print_re.search(source), f"Bare print() found in {py_file}; use structured logger"
