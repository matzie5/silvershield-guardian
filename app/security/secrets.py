"""Secure secret retrieval via Google Cloud Secret Manager with local dev fallback.

Never hardcodes API keys, database passwords, or tokens in code. In GCP
environments (`USE_SECRET_MANAGER=true`), secrets are fetched at runtime from
Google Cloud Secret Manager via Application Default Credentials (ADC) with
in-memory TTL caching. Locally, environment variables provide seamless testing.
"""

from __future__ import annotations

import importlib
import os
import time
from dataclasses import dataclass
from typing import Any

_PLACEHOLDER_MARKERS = (
    "replace-in-local-env",
    "your-api-key",
    "changeme",
    "example-secret",
    "dummy-prod-secret",
)


@dataclass
class _CachedSecret:
    value: str
    expires_at: float


class SecretResolutionError(RuntimeError):
    """Raised when a required secret cannot be resolved securely."""


class SecretManagerResolver:
    """Resolves application secrets from GCP Secret Manager or environment variables."""

    def __init__(
        self,
        *,
        project_id: str | None = None,
        use_secret_manager: bool = False,
        cache_ttl_seconds: int = 300,
        client: Any | None = None,
    ) -> None:
        self._project_id = project_id
        self._use_secret_manager = use_secret_manager
        self._cache_ttl_seconds = max(1, cache_ttl_seconds)
        self._client = client
        self._cache: dict[str, _CachedSecret] = {}

    def _get_sm_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            secretmanager: Any = importlib.import_module("google.cloud.secretmanager")
        except ImportError as exc:
            raise SecretResolutionError(
                "google-cloud-secret-manager is required when USE_SECRET_MANAGER=true. "
                "Install with: uv sync --extra gcp"
            ) from exc
        self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    def _fetch_from_secret_manager(self, secret_name: str, version: str = "latest") -> str:
        if not self._project_id:
            raise SecretResolutionError(
                "GOOGLE_CLOUD_PROJECT must be set to access GCP Secret Manager."
            )
        resource_name = (
            secret_name
            if secret_name.startswith("projects/")
            else f"projects/{self._project_id}/secrets/{secret_name}/versions/{version}"
        )
        client = self._get_sm_client()
        response = client.access_secret_version(request={"name": resource_name})
        return str(response.payload.data.decode("utf-8")).strip()

    @staticmethod
    def _validate_not_placeholder(secret_value: str, env_var: str, is_prod: bool) -> None:
        lowered = secret_value.lower()
        if is_prod and any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
            raise SecretResolutionError(
                f"Refusing to use placeholder value for secret '{env_var}' in production."
            )

    def get_secret(
        self,
        *,
        env_var: str,
        secret_name: str | None = None,
        version: str = "latest",
        required: bool = False,
        app_env: str = "local",
    ) -> str | None:
        """Retrieve a secret securely from GCP Secret Manager or environment.

        Lookup order:
        1. In-memory TTL cache.
        2. GCP Secret Manager (when `use_secret_manager=True` and `secret_name` is set).
        3. Mounted runtime environment variable (e.g., Cloud Run secret mount or local `.env`).
        """
        cache_key = f"{secret_name or env_var}:{version}"
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return cached.value

        value: str | None = None
        sm_error: Exception | None = None

        if self._use_secret_manager and secret_name:
            try:
                value = self._fetch_from_secret_manager(secret_name, version=version)
            except Exception as exc:
                sm_error = exc

        if not value:
            env_value = os.getenv(env_var)
            if env_value:
                value = env_value.strip()

        if not value:
            if required:
                detail = f" (Secret Manager error: {sm_error})" if sm_error else ""
                raise SecretResolutionError(
                    f"Required secret '{env_var}' (secret_name='{secret_name}') could not be "
                    f"resolved{detail}. Configure GCP Secret Manager or set {env_var} in environment."
                )
            return None

        self._validate_not_placeholder(
            value, env_var=env_var, is_prod=(app_env.lower() in {"prod", "production"})
        )
        self._cache[cache_key] = _CachedSecret(
            value=value, expires_at=now + self._cache_ttl_seconds
        )
        return value

    def clear_cache(self) -> None:
        """Clear cached secret values (useful after secret rotation)."""
        self._cache.clear()

    @staticmethod
    def mask_for_diagnostics(secret_value: str | None) -> str:
        """Return a safe diagnostic representation that never leaks the secret."""
        if not secret_value:
            return "<unset>"
        return f"<configured:len={len(secret_value)}>"


_DEFAULT_RESOLVER: SecretManagerResolver | None = None


def get_secret_resolver() -> SecretManagerResolver:
    """Return the process-wide `SecretManagerResolver`."""
    global _DEFAULT_RESOLVER
    if _DEFAULT_RESOLVER is None:
        _DEFAULT_RESOLVER = SecretManagerResolver(
            project_id=os.getenv("GOOGLE_CLOUD_PROJECT") or None,
            use_secret_manager=os.getenv("USE_SECRET_MANAGER", "false").lower() == "true",
        )
    return _DEFAULT_RESOLVER
