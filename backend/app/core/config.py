"""Runtime configuration, read from environment variables."""

import logging
import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    environment: Literal["development", "test", "production"] = "development"

    # Defaults point at services on localhost for running outside Docker;
    # docker-compose.yml overrides them with the in-network hostnames.
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    redis_url: str = "redis://localhost:6379/0"

    # HS256 signing key (32+ characters). Required in production; without it a
    # development server generates an ephemeral key and sessions end on restart.
    jwt_secret: SecretStr | None = None
    access_token_minutes: int = 15
    refresh_token_days: int = 7

    # Failed-login throttling, counted per username and per client IP.
    login_window_minutes: int = 15
    login_max_failures_per_user: int = 5
    login_max_failures_per_ip: int = 20

    # Read once by `python -m app.cli bootstrap` while no user exists yet.
    initial_admin_username: str = "admin"
    initial_admin_password: SecretStr | None = None

    # Prometheus metrics at /metrics (not proxied by the dashboard).
    metrics_enabled: bool = True

    # Notifications (Phase 7). Email channels need an SMTP relay; without
    # SMTP_HOST their deliveries fail with a clear error.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "ArgusAI <argusai@localhost>"
    # Base URL of the dashboard, for links in notifications.
    dashboard_url: str = "http://localhost:3000"
    # Webhook and Slack targets must be public HTTPS addresses. Allow private
    # addresses and plain HTTP only for local testing (e.g. a receiver in Compose).
    notify_allow_private_targets: bool = False

    # Retention, enforced by the notifier worker. Flows older than
    # EVENT_RETENTION_DAYS are deleted unless they are evidence for an alert
    # that is open or was closed within EVIDENCE_RETENTION_DAYS. The audit log
    # is never purged.
    event_retention_days: int = Field(14, ge=1)
    evidence_retention_days: int = Field(90, ge=1)
    delivery_retention_days: int = Field(30, ge=1)

    # Machine API (/v2), authenticated by API keys. Requests per key per minute,
    # and the largest batch one request may carry.
    api_rate_per_minute: int = Field(600, ge=1)
    api_max_flows: int = Field(1000, ge=1, le=10_000)
    # /v2/detect explains (SHAP) at most this many attack flows per request:
    # SHAP costs ~10x a prediction, and a flood batch is near-identical flows.
    api_max_explained: int = Field(20, ge=0, le=1000)
    # Model bundle for /v2/detect. Unset: the default bundle in the repository
    # (the Docker image sets it). Needs the ML stack (ml/requirements.txt).
    model_bundle: str | None = None
    # Uploaded packet captures (POST /api/v1/captures), shared by the API and the
    # capture worker. Relative paths are from the working directory.
    capture_dir: str = "captures"
    capture_max_mb: int = Field(100, ge=1, le=2048)

    @field_validator(
        "jwt_secret",
        "model_bundle",
        "initial_admin_password",
        "smtp_host",
        "smtp_username",
        "smtp_password",
        mode="before",
    )
    @classmethod
    def _empty_as_unset(cls, value: object) -> object:
        # docker-compose passes unset variables through as empty strings.
        return None if value == "" else value

    @model_validator(mode="after")
    def _check_jwt_secret(self) -> "Settings":
        if self.jwt_secret is not None and len(self.jwt_secret.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        if self.environment == "production" and self.jwt_secret is None:
            raise ValueError("JWT_SECRET is required when ENVIRONMENT=production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def jwt_signing_key() -> str:
    secret = get_settings().jwt_secret
    if secret is not None:
        return secret.get_secret_value()
    logger.warning("JWT_SECRET is not set: using an ephemeral key, sessions end on restart")
    return secrets.token_urlsafe(48)
