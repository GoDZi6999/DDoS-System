from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    StringConstraints,
)

from app.models.enums import ChannelKind, DeliveryStatus, NotificationEvent, Severity

ChannelName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
Secret = Annotated[str, StringConstraints(min_length=16, max_length=256)]


class EmailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipients: list[EmailStr] = Field(min_length=1, max_length=20)


class SlackConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    webhook_url: AnyHttpUrl = Field(description="Slack incoming-webhook URL")


class WebhookConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: AnyHttpUrl
    secret: Secret | None = Field(
        None, description="Signs each request (X-Argus-Signature, HMAC-SHA256)"
    )


CONFIG_MODELS: dict[ChannelKind, type[BaseModel]] = {
    ChannelKind.EMAIL: EmailConfig,
    ChannelKind.SLACK: SlackConfig,
    ChannelKind.WEBHOOK: WebhookConfig,
}


class ChannelCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ChannelName
    kind: ChannelKind
    enabled: bool = True
    min_severity: Severity = Severity.HIGH
    max_per_hour: int = Field(30, ge=1, le=1000)
    config: dict[str, Any] = Field(
        description="email: {recipients}; slack: {webhook_url}; webhook: {url, secret?}"
    )


class ChannelUpdate(BaseModel):
    """Only the fields sent are changed. In `config`, an omitted webhook
    `secret` keeps the stored one and `secret: null` removes it."""

    model_config = ConfigDict(extra="forbid")

    name: ChannelName | None = None
    enabled: bool | None = None
    min_severity: Severity | None = None
    max_per_hour: int | None = Field(None, ge=1, le=1000)
    config: dict[str, Any] | None = None


class ChannelOut(BaseModel):
    id: int
    name: str
    kind: ChannelKind
    enabled: bool
    min_severity: Severity
    max_per_hour: int
    config: dict[str, Any] = Field(description="Secrets are masked")
    created_at: datetime
    updated_at: datetime
    last_delivery_at: datetime | None
    last_delivery_status: DeliveryStatus | None


class ChannelRef(BaseModel):
    id: int
    name: str
    kind: ChannelKind


class DeliveryOut(BaseModel):
    id: int
    channel: ChannelRef
    alert_id: int | None
    event: NotificationEvent
    status: DeliveryStatus
    attempts: int
    last_error: str | None
    title: str
    created_at: datetime
    next_attempt_at: datetime
    sent_at: datetime | None


class TestResult(BaseModel):
    delivery_id: int
    status: Literal["pending"] = "pending"
