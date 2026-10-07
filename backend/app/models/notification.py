from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    ForeignKey,
    Identity,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    true,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, str_enum
from app.models.enums import ChannelKind, DeliveryStatus, NotificationEvent, Severity


class NotificationChannel(Base):
    """Where alert notifications go: an email list, a Slack webhook or a generic webhook."""

    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[ChannelKind] = mapped_column(str_enum(ChannelKind, "channel_kind"))
    enabled: Mapped[bool] = mapped_column(default=True, server_default=true())
    # Alerts below this severity are not sent to the channel.
    min_severity: Mapped[Severity] = mapped_column(str_enum(Severity, "channel_min_severity"))
    # Deliveries beyond this many per rolling hour are recorded as suppressed.
    max_per_hour: Mapped[int] = mapped_column(SmallInteger, default=30, server_default="30")
    # Kind-specific settings (recipients, URL, signing secret). The API masks
    # secrets when returning them.
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class NotificationDelivery(Base):
    """Outbox and delivery log: written in the same transaction as the alert
    change that triggers it, then sent (and retried) by the notifier worker."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        # One delivery per channel and alert severity band, however many
        # detections the alert absorbs.
        UniqueConstraint("channel_id", "dedupe_key"),
        Index("ix_notification_deliveries_due", "status", "next_attempt_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    channel_id: Mapped[int] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE")
    )
    alert_id: Mapped[int | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), index=True
    )
    event: Mapped[NotificationEvent] = mapped_column(str_enum(NotificationEvent, "delivery_event"))
    dedupe_key: Mapped[str] = mapped_column(String(80))
    status: Mapped[DeliveryStatus] = mapped_column(
        str_enum(DeliveryStatus, "delivery_status"), default=DeliveryStatus.PENDING
    )
    attempts: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    next_attempt_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_error: Mapped[str | None] = mapped_column(Text)
    # Snapshot of the alert when the delivery was queued; the message shows the
    # state that triggered it, even if the alert changes before it is sent.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
    sent_at: Mapped[datetime | None]
