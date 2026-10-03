from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sqlalchemy import (
    BigInteger,
    Column,
    ForeignKey,
    Identity,
    Index,
    SmallInteger,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, str_enum
from app.models.enums import AlertStatus, Severity

# Detections aggregated into an alert.
alert_events = Table(
    "alert_events",
    Base.metadata,
    Column("alert_id", ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "event_id",
        BigInteger,
        ForeignKey("network_events.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    ),
)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_last_seen_at", "status", "last_seen_at"),
        Index("ix_alerts_correlation", "attack_type", "destination_ip", "status"),
    )

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    attack_type: Mapped[str] = mapped_column(String(32))
    # Source of the highest-risk detection; an alert can span many sources.
    source_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET)
    destination_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET)
    destination_port: Mapped[int | None]
    protocol: Mapped[str] = mapped_column(String(8))
    confidence: Mapped[float]
    risk_score: Mapped[int] = mapped_column(SmallInteger)
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "alert_severity"))
    status: Mapped[AlertStatus] = mapped_column(
        str_enum(AlertStatus, "alert_status"), default=AlertStatus.NEW
    )
    description: Mapped[str] = mapped_column(Text)
    recommended_action: Mapped[str] = mapped_column(Text)
    detection_count: Mapped[int] = mapped_column(default=1)
    peak_packets_per_sec: Mapped[float]
    peak_bytes_per_sec: Mapped[float]
    # Explanation and risk breakdown of the highest-risk detection.
    explanation: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    risk_components: Mapped[dict[str, Any]] = mapped_column(JSONB)
    model_version: Mapped[str] = mapped_column(String(64))
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    acknowledged_at: Mapped[datetime | None]
    resolved_at: Mapped[datetime | None]


class AlertNote(Base):
    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
