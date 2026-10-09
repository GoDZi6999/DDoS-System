from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Identity, Index, SmallInteger, String, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, str_enum
from app.models.enums import EventSource, Severity


class NetworkEvent(Base):
    """One analysed flow, as published by the ML engine."""

    __tablename__ = "network_events"
    __table_args__ = (Index("ix_network_events_dst_ip_ts", "dst_ip", "ts"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Redis stream entry id; makes at-least-once delivery idempotent.
    stream_id: Mapped[str | None] = mapped_column(String(32), unique=True)
    ts: Mapped[datetime] = mapped_column(index=True)
    src_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET)
    dst_ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET)
    src_port: Mapped[int | None]
    dst_port: Mapped[int | None]
    protocol: Mapped[str] = mapped_column(String(8))
    packet_count: Mapped[int] = mapped_column(BigInteger)
    byte_count: Mapped[int] = mapped_column(BigInteger)
    duration: Mapped[float]
    packets_per_sec: Mapped[float]
    bytes_per_sec: Mapped[float]
    features: Mapped[dict[str, Any]] = mapped_column(JSONB)
    source: Mapped[EventSource] = mapped_column(str_enum(EventSource, "event_source"))
    # Set for flows from an uploaded capture file (the packets behind its alerts).
    capture_id: Mapped[int | None] = mapped_column(
        ForeignKey("captures.id", ondelete="SET NULL"), index=True
    )


class Prediction(Base):
    """Model output, explanation and risk score for one network event."""

    __tablename__ = "predictions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    event_id: Mapped[int] = mapped_column(
        ForeignKey("network_events.id", ondelete="CASCADE"), unique=True
    )
    model_version: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[float]
    class_probs: Mapped[dict[str, Any]] = mapped_column(JSONB)
    explanation: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    risk_score: Mapped[int] = mapped_column(SmallInteger)
    risk_components: Mapped[dict[str, Any]] = mapped_column(JSONB)
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "prediction_severity"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
