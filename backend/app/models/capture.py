from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Identity, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, str_enum
from app.models.enums import CaptureStatus


class Capture(Base):
    """A packet capture file (e.g. saved from Wireshark) uploaded for analysis.

    The file lives in CAPTURE_DIR under `stored_name`; the capture worker replays
    it through the real-time engine and writes the report here."""

    __tablename__ = "captures"

    id: Mapped[int] = mapped_column(Identity(), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(64), unique=True)
    file_format: Mapped[str] = mapped_column(String(8))  # pcap | pcapng
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    raise_alerts: Mapped[bool]
    status: Mapped[CaptureStatus] = mapped_column(
        str_enum(CaptureStatus, "capture_status"), default=CaptureStatus.QUEUED, index=True
    )
    error: Mapped[str | None] = mapped_column(Text)
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    # Seconds added to the capture's timestamps so it ends at analysis time
    # (keeps its alerts and flows inside the dashboard's time windows).
    time_offset: Mapped[float | None]
    report: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
