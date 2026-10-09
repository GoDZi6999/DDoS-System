from datetime import datetime
from typing import Any

from app.models.enums import CaptureStatus
from app.schemas.common import ORMModel


class CaptureOut(ORMModel):
    id: int
    filename: str
    file_format: str
    size_bytes: int
    sha256: str
    raise_alerts: bool
    status: CaptureStatus
    error: str | None
    uploaded_by_id: int | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    # packets, flows, attacks, attack_types, detected_by, top_sources, top_targets, max_risk,
    # first_packet_at, last_packet_at, duration_s, analysis_s, model_version
    report: dict[str, Any] | None
