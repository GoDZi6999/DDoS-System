from datetime import datetime
from typing import Any

from pydantic import BaseModel, IPvAnyAddress

from app.models.enums import EventSource, Severity


class EventSummary(BaseModel):
    id: int
    ts: datetime
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int | None
    dst_port: int | None
    protocol: str
    packet_count: int
    byte_count: int
    packets_per_sec: float
    bytes_per_sec: float
    source: EventSource
    label: str
    confidence: float
    risk_score: int
    severity: Severity


class EventDetail(EventSummary):
    duration: float
    features: dict[str, float]
    class_probs: dict[str, float]
    explanation: list[dict[str, Any]]
    risk_components: dict[str, float]
    model_version: str
    alert_ids: list[int]
