from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, StringConstraints

from app.models.enums import AlertStatus, Severity
from app.schemas.user import UserRef

NoteBody = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=5000)]


class AlertSummary(BaseModel):
    id: int
    status: AlertStatus
    severity: Severity
    attack_type: str
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    destination_port: int | None
    protocol: str
    confidence: float
    risk_score: int
    detection_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    peak_packets_per_sec: float
    peak_bytes_per_sec: float
    description: str
    assigned_to: UserRef | None


class NoteOut(BaseModel):
    id: int
    author: UserRef
    body: str
    created_at: datetime


class HistoryEntry(BaseModel):
    ts: datetime
    actor: str
    action: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None


class AlertDetail(AlertSummary):
    recommended_action: str
    explanation: list[dict[str, Any]]
    risk_components: dict[str, float]
    model_version: str
    acknowledged_by: UserRef | None
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    unique_sources: int
    allowed_transitions: list[AlertStatus]
    notes: list[NoteOut]
    history: list[HistoryEntry]


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus
    note: NoteBody | None = None


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: NoteBody


class AssigneeUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: int | None = Field(description="Analyst or admin to assign; null to unassign")
