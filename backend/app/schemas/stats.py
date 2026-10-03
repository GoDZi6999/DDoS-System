from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models.enums import AlertStatus, Severity

Window = Literal["1h", "6h", "24h", "7d"]
Bucket = Literal["1m", "5m", "15m", "1h", "6h"]


class StatsSummary(BaseModel):
    window: Window
    events: int = Field(description="Flows analysed in the window")
    attacks: int = Field(description="Flows classified as an attack in the window")
    alerts_open: int = Field(description="Alerts currently NEW, INVESTIGATING or CONTAINED")
    alerts_contained: int = Field(description="Alerts currently CONTAINED")
    alerts_by_status: dict[AlertStatus, int] = Field(description="All alerts, current status")
    open_alerts_by_severity: dict[Severity, int]
    risk_score: int = Field(description="Highest risk score among open alerts (0 if none)")
    severity: Severity


class TimeseriesPoint(BaseModel):
    ts: datetime
    events: int
    attacks: int


class Timeseries(BaseModel):
    window: Window
    bucket: Bucket
    points: list[TimeseriesPoint]


class DistributionItem(BaseModel):
    label: str
    count: int


class Distribution(BaseModel):
    window: Window
    items: list[DistributionItem]
