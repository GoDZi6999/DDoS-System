from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

SensorStatus = Literal["online", "stale", "offline"]


class Sensor(BaseModel):
    name: str
    status: SensorStatus = Field(
        description="online: reported within 15 s; stale: within 60 s; offline: older or stopped"
    )
    hostname: str
    platform: str
    interface: str
    filter: str
    started_at: datetime | None
    last_seen: datetime | None
    packets: int = Field(description="Packets captured since the sensor started")
    packets_per_s: float
    flows_sent: int
    flows_buffered: int = Field(description="Flows waiting to be sent (stack unreachable)")
    flows_dropped: int = Field(description="Flows lost because the sensor's buffer was full")
    capture_drops: int = Field(description="Packets lost because capture outran flow building")
    active_flows: int


class SensorBacklog(BaseModel):
    pending: int = Field(description="Flows read by the engine but not yet acknowledged")
    lag: int | None = Field(description="Flows in the stream not yet read by the engine")


class SensorList(BaseModel):
    items: list[Sensor]
    backlog: SensorBacklog | None = Field(
        description="Engine progress on the sensor flow stream (null until it starts reading)"
    )
