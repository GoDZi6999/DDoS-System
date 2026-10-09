"""Contract for detections published by the ML engine.

Each detection is one entry on the Redis stream `sentinel:detections`, with a
single field `data` holding this model as JSON. Documented in docs/API.md.
"""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress, StringConstraints

from app.models.enums import EventSource

BENIGN_LABEL = "benign"

Label = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,32}$")]
FeatureName = Annotated[str, StringConstraints(min_length=1, max_length=64)]


class ExplanationItem(BaseModel):
    """One feature's contribution to the prediction (SHAP)."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    feature: FeatureName
    value: float | None = Field(default=None, description="Observed feature value")
    contribution: float = Field(description="Signed SHAP value")
    weight: float = Field(ge=0, le=100, description="Share of total |SHAP| in percent")


class Detection(BaseModel):
    # Flow statistics can contain Infinity/NaN (a known CIC dataset issue);
    # they are rejected here rather than stored.
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    ts: AwareDatetime
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal["tcp", "udp", "icmp", "other"]
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    duration: float = Field(ge=0, description="Flow duration in seconds")
    packets_per_sec: float = Field(ge=0)
    bytes_per_sec: float = Field(ge=0)
    features: dict[FeatureName, float] = Field(default_factory=dict, max_length=200)
    source: EventSource
    label: Label = Field(description="Predicted class, e.g. benign, ddos, portscan")
    confidence: float = Field(ge=0, le=1)
    class_probs: dict[Label, float] = Field(default_factory=dict, max_length=50)
    explanation: list[ExplanationItem] = Field(default_factory=list, max_length=20)
    risk_score: int = Field(ge=0, le=100)
    risk_components: dict[FeatureName, float] = Field(default_factory=dict, max_length=10)
    model_version: str = Field(min_length=1, max_length=64)
    capture_id: int | None = Field(
        default=None, ge=1, description="Uploaded capture the flow came from (source pcap)"
    )
