"""The /v2 machine API: flow records in, verdicts out.

A flow record is the same JSON a capture sensor sends (engine/sentinel_engine/
flows.py, Flow.record()), so a customer can build flows with the bundled
sensor or with their own exporter that computes the same features."""

import math
from typing import Literal

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator

MAX_FLOW_S = 3_600.0


class FlowRecord(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65_535)
    dst_port: int = Field(ge=0, le=65_535)
    protocol: Literal["tcp", "udp", "icmp", "other"]
    start: float = Field(description="Flow start, Unix seconds")
    end: float = Field(description="Flow end, Unix seconds")
    duration: float = Field(ge=0, le=MAX_FLOW_S, description="Seconds")
    packet_count: int = Field(ge=1, le=10**9)
    byte_count: int = Field(ge=0, le=10**13)
    features: dict[str, float] = Field(
        max_length=64,
        description="Flow statistics keyed by feature name (see docs/ML_METHODOLOGY.md)",
    )

    @field_validator("start", "end")
    @classmethod
    def _finite_time(cls, value: float) -> float:
        if not math.isfinite(value) or value < 0:
            raise ValueError("must be a finite Unix timestamp")
        return value

    @field_validator("features")
    @classmethod
    def _finite_features(cls, value: dict[str, float]) -> dict[str, float]:
        for name, number in value.items():
            if len(name) > 64 or not math.isfinite(number) or not -1.0 <= number <= 1e15:
                raise ValueError(f"feature {name[:64]!r} is out of range")
        return value

    @model_validator(mode="after")
    def _ordered(self) -> "FlowRecord":
        if self.end < self.start:
            raise ValueError("end is before start")
        return self


class FlowBatch(BaseModel):
    flows: list[FlowRecord] = Field(min_length=1, max_length=10_000)


class Contribution(BaseModel):
    feature: str
    value: float
    contribution: float
    weight: float = Field(description="Share of the total attribution, percent")


class FlowVerdict(BaseModel):
    index: int = Field(description="Position of the flow in the request")
    label: str
    is_attack: bool
    confidence: float
    class_probs: dict[str, float]
    explanation: list[Contribution] = Field(
        description="Top SHAP contributions; empty for benign flows and beyond the explain budget"
    )
    recommended_action: str | None = Field(description="Advisory only; None for benign flows")


class DetectResponse(BaseModel):
    model_version: str
    attacks: int
    results: list[FlowVerdict]


class IngestResponse(BaseModel):
    accepted: int
    sensor: str = Field(description="Name these flows appear under in the dashboard's sensor list")
