import math

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RiskWeights(BaseModel):
    """Weights of the four risk signals (see docs/ARCHITECTURE.md §4); they must sum to 1."""

    model_config = ConfigDict(extra="forbid")

    ml_confidence: float = Field(0.40, ge=0, le=1)
    traffic_anomaly: float = Field(0.25, ge=0, le=1)
    attack_severity: float = Field(0.25, ge=0, le=1)
    source_reputation: float = Field(0.10, ge=0, le=1)

    @model_validator(mode="after")
    def _sum_to_one(self) -> "RiskWeights":
        total = (
            self.ml_confidence
            + self.traffic_anomaly
            + self.attack_severity
            + self.source_reputation
        )
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(f"risk weights must sum to 1 (got {total:g})")
        return self


class DetectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_min_risk: int = Field(
        31, ge=0, le=100, description="Detections below this risk score are stored, not alerted"
    )
    aggregation_window_minutes: int = Field(
        15, ge=1, le=1440, description="An open alert absorbs matching detections in this window"
    )
    risk_weights: RiskWeights = Field(
        default_factory=RiskWeights, description="Used by the real-time risk engine"
    )
