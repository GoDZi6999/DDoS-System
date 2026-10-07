"""Risk engine: turns a classification into a 0-100 risk score with an
explicit, inspectable breakdown (docs/ARCHITECTURE.md §4):

    risk = w1 * ml_confidence      model probability of the predicted attack class
         + w2 * traffic_anomaly    destination packet rate vs. its benign baseline
         + w3 * attack_severity    fixed impact of the attack class
         + w4 * source_reputation  recent attack detections from the same source

Weights come from the admin-editable detection settings (published by the
API to Redis); benign predictions score 0.
"""

import math
from collections import defaultdict, deque
from dataclasses import dataclass

DEFAULT_WEIGHTS = {
    "ml_confidence": 0.40,
    "traffic_anomaly": 0.25,
    "attack_severity": 0.25,
    "source_reputation": 0.10,
}
SEVERITY = {
    "ddos": 90,
    "dos": 80,
    "botnet": 80,
    "webattack": 70,
    "bruteforce": 65,
    "portscan": 50,
}
DEFAULT_SEVERITY = 60
REPUTATION_WINDOW_S = 3600.0
REPUTATION_PER_HIT = 20
MIN_BASELINE_SAMPLES = 30
# A destination's baseline is frozen while it is under attack and for this long
# after, so a flood cannot teach the baseline that flooding is normal.
BASELINE_QUIET_S = 60.0
EWMA_ALPHA = 0.02


@dataclass
class Baseline:
    """Exponentially weighted mean/variance of log packet rate."""

    n: int = 0
    mean: float = 0.0
    var: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        if self.n == 1:
            self.mean = x
            return
        delta = x - self.mean
        self.mean += EWMA_ALPHA * delta
        self.var = (1 - EWMA_ALPHA) * (self.var + EWMA_ALPHA * delta * delta)


class RiskEngine:
    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = dict(weights or DEFAULT_WEIGHTS)
        self._per_dst: dict[str, Baseline] = defaultdict(Baseline)
        self._global = Baseline()
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._attacked_at: dict[str, float] = {}

    def set_weights(self, weights: dict[str, float]) -> None:
        if set(weights) == set(DEFAULT_WEIGHTS) and math.isclose(sum(weights.values()), 1.0):
            self.weights = dict(weights)

    def observe_benign(self, dst: str, packet_rate: float, now: float) -> None:
        if now - self._attacked_at.get(dst, -math.inf) < BASELINE_QUIET_S:
            return
        x = math.log1p(packet_rate)
        self._per_dst[dst].update(x)
        self._global.update(x)

    def anomaly(self, dst: str, packet_rate: float) -> float:
        x = math.log1p(packet_rate)
        baseline = self._per_dst.get(dst)
        if baseline is None or baseline.n < MIN_BASELINE_SAMPLES:
            baseline = self._global
        if baseline.n < MIN_BASELINE_SAMPLES:
            # Cold start: score the absolute rate (10,000 packets/s -> 100).
            return min(100.0, max(0.0, x / math.log1p(10_000) * 100))
        z = (x - baseline.mean) / max(math.sqrt(baseline.var), 0.25)
        return min(100.0, max(0.0, z * 25))

    def reputation(self, src: str, now: float) -> float:
        hits = self._hits.get(src)
        if not hits:
            return 0.0
        while hits and hits[0] < now - REPUTATION_WINDOW_S:
            hits.popleft()
        return float(min(100, REPUTATION_PER_HIT * len(hits)))

    def score(
        self, label: str, confidence: float, src: str, dst: str, packet_rate: float, now: float
    ) -> tuple[int, dict[str, float]]:
        components = {
            "ml_confidence": round(confidence * 100, 1),
            "traffic_anomaly": round(self.anomaly(dst, packet_rate), 1),
            "attack_severity": float(SEVERITY.get(label, DEFAULT_SEVERITY)),
            "source_reputation": self.reputation(src, now),
        }
        risk = sum(self.weights[name] * value for name, value in components.items())
        return round(min(100.0, risk)), components

    def record_attack(self, src: str, dst: str, now: float) -> None:
        self._hits[src].append(now)
        self._attacked_at[dst] = now
