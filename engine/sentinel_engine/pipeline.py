"""The real-time pipeline:

    packets -> FlowTable -> finished flows ─┐
    ready flow records (simulator) ─────────┴-> WindowStats -> classifier -> RiskEngine
                                                 └-> port-scan rule ─────────┘
                                                         -> detections (Redis stream)
                                                         -> traffic.tick (pub/sub)

The engine clock is the traffic's own timestamps, so PCAP replay and the
simulator behave exactly like live capture.
"""

import logging
import math
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from sentinel_ml import features
from sentinel_ml.inference import Predictor

from sentinel_engine.flows import FlowTable
from sentinel_engine.packets import Heartbeat, Packet
from sentinel_engine.risk import RiskEngine
from sentinel_engine.window import PORTSCAN_MIN_PORTS, WindowStats

logger = logging.getLogger(__name__)

RULE_PORTSCAN = "rule:portscan-v1"
RULE_CONFIDENCE = 0.9
PROTOCOLS = {"tcp", "udp", "icmp"}
# SHAP explanations per (attack label, destination) per second; see _explain_budget.
EXPLAIN_PER_TARGET_S = 5


def _finite(value: float) -> float:
    value = float(value)
    return value if math.isfinite(value) else 0.0


class Engine:
    def __init__(
        self,
        predictor: Predictor,
        publisher,
        source_kind: str,
        tick_s: float = 1.0,
        config_refresh_s: float = 10.0,
        portscan_min_ports: int = PORTSCAN_MIN_PORTS,
        heartbeat_file: Path | None = None,
        explain_per_target_s: int = EXPLAIN_PER_TARGET_S,
    ) -> None:
        self.predictor = predictor
        self.publisher = publisher
        self.source_kind = source_kind  # live | pcap | sim
        self.tick_s = tick_s
        self.config_refresh_s = config_refresh_s
        self.portscan_min_ports = portscan_min_ports
        self.heartbeat_file = heartbeat_file
        self.explain_per_target_s = explain_per_target_s
        self._explain_second = -1
        self._explained: dict[tuple[str, str], int] = {}
        self.table = FlowTable()
        self.window = WindowStats()
        self.risk = RiskEngine()
        meta = predictor.bundle.metadata
        self.model_version = f"{meta['name']}-{meta['version']}"
        self._scan_reported: dict[tuple[str, str], float] = {}
        self._tick = {"flows": 0, "packets": 0, "attacks": 0, "max_risk": 0}
        self._next_config = 0.0

    # --- classification ---------------------------------------------------

    def _detection(self, record: dict, prediction, risk: int, components: dict) -> dict:
        duration = max(float(record["duration"]), 0.0)
        packets, octets = int(record["packet_count"]), int(record["byte_count"])
        protocol = record["protocol"] if record["protocol"] in PROTOCOLS else "other"
        feature_values = {k: _finite(v) for k, v in record["features"].items()}
        feature_values |= self.window.context(record)
        return {
            "ts": datetime.fromtimestamp(record["end"], UTC).isoformat(),
            "src_ip": record["src_ip"],
            "dst_ip": record["dst_ip"],
            "src_port": int(record["src_port"]),
            "dst_port": int(record["dst_port"]),
            "protocol": protocol,
            "packet_count": packets,
            "byte_count": octets,
            "duration": duration,
            "packets_per_sec": packets / duration if duration > 0 else 0.0,
            "bytes_per_sec": octets / duration if duration > 0 else 0.0,
            "features": feature_values,
            "source": self.source_kind,
            "label": prediction.label,
            "confidence": float(prediction.confidence),
            "class_probs": prediction.class_probs,
            "explanation": [
                {k: _finite(v) if k != "feature" else v for k, v in item.items()}
                for item in prediction.explanation
            ],
            "risk_score": risk,
            "risk_components": components,
            "model_version": self.model_version,
        }

    def _portscan_rule(self, now: float) -> list[dict]:
        detections = []
        for src, dst, ports in self.window.scanners(self.portscan_min_ports):
            if now - self._scan_reported.get((src, dst), -math.inf) < self.window.window_s:
                continue
            self._scan_reported[(src, dst)] = now
            record = {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "tcp",
                "end": now,
                "duration": self.window.window_s,
                "packet_count": ports,
                "byte_count": 0,
                "features": {},
            }
            rule = _RuleVerdict(
                label="portscan",
                confidence=RULE_CONFIDENCE,
                class_probs={"portscan": RULE_CONFIDENCE},
                explanation=[
                    {
                        "feature": "window_distinct_ports_src_to_dst",
                        "value": float(ports),
                        "contribution": 1.0,
                        "weight": 100.0,
                    }
                ],
            )
            risk, components = self.risk.score(
                "portscan", RULE_CONFIDENCE, src, dst, self.window.dst_packet_rate(dst), now
            )
            self.risk.record_attack(src, dst, now)
            detection = self._detection(record, rule, risk, components)
            detection["model_version"] = RULE_PORTSCAN
            detections.append(detection)
        return detections

    def handle_flows(self, records: list[dict], now: float) -> list[dict]:
        self._refresh_config(now)
        for record in records:
            self.window.add(record)
        self.window.evict(now)
        detections = []
        if records:
            frame = features.from_records([r["features"] for r in records])
            predictions = self.predictor.predict(frame, explain="none")
            self.predictor.explain_rows(
                frame, predictions, self._explain_budget(records, predictions, now)
            )
            for record, prediction in zip(records, predictions, strict=True):
                src, dst = record["src_ip"], record["dst_ip"]
                rate = self.window.dst_packet_rate(dst)
                if prediction.is_attack:
                    risk, components = self.risk.score(
                        prediction.label, prediction.confidence, src, dst, rate, now
                    )
                    self.risk.record_attack(src, dst, now)
                else:
                    self.risk.observe_benign(dst, rate, now)
                    risk, components = 0, {}
                detections.append(self._detection(record, prediction, risk, components))
        detections += self._portscan_rule(now)
        self.publisher.detections(detections)

        attacks = [d for d in detections if d["label"] != "benign"]
        self._tick["flows"] += len(records)
        self._tick["packets"] += sum(int(r["packet_count"]) for r in records)
        self._tick["attacks"] += len(attacks)
        self._tick["max_risk"] = max([self._tick["max_risk"], *(d["risk_score"] for d in attacks)])
        return detections

    def _explain_budget(self, records: list[dict], predictions: list, now: float) -> list[int]:
        """Pick the attack flows to explain. SHAP is the engine's main cost
        (~10x a prediction), and a flood can bring thousands of near-identical
        flows per second against one target, while an alert shows a single
        explanation. So at most EXPLAIN_PER_TARGET_S attack flows per
        (label, destination) are explained per second; the rest carry an empty
        explanation, and the alert keeps the one it has."""
        second = int(now)
        if second != self._explain_second:
            self._explain_second, self._explained = second, {}
        rows = []
        for row, (record, prediction) in enumerate(zip(records, predictions, strict=True)):
            if not prediction.is_attack:
                continue
            key = (prediction.label, record["dst_ip"])
            if self._explained.get(key, 0) < self.explain_per_target_s:
                self._explained[key] = self._explained.get(key, 0) + 1
                rows.append(row)
        return rows

    def _refresh_config(self, now: float) -> None:
        if now < self._next_config:
            return
        self._next_config = now + self.config_refresh_s
        config = self.publisher.detection_config()
        if config and isinstance(config.get("risk_weights"), dict):
            self.risk.set_weights(config["risk_weights"])

    def _emit_tick(self, now: float, span: float) -> None:
        span = max(span, 1e-6)
        self.publisher.event(
            "traffic.tick",
            {
                "ts": datetime.fromtimestamp(now, UTC).isoformat(),
                "flows_per_s": round(self._tick["flows"] / span, 2),
                "packets_per_s": round(self._tick["packets"] / span, 2),
                "attacks": self._tick["attacks"],
                "attacks_per_s": round(self._tick["attacks"] / span, 2),
                "max_risk": self._tick["max_risk"],
                "active_flows": len(self.table),
            },
        )
        self._tick = {"flows": 0, "packets": 0, "attacks": 0, "max_risk": 0}
        if self.heartbeat_file is not None:
            try:
                self.heartbeat_file.write_text(str(time.time()))
            except OSError:
                logger.debug("Could not write heartbeat", exc_info=True)

    # --- main loop ----------------------------------------------------------

    def run(self, source: Iterable) -> int:
        """Consume a source until it ends; returns the number of detections."""
        pending: list[dict] = []
        total = 0
        last_tick = now = None
        for item in source:
            if isinstance(item, Packet):
                self.table.add(item)
                now = item.ts
            elif isinstance(item, Heartbeat):
                now = item.ts
            else:
                pending.append(item)
                now = item["end"]
            if last_tick is None:
                last_tick = now
            if now - last_tick >= self.tick_s:
                total += len(self.handle_flows(pending + self.table.sweep(now), now))
                pending = []
                self._emit_tick(now, now - last_tick)
                last_tick = now
        if now is not None:
            total += len(self.handle_flows(pending + self.table.flush(), now))
            self._emit_tick(now, max(now - (last_tick or now), self.tick_s))
        return total


class _RuleVerdict:
    """Duck-types sentinel_ml.inference.Prediction for rule-based detections."""

    def __init__(self, label, confidence, class_probs, explanation) -> None:
        self.label = label
        self.confidence = confidence
        self.class_probs = class_probs
        self.explanation = explanation
