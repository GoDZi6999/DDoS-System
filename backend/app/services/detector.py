"""Synchronous flow classification for POST /v2/detect.

Uses the same model bundle and feature code as the real-time engine
(ml/sentinel_ml). The ML stack is imported lazily: the rest of the API, the
alert engine and the notifier run without it, and /v2/detect answers 503 when
it is missing.
"""

import logging
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.models.enums import Severity
from app.schemas.flow import Contribution, DetectResponse, FlowRecord, FlowVerdict
from app.services.playbook import recommended_action

logger = logging.getLogger(__name__)

# The default bundle, relative to the repository root (the Docker image sets MODEL_BUNDLE).
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BUNDLE = REPO_ROOT / "models" / "sentinel-flow" / "2026.10.03"


class DetectorUnavailable(Exception):
    pass


class InvalidFlows(Exception):
    pass


class Detector:
    def __init__(self, predictor: Any) -> None:
        self.predictor = predictor
        meta = predictor.bundle.metadata
        self.model_version = f"{meta['name']}-{meta['version']}"
        # The SHAP explainer is built lazily and is not safe to build twice at once.
        self._lock = threading.Lock()

    def detect(self, flows: list[FlowRecord], max_explained: int) -> DetectResponse:
        from sentinel_ml import features

        try:
            frame = features.from_records([flow.features for flow in flows])
        except (ValueError, KeyError) as exc:
            raise InvalidFlows(str(exc)) from exc
        with self._lock:
            predictions = self.predictor.predict(frame, explain="none")
            attacks = [i for i, p in enumerate(predictions) if p.is_attack]
            if max_explained and attacks:
                self.predictor.explain_rows(frame, predictions, attacks[:max_explained])

        results = []
        for index, (flow, prediction) in enumerate(zip(flows, predictions, strict=True)):
            action = None
            if prediction.is_attack:
                # HIGH: the plain playbook text, without the CRITICAL escalation
                # line, since a single verdict carries no risk score.
                action = recommended_action(
                    prediction.label, Severity.HIGH, flow.src_ip, flow.dst_ip
                )
            results.append(
                FlowVerdict(
                    index=index,
                    label=prediction.label,
                    is_attack=prediction.is_attack,
                    confidence=float(prediction.confidence),
                    class_probs={k: float(v) for k, v in prediction.class_probs.items()},
                    explanation=[
                        Contribution(
                            feature=item["feature"],
                            value=float(item["value"]),
                            contribution=float(item["contribution"]),
                            weight=float(item["weight"]),
                        )
                        for item in prediction.explanation
                    ],
                    recommended_action=action,
                )
            )
        return DetectResponse(
            model_version=self.model_version, attacks=len(attacks), results=results
        )


_load_lock = threading.Lock()


@lru_cache(maxsize=1)
def _load(path: str) -> Detector:
    try:
        from sentinel_ml.inference import Predictor
    except ImportError as exc:
        raise DetectorUnavailable("The detection model is not installed on this server") from exc
    try:
        predictor = Predictor.from_bundle(path)
    except Exception as exc:  # missing files, checksum mismatch, incompatible pickle
        logger.exception("Could not load model bundle %s", path)
        raise DetectorUnavailable("The detection model could not be loaded") from exc
    logger.info("Loaded model bundle %s", path)
    return Detector(predictor)


def get_detector() -> Detector:
    """Load the bundle on first use (a few seconds), then reuse it."""
    # Relative paths (as in .env, shared with the engine) are from the repo root.
    path = str(REPO_ROOT / (get_settings().model_bundle or DEFAULT_BUNDLE))
    with _load_lock:
        return _load(path)
