"""The single definition of SentinelAI's flow features.

Both training (from CIC-IDS2017 CSVs) and live inference (from the Phase 5
flow builder) go through this module, so a feature always means the same
thing in both places. Units are normalised here: durations and inter-arrival
times in seconds, sizes in bytes.

Live producers emit one dict per flow keyed by FEATURE_NAMES (plus optional
extras, which are ignored). Rates are always recomputed from totals and
duration, so a zero-duration flow gets rate 0 instead of CICFlowMeter's
Infinity.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

import numpy as np
import pandas as pd

MICROSECONDS = 1e-6


@dataclass(frozen=True)
class Feature:
    name: str
    description: str
    cic_column: str | None  # CICFlowMeter column it is read from offline
    scale: float = 1.0  # multiplier from the CIC unit to ours


# Order matters: it is the column order of the model input.
FEATURES: tuple[Feature, ...] = (
    Feature("flow_duration_s", "Flow duration (s)", "Flow Duration", MICROSECONDS),
    Feature("fwd_packets", "Packets client -> server", "Total Fwd Packets"),
    Feature("bwd_packets", "Packets server -> client", "Total Backward Packets"),
    Feature("fwd_bytes", "Payload bytes client -> server", "Total Length of Fwd Packets"),
    Feature("bwd_bytes", "Payload bytes server -> client", "Total Length of Bwd Packets"),
    Feature("fwd_pkt_len_max", "Largest forward packet (bytes)", "Fwd Packet Length Max"),
    Feature("fwd_pkt_len_min", "Smallest forward packet (bytes)", "Fwd Packet Length Min"),
    Feature("fwd_pkt_len_mean", "Mean forward packet size (bytes)", "Fwd Packet Length Mean"),
    Feature("fwd_pkt_len_std", "Forward packet size std (bytes)", "Fwd Packet Length Std"),
    Feature("bwd_pkt_len_max", "Largest backward packet (bytes)", "Bwd Packet Length Max"),
    Feature("bwd_pkt_len_min", "Smallest backward packet (bytes)", "Bwd Packet Length Min"),
    Feature("bwd_pkt_len_mean", "Mean backward packet size (bytes)", "Bwd Packet Length Mean"),
    Feature("bwd_pkt_len_std", "Backward packet size std (bytes)", "Bwd Packet Length Std"),
    Feature("flow_bytes_per_s", "Payload bytes per second (recomputed)", None),
    Feature("flow_packets_per_s", "Packets per second (recomputed)", None),
    Feature("flow_iat_mean", "Mean inter-arrival time (s)", "Flow IAT Mean", MICROSECONDS),
    Feature("flow_iat_std", "Inter-arrival time std (s)", "Flow IAT Std", MICROSECONDS),
    Feature("flow_iat_max", "Longest inter-arrival time (s)", "Flow IAT Max", MICROSECONDS),
    Feature("flow_iat_min", "Shortest inter-arrival time (s)", "Flow IAT Min", MICROSECONDS),
    Feature("fwd_iat_total", "Forward inter-arrival total (s)", "Fwd IAT Total", MICROSECONDS),
    Feature("fwd_iat_mean", "Forward inter-arrival mean (s)", "Fwd IAT Mean", MICROSECONDS),
    Feature("bwd_iat_total", "Backward inter-arrival total (s)", "Bwd IAT Total", MICROSECONDS),
    Feature("bwd_iat_mean", "Backward inter-arrival mean (s)", "Bwd IAT Mean", MICROSECONDS),
    Feature("fwd_psh_flags", "Forward packets with PSH", "Fwd PSH Flags"),
    Feature("fin_flag_count", "Packets with FIN", "FIN Flag Count"),
    Feature("syn_flag_count", "Packets with SYN", "SYN Flag Count"),
    Feature("rst_flag_count", "Packets with RST", "RST Flag Count"),
    Feature("psh_flag_count", "Packets with PSH", "PSH Flag Count"),
    Feature("ack_flag_count", "Packets with ACK", "ACK Flag Count"),
    Feature("urg_flag_count", "Packets with URG", "URG Flag Count"),
    Feature("init_win_bytes_fwd", "First forward TCP window (-1: none)", "Init_Win_bytes_forward"),
    Feature(
        "init_win_bytes_bwd", "First backward TCP window (-1: none)", "Init_Win_bytes_backward"
    ),
    Feature("pkt_len_mean", "Mean packet size (bytes)", "Packet Length Mean"),
    Feature("pkt_len_std", "Packet size std (bytes)", "Packet Length Std"),
    Feature("down_up_ratio", "Backward/forward packet ratio", "Down/Up Ratio"),
    Feature("active_mean", "Mean active period (s)", "Active Mean", MICROSECONDS),
    Feature("idle_mean", "Mean idle period (s)", "Idle Mean", MICROSECONDS),
)

FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURES)
CIC_COLUMNS: tuple[str, ...] = tuple(f.cic_column for f in FEATURES if f.cic_column)


def _add_rates(frame: pd.DataFrame) -> pd.DataFrame:
    duration = frame["flow_duration_s"]
    positive = duration > 0
    safe = duration.where(positive, 1.0)
    total_bytes = frame["fwd_bytes"] + frame["bwd_bytes"]
    total_packets = frame["fwd_packets"] + frame["bwd_packets"]
    frame["flow_bytes_per_s"] = (total_bytes / safe).where(positive, 0.0)
    frame["flow_packets_per_s"] = (total_packets / safe).where(positive, 0.0)
    return frame


def _finalise(frame: pd.DataFrame) -> pd.DataFrame:
    frame = _add_rates(frame)
    values = frame[list(FEATURE_NAMES)].astype("float64")
    return values.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def from_cic(frame: pd.DataFrame) -> pd.DataFrame:
    """Offline path: CICFlowMeter columns (names already stripped) -> feature frame."""
    out = pd.DataFrame(index=frame.index)
    for feature in FEATURES:
        if feature.cic_column is not None:
            out[feature.name] = pd.to_numeric(frame[feature.cic_column], errors="coerce") * (
                feature.scale
            )
    return _finalise(out)


def from_records(records: Iterable[Mapping[str, float]]) -> pd.DataFrame:
    """Live path: flow-builder dicts keyed by FEATURE_NAMES -> feature frame.

    Rate fields are optional and ignored (they are recomputed); any other
    missing feature is an error, so a broken producer fails loudly.
    """
    raw = pd.DataFrame.from_records(list(records))
    required = [f.name for f in FEATURES if f.cic_column is not None]
    missing = [name for name in required if name not in raw.columns]
    if missing:
        raise ValueError(f"flow records are missing features: {missing}")
    return _finalise(raw[required].copy())
