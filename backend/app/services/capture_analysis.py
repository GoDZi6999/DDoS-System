"""Offline analysis of uploaded packet captures, and packet evidence for alerts.

Synchronous and CPU-bound (Scapy parsing, the model): the capture worker and
the API call these from a thread. sentinel_engine (engine/) and Scapy are
imported lazily, like sentinel_ml in app/services/detector.py.

- `analyze` replays a capture through the real-time engine, the same code that
  handles live traffic, at full speed. Timestamps are shifted so the capture
  ends at analysis time, which keeps its flows and alerts inside the
  dashboard's time windows. Detections are tagged with the capture's id and,
  if requested, published to the alert engine like any other detection.
- `carve` cuts the packets of given flows out of a capture, so an alert's
  traffic can be opened in Wireshark.
"""

import dataclasses
import io
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap",  # microsecond, little-endian
    b"\xa1\xb2\xc3\xd4": "pcap",  # microsecond, big-endian
    b"\x4d\x3c\xb2\xa1": "pcap",  # nanosecond, little-endian
    b"\xa1\xb2\x3c\x4d": "pcap",  # nanosecond, big-endian
    b"\x0a\x0d\x0d\x0a": "pcapng",  # section header block
}
BENIGN = "benign"
TOP_N = 5
# Packets around each flow's recorded start and end that still belong to it.
CARVE_SLACK_S = 1.0


class CaptureError(Exception):
    """The file cannot be analysed (corrupt, truncated, no IP traffic)."""


def file_format(head: bytes) -> str | None:
    """'pcap' or 'pcapng' from the first four bytes, else None."""
    return PCAP_MAGIC.get(head[:4])


def _packets(path: Path) -> Iterator[Any]:
    """Engine packets (IP only) in file order, original timestamps."""
    from sentinel_engine.sources import pcap_source

    try:
        yield from pcap_source(path, retime=False, realtime=False)
    except CaptureError:
        raise
    except Exception as exc:  # Scapy raises assorted errors on damaged files
        raise CaptureError(f"Could not read the capture: {exc}") from exc


def _span(path: Path) -> tuple[int, float, float]:
    """(IP packets, first timestamp, last timestamp)."""
    count, first, last = 0, None, None
    for packet in _packets(path):
        count += 1
        first = packet.ts if first is None else min(first, packet.ts)
        last = packet.ts if last is None else max(last, packet.ts)
    if first is None or last is None:
        raise CaptureError("The capture contains no IPv4 or IPv6 packets")
    return count, first, last


class _CapturePublisher:
    """Engine output for one capture: tags detections with the capture id,
    tallies the report and optionally forwards them to the alert engine.
    Live traffic ticks are dropped; a replay at full speed would garble the
    dashboard's live chart."""

    def __init__(self, capture_id: int, forward=None) -> None:
        self.capture_id = capture_id
        self.forward = forward
        self.flows = 0
        self.labels: Counter[str] = Counter()
        self.sources: Counter[str] = Counter()
        self.targets: Counter[str] = Counter()
        self.max_risk = 0

    def detections(self, items: list[dict]) -> None:
        for item in items:
            item["capture_id"] = self.capture_id
            self.flows += 1
            if item["label"] == BENIGN:
                continue
            self.labels[item["label"]] += 1
            self.sources[item["src_ip"]] += 1
            port = item["dst_port"]
            self.targets[f"{item['dst_ip']}:{port}" if port else item["dst_ip"]] += 1
            self.max_risk = max(self.max_risk, int(item["risk_score"]))
        if self.forward is not None:
            self.forward.detections(items)

    def event(self, event_type: str, data: dict) -> None:
        pass

    def detection_config(self) -> dict | None:
        return self.forward.detection_config() if self.forward is not None else None


@dataclass
class Analysis:
    time_offset: float
    report: dict[str, Any]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat()


def analyze(
    path: Path,
    capture_id: int,
    predictor,
    forward=None,
    now: float | None = None,
) -> Analysis:
    """Run the capture through the engine. `forward` is an engine publisher
    (sentinel_engine.publisher.RedisPublisher) to raise alerts, or None to
    only report."""
    from sentinel_engine.pipeline import Engine

    started = time.monotonic()
    packets, first, last = _span(path)
    offset = (now if now is not None else time.time()) - last

    def shifted() -> Iterator[Any]:
        for packet in _packets(path):
            yield dataclasses.replace(packet, ts=packet.ts + offset)

    publisher = _CapturePublisher(capture_id, forward)
    Engine(predictor, publisher, "pcap").run(shifted())
    if forward is not None and getattr(forward, "pending", None):
        raise CaptureError("The alert queue (Redis) is unavailable; detections were not sent")

    attacks = sum(publisher.labels.values())
    return Analysis(
        time_offset=offset,
        report={
            "packets": packets,
            "flows": publisher.flows,
            "attacks": attacks,
            "attack_types": dict(publisher.labels.most_common()),
            "top_sources": [
                {"ip": ip, "detections": n} for ip, n in publisher.sources.most_common(TOP_N)
            ],
            "top_targets": [
                {"target": t, "detections": n} for t, n in publisher.targets.most_common(TOP_N)
            ],
            "max_risk": publisher.max_risk,
            "first_packet_at": _iso(first),
            "last_packet_at": _iso(last),
            "duration_s": round(last - first, 3),
            "analysis_s": round(time.monotonic() - started, 2),
            "model_version": "{name}-{version}".format(**predictor.bundle.metadata),
        },
    )


# --- evidence ---------------------------------------------------------------


@dataclass(frozen=True)
class FlowKey:
    """One flow of an alert, in the capture's original time."""

    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    start: float
    end: float


def _merge(index: dict, key, start: float, end: float) -> None:
    if key in index:
        start, end = min(start, index[key][0]), max(end, index[key][1])
    index[key] = (start, end)


class _FlowIndex:
    """Which packets belong to a set of flows. A port of 0 matches any port:
    rule detections (port scan, beaconing) span many ports, and ICMP has none."""

    def __init__(self, flows: Iterable[FlowKey]) -> None:
        self.exact: dict[tuple, tuple[float, float]] = {}
        self.pairs: dict[tuple, tuple[float, float]] = {}
        self.partial: dict[tuple, list[FlowKey]] = {}
        for flow in flows:
            start, end = flow.start - CARVE_SLACK_S, flow.end + CARVE_SLACK_S
            pair = (frozenset({flow.src, flow.dst}), flow.protocol)
            if not flow.sport and not flow.dport:
                _merge(self.pairs, pair, start, end)
            elif not flow.sport or not flow.dport:
                widened = dataclasses.replace(flow, start=start, end=end)
                self.partial.setdefault(pair, []).append(widened)
            else:
                ends = frozenset({(flow.src, flow.sport), (flow.dst, flow.dport)})
                _merge(self.exact, (ends, flow.protocol), start, end)

    def matches(self, packet) -> bool:
        ts = packet.ts
        window = self.exact.get(
            (frozenset({(packet.src, packet.sport), (packet.dst, packet.dport)}), packet.proto)
        )
        if window is not None and window[0] <= ts <= window[1]:
            return True
        pair = (frozenset({packet.src, packet.dst}), packet.proto)
        window = self.pairs.get(pair)
        if window is not None and window[0] <= ts <= window[1]:
            return True
        for flow in self.partial.get(pair, ()):
            if not flow.start <= ts <= flow.end:
                continue
            for src, sport, dport in (
                (packet.src, packet.sport, packet.dport),
                (packet.dst, packet.dport, packet.sport),
            ):
                if src == flow.src and flow.sport in (0, sport) and flow.dport in (0, dport):
                    return True
        return False


def carve(path: Path, flows: Iterable[FlowKey], max_packets: int) -> tuple[bytes, int, bool]:
    """Packets of `flows` (either direction) as a pcap file.

    Returns (file bytes, packets written, truncated)."""
    import scapy.layers.all  # noqa: F401  (link-layer decoders, e.g. Ethernet)
    from scapy.utils import PcapReader, PcapWriter
    from sentinel_engine.packets import from_scapy

    index = _FlowIndex(flows)
    out = io.BytesIO()
    written, truncated = 0, False
    try:
        with PcapReader(str(path)) as reader:
            writer = None
            for raw in reader:
                packet = from_scapy(raw)
                if packet is None or not index.matches(packet):
                    continue
                if written >= max_packets:
                    truncated = True
                    break
                if writer is None:
                    # pcapng readers have no single link type; the writer then takes the packet's.
                    linktype = getattr(reader, "linktype", None)
                    writer = PcapWriter(out, linktype=linktype, sync=True)
                writer.write(raw)
                written += 1
    except Exception as exc:
        raise CaptureError(f"Could not read the capture: {exc}") from exc
    return out.getvalue(), written, truncated
