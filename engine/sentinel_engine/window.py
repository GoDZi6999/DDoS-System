"""Sliding-window behaviour across flows.

Per-flow features cannot see patterns that only exist across many flows: a
port scan is one source touching many ports, a DDoS is many sources hitting
one destination. This window (default 10 s) tracks those aggregates for the
risk engine and drives the explicit port-scan rule, which covers the
classifier's weakest class (see docs/ML_METHODOLOGY.md). A longer per-pair
history (BeaconTracker) drives the botnet beaconing rule.
"""

from collections import Counter, defaultdict, deque
from dataclasses import dataclass

import numpy as np

WINDOW_S = 10.0
PORTSCAN_MIN_PORTS = 20


@dataclass(frozen=True)
class FlowSeen:
    ts: float
    src: str
    dst: str
    dport: int
    packets: int


class WindowStats:
    def __init__(self, window_s: float = WINDOW_S) -> None:
        self.window_s = window_s
        self._flows: deque[FlowSeen] = deque()
        self._ports: dict[tuple[str, str], Counter[int]] = defaultdict(Counter)
        self._sources: dict[str, Counter[str]] = defaultdict(Counter)
        self._dst_packets: Counter[str] = Counter()
        self._dst_flows: Counter[str] = Counter()

    def add(self, record: dict) -> None:
        seen = FlowSeen(
            record["end"],
            record["src_ip"],
            record["dst_ip"],
            record["dst_port"],
            record["packet_count"],
        )
        self._flows.append(seen)
        self._ports[(seen.src, seen.dst)][seen.dport] += 1
        self._sources[seen.dst][seen.src] += 1
        self._dst_packets[seen.dst] += seen.packets
        self._dst_flows[seen.dst] += 1

    def evict(self, now: float) -> None:
        while self._flows and self._flows[0].ts < now - self.window_s:
            old = self._flows.popleft()
            ports = self._ports[(old.src, old.dst)]
            ports[old.dport] -= 1
            if ports[old.dport] <= 0:
                del ports[old.dport]
            if not ports:
                del self._ports[(old.src, old.dst)]
            sources = self._sources[old.dst]
            sources[old.src] -= 1
            if sources[old.src] <= 0:
                del sources[old.src]
            if not sources:
                del self._sources[old.dst]
            self._dst_packets[old.dst] -= old.packets
            self._dst_flows[old.dst] -= 1
            if self._dst_flows[old.dst] <= 0:
                del self._dst_flows[old.dst], self._dst_packets[old.dst]

    def distinct_ports(self, src: str, dst: str) -> int:
        return len(self._ports.get((src, dst), ()))

    def distinct_sources(self, dst: str) -> int:
        return len(self._sources.get(dst, ()))

    def dst_packet_rate(self, dst: str) -> float:
        return self._dst_packets.get(dst, 0) / self.window_s

    def dst_flow_rate(self, dst: str) -> float:
        return self._dst_flows.get(dst, 0) / self.window_s

    def scanners(self, min_ports: int = PORTSCAN_MIN_PORTS) -> list[tuple[str, str, int]]:
        """(source, destination, distinct ports) pairs at or above the threshold."""
        return [(s, d, len(p)) for (s, d), p in self._ports.items() if len(p) >= min_ports]

    def context(self, record: dict) -> dict[str, float]:
        """Window features attached to a detection (shown with its explanation)."""
        src, dst = record["src_ip"], record["dst_ip"]
        return {
            "window_distinct_ports_src_to_dst": float(self.distinct_ports(src, dst)),
            "window_distinct_sources_to_dst": float(self.distinct_sources(dst)),
            "window_flows_per_s_to_dst": self.dst_flow_rate(dst),
            "window_packets_per_s_to_dst": self.dst_packet_rate(dst),
        }


# Beaconing: a bot polls its command-and-control server at a steady rhythm,
# so one (source, destination, port) sees many flows at near-constant
# intervals. Per-flow statistics cannot see a rhythm, and botnet is the
# classifier's least stable class (docs/ML_METHODOLOGY.md, section 9).
BEACON_WINDOW_S = 300.0
BEACON_MIN_FLOWS = 8
BEACON_MAX_JITTER = 0.2  # coefficient of variation of the intervals
# Bots poll every few seconds to minutes; faster rhythms are retries, bursts
# or an application's own chatter (e.g. several HTTPS requests per second).
BEACON_MIN_INTERVAL_S = 1.0
BEACON_HISTORY = 256  # latest flows kept per pair, so a flood cannot grow memory


@dataclass(frozen=True)
class Beacon:
    src: str
    dst: str
    dport: int
    flows: int
    interval_s: float
    jitter: float


class BeaconTracker:
    """Flow arrival times per (source, destination, port) over a long window.

    Human and application traffic arrives irregularly (interval jitter around
    1 for Poisson-like arrivals); a beacon's intervals vary by a few percent.
    Legitimate periodic traffic (health checks, NTP, telemetry) looks the same,
    so this flags a pattern worth a look, not proof of compromise.
    """

    def __init__(
        self,
        window_s: float = BEACON_WINDOW_S,
        min_flows: int = BEACON_MIN_FLOWS,
        max_jitter: float = BEACON_MAX_JITTER,
        min_interval_s: float = BEACON_MIN_INTERVAL_S,
    ) -> None:
        self.window_s = window_s
        self.min_flows = min_flows
        self.max_jitter = max_jitter
        self.min_interval_s = min_interval_s
        self._times: dict[tuple[str, str, int], deque[float]] = defaultdict(
            lambda: deque(maxlen=BEACON_HISTORY)
        )

    def add(self, record: dict) -> None:
        key = (record["src_ip"], record["dst_ip"], int(record["dst_port"]))
        self._times[key].append(float(record.get("start", record["end"])))

    def evict(self, now: float) -> None:
        for key in list(self._times):
            times = self._times[key]
            while times and times[0] < now - self.window_s:
                times.popleft()
            if not times:
                del self._times[key]

    def beacons(self) -> list[Beacon]:
        found = []
        for (src, dst, dport), times in self._times.items():
            if len(times) < self.min_flows:
                continue
            intervals = np.diff(np.sort(np.fromiter(times, dtype=float)))
            mean = float(intervals.mean())
            if mean < self.min_interval_s:
                continue
            jitter = float(intervals.std() / mean)
            if jitter <= self.max_jitter:
                found.append(Beacon(src, dst, dport, len(times), mean, jitter))
        return found
