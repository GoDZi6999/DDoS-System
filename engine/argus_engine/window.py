"""Sliding-window behaviour across flows.

Per-flow features cannot see patterns that only exist across many flows: a
port scan is one source touching many ports, a DDoS is many sources hitting
one destination. This window (default 10 s) tracks those aggregates for the
risk engine and drives the explicit port-scan rule, which covers the
classifier's weakest class (see docs/ML_METHODOLOGY.md).
"""

from collections import Counter, defaultdict, deque
from dataclasses import dataclass

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
