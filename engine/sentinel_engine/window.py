"""Sliding-window behaviour across flows.

Per-flow features cannot see patterns that only exist across many flows: a
port scan is one source touching many ports, a DDoS is many sources hitting
one destination. This window (default 10 s) tracks those aggregates for the
risk engine and drives the explicit port-scan rule, which covers the
classifier's weakest class (see docs/ML_METHODOLOGY.md). A longer per-pair
history (BeaconTracker) drives the botnet beaconing rule, and new flows per
target (FloodTracker) drive the flood rule.
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


# Floods: the classifier learned CIC-IDS2017's floods, whose captures mostly
# miss each connection's handshake, so a flood with full handshakes or a plain
# SYN flood looks benign to it (docs/ML_METHODOLOGY.md, section 7). This rule
# counts new flows per target instead, which does not depend on flow shape.
FLOOD_WINDOW_S = 10.0
# Half-open TCP flows (SYN, then no ACK from the client) to one service.
FLOOD_MIN_HALF_OPEN_PER_S = 20.0
# Completed connections (or UDP flows) to one target...
FLOOD_MIN_FLOWS_PER_S = 50.0
# ... counted only from sources that each opened this many in the window, so a
# busy server's ordinary clients are not counted (or labelled) with the flood.
FLOOD_MIN_FLOWS_PER_SOURCE = 20
# A flood from at least this many sources is distributed (ddos), else dos.
FLOOD_DDOS_MIN_SOURCES = 3
FLOOD_HISTORY = 100_000  # flows kept per target, so memory stays bounded


def flood_target(record: dict) -> tuple[str, int, str]:
    """TCP floods hit one service; UDP floods often spray ports, so UDP and
    other protocols are grouped by host (port 0)."""
    protocol = record["protocol"]
    port = int(record["dst_port"]) if protocol == "tcp" else 0
    return record["dst_ip"], port, protocol


def is_half_open(record: dict) -> bool:
    """A TCP flow that never completed its handshake: a SYN, at most the
    server's SYN-ACK in return (one ACK flag), and no client data."""
    features = record["features"]
    return (
        record["protocol"] == "tcp"
        and features.get("syn_flag_count", 0) >= 1
        and features.get("ack_flag_count", 0) <= 1
        and features.get("fwd_bytes", 0) == 0
    )


@dataclass(frozen=True)
class Flood:
    dst: str
    dport: int
    protocol: str
    kind: str  # syn | connection
    flows: int  # flows counted towards the flood in the window
    flows_per_s: float
    sources: int
    top_source: str
    label: str  # ddos | dos
    heavy_sources: frozenset[str] = frozenset()  # connection floods only

    def includes(self, record: dict) -> bool:
        """Whether a flow to this target is part of the flood."""
        if self.kind == "syn":
            return is_half_open(record)
        return not is_half_open(record) and record["src_ip"] in self.heavy_sources


class FloodTracker:
    """New flows per target over a short window, split into half-open and
    other flows, with per-source counts.

    Thresholds are absolute, so a server that legitimately takes more than
    FLOOD_MIN_FLOWS_PER_S connections per second from a few heavy clients
    (a load balancer, a proxy) needs them raised or its sources allowed."""

    def __init__(
        self,
        window_s: float = FLOOD_WINDOW_S,
        min_half_open_per_s: float = FLOOD_MIN_HALF_OPEN_PER_S,
        min_flows_per_s: float = FLOOD_MIN_FLOWS_PER_S,
    ) -> None:
        self.window_s = window_s
        self.min_half_open = min_half_open_per_s * window_s
        self.min_flows = min_flows_per_s * window_s
        self._flows: dict[tuple[str, int, str], deque[tuple[float, str, bool]]] = defaultdict(
            lambda: deque(maxlen=FLOOD_HISTORY)
        )
        self._half_open: dict[tuple[str, int, str], Counter[str]] = defaultdict(Counter)
        self._other: dict[tuple[str, int, str], Counter[str]] = defaultdict(Counter)

    def add(self, record: dict) -> None:
        key = flood_target(record)
        flows = self._flows[key]
        if len(flows) == flows.maxlen:
            self._forget(key, *flows[0])
        half_open = is_half_open(record)
        flows.append((float(record["end"]), record["src_ip"], half_open))
        (self._half_open if half_open else self._other)[key][record["src_ip"]] += 1

    def _forget(self, key, _ts: float, src: str, half_open: bool) -> None:
        counts = (self._half_open if half_open else self._other)[key]
        counts[src] -= 1
        if counts[src] <= 0:
            del counts[src]

    def evict(self, now: float) -> None:
        for key in list(self._flows):
            flows = self._flows[key]
            while flows and flows[0][0] < now - self.window_s:
                self._forget(key, *flows.popleft())
            if not flows:
                del self._flows[key]
                self._half_open.pop(key, None)
                self._other.pop(key, None)

    def floods(self) -> dict[tuple[str, int, str], list[Flood]]:
        found: dict[tuple[str, int, str], list[Flood]] = {}
        for key, half_open in self._half_open.items():
            total = sum(half_open.values())
            if total >= self.min_half_open:
                found.setdefault(key, []).append(self._flood(key, "syn", half_open))
        for key, other in self._other.items():
            heavy = Counter({src: n for src, n in other.items() if n >= FLOOD_MIN_FLOWS_PER_SOURCE})
            if sum(heavy.values()) >= self.min_flows:
                found.setdefault(key, []).append(self._flood(key, "connection", heavy))
        return found

    def _flood(self, key, kind: str, counts: Counter[str]) -> Flood:
        dst, dport, protocol = key
        flows = sum(counts.values())
        return Flood(
            dst=dst,
            dport=dport,
            protocol=protocol,
            kind=kind,
            flows=flows,
            flows_per_s=flows / self.window_s,
            sources=len(counts),
            top_source=counts.most_common(1)[0][0],
            label="ddos" if len(counts) >= FLOOD_DDOS_MIN_SOURCES else "dos",
            heavy_sources=frozenset(counts) if kind == "connection" else frozenset(),
        )
