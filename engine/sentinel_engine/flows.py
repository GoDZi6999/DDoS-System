"""Bidirectional flow builder computing ArgusAI's 37 flow features.

Definitions follow CICFlowMeter (which produced the training data) so live
flows are comparable with CIC-IDS2017:

- a flow is a 5-tuple conversation; "forward" is the direction of its first
  packet (the initiator);
- packet lengths are transport payload bytes; standard deviations are sample
  standard deviations (n-1), 0 below two values;
- inter-arrival times (IAT) are taken over all packets (flow IAT) and per
  direction; fwd/bwd IAT totals are the span between first and last packet
  in that direction;
- flag counts include both directions; `fwd_psh_flags` only forward packets;
- initial windows are the TCP window of the first packet per direction
  (-1 when there is none);
- a gap longer than ACTIVITY_GAP_S (CICFlowMeter's activity timeout, 5 s)
  separates active periods; active/idle means are 0 for flows without such
  a gap;
- a flow ends on RST, after FIN in both directions, or FLOW_TIMEOUT_S after
  its first packet (CICFlowMeter's flow timeout, 120 s). Silence alone does
  not end a flow, as in CICFlowMeter: a connection that pauses for 30 s stays
  one flow with an idle period, which is what the model was trained on.

Holding flows for up to 120 s delays the finished record, so the table also
emits one early *preview* of each flow still open PREVIEW_AFTER_S after its
first packet (`"preview": True`). Previews feed the engine's cross-flow
rules (scans, floods, beacons), which only need to know a flow exists, and
are never classified: the model only sees finished flows. The finished
record of a previewed flow carries `"previewed": True`.

Exact equivalence with CICFlowMeter still has to be validated on a sample
capture (see docs/ML_METHODOLOGY.md, threats to validity).
"""

import heapq
import math
from dataclasses import dataclass, field

from sentinel_engine.packets import Packet

FLOW_TIMEOUT_S = 120.0
ACTIVITY_GAP_S = 5.0
PREVIEW_AFTER_S = 5.0
# Open flows are held for up to FLOW_TIMEOUT_S, so a flood of spoofed SYNs
# would grow the table without bound. Past this many, the flows silent the
# longest are finished early (CICFlowMeter has no such cap).
MAX_FLOWS = 100_000

FlowKey = tuple[tuple[str, int], tuple[str, int], str]


@dataclass
class RunningStats:
    """Welford's online mean/variance with min, max and total."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0
    total: float = 0.0
    low: float = math.inf
    high: float = -math.inf

    def add(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (value - self.mean)
        self.total += value
        self.low = min(self.low, value)
        self.high = max(self.high, value)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    @property
    def minimum(self) -> float:
        return self.low if self.n else 0.0

    @property
    def maximum(self) -> float:
        return self.high if self.n else 0.0


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    start: float
    last: float
    fwd_len: RunningStats = field(default_factory=RunningStats)
    bwd_len: RunningStats = field(default_factory=RunningStats)
    all_len: RunningStats = field(default_factory=RunningStats)
    flow_iat: RunningStats = field(default_factory=RunningStats)
    fwd_iat: RunningStats = field(default_factory=RunningStats)
    bwd_iat: RunningStats = field(default_factory=RunningStats)
    last_fwd: float | None = None
    last_bwd: float | None = None
    flags: dict[str, int] = field(default_factory=lambda: dict.fromkeys("FSRPAU", 0))
    fwd_psh: int = 0
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    fin_fwd: bool = False
    fin_bwd: bool = False
    reset: bool = False
    previewed: bool = False
    active: RunningStats = field(default_factory=RunningStats)
    idle: RunningStats = field(default_factory=RunningStats)
    active_start: float = 0.0

    @classmethod
    def open(cls, p: Packet) -> "Flow":
        flow = cls(p.src, p.dst, p.sport, p.dport, p.proto, start=p.ts, last=p.ts)
        flow.active_start = p.ts
        flow._record(p, forward=True, first=True)
        return flow

    def is_forward(self, p: Packet) -> bool:
        return p.src == self.src and p.sport == self.sport

    def add(self, p: Packet) -> None:
        self._record(p, forward=self.is_forward(p), first=False)

    def _record(self, p: Packet, forward: bool, first: bool) -> None:
        if not first:
            gap = p.ts - self.last
            self.flow_iat.add(gap)
            if gap > ACTIVITY_GAP_S:
                if self.last > self.active_start:
                    self.active.add(self.last - self.active_start)
                self.idle.add(gap)
                self.active_start = p.ts
            self.last = p.ts
        self.all_len.add(p.payload)
        if forward:
            if self.last_fwd is not None:
                self.fwd_iat.add(p.ts - self.last_fwd)
            self.last_fwd = p.ts
            self.fwd_len.add(p.payload)
            if self.init_win_fwd < 0 and p.window is not None:
                self.init_win_fwd = p.window
            if "P" in p.flags:
                self.fwd_psh += 1
            self.fin_fwd |= "F" in p.flags
        else:
            if self.last_bwd is not None:
                self.bwd_iat.add(p.ts - self.last_bwd)
            self.last_bwd = p.ts
            self.bwd_len.add(p.payload)
            if self.init_win_bwd < 0 and p.window is not None:
                self.init_win_bwd = p.window
            self.fin_bwd |= "F" in p.flags
        for letter in p.flags:
            if letter in self.flags:
                self.flags[letter] += 1
        self.reset |= "R" in p.flags

    @property
    def finished(self) -> bool:
        return self.reset or (self.fin_fwd and self.fin_bwd)

    def features(self) -> dict[str, float]:
        """The 37 model features (rates are recomputed by sentinel_ml.features)."""
        active, idle = self.active, self.idle
        active_mean = idle_mean = 0.0
        if idle.n:
            # Close the final active period, as CICFlowMeter does at flow end.
            tail = RunningStats(**vars(active))
            if self.last > self.active_start:
                tail.add(self.last - self.active_start)
            active_mean, idle_mean = tail.mean, idle.mean
        fwd, bwd = self.fwd_len, self.bwd_len
        return {
            "flow_duration_s": self.last - self.start,
            "fwd_packets": fwd.n,
            "bwd_packets": bwd.n,
            "fwd_bytes": fwd.total,
            "bwd_bytes": bwd.total,
            "fwd_pkt_len_max": fwd.maximum,
            "fwd_pkt_len_min": fwd.minimum,
            "fwd_pkt_len_mean": fwd.mean,
            "fwd_pkt_len_std": fwd.std,
            "bwd_pkt_len_max": bwd.maximum,
            "bwd_pkt_len_min": bwd.minimum,
            "bwd_pkt_len_mean": bwd.mean,
            "bwd_pkt_len_std": bwd.std,
            "flow_iat_mean": self.flow_iat.mean,
            "flow_iat_std": self.flow_iat.std,
            "flow_iat_max": self.flow_iat.maximum,
            "flow_iat_min": self.flow_iat.minimum,
            "fwd_iat_total": self.fwd_iat.total,
            "fwd_iat_mean": self.fwd_iat.mean,
            "bwd_iat_total": self.bwd_iat.total,
            "bwd_iat_mean": self.bwd_iat.mean,
            "fwd_psh_flags": self.fwd_psh,
            "fin_flag_count": self.flags["F"],
            "syn_flag_count": self.flags["S"],
            "rst_flag_count": self.flags["R"],
            "psh_flag_count": self.flags["P"],
            "ack_flag_count": self.flags["A"],
            "urg_flag_count": self.flags["U"],
            "init_win_bytes_fwd": self.init_win_fwd,
            "init_win_bytes_bwd": self.init_win_bwd,
            "pkt_len_mean": self.all_len.mean,
            "pkt_len_std": self.all_len.std,
            "down_up_ratio": bwd.n // fwd.n if fwd.n else 0,  # integer, like CICFlowMeter
            "active_mean": active_mean,
            "idle_mean": idle_mean,
        }

    def record(self) -> dict:
        """Flow metadata + features, the unit the engine classifies."""
        duration = self.last - self.start
        packets = self.fwd_len.n + self.bwd_len.n
        payload = self.fwd_len.total + self.bwd_len.total
        return {
            "src_ip": self.src,
            "dst_ip": self.dst,
            "src_port": self.sport,
            "dst_port": self.dport,
            "protocol": self.proto,
            "start": self.start,
            "end": self.last,
            "packet_count": packets,
            "byte_count": int(payload),
            "duration": duration,
            "features": self.features(),
            "previewed": self.previewed,
        }

    def preview(self) -> dict:
        """The flow so far, for the cross-flow rules; marks it previewed."""
        self.previewed = True
        return self.record() | {"preview": True, "previewed": False}


def flow_key(p: Packet) -> FlowKey:
    a, b = (p.src, p.sport), (p.dst, p.dport)
    return (a, b, p.proto) if a <= b else (b, a, p.proto)


class FlowTable:
    def __init__(
        self,
        flow_timeout: float = FLOW_TIMEOUT_S,
        preview_after: float | None = PREVIEW_AFTER_S,
        max_flows: int = MAX_FLOWS,
    ) -> None:
        self.flow_timeout = flow_timeout
        self.preview_after = preview_after
        self.max_flows = max_flows
        self.flows: dict[FlowKey, Flow] = {}
        self._expired: list[Flow] = []

    def __len__(self) -> int:
        return len(self.flows)

    def add(self, p: Packet) -> None:
        key = flow_key(p)
        flow = self.flows.get(key)
        if flow is not None and p.ts - flow.start > self.flow_timeout:
            # Like CICFlowMeter, a packet past the timeout ends the flow and
            # opens the next one, whenever the table is next swept.
            self._expired.append(flow)
            flow = None
        if flow is None or (flow.finished and flow.last < p.ts - 1.0):
            self.flows[key] = Flow.open(p)
        else:
            flow.add(p)

    def sweep(self, now: float) -> list[dict]:
        """Remove and return flows that are finished or timed out, plus
        previews of flows open longer than `preview_after`.

        Finished flows wait for one sweep so the trailing ACK of a FIN
        exchange joins its flow instead of opening a new one.
        """
        done = [
            key
            for key, flow in self.flows.items()
            if (flow.finished and now - flow.last >= 0.5) or now - flow.start >= self.flow_timeout
        ]
        records = [flow.record() for flow in self._expired]
        self._expired = []
        records += [self.flows.pop(key).record() for key in done]
        overflow = len(self.flows) - self.max_flows
        if overflow > 0:
            stale = heapq.nsmallest(overflow, self.flows, key=lambda k: self.flows[k].last)
            records += [self.flows.pop(key).record() for key in stale]
        if self.preview_after is not None:
            records += [
                flow.preview()
                for flow in self.flows.values()
                if not flow.previewed and now - flow.start >= self.preview_after
            ]
        return records

    def flush(self) -> list[dict]:
        records = [flow.record() for flow in self._expired]
        records += [flow.record() for flow in self.flows.values()]
        self._expired = []
        self.flows.clear()
        return records
