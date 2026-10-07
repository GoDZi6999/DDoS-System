"""Safe lab traffic simulator. Nothing is sent on any network.

It produces the engine's input directly, along a scenario timeline:

- benign, DDoS, DoS, brute-force, web-attack and botnet traffic as flow
  records whose statistics are *real held-out CIC-IDS2017 flows*
  (data/samples/flow_profiles.csv), with lab addresses assigned here;
- port scans as individual packets (SYN probes answered by RST), which go
  through the real flow builder and the window rule.

Because the attack statistics come from CIC-IDS2017, a demo shows the model
working on traffic like its test set; it is not evidence that the model
generalises to other networks.
"""

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from argus_engine.packets import Packet

SLOT_S = 0.1
CLIENTS = [f"10.10.0.{i}" for i in range(20, 120)]
SERVERS = {"web": ("10.20.0.10", 80), "app": ("10.20.0.11", 8080), "ssh": ("10.20.0.12", 22)}
SCAN_TARGET = "10.20.0.13"


@dataclass(frozen=True)
class Attack:
    label: str  # profile label
    sources: tuple[str, ...]
    target: tuple[str, int]
    start_rate: float  # flows (or probes) per second at phase start
    end_rate: float  # ... and at phase end (linear ramp)


ATTACKS = {
    "ddos": Attack(
        "ddos", tuple(f"198.51.100.{i}" for i in range(1, 255)), SERVERS["web"], 30, 400
    ),
    "dos": Attack("dos", ("203.0.113.66",), SERVERS["web"], 80, 150),
    "bruteforce": Attack("bruteforce", ("203.0.113.77",), SERVERS["ssh"], 10, 20),
    "webattack": Attack("webattack", ("203.0.113.88",), SERVERS["web"], 5, 12),
    "botnet": Attack("botnet", ("10.10.0.66",), ("203.0.113.200", 8080), 2, 4),
    "portscan": Attack("portscan", ("203.0.113.99",), (SCAN_TARGET, 0), 80, 80),
}

# (phase, seconds); "normal" is benign background only.
SCENARIOS: dict[str, list[tuple[str, float]]] = {
    "normal": [("normal", 60)],
    "demo": [
        ("normal", 45),
        ("ddos", 40),
        ("normal", 30),
        ("portscan", 25),
        ("normal", 30),
        ("dos", 30),
        ("normal", 30),
        ("bruteforce", 30),
        ("normal", 30),
        ("webattack", 25),
        ("normal", 30),
        ("botnet", 25),
    ],
    **{name: [(name, 30)] for name in ATTACKS},
}


class Simulator:
    def __init__(
        self,
        profiles: pd.DataFrame,
        seed: int = 0,
        benign_rate: float = 15.0,
        realtime: bool = True,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rng = np.random.default_rng(seed)
        self.benign_rate = benign_rate
        self.realtime = realtime
        self.clock = clock
        self.sleep = sleep
        feature_columns = [c for c in profiles.columns if c != "label"]
        self.profiles = {
            label: group[feature_columns].to_dict(orient="records")
            for label, group in profiles.groupby("label")
        }

    @classmethod
    def from_csv(cls, path: Path, **kwargs) -> "Simulator":
        return cls(pd.read_csv(path), **kwargs)

    def _flow(self, label: str, src: str, dst: str, dport: int, end: float) -> dict:
        rows = self.profiles[label]
        feats = dict(rows[int(self.rng.integers(len(rows)))])
        duration = float(feats["flow_duration_s"])
        return {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": int(self.rng.integers(32768, 61000)),
            "dst_port": dport,
            "protocol": "tcp",
            "start": end - duration,
            "end": end,
            "packet_count": int(feats["fwd_packets"] + feats["bwd_packets"]),
            "byte_count": int(feats["fwd_bytes"] + feats["bwd_bytes"]),
            "duration": duration,
            "features": feats,
        }

    def _benign(self, t: float) -> Iterator[dict]:
        for _ in range(self.rng.poisson(self.benign_rate * SLOT_S)):
            server, port = SERVERS[self.rng.choice(list(SERVERS))]
            yield self._flow("benign", str(self.rng.choice(CLIENTS)), server, port, t)

    def _probe(self, attacker: str, port: int, t: float) -> Iterator[Packet]:
        sport = int(self.rng.integers(32768, 61000))
        yield Packet(t, attacker, SCAN_TARGET, sport, port, "tcp", 0, "S", 1024)
        yield Packet(t + 0.0004, SCAN_TARGET, attacker, port, sport, "tcp", 0, "RA", 0)

    def _phase(self, name: str, start: float, seconds: float) -> Iterator:
        attack = ATTACKS.get(name)
        next_port = 1
        slots = int(seconds / SLOT_S)
        for k in range(slots):
            t = start + k * SLOT_S
            if self.realtime:
                delay = t - self.clock()
                if delay > 0:
                    self.sleep(delay)
            items: list = list(self._benign(t)) if self.benign_rate else []
            if attack is not None:
                rate = attack.start_rate + (attack.end_rate - attack.start_rate) * k / max(slots, 1)
                count = self.rng.poisson(rate * SLOT_S)
                for _ in range(count):
                    src = str(self.rng.choice(attack.sources))
                    if attack.label == "portscan":
                        items.extend(self._probe(src, next_port, t))
                        next_port = next_port % 1024 + 1
                    else:
                        items.append(self._flow(attack.label, src, *attack.target, t))
            items.sort(key=lambda i: i.ts if isinstance(i, Packet) else i["end"])
            yield from items

    def run(self, scenario: str, loop: bool = False, duration: float | None = None) -> Iterator:
        phases = SCENARIOS[scenario]
        start = self.clock()
        t = start
        while True:
            for name, seconds in phases:
                if duration is not None:
                    seconds = min(seconds, start + duration - t)
                    if seconds <= 0:
                        return
                yield from self._phase(name, t, seconds)
                t += seconds
            if not loop:
                return
