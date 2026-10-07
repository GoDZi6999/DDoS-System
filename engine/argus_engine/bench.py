"""Engine benchmark: classification + explanation + risk, in process.

    python -m argus_engine bench [--flows 3000] [--json]

Runs the real model bundle on flows sampled from the held-out profiles
(data/samples/flow_profiles.csv), through Engine.handle_flows, which is what
every simulator tick, PCAP batch or live capture batch goes through. No Redis
is needed: detections go to an in-memory publisher. Attack flows cost more
than benign ones because each gets a SHAP explanation.
"""

import json
import os
import platform
import time
from pathlib import Path

import numpy as np
from argus_ml.inference import Predictor

from argus_engine.pipeline import Engine
from argus_engine.publisher import MemoryPublisher
from argus_engine.simulator import Simulator


def _records(sim: Simulator, label: str, count: int, now: float) -> list[dict]:
    return [
        sim._flow(label, f"10.10.{i % 200}.{i % 250 + 1}", f"10.20.0.{i % 20 + 1}", 80, now)
        for i in range(count)
    ]


def _percentiles(samples_ms: list[float]) -> dict[str, float]:
    ordered = np.sort(np.asarray(samples_ms))
    return {
        "p50_ms": round(float(np.percentile(ordered, 50)), 2),
        "p95_ms": round(float(np.percentile(ordered, 95)), 2),
        "p99_ms": round(float(np.percentile(ordered, 99)), 2),
    }


def latency(engine: Engine, sim: Simulator, label: str, samples: int) -> dict:
    """One flow per call: the worst case for per-flow overhead."""
    timings = []
    for record in _records(sim, label, samples, time.time()):
        start = time.perf_counter()
        engine.handle_flows([record], time.time())
        timings.append((time.perf_counter() - start) * 1000)
    return {"label": label, "samples": samples, **_percentiles(timings)}


def throughput(engine: Engine, sim: Simulator, attack_share: float, flows: int, batch: int) -> dict:
    """Batches the size of a busy one-second tick."""
    attacks = int(flows * attack_share)
    records = _records(sim, "ddos", attacks, time.time()) + _records(
        sim, "benign", flows - attacks, time.time()
    )
    sim.rng.shuffle(records)
    start = time.perf_counter()
    for offset in range(0, len(records), batch):
        engine.handle_flows(records[offset : offset + batch], time.time())
    elapsed = time.perf_counter() - start
    return {
        "attack_share": attack_share,
        "flows": flows,
        "batch": batch,
        "flows_per_s": round(flows / elapsed),
    }


def run(bundle: str, profiles: Path, flows: int, samples: int, batch: int) -> dict:
    predictor = Predictor.from_bundle(bundle)
    sim = Simulator.from_csv(profiles, realtime=False)
    engine = Engine(predictor, MemoryPublisher(), "sim")
    engine.handle_flows(_records(sim, "ddos", 50, time.time()), time.time())  # warm-up
    return {
        "model": engine.model_version,
        "machine": f"{platform.processor() or platform.machine()}, "
        f"{os.cpu_count()} CPUs, Python {platform.python_version()}",
        "latency": [latency(engine, sim, label, samples) for label in ("benign", "ddos")],
        "throughput": [throughput(engine, sim, share, flows, batch) for share in (0.0, 0.1, 1.0)],
    }


def report(result: dict) -> str:
    lines = [
        f"Model {result['model']} on {result['machine']}",
        "",
        "Per-flow latency (one flow per call)",
        "| Flow | p50 | p95 | p99 |",
        "|---|---:|---:|---:|",
    ]
    for row in result["latency"]:
        lines.append(
            f"| {row['label']} | {row['p50_ms']} ms | {row['p95_ms']} ms | {row['p99_ms']} ms |"
        )
    lines += ["", f"Throughput (batches of {result['throughput'][0]['batch']} flows)"]
    lines += ["| Attack share | Flows/s |", "|---|---:|"]
    for row in result["throughput"]:
        lines.append(f"| {row['attack_share']:.0%} | {row['flows_per_s']:,} |")
    return "\n".join(lines)


def main(bundle: str, profiles: Path, flows: int, as_json: bool) -> int:
    result = run(bundle, profiles, flows=flows, samples=300, batch=100)
    print(json.dumps(result, indent=2) if as_json else report(result))
    return 0
