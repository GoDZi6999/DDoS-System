#!/usr/bin/env python3
"""Benchmark a running stack (docker compose up -d --wait).

    ADMIN_PASSWORD=... python3 scripts/benchmark_stack.py [--detections 5000] [--trials 3]

Measures, through the public API:
  1. alert-engine ingestion: synthetic detections pushed into the Redis
     stream (`app.cli demo-detections`) until all are stored;
  2. API latency (p50/p95) of the endpoints the dashboard polls;
  3. detection-to-alert latency: a simulated DDoS is injected and the time
     from the creating flow's end (alert first_seen_at) to the alert being
     committed (its `alert.created` history entry) is read from the alert.
     Open DDoS alerts on the simulator's web server are resolved first so
     each trial raises a new alert; run it on a test stack only.

Standard library only. Prints a Markdown report.
"""

import argparse
import json
import os
import statistics
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime

API = os.environ.get("BACKEND_URL", "http://localhost:8000") + "/api/v1"
TARGET = "10.20.0.10"  # the simulator's web server
DEMO_TARGET = "203.0.113.200"  # TEST-NET-3, used only by this benchmark


class Client:
    def __init__(self) -> None:
        body = urllib.parse.urlencode(
            {"username": os.environ.get("ADMIN_USERNAME", "admin"), "password": os.environ["ADMIN_PASSWORD"]}
        ).encode()
        with urllib.request.urlopen(f"{API}/auth/login", body) as response:  # noqa: S310
            self.token = json.load(response)["access_token"]

    def request(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 (fixed local URL)
            f"{API}{path}",
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request) as response:  # noqa: S310
            return json.load(response) if response.status != 204 else None

    def get(self, path: str):
        return self.request("GET", path)


def compose(*args: str) -> None:
    subprocess.run(["docker", "compose", "exec", "-T", *args], check=True, capture_output=True)


def percentiles(samples: list[float]) -> tuple[float, float]:
    ordered = sorted(samples)
    return ordered[len(ordered) // 2], ordered[int(len(ordered) * 0.95) - 1]


def ingestion(client: Client, count: int) -> dict:
    """Queue `count` detections while the alert engine is stopped, then time
    how fast it drains the backlog (from its first stored event to the last),
    so neither the publisher nor container start-up is measured."""
    events = f"/events?ip={DEMO_TARGET}&limit=1"
    subprocess.run(["docker", "compose", "stop", "alert-engine"], check=True, capture_output=True)
    try:
        before = client.get(events)["total"]
        subprocess.run(
            ["docker", "compose", "run", "--rm", "--no-deps", "alert-engine", "python", "-m",
             "app.cli", "demo-detections", "--count", str(count), "--target", DEMO_TARGET],
            check=True, capture_output=True,
        )
    finally:
        subprocess.run(["docker", "compose", "start", "alert-engine"], check=True, capture_output=True)
    deadline = time.monotonic() + 600
    while (stored := client.get(events)["total"]) == before:
        if time.monotonic() > deadline:
            raise TimeoutError("the alert engine did not start storing detections")
        time.sleep(0.05)
    start, first = time.perf_counter(), stored
    while (stored := client.get(events)["total"]) < before + count:
        if time.monotonic() > deadline:
            raise TimeoutError("detections were not all stored within 10 minutes")
        time.sleep(0.05)
    elapsed = time.perf_counter() - start
    return {"count": before + count - first, "seconds": elapsed, "per_s": (before + count - first) / elapsed}


def api_latency(client: Client, requests: int) -> list[dict]:
    alert = client.get("/alerts?limit=1")["items"]
    paths = [
        "/alerts?limit=50",
        "/stats/summary?window=24h",
        "/stats/timeseries?window=24h&bucket=15m",
        "/stats/distribution?window=24h",
        "/events?limit=50",
    ]
    if alert:
        paths.insert(1, f"/alerts/{alert[0]['id']}")
    rows = []
    for path in paths:
        client.get(path)  # warm-up
        timings = []
        for _ in range(requests):
            start = time.perf_counter()
            client.get(path)
            timings.append((time.perf_counter() - start) * 1000)
        p50, p95 = percentiles(timings)
        rows.append({"path": path, "p50_ms": p50, "p95_ms": p95})
    return rows


def resolve_open_alerts(client: Client) -> None:
    """Resolve open DDoS alerts on the target until none reappears for a few
    seconds (the alert engine may still be draining a previous flood, and a
    closed alert never absorbs new detections)."""
    query = f"/alerts?ip={TARGET}&attack_type=ddos&status=NEW&status=INVESTIGATING&status=CONTAINED"
    quiet_since = time.monotonic()
    while time.monotonic() - quiet_since < 4:
        for alert in client.get(query)["items"]:
            if alert["status"] == "NEW":
                client.request("POST", f"/alerts/{alert['id']}/ack")
            client.request("PATCH", f"/alerts/{alert['id']}/status", {"status": "RESOLVED"})
            quiet_since = time.monotonic()
        time.sleep(0.5)


def alert_latency(client: Client) -> float:
    resolve_open_alerts(client)
    known = {a["id"] for a in client.get(f"/alerts?ip={TARGET}&attack_type=ddos&limit=200")["items"]}
    compose("engine", "python", "-m", "sentinel_engine", "inject", "--scenario", "ddos", "--duration", "5")
    for _ in range(100):
        fresh = [
            a for a in client.get(f"/alerts?ip={TARGET}&attack_type=ddos&limit=200")["items"]
            if a["id"] not in known
        ]
        if fresh:
            detail = client.get(f"/alerts/{fresh[0]['id']}")
            created = next(h["ts"] for h in detail["history"] if h["action"] == "alert.created")
            first_seen = datetime.fromisoformat(detail["first_seen_at"])
            return (datetime.fromisoformat(created) - first_seen).total_seconds() * 1000
        time.sleep(0.2)
    raise TimeoutError("no alert raised")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--detections", type=int, default=5000)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    client = Client()

    ingest = ingestion(client, args.detections)
    print(f"Alert-engine ingestion: a backlog of {ingest['count']} detections drained in "
          f"{ingest['seconds']:.1f} s = {ingest['per_s']:,.0f} detections/s\n", flush=True)

    print(f"API latency ({args.requests} sequential requests each)\n")
    print("| Endpoint | p50 | p95 |\n|---|---:|---:|")
    for row in api_latency(client, args.requests):
        print(f"| `GET {row['path']}` | {row['p50_ms']:.1f} ms | {row['p95_ms']:.1f} ms |")

    alerts = [alert_latency(client) for _ in range(args.trials)]
    print(f"\nDetection-to-alert latency over {len(alerts)} trials: "
          f"median {statistics.median(alerts):.0f} ms, max {max(alerts):.0f} ms "
          f"({', '.join(f'{a:.0f}' for a in alerts)} ms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
