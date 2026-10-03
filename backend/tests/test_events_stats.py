from datetime import UTC, datetime, timedelta
from itertools import pairwise

from tests.helpers import ingest


def test_events_list_filters_and_detail(client, viewer_headers):
    now = datetime.now(UTC)
    attack = ingest(client, ts=now, risk_score=88)
    ingest(client, ts=now - timedelta(minutes=1), label="benign", risk_score=0, src_ip="192.0.2.1")
    ingest(client, ts=now - timedelta(minutes=2), label="portscan", risk_score=50)

    def labels(**params):
        response = client.get("/api/v1/events", params=params, headers=viewer_headers)
        assert response.status_code == 200
        return [e["label"] for e in response.json()["items"]]

    assert labels() == ["ddos", "benign", "portscan"]
    assert labels(label="benign") == ["benign"]
    assert labels(ip="192.0.2.1") == ["benign"]
    assert labels(min_risk=60) == ["ddos"]
    assert labels(since=(now - timedelta(seconds=90)).isoformat()) == ["ddos", "benign"]

    detail = client.get(f"/api/v1/events/{attack.event_id}", headers=viewer_headers).json()
    assert detail["severity"] == "CRITICAL"
    assert detail["features"] == {"syn_ratio": 0.9}
    assert detail["class_probs"]["ddos"] == 0.97
    assert detail["explanation"][0]["feature"] == "packets_per_sec"
    assert detail["alert_ids"] == [attack.alert.id]
    assert client.get("/api/v1/events/999", headers=viewer_headers).status_code == 404


def test_naive_timestamps_are_rejected(client, viewer_headers):
    response = client.get(
        "/api/v1/events", params={"since": "2026-01-01T00:00:00"}, headers=viewer_headers
    )

    assert response.status_code == 422


def test_summary_counts_window_and_open_alert_risk(client, analyst_headers):
    now = datetime.now(UTC)
    ingest(client, ts=now, risk_score=72, dst_ip="203.0.113.1")
    ingest(client, ts=now, risk_score=40, dst_ip="203.0.113.2")
    contained = ingest(client, ts=now, risk_score=95, dst_ip="203.0.113.3").alert.id
    ingest(client, ts=now, label="benign", risk_score=0)
    ingest(client, ts=now - timedelta(days=2), risk_score=90, dst_ip="203.0.113.4")
    client.post(f"/api/v1/alerts/{contained}/ack", headers=analyst_headers)
    client.patch(
        f"/api/v1/alerts/{contained}/status",
        json={"status": "CONTAINED"},
        headers=analyst_headers,
    )

    day = client.get("/api/v1/stats/summary", headers=analyst_headers).json()
    week = client.get("/api/v1/stats/summary?window=7d", headers=analyst_headers).json()

    assert (day["events"], day["attacks"]) == (4, 3)
    assert (week["events"], week["attacks"]) == (5, 4)
    assert day["alerts_open"] == 4
    assert day["alerts_contained"] == 1
    assert day["alerts_by_status"]["NEW"] == 3
    assert day["open_alerts_by_severity"] == {"LOW": 0, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 2}
    assert day["risk_score"] == 95
    assert day["severity"] == "CRITICAL"


def test_empty_summary(client, viewer_headers):
    summary = client.get("/api/v1/stats/summary", headers=viewer_headers).json()

    assert summary["events"] == summary["alerts_open"] == summary["risk_score"] == 0
    assert summary["severity"] == "LOW"


def test_timeseries_fills_buckets(client, viewer_headers):
    now = datetime.now(UTC)
    ingest(client, ts=now)
    ingest(client, ts=now, label="benign", risk_score=0)
    ingest(client, ts=now - timedelta(minutes=30))

    series = client.get(
        "/api/v1/stats/timeseries", params={"window": "1h", "bucket": "5m"}, headers=viewer_headers
    ).json()

    points = series["points"]
    assert 12 <= len(points) <= 13
    assert sum(p["events"] for p in points) == 3
    assert sum(p["attacks"] for p in points) == 2
    assert points[-1]["events"] == 2  # the current bucket
    timestamps = [datetime.fromisoformat(p["ts"]) for p in points]
    assert all(b - a == timedelta(minutes=5) for a, b in pairwise(timestamps))


def test_timeseries_rejects_too_many_points(client, viewer_headers):
    response = client.get(
        "/api/v1/stats/timeseries", params={"window": "7d", "bucket": "1m"}, headers=viewer_headers
    )

    assert response.status_code == 422


def test_distribution_by_label(client, viewer_headers):
    now = datetime.now(UTC)
    for _ in range(3):
        ingest(client, ts=now, label="benign", risk_score=0)
    ingest(client, ts=now)
    ingest(client, ts=now, label="portscan")
    ingest(client, ts=now - timedelta(days=3), label="botnet")

    items = client.get("/api/v1/stats/distribution", headers=viewer_headers).json()["items"]

    assert items == [
        {"label": "benign", "count": 3},
        {"label": "ddos", "count": 1},
        {"label": "portscan", "count": 1},
    ]
