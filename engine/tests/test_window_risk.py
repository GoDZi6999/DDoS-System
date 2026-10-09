import numpy as np
import pytest

from sentinel_engine.risk import DEFAULT_WEIGHTS, RiskEngine
from sentinel_engine.window import BeaconTracker, WindowStats


def flow(end, src, dst, dport, packets=2):
    return {"end": end, "src_ip": src, "dst_ip": dst, "dst_port": dport, "packet_count": packets}


def test_window_tracks_ports_sources_and_rates_and_forgets_old_flows():
    window = WindowStats(window_s=10)
    for port in range(1, 31):
        window.add(flow(1.0, "6.6.6.6", "10.0.0.5", port))
    window.add(flow(2.0, "7.7.7.7", "10.0.0.5", 80, packets=40))

    assert window.distinct_ports("6.6.6.6", "10.0.0.5") == 30
    assert window.distinct_sources("10.0.0.5") == 2
    assert window.dst_packet_rate("10.0.0.5") == pytest.approx((30 * 2 + 40) / 10)
    assert window.scanners(min_ports=20) == [("6.6.6.6", "10.0.0.5", 30)]

    window.evict(11.5)  # first batch is older than 10 s

    assert window.distinct_ports("6.6.6.6", "10.0.0.5") == 0
    assert window.scanners(min_ports=20) == []
    assert window.dst_packet_rate("10.0.0.5") == pytest.approx(4.0)
    window.evict(20.0)
    assert window.distinct_sources("10.0.0.5") == 0


def test_beacons_are_regular_repeated_contacts_not_bursts_or_human_traffic():
    rng = np.random.default_rng(0)
    tracker = BeaconTracker()
    polls = 1000 + np.cumsum(30 * (1 + rng.normal(0, 0.03, 12)))
    for t in polls:  # a bot polling its C2 every 30 s with 3% jitter
        tracker.add(flow(t, "10.0.0.66", "203.0.113.9", 443))
    for t in np.cumsum(rng.exponential(20, 12)):  # a person browsing: irregular gaps
        tracker.add(flow(1000 + t, "10.0.0.20", "10.20.0.10", 80))
    for i in range(50):  # requests 0.2 s apart: regular, but too fast for a beacon
        tracker.add(flow(1000 + i * 0.2, "10.0.0.21", "10.20.0.11", 8080))
    for i in range(5):  # regular, but too few flows to call it
        tracker.add(flow(1000 + i * 30, "10.0.0.22", "10.20.0.12", 22))

    found = tracker.beacons()

    assert [(b.src, b.dst, b.dport) for b in found] == [("10.0.0.66", "203.0.113.9", 443)]
    assert found[0].flows == 12
    assert found[0].interval_s == pytest.approx(30, rel=0.05)
    assert found[0].jitter < 0.1

    tracker.evict(polls[-1] + 300 - 60)  # only the last couple of polls are recent
    assert tracker.beacons() == []


def test_risk_components_and_weighted_score():
    risk = RiskEngine()

    score, parts = risk.score("ddos", 0.99, "1.1.1.1", "10.0.0.5", packet_rate=0.0, now=0.0)

    assert parts == {
        "ml_confidence": 99.0,
        "traffic_anomaly": 0.0,
        "attack_severity": 90.0,
        "source_reputation": 0.0,
    }
    assert score == round(0.4 * 99 + 0.25 * 90)


def test_anomaly_compares_against_the_destination_baseline():
    risk = RiskEngine()
    for t in range(100):
        risk.observe_benign("10.0.0.5", 20.0, float(t))

    normal = risk.anomaly("10.0.0.5", 20.0)
    flood = risk.anomaly("10.0.0.5", 20_000.0)

    assert normal < 5
    assert flood == 100


def test_repeat_offenders_gain_reputation_that_expires():
    risk = RiskEngine()
    for t in range(3):
        risk.record_attack("6.6.6.6", "10.0.0.5", float(t))

    assert risk.reputation("6.6.6.6", 10.0) == 60
    assert risk.reputation("6.6.6.6", 10_000.0) == 0  # older than an hour


def test_invalid_weights_are_ignored():
    risk = RiskEngine()

    risk.set_weights({"ml_confidence": 1.0})
    assert risk.weights == DEFAULT_WEIGHTS
    risk.set_weights(dict.fromkeys(DEFAULT_WEIGHTS, 0.25))
    assert risk.weights["traffic_anomaly"] == 0.25


def test_an_ongoing_attack_does_not_become_the_new_normal():
    risk = RiskEngine()
    for t in range(100):
        risk.observe_benign("10.0.0.5", 20.0, float(t))
    risk.record_attack("6.6.6.6", "10.0.0.5", 100.0)

    for t in range(100, 160):  # benign flows during the flood see the flood's rate
        risk.observe_benign("10.0.0.5", 20_000.0, float(t))

    assert risk.anomaly("10.0.0.5", 20_000.0) == 100
