import pytest

from argus_engine.risk import DEFAULT_WEIGHTS, RiskEngine
from argus_engine.window import WindowStats


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
