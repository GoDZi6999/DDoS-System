from sentinel_ml import gate


def _metrics(fpr: float, recalls: dict[str, float]) -> dict:
    return {
        "false_positive_rate": fpr,
        "per_class": {c: {"recall": r, "support": 10} for c, r in recalls.items()},
    }


def test_gate_needs_fewer_false_positives_and_bounded_recall_loss():
    reference = _metrics(0.002, {"benign": 0.99, "botnet": 0.92, "portscan": 0.88})

    passed = gate.check(
        _metrics(0.001, {"benign": 0.99, "botnet": 0.83, "portscan": 0.95}), reference
    )
    assert passed["passed"]

    lost_botnet = gate.check(
        _metrics(0.001, {"benign": 0.99, "botnet": 0.75, "portscan": 0.9}), reference
    )
    assert not lost_botnet["passed"]
    assert [c["name"] for c in lost_botnet["checks"] if not c["passed"]] == ["recall_botnet"]

    same_fpr = gate.check(
        _metrics(0.002, {"benign": 0.99, "botnet": 0.92, "portscan": 0.88}), reference
    )
    assert not same_fpr["passed"]


def test_reference_metrics_are_read_from_the_committed_default_bundle(tmp_path):
    assert gate.reference_metrics(tmp_path) is None
