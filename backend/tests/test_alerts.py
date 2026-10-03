import json
from datetime import UTC, datetime, timedelta

from app.models import NetworkEvent
from app.models.enums import Role
from app.schemas.config import DetectionConfig
from app.services.notify import EVENTS_CHANNEL
from tests.helpers import audit_actions, bearer, count_rows, create_user, ingest


def _alert(client, alert_id, headers):
    response = client.get(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert response.status_code == 200
    return response.json()


def test_attack_detection_raises_an_explained_alert(client, viewer_headers):
    result = ingest(client)

    assert result.created
    alert = _alert(client, result.alert.id, viewer_headers)
    assert alert["status"] == "NEW"
    assert alert["severity"] == "CRITICAL"
    assert alert["attack_type"] == "ddos"
    assert alert["description"] == "DDoS detected — confidence 97.0% — target 203.0.113.10:80"
    assert alert["recommended_action"].startswith("Escalate to the on-call responder now.")
    assert [item["feature"] for item in alert["explanation"]] == ["packets_per_sec", "syn_ratio"]
    assert alert["risk_components"] == {"ml_confidence": 97.0, "traffic_anomaly": 90.0}
    assert alert["unique_sources"] == 1
    assert alert["allowed_transitions"] == ["INVESTIGATING", "FALSE_POSITIVE"]
    assert [entry["action"] for entry in alert["history"]] == ["alert.created"]


def test_benign_and_low_risk_detections_are_stored_without_alerts(client):
    benign = ingest(client, label="benign", risk_score=0)
    low_risk = ingest(client, risk_score=20)

    assert benign.alert is None and low_risk.alert is None
    assert count_rows(client, NetworkEvent) == 2


def test_detections_against_one_target_aggregate_into_one_alert(client, viewer_headers):
    start = datetime.now(UTC)
    first = ingest(client, ts=start, risk_score=45, src_ip="198.51.100.1", packets_per_sec=1000.0)
    ingest(client, ts=start + timedelta(seconds=5), risk_score=70, src_ip="198.51.100.2")
    peak = ingest(
        client,
        ts=start + timedelta(seconds=10),
        risk_score=92,
        src_ip="198.51.100.3",
        packets_per_sec=90000.0,
    )

    assert peak.alert.id == first.alert.id
    assert peak.escalated
    alert = _alert(client, first.alert.id, viewer_headers)
    assert alert["detection_count"] == 3
    assert alert["peak_packets_per_sec"] == 90000.0
    assert alert["risk_score"] == 92
    assert alert["severity"] == "CRITICAL"
    assert alert["source_ip"] == "198.51.100.3"  # source of the highest-risk detection
    assert alert["unique_sources"] == 3
    assert [e["action"] for e in alert["history"]] == [
        "alert.created",
        "alert.escalated",
        "alert.escalated",
    ]


def test_separate_alerts_per_target_type_and_window(client):
    start = datetime.now(UTC) - timedelta(hours=1)
    base = ingest(client, ts=start)

    other_target = ingest(client, ts=start, dst_ip="203.0.113.99")
    other_type = ingest(client, ts=start, label="portscan")
    after_window = ingest(client, ts=start + timedelta(minutes=20))
    narrow = DetectionConfig(aggregation_window_minutes=1)
    narrow_window = ingest(client, config=narrow, ts=start + timedelta(minutes=22))

    ids = {r.alert.id for r in (base, other_target, other_type, after_window, narrow_window)}
    assert len(ids) == 5


def test_closed_alert_does_not_absorb_new_detections(client, analyst_headers):
    first = ingest(client).alert.id
    client.post(f"/api/v1/alerts/{first}/ack", headers=analyst_headers)
    client.patch(
        f"/api/v1/alerts/{first}/status", json={"status": "RESOLVED"}, headers=analyst_headers
    )

    again = ingest(client)

    assert again.created and again.alert.id != first


def test_redelivered_stream_entry_is_stored_once(client):
    first = ingest(client, stream_id="1700000000000-0")
    again = ingest(client, stream_id="1700000000000-0")

    assert again.duplicate and again.event_id == first.event_id
    assert count_rows(client, NetworkEvent) == 1


def test_full_workflow_with_audit_trail(client):
    analyst_id = create_user(client, "analyst01", Role.ANALYST)
    headers = bearer(analyst_id)
    alert_id = ingest(client).alert.id

    acked = client.post(f"/api/v1/alerts/{alert_id}/ack", headers=headers).json()
    assert acked["status"] == "INVESTIGATING"
    assert acked["acknowledged_by"] == {"id": analyst_id, "username": "analyst01"}

    contained = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        json={"status": "CONTAINED", "note": "Rate limit applied upstream"},
        headers=headers,
    ).json()
    assert contained["notes"][0]["body"] == "Rate limit applied upstream"

    resolved = client.patch(
        f"/api/v1/alerts/{alert_id}/status", json={"status": "RESOLVED"}, headers=headers
    ).json()
    assert resolved["resolved_at"] is not None
    assert resolved["allowed_transitions"] == ["INVESTIGATING"]

    reopened = client.patch(
        f"/api/v1/alerts/{alert_id}/status", json={"status": "INVESTIGATING"}, headers=headers
    ).json()
    assert reopened["resolved_at"] is None
    assert [(e["actor"], e["action"]) for e in reopened["history"]] == [
        ("system", "alert.created"),
        ("analyst01", "alert.acknowledged"),
        ("analyst01", "alert.status_changed"),
        ("analyst01", "alert.status_changed"),
        ("analyst01", "alert.status_changed"),
    ]


def test_invalid_transitions_conflict(client, analyst_headers):
    alert_id = ingest(client).alert.id

    skip_ahead = client.patch(
        f"/api/v1/alerts/{alert_id}/status", json={"status": "RESOLVED"}, headers=analyst_headers
    )
    assert skip_ahead.status_code == 409
    assert client.post(f"/api/v1/alerts/{alert_id}/ack", headers=analyst_headers).status_code == 200
    assert client.post(f"/api/v1/alerts/{alert_id}/ack", headers=analyst_headers).status_code == 409
    missing = client.post("/api/v1/alerts/999/ack", headers=analyst_headers)
    assert missing.status_code == 404


def test_notes_and_assignment(client, analyst_headers):
    alert_id = ingest(client).alert.id
    other_analyst = create_user(client, "analyst02", Role.ANALYST)
    viewer = create_user(client, "viewer02", Role.VIEWER)

    note = client.post(
        f"/api/v1/alerts/{alert_id}/notes",
        json={"body": "  Traffic from a single ASN  "},
        headers=analyst_headers,
    )
    blank = client.post(
        f"/api/v1/alerts/{alert_id}/notes", json={"body": "   "}, headers=analyst_headers
    )
    assigned = client.put(
        f"/api/v1/alerts/{alert_id}/assignee",
        json={"user_id": other_analyst},
        headers=analyst_headers,
    )
    to_viewer = client.put(
        f"/api/v1/alerts/{alert_id}/assignee", json={"user_id": viewer}, headers=analyst_headers
    )
    unassigned = client.put(
        f"/api/v1/alerts/{alert_id}/assignee", json={"user_id": None}, headers=analyst_headers
    )

    assert note.status_code == 201
    assert note.json()["body"] == "Traffic from a single ASN"
    assert note.json()["author"]["username"] == "analyst-user"
    assert blank.status_code == 422
    assert assigned.json()["assigned_to"] == {"id": other_analyst, "username": "analyst02"}
    assert to_viewer.status_code == 422
    assert unassigned.json()["assigned_to"] is None
    assert len(audit_actions(client, "alert.note_added")) == 1
    assert len(audit_actions(client, "alert.assigned")) == 2


def test_list_filters_sorting_and_pagination(client, analyst_headers):
    now = datetime.now(UTC)
    critical = ingest(client, ts=now, risk_score=95).alert.id
    medium = ingest(client, ts=now - timedelta(minutes=5), risk_score=40, dst_ip="10.0.0.5").alert
    scan = ingest(client, ts=now - timedelta(hours=3), label="portscan", risk_score=65).alert.id
    client.post(f"/api/v1/alerts/{scan}/ack", headers=analyst_headers)

    def ids(**params):
        response = client.get("/api/v1/alerts", params=params, headers=analyst_headers)
        assert response.status_code == 200
        return [a["id"] for a in response.json()["items"]]

    assert ids() == [critical, medium.id, scan]  # newest activity first
    assert ids(sort="risk") == [critical, scan, medium.id]
    assert ids(status="NEW") == [critical, medium.id]
    assert ids(status=["NEW", "INVESTIGATING"], severity="HIGH") == [scan]
    assert ids(attack_type="portscan") == [scan]
    assert ids(ip="10.0.0.5") == [medium.id]
    assert ids(since=(now - timedelta(hours=1)).isoformat()) == [critical, medium.id]
    page = client.get("/api/v1/alerts", params={"limit": 1, "offset": 1}, headers=analyst_headers)
    assert page.json()["total"] == 3
    assert [a["id"] for a in page.json()["items"]] == [medium.id]
    assert client.get("/api/v1/alerts?status=BOGUS", headers=analyst_headers).status_code == 422
    assert client.get("/api/v1/alerts?ip=not-an-ip", headers=analyst_headers).status_code == 422


def test_alert_events_lists_the_aggregated_detections(client, viewer_headers):
    first = ingest(client, src_ip="198.51.100.1")
    ingest(client, src_ip="198.51.100.2")

    response = client.get(f"/api/v1/alerts/{first.alert.id}/events", headers=viewer_headers)

    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert {e["src_ip"] for e in response.json()["items"]} == {"198.51.100.1", "198.51.100.2"}
    assert client.get("/api/v1/alerts/999/events", headers=viewer_headers).status_code == 404


def test_workflow_changes_are_pushed_to_live_dashboards(client, analyst_headers, redis_client):
    alert_id = ingest(client).alert.id
    pubsub = redis_client.pubsub()
    pubsub.subscribe(EVENTS_CHANNEL)
    assert pubsub.get_message(timeout=1)["type"] == "subscribe"

    client.post(f"/api/v1/alerts/{alert_id}/ack", headers=analyst_headers)

    message = pubsub.get_message(timeout=2)
    event = json.loads(message["data"])
    assert event["type"] == "alert.updated"
    assert event["data"]["id"] == alert_id
    assert event["data"]["status"] == "INVESTIGATING"
    pubsub.close()
