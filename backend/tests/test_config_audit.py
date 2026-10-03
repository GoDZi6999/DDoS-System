import json

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.services.detection_config import get_detection_config
from app.services.notify import CONFIG_KEY
from tests.helpers import audit_actions, ingest, run

DEFAULTS = {
    "alert_min_risk": 31,
    "aggregation_window_minutes": 15,
    "risk_weights": {
        "ml_confidence": 0.4,
        "traffic_anomaly": 0.25,
        "attack_severity": 0.25,
        "source_reputation": 0.1,
    },
}


def test_detection_config_defaults(client, analyst_headers):
    response = client.get("/api/v1/config/detection", headers=analyst_headers)

    assert response.status_code == 200
    assert response.json() == DEFAULTS


def test_admin_updates_detection_config_and_change_is_audited(client, admin_headers, redis_client):
    new = DEFAULTS | {"alert_min_risk": 90}

    response = client.put("/api/v1/config/detection", json=new, headers=admin_headers)

    assert response.status_code == 200
    assert client.get("/api/v1/config/detection", headers=admin_headers).json() == new
    assert json.loads(redis_client.get(CONFIG_KEY))["alert_min_risk"] == 90  # for the engine
    entry = audit_actions(client, "config.updated")[0]
    assert entry.actor == "admin-user"
    assert entry.before["alert_min_risk"] == 31
    assert entry.after["alert_min_risk"] == 90

    async def stored():
        async with client.app.state.sessionmaker() as session:
            return await get_detection_config(session)

    # The alert engine honours the stored threshold.
    assert ingest(client, config=run(client, stored), risk_score=85).alert is None


@pytest.mark.parametrize(
    "body",
    [
        DEFAULTS | {"risk_weights": DEFAULTS["risk_weights"] | {"ml_confidence": 0.9}},
        DEFAULTS | {"alert_min_risk": 101},
        DEFAULTS | {"aggregation_window_minutes": 0},
        DEFAULTS | {"unknown": True},
    ],
    ids=["weights-sum", "risk-range", "window-range", "extra-field"],
)
def test_invalid_detection_config_is_rejected(client, admin_headers, body):
    response = client.put("/api/v1/config/detection", json=body, headers=admin_headers)

    assert response.status_code == 422


def test_audit_log_lists_newest_first_with_filters(client, admin_headers):
    client.put("/api/v1/config/detection", json=DEFAULTS, headers=admin_headers)
    ingest(client)

    everything = client.get("/api/v1/audit", headers=admin_headers).json()
    by_actor = client.get("/api/v1/audit", params={"actor": "system"}, headers=admin_headers)
    by_action = client.get(
        "/api/v1/audit", params={"action": "config.updated"}, headers=admin_headers
    )
    by_entity = client.get(
        "/api/v1/audit", params={"entity_type": "alert", "entity_id": "1"}, headers=admin_headers
    )

    assert [e["action"] for e in everything["items"]] == ["alert.created", "config.updated"]
    assert everything["total"] == 2
    assert [e["actor"] for e in by_actor.json()["items"]] == ["system"]
    assert by_action.json()["items"][0]["actor"] == "admin-user"
    assert by_entity.json()["total"] == 1


def test_audit_log_rejects_updates_and_deletes(client):
    ingest(client)

    async def tamper(statement: str) -> None:
        async with client.app.state.engine.begin() as conn:
            await conn.execute(text(statement))

    with pytest.raises(DBAPIError, match="append-only"):
        run(client, tamper, "UPDATE audit_logs SET actor = 'someone-else'")
    with pytest.raises(DBAPIError, match="append-only"):
        run(client, tamper, "DELETE FROM audit_logs")
    with pytest.raises(DBAPIError, match="append-only"):
        run(client, tamper, "TRUNCATE audit_logs")
    assert len(audit_actions(client)) == 1
