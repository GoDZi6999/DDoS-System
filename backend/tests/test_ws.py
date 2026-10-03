from datetime import UTC, datetime, timedelta

import jwt
import pytest
from starlette.websockets import WebSocketDisconnect

from app.api.v1 import ws
from app.core.security import JWT_AUDIENCE, JWT_ISSUER, create_access_token
from app.models.enums import Role
from app.services.notify import publish
from tests.helpers import create_user, ingest, run

SECRET = "test-only-secret-0123456789abcdefghijklmnopqrstuvwxyz"


def _expect_close(session) -> int:
    with pytest.raises(WebSocketDisconnect) as closed:
        session.receive_json()
    return closed.value.code


@pytest.mark.parametrize(
    "message",
    [
        {"type": "auth", "token": "not-a-token"},
        {"type": "auth"},
        {"type": "hello", "token": "x"},
        ["not", "an", "object"],
    ],
)
def test_bad_authentication_closes_with_4401(client, message):
    with client.websocket_connect("/api/v1/ws") as session:
        session.send_json(message)
        assert _expect_close(session) == 4401


def test_silent_client_is_disconnected(client, monkeypatch):
    monkeypatch.setattr(ws, "AUTH_TIMEOUT_S", 0.1)

    with client.websocket_connect("/api/v1/ws") as session:
        assert _expect_close(session) == 4401


def test_authenticated_client_receives_live_events(client):
    user_id = create_user(client, "watcher", Role.VIEWER)
    token = create_access_token(user_id, 0).token

    with client.websocket_connect("/api/v1/ws") as session:
        session.send_json({"type": "auth", "token": token})
        assert session.receive_json() == {
            "type": "auth.ok",
            "user": {"id": user_id, "username": "watcher", "role": "viewer"},
        }

        run(client, publish, client.app.state.redis, "alert.new", {"id": 7})

        assert session.receive_json() == {"type": "alert.new", "data": {"id": 7}}


def test_workflow_change_reaches_connected_dashboard(client):
    analyst_id = create_user(client, "responder", Role.ANALYST)
    token = create_access_token(analyst_id, 0).token
    alert_id = ingest(client).alert.id

    with client.websocket_connect("/api/v1/ws") as session:
        session.send_json({"type": "auth", "token": token})
        session.receive_json()

        client.post(f"/api/v1/alerts/{alert_id}/ack", headers={"Authorization": f"Bearer {token}"})

        event = session.receive_json()
        assert event["type"] == "alert.updated"
        assert (event["data"]["id"], event["data"]["status"]) == (alert_id, "INVESTIGATING")


def test_connection_closes_when_the_token_expires(client, monkeypatch):
    monkeypatch.setattr(ws, "POLL_INTERVAL_S", 0.1)
    user_id = create_user(client, "short-lived", Role.VIEWER)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "ver": 0,
            "type": "access",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(seconds=2),
        },
        SECRET,
        algorithm="HS256",
    )

    with client.websocket_connect("/api/v1/ws") as session:
        session.send_json({"type": "auth", "token": token})
        assert session.receive_json()["type"] == "auth.ok"
        assert _expect_close(session) == 4401
