from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.security import JWT_AUDIENCE, JWT_ISSUER
from app.models import User
from app.models.enums import Role
from tests.helpers import PASSWORD, audit_actions, bearer, create_user, login, run

SECRET = "test-only-secret-0123456789abcdefghijklmnopqrstuvwxyz"


def _jwt(claims: dict, key: str = SECRET, algorithm: str = "HS256") -> str:
    now = datetime.now(UTC)
    base = {
        "sub": "1",
        "ver": 0,
        "type": "access",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    return jwt.encode(base | claims, key, algorithm=algorithm)


def test_login_returns_tokens_that_identify_the_user(client):
    create_user(client, "analyst01", Role.ANALYST)

    response = login(client, "Analyst01")  # usernames are case-insensitive

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert 0 < body["expires_in"] <= 15 * 60
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["username"] == "analyst01"
    assert me.json()["role"] == "analyst"
    assert [entry.actor for entry in audit_actions(client, "auth.login")] == ["analyst01"]


def test_wrong_password_and_unknown_user_look_identical(client):
    create_user(client, "viewer01")

    wrong_password = login(client, "viewer01", "not-the-password")
    unknown_user = login(client, "nobody", PASSWORD)

    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()
    assert wrong_password.headers["www-authenticate"] == "Bearer"
    failures = audit_actions(client, "auth.login_failed")
    assert [entry.after["username"] for entry in failures] == ["viewer01", "nobody"]
    assert all(entry.after["reason"] == "bad_credentials" for entry in failures)


def test_oversized_password_is_refused_without_hashing(client, monkeypatch):
    create_user(client, "big-input")

    def fail_if_called(*_args):
        raise AssertionError("an oversized password must not be hashed")

    monkeypatch.setattr("app.services.auth.verify_password", fail_if_called)
    response = login(client, "big-input", "x" * 100_000)

    assert response.status_code == 401
    assert len(audit_actions(client, "auth.login_failed")) == 1


def test_inactive_user_cannot_log_in(client):
    create_user(client, "former", is_active=False)

    response = login(client, "former")

    assert response.status_code == 401
    assert audit_actions(client, "auth.login_failed")[0].after["reason"] == "inactive"


def test_repeated_failures_lock_the_account(client):
    create_user(client, "target")
    for _ in range(5):
        assert login(client, "target", "guess-guess-guess").status_code == 401

    locked = login(client, "target")  # even the right password is refused now

    assert locked.status_code == 429
    assert 0 < int(locked.headers["retry-after"]) <= 15 * 60
    assert len(audit_actions(client, "auth.locked")) == 1


def test_successful_login_resets_the_failure_counter(client):
    create_user(client, "forgetful")
    for _ in range(4):
        login(client, "forgetful", "wrong-password-1")
    assert login(client, "forgetful").status_code == 200

    for _ in range(4):
        login(client, "forgetful", "wrong-password-2")

    assert login(client, "forgetful").status_code == 200


def test_refresh_rotates_the_token_pair(client):
    create_user(client, "rotator")
    first = login(client, "rotator").json()

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})

    assert response.status_code == 200
    second = response.json()
    assert second["refresh_token"] != first["refresh_token"]
    headers = {"Authorization": f"Bearer {second['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200


def test_replayed_refresh_token_ends_the_whole_session(client):
    create_user(client, "victim")
    stolen = login(client, "victim").json()["refresh_token"]
    current = client.post("/api/v1/auth/refresh", json={"refresh_token": stolen}).json()

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})

    assert replay.status_code == 401
    # The legitimate client's newer tokens are revoked as well.
    newer = client.post("/api/v1/auth/refresh", json={"refresh_token": current["refresh_token"]})
    assert newer.status_code == 401
    headers = {"Authorization": f"Bearer {current['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert len(audit_actions(client, "auth.refresh_reuse_detected")) == 1


def test_logout_revokes_the_refresh_token(client):
    create_user(client, "leaver")
    tokens = login(client, "leaver").json()

    response = client.post("/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]})

    assert response.status_code == 204
    again = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert again.status_code == 401
    unknown = client.post("/api/v1/auth/logout", json={"refresh_token": "not-a-token"})
    assert unknown.status_code == 204
    assert len(audit_actions(client, "auth.logout")) == 1


def test_password_change_requires_the_current_password_and_ends_sessions(client):
    create_user(client, "changer")
    tokens = login(client, "changer").json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    new_password = "a-brand-new-passphrase"

    wrong = client.post(
        "/api/v1/auth/password",
        json={"current_password": "wrong", "new_password": new_password},
        headers=headers,
    )
    same = client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": PASSWORD},
        headers=headers,
    )
    changed = client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": new_password},
        headers=headers,
    )

    assert (wrong.status_code, same.status_code, changed.status_code) == (400, 400, 204)
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401
    assert login(client, "changer").status_code == 401
    assert login(client, "changer", new_password).status_code == 200


def test_short_new_password_is_rejected(client):
    user_id = create_user(client, "shorty")

    response = client.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "short"},
        headers=bearer(user_id),
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt",
        _jwt({}, key="some-other-secret-0123456789abcdefghijklmnop"),
        _jwt({"exp": datetime.now(UTC) - timedelta(seconds=1)}),
        _jwt({"aud": "another-service"}),
        _jwt({"iss": "someone-else"}),
        _jwt({"type": "refresh"}),
        _jwt({"ver": 1}),  # token_version no longer matches
        jwt.encode({"sub": "1", "ver": 0, "type": "access"}, None, algorithm="none"),
    ],
    ids=["garbage", "wrong-key", "expired", "audience", "issuer", "type", "version", "alg-none"],
)
def test_invalid_tokens_are_rejected(client, token):
    assert create_user(client, "holder") == 1

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


def test_missing_token_is_rejected_with_a_bearer_challenge(client):
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_deactivation_takes_effect_on_the_next_request(client):
    user_id = create_user(client, "soon-gone")
    headers = bearer(user_id)
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    async def deactivate() -> None:
        async with client.app.state.sessionmaker() as session:
            user = await session.get(User, user_id)
            user.is_active = False
            await session.commit()

    run(client, deactivate)

    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_api_responses_carry_security_headers(client):
    response = client.get("/api/v1/auth/me")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'none'" in response.headers["content-security-policy"]
