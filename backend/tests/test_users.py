from app.models.enums import Role
from tests.helpers import audit_actions, bearer, create_user, login


def test_admin_creates_a_user_who_can_log_in(client, admin_headers):
    response = client.post(
        "/api/v1/users",
        json={
            "username": "  New.Analyst ",
            "password": "long-enough-passphrase",
            "role": "analyst",
            "email": "analyst@example.com",
        },
        headers=admin_headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "new.analyst"
    assert body["role"] == "analyst"
    assert "password_hash" not in body
    assert login(client, "new.analyst", "long-enough-passphrase").status_code == 200
    created = audit_actions(client, "user.created")[0]
    assert created.actor == "admin-user"
    assert created.after == {
        "username": "new.analyst",
        "email": "analyst@example.com",
        "role": "analyst",
        "is_active": True,
    }


def test_user_creation_validates_input(client, admin_headers):
    base = {"username": "valid_name", "password": "long-enough-passphrase", "role": "viewer"}
    invalid = [
        base | {"password": "too-short"},
        base | {"username": "x"},
        base | {"username": "has spaces"},
        base | {"role": "superuser"},
        base | {"email": "not-an-email"},
        base | {"is_admin": True},
    ]

    statuses = [
        client.post("/api/v1/users", json=body, headers=admin_headers).status_code
        for body in invalid
    ]

    assert statuses == [422] * len(invalid)


def test_duplicate_username_conflicts(client, admin_headers):
    body = {"username": "dupe", "password": "long-enough-passphrase", "role": "viewer"}
    assert client.post("/api/v1/users", json=body, headers=admin_headers).status_code == 201

    response = client.post("/api/v1/users", json=body | {"username": "DUPE"}, headers=admin_headers)

    assert response.status_code == 409


def test_list_and_get_users(client, admin_headers):
    for name in ("u1", "u2", "u3"):
        create_user(client, name)

    page = client.get("/api/v1/users", params={"limit": 2, "offset": 1}, headers=admin_headers)
    single = client.get("/api/v1/users/2", headers=admin_headers)
    missing = client.get("/api/v1/users/999", headers=admin_headers)

    assert page.status_code == 200
    assert page.json()["total"] == 4
    assert [u["username"] for u in page.json()["items"]] == ["u1", "u2"]
    assert single.json()["username"] == "u1"
    assert missing.status_code == 404


def test_update_changes_only_sent_fields_and_is_audited(client, admin_headers):
    user_id = create_user(client, "promote-me")

    promoted = client.patch(
        f"/api/v1/users/{user_id}",
        json={"role": "analyst", "email": "p@example.com"},
        headers=admin_headers,
    )
    cleared = client.patch(f"/api/v1/users/{user_id}", json={"email": None}, headers=admin_headers)

    assert promoted.json()["role"] == "analyst"
    assert cleared.json() == promoted.json() | {"email": None}
    first_update = audit_actions(client, "user.updated")[0]
    assert first_update.before["role"] == "viewer"
    assert first_update.after["role"] == "analyst"


def test_password_reset_and_deactivation_end_sessions(client, admin_headers):
    user_id = create_user(client, "reset-me")
    headers = bearer(user_id)

    reset = client.patch(
        f"/api/v1/users/{user_id}",
        json={"password": "admin-chosen-passphrase"},
        headers=admin_headers,
    )

    assert reset.status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert login(client, "reset-me", "admin-chosen-passphrase").status_code == 200
    assert audit_actions(client, "user.updated")[0].after["password_reset"] is True

    deactivated = client.patch(
        f"/api/v1/users/{user_id}", json={"is_active": False}, headers=admin_headers
    )
    assert deactivated.json()["is_active"] is False
    assert login(client, "reset-me", "admin-chosen-passphrase").status_code == 401


def test_last_active_admin_cannot_be_removed(client):
    admin_id = create_user(client, "only-admin", Role.ADMIN)
    headers = bearer(admin_id)

    demote = client.patch(f"/api/v1/users/{admin_id}", json={"role": "viewer"}, headers=headers)
    deactivate = client.patch(
        f"/api/v1/users/{admin_id}", json={"is_active": False}, headers=headers
    )

    assert demote.status_code == deactivate.status_code == 409

    create_user(client, "second-admin", Role.ADMIN)
    allowed = client.patch(f"/api/v1/users/{admin_id}", json={"role": "analyst"}, headers=headers)
    assert allowed.status_code == 200
