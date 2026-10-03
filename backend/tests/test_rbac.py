"""Role matrix: every protected endpoint, called by every role.

test_matrix_covers_every_endpoint fails when an endpoint is added without
being listed here, so new routes cannot skip authorisation testing.
"""

import pytest

from app.main import create_app
from app.models.enums import Role
from tests.helpers import bearer, create_user

ADMIN, ANALYST, VIEWER = Role.ADMIN, Role.ANALYST, Role.VIEWER

# (method, path template, minimum role, JSON body)
MATRIX = [
    ("GET", "/api/v1/auth/me", VIEWER, None),
    ("GET", "/api/v1/alerts", VIEWER, None),
    ("GET", "/api/v1/alerts/{alert_id}", VIEWER, None),
    ("GET", "/api/v1/alerts/{alert_id}/events", VIEWER, None),
    ("POST", "/api/v1/alerts/{alert_id}/ack", ANALYST, None),
    ("PATCH", "/api/v1/alerts/{alert_id}/status", ANALYST, {"status": "CONTAINED"}),
    ("POST", "/api/v1/alerts/{alert_id}/notes", ANALYST, {"body": "note"}),
    ("PUT", "/api/v1/alerts/{alert_id}/assignee", ANALYST, {"user_id": None}),
    ("GET", "/api/v1/events", VIEWER, None),
    ("GET", "/api/v1/events/{event_id}", VIEWER, None),
    ("GET", "/api/v1/stats/summary", VIEWER, None),
    ("GET", "/api/v1/stats/timeseries", VIEWER, None),
    ("GET", "/api/v1/stats/distribution", VIEWER, None),
    ("GET", "/api/v1/config/detection", ANALYST, None),
    ("PUT", "/api/v1/config/detection", ADMIN, {}),
    ("GET", "/api/v1/users", ADMIN, None),
    (
        "POST",
        "/api/v1/users",
        ADMIN,
        {"username": "matrix-user", "password": "long-enough-passphrase", "role": "viewer"},
    ),
    ("GET", "/api/v1/users/{user_id}", ADMIN, None),
    ("PATCH", "/api/v1/users/{user_id}", ADMIN, {"email": "matrix@example.com"}),
    ("GET", "/api/v1/audit", ADMIN, None),
]

# Reachable without a role: health probes and the token endpoints themselves.
# /auth/password needs a valid session but no particular role.
PUBLIC_OR_SELF = {
    ("GET", "/health"),
    ("GET", "/health/ready"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/password"),
}


def test_matrix_covers_every_endpoint():
    documented = {
        (method.upper(), path)
        for path, operations in create_app().openapi()["paths"].items()
        for method in operations
    }
    tested = {(method, path) for method, path, _, _ in MATRIX}

    assert documented - PUBLIC_OR_SELF == tested


@pytest.mark.parametrize(("method", "template", "minimum", "body"), MATRIX)
def test_role_matrix(client, method, template, minimum, body):
    path = template.format(alert_id=1, event_id=1, user_id=1)
    users = {role: create_user(client, f"{role.value}-matrix", role) for role in Role}

    anonymous = client.request(method, path, json=body)
    assert anonymous.status_code == 401

    for role, user_id in users.items():
        response = client.request(method, path, json=body, headers=bearer(user_id))
        if role.includes(minimum):
            # Allowed: anything except an authorisation failure (404/422 are fine here).
            assert response.status_code not in (401, 403), (role, response.text)
        else:
            assert response.status_code == 403, (role, response.status_code)
