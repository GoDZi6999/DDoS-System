import asyncio

from app.api import health


async def _ok(_client) -> bool:
    return True


async def _refused(_client) -> bool:
    raise ConnectionError("connection refused by db:5432")


async def _hang(_client) -> bool:
    await asyncio.sleep(10)
    return True


def test_liveness_does_not_need_dependencies(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_when_all_dependencies_respond(client, monkeypatch):
    monkeypatch.setattr(health, "check_database", _ok)
    monkeypatch.setattr(health, "check_redis", _ok)

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok", "redis": "ok"}}


def test_unavailable_when_a_dependency_fails(client, monkeypatch):
    monkeypatch.setattr(health, "check_database", _refused)
    monkeypatch.setattr(health, "check_redis", _ok)

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "checks": {"database": "error", "redis": "ok"},
    }
    assert "db:5432" not in response.text  # failure details stay in the server log


def test_hung_dependency_times_out(client, monkeypatch):
    monkeypatch.setattr(health, "CHECK_TIMEOUT_S", 0.05)
    monkeypatch.setattr(health, "check_database", _ok)
    monkeypatch.setattr(health, "check_redis", _hang)

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["checks"] == {"database": "ok", "redis": "error"}


def test_ready_against_real_services(client):
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok", "redis": "ok"}}
