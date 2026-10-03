import asyncio

from app import cli
from app.core import config
from app.models import User
from app.schemas.detection import Detection
from app.workers.alert_engine import DETECTIONS_STREAM
from tests.helpers import audit_actions, bearer, count_rows, create_user, login


def _bootstrap(monkeypatch, **env: str) -> int:
    monkeypatch.delenv("INITIAL_ADMIN_PASSWORD", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    config.get_settings.cache_clear()
    return asyncio.run(cli.bootstrap())


def test_bootstrap_creates_one_admin_with_a_generated_password(client, monkeypatch, capsys):
    assert _bootstrap(monkeypatch) == 0
    output = capsys.readouterr().out
    password = output.split("change it after logging in): ")[1].strip()

    assert login(client, "admin", password).status_code == 200
    assert _bootstrap(monkeypatch) == 0
    assert "skipped" in capsys.readouterr().out
    assert count_rows(client, User) == 1
    created = audit_actions(client, "user.created")[0]
    assert (created.actor, created.after["source"]) == ("system", "bootstrap")


def test_bootstrap_uses_the_configured_credentials(client, monkeypatch, capsys):
    code = _bootstrap(
        monkeypatch,
        INITIAL_ADMIN_USERNAME="SOC-Admin",
        INITIAL_ADMIN_PASSWORD="configured-passphrase",
    )

    assert code == 0
    assert "Generated password" not in capsys.readouterr().out
    assert login(client, "soc-admin", "configured-passphrase").status_code == 200


def test_bootstrap_rejects_a_weak_password(client, monkeypatch, capsys):
    assert _bootstrap(monkeypatch, INITIAL_ADMIN_PASSWORD="short") == 2
    assert "INITIAL_ADMIN_PASSWORD" in capsys.readouterr().err
    assert count_rows(client, User) == 0


def test_demo_detections_publish_synthetic_entries(client, redis_client):
    assert cli.main(["demo-detections", "--count", "5"]) == 0

    entries = redis_client.xrange(DETECTIONS_STREAM)
    assert len(entries) == 5
    first = Detection.model_validate_json(entries[0][1][b"data"])
    assert (first.source, first.model_version) == ("sim", "synthetic-demo")
    assert str(first.dst_ip) == "203.0.113.10"


def test_reset_password_recovers_an_account(client, capsys):
    user_id = create_user(client, "locked-out")
    old_session = bearer(user_id)

    assert cli.main(["reset-password", "Locked-Out"]) == 0
    password = capsys.readouterr().out.split("change it after logging in): ")[1].strip()

    assert login(client, "locked-out", password).status_code == 200
    assert client.get("/api/v1/auth/me", headers=old_session).status_code == 401
    assert audit_actions(client, "user.updated")[0].after == {
        "password_reset": True,
        "source": "cli",
    }
    assert cli.main(["reset-password", "nobody"]) == 1
