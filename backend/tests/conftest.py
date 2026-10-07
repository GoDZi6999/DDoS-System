"""Test fixtures. Tests run against real PostgreSQL and Redis (CI service containers,
or `docker run` locally), because the schema relies on PostgreSQL features
(INET, JSONB, triggers, advisory locks)."""

import asyncio
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://argus:argus@localhost:5432/argus_test"
)
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/15")

# Must be set before the app reads its settings.
os.environ.update(
    ENVIRONMENT="test",
    DATABASE_URL=TEST_DATABASE_URL,
    REDIS_URL=TEST_REDIS_URL,
    JWT_SECRET="test-only-secret-0123456789abcdefghijklmnopqrstuvwxyz",
)

import asyncpg  # noqa: E402
import redis  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pwdlib import PasswordHash  # noqa: E402
from pwdlib.hashers.argon2 import Argon2Hasher  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

from app.core import config, security  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.enums import Role  # noqa: E402
from tests.helpers import bearer, create_user  # noqa: E402

BACKEND_DIR = Path(__file__).resolve().parents[1]


def alembic_config() -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.attributes["configure_logger"] = False
    cfg.attributes["database_url"] = TEST_DATABASE_URL
    return cfg


async def _recreate_database() -> None:
    url = make_url(TEST_DATABASE_URL)
    conn = await asyncpg.connect(
        user=url.username, password=url.password, host=url.host, port=url.port, database="postgres"
    )
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)')
        await conn.execute(f'CREATE DATABASE "{url.database}"')
    finally:
        await conn.close()


@pytest.fixture(scope="session", autouse=True)
def database() -> None:
    asyncio.run(_recreate_database())
    command.upgrade(alembic_config(), "head")


@pytest.fixture(autouse=True)
def fast_password_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    cheap = PasswordHash((Argon2Hasher(time_cost=1, memory_cost=1024, parallelism=1),))
    monkeypatch.setattr(security, "password_hasher", cheap)


async def _reset_state(app) -> None:
    async with app.state.engine.begin() as conn:
        tables = await conn.scalars(
            text(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = 'public' AND tablename <> 'alembic_version'"
            )
        )
        names = ", ".join(f'"{name}"' for name in tables)
        # Superuser-only: skips the append-only trigger on audit_logs.
        await conn.execute(text("SET LOCAL session_replication_role = replica"))
        await conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
    await app.state.redis.flushdb()


@pytest.fixture
def client() -> Iterator[TestClient]:
    config.get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as test_client:
        test_client.portal.call(_reset_state, app)
        yield test_client


@pytest.fixture
def redis_client() -> Iterator[redis.Redis]:
    client = redis.Redis.from_url(TEST_REDIS_URL)
    yield client
    client.close()


@pytest.fixture
def admin_headers(client: TestClient) -> dict[str, str]:
    return bearer(create_user(client, "admin-user", Role.ADMIN))


@pytest.fixture
def analyst_headers(client: TestClient) -> dict[str, str]:
    return bearer(create_user(client, "analyst-user", Role.ANALYST))


@pytest.fixture
def viewer_headers(client: TestClient) -> dict[str, str]:
    return bearer(create_user(client, "viewer-user", Role.VIEWER))


@pytest.fixture
def alembic_cfg() -> Config:
    return alembic_config()
