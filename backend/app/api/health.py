"""Operational probes. Served at the root, outside the versioned /api/v1 prefix."""

import asyncio
import logging
from collections.abc import Awaitable
from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ops"])

CHECK_TIMEOUT_S = 3.0

CheckState = Literal["ok", "error"]


class Liveness(BaseModel):
    status: Literal["ok"]


class Readiness(BaseModel):
    status: Literal["ready", "unavailable"]
    checks: dict[str, CheckState]


async def check_database(engine: AsyncEngine) -> bool:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True


async def check_redis(client: Redis) -> bool:
    return bool(await client.ping())


async def _probe(name: str, check: Awaitable[bool]) -> CheckState:
    try:
        ok = await asyncio.wait_for(check, timeout=CHECK_TIMEOUT_S)
    except Exception:
        # Details go to the log only; the response must not expose internals.
        logger.warning("Readiness check '%s' failed", name, exc_info=True)
        return "error"
    return "ok" if ok else "error"


@router.get("/health", response_model=Liveness)
async def liveness() -> Liveness:
    """The process is serving requests. Does not touch dependencies."""
    return Liveness(status="ok")


@router.get(
    "/health/ready",
    response_model=Readiness,
    responses={503: {"model": Readiness, "description": "A dependency is unavailable"}},
)
async def readiness(request: Request, response: Response) -> Readiness:
    """PostgreSQL and Redis are reachable."""
    state = request.app.state
    database, redis = await asyncio.gather(
        _probe("database", check_database(state.engine)),
        _probe("redis", check_redis(state.redis)),
    )
    checks = {"database": database, "redis": redis}
    ready = all(value == "ok" for value in checks.values())
    if not ready:
        response.status_code = 503
    return Readiness(status="ready" if ready else "unavailable", checks=checks)
