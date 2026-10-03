"""FastAPI application entry point: `uvicorn app.main:app`."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import create_async_engine

from app import __version__
from app.api import health
from app.core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    # Both clients connect lazily, so startup does not fail while a dependency
    # is still booting; /health/ready reports their state instead.
    app.state.engine = create_async_engine(
        settings.database_url, pool_pre_ping=True, connect_args={"timeout": 2}
    )
    app.state.redis = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
    try:
        yield
    finally:
        await app.state.redis.aclose()
        await app.state.engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="SentinelAI API", version=__version__, lifespan=lifespan)
    app.include_router(health.router)
    return app


app = create_app()
