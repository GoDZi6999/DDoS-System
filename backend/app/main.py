"""FastAPI application entry point: `uvicorn app.main:app`."""

import math
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from app import __version__
from app.api import health, metrics
from app.api.v1 import router as api_v1_router
from app.api.v2 import router as api_v2_router
from app.core.config import get_settings
from app.db.session import create_engine, create_sessionmaker
from app.services.errors import ConflictError, NotFoundError, UnprocessableError

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}
# Not applied to /docs, which loads Swagger UI assets from a CDN.
API_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def _json_safe(value: Any) -> Any:
    """Validation errors echo the rejected input, which may be a float JSON cannot
    encode (a number like 1e400 parses to infinity)."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    # Both clients connect lazily, so startup does not fail while a dependency
    # is still booting; /health/ready reports their state instead.
    app.state.engine = create_engine(settings.database_url)
    app.state.sessionmaker = create_sessionmaker(app.state.engine)
    app.state.redis = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=5)
    try:
        yield
    finally:
        await app.state.redis.aclose()
        await app.state.engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(title="ArgusAI API", version=__version__, lifespan=lifespan)
    app.include_router(health.router)
    app.include_router(api_v1_router)
    app.include_router(api_v2_router)
    if get_settings().metrics_enabled:
        app.include_router(metrics.router)

    @app.exception_handler(NotFoundError)
    async def not_found(_: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=status.HTTP_404_NOT_FOUND)

    @app.exception_handler(ConflictError)
    async def conflict(_: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=status.HTTP_409_CONFLICT)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, exc: RequestValidationError) -> JSONResponse:
        detail = _json_safe(jsonable_encoder(exc.errors()))
        return JSONResponse({"detail": detail}, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)

    @app.exception_handler(UnprocessableError)
    async def unprocessable(_: Request, exc: UnprocessableError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        timer = metrics.Timer()
        response = await call_next(request)
        metrics.observe(
            metrics.route_template(request), request.method, response.status_code, timer.elapsed()
        )
        headers = SECURITY_HEADERS | (
            API_HEADERS if request.url.path.startswith(("/api/", "/v2/")) else {}
        )
        for name, value in headers.items():
            response.headers.setdefault(name, value)
        return response

    return app


app = create_app()
