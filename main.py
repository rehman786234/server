import logging
import os
import sys
from contextlib import asynccontextmanager

import anyio.to_thread
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from config import Config
from database import init_connection_pool, close_all_connections, health_check
from indexes import ensure_indexes
from init_db import init_database
from routes import router
from security import SECURITY_HEADERS, RateLimiter, client_ip

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        logger.info("Starting up FastAPI application...")
        logger.info(f"Environment: {os.getenv('ENV', 'production')}")
        Config.validate()
        if not Config.SECRET_KEY:
            logger.warning("SECRET_KEY not set - login tokens reset on every restart")

        # Sync (def) endpoints run in this thread pool - make it big enough
        anyio.to_thread.current_default_thread_limiter().total_tokens = Config.THREADPOOL_SIZE

        init_connection_pool()
        init_database()
        ensure_indexes()
        logger.info("Database initialization completed")

        if health_check():
            logger.info("Database health check passed")
        else:
            logger.warning("Database health check failed")
        yield
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise
    finally:
        logger.info("Shutting down FastAPI application...")
        close_all_connections()


app = FastAPI(
    title="FastAPI Backend",
    description="FastAPI backend with PostgreSQL on Render",
    version="2.1.0",
    lifespan=lifespan,
    docs_url="/docs" if Config.ENABLE_DOCS else None,
    redoc_url="/redoc" if Config.ENABLE_DOCS else None,
    openapi_url="/openapi.json" if Config.ENABLE_DOCS else None,
)

_limiter = RateLimiter()
_AUTH_PATHS = {"/login", "/register", "/apikey/gen", "/profile/update", "/profile/password"}


class SecurityMiddleware:
    """Rate limiting, body-size limit and security headers (pure ASGI = fast)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                have = {k.lower() for k, _ in hdrs}
                hdrs += [(k, v) for k, v in SECURITY_HEADERS if k not in have]
                message["headers"] = hdrs
            await send(message)

        path = scope["path"]
        if scope["method"] != "OPTIONS" and path != "/health":
            headers = dict(scope["headers"])
            peer = scope["client"][0] if scope.get("client") else None
            ip = client_ip(headers.get(b"x-forwarded-for", b"").decode("latin-1"), peer)

            if not _limiter.allow(f"g|{ip}", Config.RATE_LIMIT_PER_MIN) or (
                path in _AUTH_PATHS and not _limiter.allow(f"a|{ip}", Config.AUTH_RATE_LIMIT_PER_MIN)
            ):
                resp = JSONResponse({"error": "Too many requests", "status_code": 429},
                                    status_code=429, headers={"Retry-After": "60"})
                await resp(scope, receive, send_wrapper)
                return

            cl = headers.get(b"content-length", b"")
            if cl.isdigit() and int(cl) > Config.MAX_BODY_BYTES:
                resp = JSONResponse({"error": "Request body too large", "status_code": 413},
                                    status_code=413)
                await resp(scope, receive, send_wrapper)
                return

        await self.app(scope, receive, send_wrapper)


# Last added = outermost, so CORS headers also appear on 429/413 replies
app.add_middleware(SecurityMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)
_allow_all = "*" in Config.ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.ORIGINS,
    allow_credentials=not _allow_all,  # credentials + "*" is unsafe/invalid; auth uses headers
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTP Exception: {exc.detail}")
    return JSONResponse(status_code=exc.status_code,
                        content={"error": exc.detail, "status_code": exc.status_code})


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(status_code=500,
                        content={"error": "Internal server error", "status_code": 500})


@app.get("/")
async def root():
    return {
        "message": "FastAPI Server Running Successfully",
        "database": "PostgreSQL",
        "environment": os.getenv("ENV", "production"),
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, workers=2)
