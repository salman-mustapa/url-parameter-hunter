from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.router import router
from app.core.config import settings
from app.core.db import engine, init_db, ping
from app.core.events import event_bus
from app.core.logging import setup_logging
from app.core.http_security import HTTPSecurityMiddleware
from app.services.results import result_service

setup_logging()
logger = logging.getLogger("app")

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    event_bus.set_persister(result_service.persist_event)
    # Connect EventBus to Redis (§9, §42) — falls back to in-memory if unavailable
    await event_bus.connect_redis(settings.redis_url)
    
    # Auto-resume is configurable because small SQLite/local deployments can
    # lock up if many interrupted scans rehydrate at once.
    if settings.auto_resume_scans_on_startup:
        from app.services.scan_manager import scan_manager

        task = asyncio.create_task(
            scan_manager.resume_pending_scans(max_scans=settings.max_auto_resume_scans)
        )

        def _log_resume_error(done_task: asyncio.Task) -> None:
            try:
                done_task.result()
            except Exception as exc:
                logger.warning("Auto-resume scans failed: %s", exc)

        task.add_done_callback(_log_resume_error)
    else:
        logger.info("Auto-resume pending scans disabled; startup stays idle until a scan is requested.")

    logger.info("Bug Hunter v%s started. DB ready.", settings.app_version)
    try:
        yield
    finally:
        from app.services.scan_manager import scan_manager
        await scan_manager.close()
        await result_service.close()
        await event_bus.close()
        await engine.dispose()


from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html


app = FastAPI(
    title="Hunter Aja — Attack Surface & Parameter API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()],
    allow_credentials="*" not in settings.cors_origins.split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.add_middleware(HTTPSecurityMiddleware)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    healthy = await ping()
    return JSONResponse({"ready": healthy}, status_code=200 if healthy else 503)


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Hunter Aja API — Interactive Documentation",
        swagger_js_url="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js",
        swagger_css_url="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@app.get("/redoc", include_in_schema=False)
async def custom_redoc():
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="Hunter Aja API — ReDoc Reference",
        redoc_js_url="https://cdnjs.cloudflare.com/ajax/libs/redoc/2.1.3/redoc.standalone.js",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# ---- frontend SPA ----
frontend_path = BASE_DIR / "frontend"


@app.get("/")
async def root():
    index = frontend_path / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Hunter Aja API", "docs": "/docs", "version": "1.0.0"}


if frontend_path.exists():
    for static_dir in ("css", "js", "vendor", "views"):
        p = frontend_path / static_dir
        if p.exists():
            app.mount(f"/{static_dir}", StaticFiles(directory=p), name=f"frontend-{static_dir}")

    @app.get("/{full_path:path}")
    async def serve_frontend(request: Request, full_path: str):
        if full_path in ("docs", "redoc", "openapi.json") or full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        path = (frontend_path / full_path).resolve()
        if not path.is_relative_to(frontend_path.resolve()):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        if full_path and path.exists() and path.is_file():
            return FileResponse(path)
        return FileResponse(frontend_path / "index.html")
