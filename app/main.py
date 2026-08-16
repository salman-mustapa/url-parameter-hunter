from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.router import router
from app.core.config import settings
from app.core.db import AsyncSessionLocal, init_db, ping
from app.core.events import event_bus
from app.core.logging import setup_logging
from app.services.results import result_service

setup_logging()
logger = logging.getLogger("app")

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    event_bus.set_persister(result_service.persist_event)
    logger.info("Bug Hunter started. DB ready.")
    yield


app = FastAPI(title="Bug Hunter API", version="0.4.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready():
    return {"ready": await ping()}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(status_code=500, content={"detail": f"Internal server error: {type(exc).__name__}: {str(exc)}"})


# ---- frontend SPA ----
frontend_path = BASE_DIR / "frontend"


@app.get("/")
async def root():
    index = frontend_path / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Bug Hunter API", "docs": "/docs", "version": "0.4.0"}


if frontend_path.exists():
    for static_dir in ("css", "js"):
        p = frontend_path / static_dir
        if p.exists():
            app.mount(f"/{static_dir}", StaticFiles(directory=p), name=f"frontend-{static_dir}")

    @app.get("/{full_path:path}")
    async def serve_frontend(request: Request, full_path: str):
        path = frontend_path / full_path
        if full_path and path.exists() and path.is_file():
            return FileResponse(path)
        return FileResponse(frontend_path / "index.html")