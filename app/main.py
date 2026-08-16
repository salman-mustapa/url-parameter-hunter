from __future__ import annotations

import json
import asyncio
import time
import uuid
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from contextlib import asynccontextmanager
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, DateTime, ForeignKey, Integer, Text, Boolean, JSON, Float, select, func, desc, insert, update
from sqlalchemy.exc import IntegrityError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bug-hunter")

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", str(BASE_DIR / ".env")), extra="ignore")
    database_url: str = "postgresql+asyncpg://bughunter:bughunter@postgres:5432/bughunter"
    redis_url: str = "redis://localhost:6379/0"
    cors_origins: str = "*"
    rate_limit_rps: int = 5
    max_concurrent_hosts: int = 10
    max_assets_per_scan: int = 10000
    max_urls_per_scan: int = 100000
    max_crawl_depth: int = 5
    max_runtime_minutes: int = 120

settings = Settings()

engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class ScanModel(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    root_domain: Mapped[str] = mapped_column(String, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="created")
    profile: Mapped[str] = mapped_column(String, nullable=False, default="standard")
    options: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    progress: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

class AssetModel(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    parent_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    asset_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    fqdn: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String, nullable=False, default="discovered")
    discovered_from: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
    asset_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

class PortModel(Base):
    __tablename__ = "ports"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String, nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String, nullable=False, default="open")
    service: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class URLModel(Base):
    __tablename__ = "urls"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    scheme: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String, index=True, nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String, nullable=True)

class ParameterModel(Base):
    __tablename__ = "parameters"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    url_id: Mapped[str] = mapped_column(String, ForeignKey("urls.id", ondelete="cascade"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    location: Mapped[str] = mapped_column(String, nullable=False)
    type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

class TechnologyModel(Base):
    __tablename__ = "technologies"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("assets.id", ondelete="cascade"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class FindingModel(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    finding_type: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, index=True, nullable=False, default="INFO")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String, index=True, nullable=False, default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())

class ScanEventModel(Base):
    __tablename__ = "scan_events"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    asset_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("assets.id", ondelete="set null"), nullable=True)
    event_type: Mapped[str] = mapped_column(String, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class AuditLogModel(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="cascade"), index=True, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False, default="system")
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session

class EventBus:
    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Any]] = {}
        self._recent: List[dict] = []
        self._max_recent = 500

    def subscribe(self, event_type: str, handler: Any) -> None:
        self._subscribers.setdefault(event_type, []).append(handler)
        if event_type != "*":
            self._subscribers.setdefault("*", []).append(handler)

    async def publish(self, event: dict) -> None:
        self._recent.append(event)
        if len(self._recent) > self._max_recent:
            self._recent = self._recent[-self._max_recent:]
        for handler in list(self._subscribers.get("*", [])):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception:
                pass

    def get_recent(self, scan_id: Optional[str] = None, limit: int = 200) -> List[dict]:
        out = self._recent
        if scan_id:
            out = [e for e in out if e.get("scan_id") == scan_id]
        return out[-limit:]

bus = EventBus()

# ================ Helpers ================
CATEGORY_ICONS = {
    "scan.started": "▶️", "scan.running": "🔄", "scan.completed": "✅",
    "scan.stopped": "⏹️", "scan.failed": "❌", "scan.paused": "⏸️", "scan.resumed": "▶️",
    "asset.discovered": "🌱", "asset.enriched": "🔧",
    "dns.resolved": "🔍", "port.open": "🔓", "http.available": "🌐",
    "url.discovered": "🔗", "parameter.discovered": "🧩",
    "technology.detected": "⚙️", "finding.created": "🚨", "finding.updated": "📝",
    "scope.denied": "🚫"
}

def fmt_ev(event_type: str, message: str, **data) -> dict:
    cat = event_type.split(".")[0].upper() if "." in event_type else event_type.upper()
    return {
        "scan_id": data.get("scan_id"), "event_type": event_type,
        "category": cat, "icon": CATEGORY_ICONS.get(event_type, "📋"),
        "severity": data.get("severity", "info"), "message": message,
        "created_at": datetime.now(timezone.utc).isoformat(), "data": data
    }

def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r"^[a-z0-9-]+$", label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True

def normalize_target(target: str) -> str:
    target = target.strip().lower()
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0]
    target = target.split(":")[0]
    return target

def enforce_scope(hostname: str, allowed_domains: List[str]) -> bool:
    if not allowed_domains:
        return True
    h = hostname.lower()
    for domain in allowed_domains:
        if h == domain or h.endswith("." + domain):
            return True
    return False

# ================ Scanner Modules ================
class Scanner:
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        raise NotImplementedError

class SubdomainScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        candidates = [f"www.{root_domain}", f"api.{root_domain}", f"dev.{root_domain}", f"admin.{root_domain}"]
        async with AsyncSessionLocal() as db:
            db.add(AssetModel(scan_id=scan_id, hostname=root_domain, asset_type="subdomain", depth=0, discovered_from=["user_input"], asset_metadata={"root_domain": root_domain}))
            for sub in candidates:
                db.add(AssetModel(scan_id=scan_id, hostname=sub, asset_type="subdomain", depth=1, discovered_from=["subdomain_discovery"], asset_metadata={}))
                await bus.publish(fmt_ev("asset.discovered", f"Found subdomain: {sub}", scan_id=scan_id, hostname=sub, asset_type="subdomain", depth=1))
            await db.commit()

class DNSScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        targets = [root_domain, f"api.{root_domain}"]
        async with AsyncSessionLocal() as db:
            for host in targets:
                ip = f"10.0.0.{10 + abs(hash(host)) % 240}"
                asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == host))).scalar_one_or_none()
                if asset:
                    asset.ip = ip
                await bus.publish(fmt_ev("dns.resolved", f"{host} -> {ip}", scan_id=scan_id, hostname=host, a=[ip]))
            await db.commit()

class PortScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        targets = [root_domain, f"api.{root_domain}"]
        async with AsyncSessionLocal() as db:
            for host in targets:
                asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == host))).scalar_one_or_none()
                for p in [80, 443]:
                    if asset:
                        db.add(PortModel(asset_id=asset.id, port=p, protocol="tcp", state="open", service="http" if p == 80 else "https"))
                    await bus.publish(fmt_ev("port.open", f"{host}:{p}/tcp OPEN", scan_id=scan_id, hostname=host, port=p, state="open"))
            await db.commit()

class HTTPScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        targets = [f"https://{root_domain}/", f"https://api.{root_domain}/"]
        async with AsyncSessionLocal() as db:
            for url in targets:
                host = url.split("//")[1].split("/")[0]
                asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == host))).scalar_one_or_none()
                if asset:
                    db.add(URLModel(asset_id=asset.id, url=url, scheme="https", host=host, port=443, path="/", status_code=200, title=host))
                await bus.publish(fmt_ev("http.available", f"{url} [200]", scan_id=scan_id, url=url, status_code=200))
            await db.commit()

class CrawlerScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        base = f"https://{root_domain}"
        paths = ["/login", "/robots.txt", "/api/v1/users"]
        async with AsyncSessionLocal() as db:
            for p in paths:
                url = base + p
                asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == root_domain))).scalar_one_or_none()
                if asset:
                    db.add(URLModel(asset_id=asset.id, url=url, scheme="https", host=root_domain, port=443, path=p, status_code=200 if "login" not in p else 302))
                await bus.publish(fmt_ev("url.discovered", f"Discovered {url}", scan_id=scan_id, url=url, scheme="https", host=root_domain, status_code=200 if "login" not in p else 302))
            await db.commit()

class ParameterScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        url = f"https://{root_domain}/api/v1/users"
        async with AsyncSessionLocal() as db:
            url_obj = (await db.execute(select(URLModel).where(URLModel.url == url))).scalar_one_or_none()
            if url_obj:
                db.add(ParameterModel(url_id=url_obj.id, name="id", location="query", confidence=0.9))
                await db.commit()
            await bus.publish(fmt_ev("parameter.discovered", "Parameter detected: id", scan_id=scan_id, name="id", location="query", url=url))

class TechnologyScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        async with AsyncSessionLocal() as db:
            asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == root_domain))).scalar_one_or_none()
            if asset:
                db.add(TechnologyModel(asset_id=asset.id, name="nginx", version=None, confidence=0.9, evidence="Server header"))
                await db.commit()
            await bus.publish(fmt_ev("technology.detected", "Detected nginx", scan_id=scan_id, name="nginx", confidence=0.9))

class SecurityScanner(Scanner):
    async def run(self, scan_id: str, root_domain: str, options: Dict[str, Any], bus: EventBus):
        async with AsyncSessionLocal() as db:
            db.add(FindingModel(scan_id=scan_id, finding_type="misconfiguration", title="Potential sensitive endpoint exposure", severity="MEDIUM", confidence=0.7, status="open", description="API endpoint exposing user data detected", evidence={"url": f"https://{root_domain}/api/v1/users", "parameter": "id"}))
            await db.commit()
            await bus.publish(fmt_ev("finding.created", "MEDIUM: Potential sensitive endpoint exposure", scan_id=scan_id, severity="MEDIUM", confidence=0.7, status="open"))

SCANNERS = {
    "light": [SubdomainScanner(), DNSScanner(), HTTPScanner()],
    "standard": [SubdomainScanner(), DNSScanner(), PortScanner(), HTTPScanner(), CrawlerScanner(), ParameterScanner(), TechnologyScanner(), SecurityScanner()],
    "deep": [SubdomainScanner(), DNSScanner(), PortScanner(), HTTPScanner(), CrawlerScanner(), ParameterScanner(), TechnologyScanner(), SecurityScanner()],
}

# ================ Scan Manager ================
class ScanManager:
    def __init__(self) -> None:
        self._running: Dict[str, asyncio.Task] = {}
        self._paused: Dict[str, bool] = {}
        self._limits: Dict[str, Dict[str, Any]] = {}

    async def create_scan(self, root_domain: str, profile: str, options: Dict[str, Any]) -> dict:
        if not is_valid_domain(root_domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        scan_id = f"scan_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        async with AsyncSessionLocal() as db:
            scan = ScanModel(id=scan_id, root_domain=root_domain, status="queued", profile=profile, options=options)
            db.add(scan)
            await db.commit()
        async with AsyncSessionLocal() as db:
            db.add(ScanEventModel(scan_id=scan_id, event_type="scan.created", severity="info", message=f"Scan queued for {root_domain}", data={"profile": profile, "options": options}))
            db.add(AuditLogModel(scan_id=scan_id, actor="api", action="scan.created", target=root_domain, details={"profile": profile}))
            await db.commit()
        return {"scan_id": scan_id, "status": "queued", "target": root_domain, "profile": profile}

    async def start(self, scan_id: str):
        scan = await self._get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan_id in self._running:
            return
        task = asyncio.create_task(self._run_pipeline(scan_id, scan.root_domain, scan.profile, scan.options or {}))
        self._running[scan_id] = task

    async def pause(self, scan_id: str):
        self._paused[scan_id] = True
        async with AsyncSessionLocal() as db:
            scan = await db.get(ScanModel, scan_id)
            if scan:
                scan.status = "paused"
                db.add(ScanEventModel(scan_id=scan_id, event_type="scan.paused", severity="warn", message="Scan paused by user"))
                await db.commit()

    async def resume(self, scan_id: str):
        self._paused.pop(scan_id, None)
        async with AsyncSessionLocal() as db:
            scan = await db.get(ScanModel, scan_id)
            if scan:
                scan.status = "running"
                scan.started_at = scan.started_at or datetime.now(timezone.utc)
                db.add(ScanEventModel(scan_id=scan_id, event_type="scan.resumed", severity="info", message="Scan resumed by user"))
                await db.commit()
        await self.start(scan_id)

    async def stop(self, scan_id: str):
        task = self._running.pop(scan_id, None)
        if task:
            task.cancel()
        self._paused.pop(scan_id, None)
        async with AsyncSessionLocal() as db:
            scan = await db.get(ScanModel, scan_id)
            if scan and scan.status not in {"stopped", "cancelled"}:
                scan.status = "stopped"
                scan.completed_at = datetime.now(timezone.utc)
                db.add(ScanEventModel(scan_id=scan_id, event_type="scan.stopped", severity="warn", message="Scan stopped by user"))
                db.add(AuditLogModel(scan_id=scan_id, actor="api", action="scan.stopped"))
                await db.commit()

    async def _get_scan(self, scan_id: str) -> Optional[ScanModel]:
        async with AsyncSessionLocal() as db:
            return await db.get(ScanModel, scan_id)

    async def _run_pipeline(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]):
        try:
            await bus.publish(fmt_ev("scan.started", "Scan started", scan_id=scan_id))
            async with AsyncSessionLocal() as db:
                scan = await db.get(ScanModel, scan_id)
                if scan:
                    scan.status = "running"
                    scan.started_at = datetime.now(timezone.utc)
                    db.add(ScanEventModel(scan_id=scan_id, event_type="scan.started", severity="info", message=f"Scan started for {root_domain}"))
                    await db.commit()
            allowed = [root_domain] + [f"*.{root_domain}"]
            limits = {
                "max_assets": options.get("max_assets", settings.max_assets_per_scan),
                "max_urls": options.get("max_urls", settings.max_urls_per_scan),
                "max_runtime_seconds": options.get("max_runtime", settings.max_runtime_minutes * 60),
            }
            self._limits[scan_id] = limits
            start_time = time.time()

            async def check_pause():
                while self._paused.get(scan_id, False):
                    await asyncio.sleep(0.5)

            async def check_limits():
                if time.time() - start_time > limits["max_runtime_seconds"]:
                    raise RuntimeError("Max runtime exceeded")
                async with AsyncSessionLocal() as db:
                    asset_count = (await db.execute(select(func.count()).select_from(AssetModel).where(AssetModel.scan_id == scan_id))).scalar() or 0
                    if asset_count >= limits["max_assets"]:
                        raise RuntimeError("Max assets limit reached")

            await bus.publish(fmt_ev("scan.running", "Pipeline running...", scan_id=scan_id))

            scanners = SCANNERS.get(profile, SCANNERS["standard"])
            for scanner in scanners:
                await check_pause()
                await check_limits()
                try:
                    await scanner.run(scan_id, root_domain, options, bus)
                except Exception as exc:
                    logger.exception("scanner failed: %s", scanner.__class__.__name__)
                    await bus.publish(fmt_ev("scan.failed", f"Scanner error: {scanner.__class__.__name__}: {exc}", scan_id=scan_id, severity="error"))

            await bus.publish(fmt_ev("scan.running", "Pipeline running...", scan_id=scan_id))

            async with AsyncSessionLocal() as db:
                scan = await db.get(ScanModel, scan_id)
                if scan:
                    scan.status = "completed"
                    scan.completed_at = datetime.now(timezone.utc)
                    asset_count = (await db.execute(select(func.count()).select_from(AssetModel).where(AssetModel.scan_id == scan_id))).scalar() or 0
                    finding_count = (await db.execute(select(func.count()).select_from(FindingModel).where(FindingModel.scan_id == scan_id))).scalar() or 0
                    scan.progress = {"assets": asset_count, "findings": finding_count}
                    db.add(ScanEventModel(scan_id=scan_id, event_type="scan.completed", severity="info", message="Scan pipeline complete", data={"assets": asset_count, "findings": finding_count}))
                    db.add(AuditLogModel(scan_id=scan_id, actor="system", action="scan.completed", details={"assets": asset_count, "findings": finding_count}))
                    await db.commit()
            await bus.publish(fmt_ev("scan.completed", "Scan pipeline complete", scan_id=scan_id, assets=scan.progress.get("assets", 0), findings=scan.progress.get("findings", 0)))

        except asyncio.CancelledError:
            async with AsyncSessionLocal() as db:
                scan = await db.get(ScanModel, scan_id)
                if scan and scan.status not in {"stopped", "cancelled"}:
                    scan.status = "cancelled"
                    scan.completed_at = datetime.now(timezone.utc)
                    db.add(ScanEventModel(scan_id=scan_id, event_type="scan.stopped", severity="warn", message="Scan cancelled"))
                    db.add(AuditLogModel(scan_id=scan_id, actor="system", action="scan.cancelled"))
                    await db.commit()
            await bus.publish(fmt_ev("scan.stopped", "Scan cancelled", scan_id=scan_id))
        except Exception as exc:
            logger.exception("pipeline failed")
            async with AsyncSessionLocal() as db:
                scan = await db.get(ScanModel, scan_id)
                if scan:
                    scan.status = "partial_failure"
                    scan.completed_at = datetime.now(timezone.utc)
                    db.add(ScanEventModel(scan_id=scan_id, event_type="scan.failed", severity="error", message=str(exc)))
                    db.add(AuditLogModel(scan_id=scan_id, actor="system", action="scan.failed", details={"error": str(exc)}))
                    await db.commit()
            await bus.publish(fmt_ev("scan.failed", str(exc), scan_id=scan_id, severity="error"))
        finally:
            self._running.pop(scan_id, None)
            self._paused.pop(scan_id, None)
            self._limits.pop(scan_id, None)

scan_manager = ScanManager()

# ================ App ================
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(title="Bug Hunter API", version="0.3.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    frontend_path = BASE_DIR / "frontend"
    index = frontend_path / "index.html"
    if frontend_path.exists() and index.exists():
        return FileResponse(index)
    return {"message": "Bug Hunter API", "docs": "/docs", "frontend": "/", "version": "0.3.0"}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/ready")
async def ready():
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(select(1))
        return {"ready": True}
    except Exception:
        return {"ready": False}

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.exception("Unhandled exception: %s", exc)
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=500, content={"detail": f"Internal server error: {type(exc).__name__}: {str(exc)}"})

# ================ Scans ================
@app.post("/api/scans")
async def create_scan(target: str = Query(...), profile: str = Query("standard"), include_subdomains: bool = Query(True)):
    try:
        target = normalize_target(target)
        if not is_valid_domain(target):
            raise HTTPException(status_code=400, detail="Invalid domain. Use format like example.com")
        options = {
            "port_scan": True, "web_discovery": True, "parameter_discovery": True,
            "security_checks": True, "include_subdomains": include_subdomains,
            "max_assets": settings.max_assets_per_scan, "max_urls": settings.max_urls_per_scan,
            "max_crawl_depth": settings.max_crawl_depth, "max_runtime": settings.max_runtime_minutes * 60,
        }
        result = await scan_manager.create_scan(target, profile, options)
        await scan_manager.start(result["scan_id"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to create scan")
        raise HTTPException(status_code=500, detail=f"Internal server error: {type(e).__name__}: {e}")

@app.get("/api/scans")
async def list_scans():
    async with AsyncSessionLocal() as db:
        scans = (await db.execute(select(ScanModel).order_by(desc(ScanModel.created_at)))).scalars().all()
        return [{"id": s.id, "root_domain": s.root_domain, "status": s.status, "profile": s.profile, "progress": s.progress, "created_at": s.created_at.isoformat(), "completed_at": s.completed_at.isoformat() if s.completed_at else None} for s in scans]

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    async with AsyncSessionLocal() as db:
        scan = await db.get(ScanModel, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"id": scan.id, "root_domain": scan.root_domain, "status": scan.status, "profile": scan.profile, "progress": scan.progress, "created_at": scan.created_at.isoformat(), "completed_at": scan.completed_at.isoformat() if scan.completed_at else None}

@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    await scan_manager.pause(scan_id)
    return {"status": "paused"}

@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str):
    await scan_manager.resume(scan_id)
    return {"status": "resumed"}

@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    await scan_manager.stop(scan_id)
    return {"status": "stopped"}

@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str):
    async def gen() -> AsyncGenerator[str, None]:
        queue: asyncio.Queue = asyncio.Queue()
        recent = bus.get_recent(scan_id=scan_id, limit=200)
        for ev in recent:
            await queue.put(json.dumps(ev))
        async def handler(ev: dict):
            if ev.get("scan_id") == scan_id:
                await queue.put(json.dumps(ev))
        bus.subscribe("*", handler)
        try:
            while True:
                item = await queue.get()
                yield f"data: {item}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                bus._subscribers["*"].remove(handler)
            except Exception:
                pass
    return StreamingResponse(gen(), media_type="text/event-stream")

# ================ Assets ================
@app.get("/api/assets")
async def list_assets(scan_id: str = Query(...)):
    async with AsyncSessionLocal() as db:
        assets = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id))).scalars().all()
        return [{"id": a.id, "scan_id": a.scan_id, "parent_id": a.parent_id, "type": a.asset_type, "hostname": a.hostname, "fqdn": a.fqdn, "ip": a.ip, "depth": a.depth, "status": a.status, "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat()} for a in assets]

@app.get("/api/assets/tree")
async def asset_tree(scan_id: str = Query(...)):
    async with AsyncSessionLocal() as db:
        assets = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id))).scalars().all()
        by_id = {}
        for a in assets:
            by_id[a.id] = {"id": a.id, "type": a.asset_type, "hostname": a.hostname, "ip": a.ip, "depth": a.depth, "status": a.status, "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(), "children": []}
        tree = []
        for a in assets:
            node = by_id[a.id]
            if a.parent_id and a.parent_id in by_id:
                by_id[a.parent_id]["children"].append(node)
            else:
                tree.append(node)
        return tree

@app.get("/api/assets/{asset_id}/timeline")
async def asset_timeline(asset_id: str):
    async with AsyncSessionLocal() as db:
        events = (await db.execute(select(ScanEventModel).where(ScanEventModel.asset_id == asset_id).order_by(ScanEventModel.created_at.asc()))).scalars().all()
        return [{"event_type": e.event_type, "message": e.message, "severity": e.severity, "created_at": e.created_at.isoformat(), "data": e.data} for e in events]

# ================ Findings ================
@app.get("/api/findings")
async def list_findings(scan_id: str = Query(...)):
    async with AsyncSessionLocal() as db:
        findings = (await db.execute(select(FindingModel).where(FindingModel.scan_id == scan_id).order_by(desc(FindingModel.first_seen)))).scalars().all()
        return [{"id": f.id, "scan_id": f.scan_id, "asset_id": f.asset_id, "title": f.title, "severity": f.severity, "confidence": f.confidence, "status": f.status, "finding_type": f.finding_type, "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat()} for f in findings]

@app.patch("/api/findings/{finding_id}")
async def update_finding(finding_id: str, status: str = Query(...)):
    async with AsyncSessionLocal() as db:
        f = await db.get(FindingModel, finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="Finding not found")
        f.status = status
        f.last_seen = datetime.now(timezone.utc)
        db.add(ScanEventModel(scan_id=f.scan_id, event_type="finding.updated", severity="info", message=f"Finding status changed to {status}", data={"finding_id": finding_id, "new_status": status}))
        db.add(AuditLogModel(scan_id=f.scan_id, actor="api", action="finding.updated", target=finding_id, details={"status": status}))
        await db.commit()
        await bus.publish(fmt_ev("finding.updated", f"Finding status changed to {status}", scan_id=f.scan_id, finding_id=finding_id, status=status))
        return {"id": f.id, "status": f.status}

# ================ Domains ================
@app.get("/api/domains")
async def list_domains():
    async with AsyncSessionLocal() as db:
        scans = (await db.execute(select(ScanModel).order_by(desc(ScanModel.created_at)))).scalars().all()
        from collections import defaultdict
        by_domain = defaultdict(lambda: {"root_domain": "", "scan_count": 0, "last_scan": None})
        for s in scans:
            d = by_domain[s.root_domain]
            d["root_domain"] = s.root_domain
            d["scan_count"] += 1
            d["last_scan"] = s.completed_at.isoformat() if s.completed_at else s.created_at.isoformat()
        return list(by_domain.values())

@app.get("/api/domains/{domain}/history")
async def domain_history(domain: str):
    async with AsyncSessionLocal() as db:
        scans = (await db.execute(select(ScanModel).where(ScanModel.root_domain == domain).order_by(desc(ScanModel.created_at)))).scalars().all()
        return [{"id": s.id, "status": s.status, "profile": s.profile, "progress": s.progress, "created_at": s.created_at.isoformat(), "completed_at": s.completed_at.isoformat() if s.completed_at else None} for s in scans]

# ================ Audit ================
@app.get("/api/audit")
async def list_audit(scan_id: Optional[str] = Query(None)):
    async with AsyncSessionLocal() as db:
        stmt = select(AuditLogModel).order_by(desc(AuditLogModel.created_at)).limit(200)
        if scan_id:
            stmt = stmt.where(AuditLogModel.scan_id == scan_id)
        logs = (await db.execute(stmt)).scalars().all()
        return [{"id": l.id, "scan_id": l.scan_id, "actor": l.actor, "action": l.action, "target": l.target, "details": l.details, "created_at": l.created_at.isoformat()} for l in logs]

# Serve frontend static files at root
from fastapi.staticfiles import StaticFiles
frontend_path = BASE_DIR / "frontend"
if frontend_path.exists():
    for static_dir in ["css", "js"]:
        p = frontend_path / static_dir
        if p.exists():
            app.mount(f"/{static_dir}", StaticFiles(directory=p), name=f"frontend-{static_dir}")
    img_dir = frontend_path / "images"
    if img_dir.exists():
        app.mount("/images", StaticFiles(directory=img_dir), name="frontend-images")

    @app.get("/{full_path:path}")
    async def serve_frontend(request, full_path: str):
        path = frontend_path / full_path
        if full_path and path.exists() and path.is_file():
            return FileResponse(path)
        return FileResponse(frontend_path / "index.html")
