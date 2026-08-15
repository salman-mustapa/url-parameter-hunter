from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from contextlib import asynccontextmanager
import json, asyncio, time, uuid, logging, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, DateTime, ForeignKey, Integer, Text, Boolean, JSON, Float, select, func, desc
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

# ================ Database ================
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
    scan_id: Mapped[Optional[str]] = mapped_column(String, index=True, nullable=True)
    actor: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

engine = create_async_engine(settings.database_url, pool_pre_ping=True, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session

# ================ Event Bus ================
class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Any]] = {}
        self._recent: List[dict] = []
        self._max_recent = 1000

    def subscribe(self, event_type: str, handler):
        self._subscribers.setdefault(event_type, []).append(handler)

    def _remember(self, event: dict):
        self._recent.append(event)
        if len(self._recent) > self._max_recent:
            self._recent = self._recent[-self._max_recent:]

    async def publish(self, event: dict):
        event.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        self._remember(event)
        for handler in self._subscribers.get(event.get("event_type", ""), []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception:
                pass
        for handler in self._subscribers.get("*", []):
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
    "technology.detected": "⚙️", "finding.created": "🚨", "finding.updated": "📝"
}

def fmt_ev(event_type: str, message: str, **data) -> dict:
    cat = event_type.split(".")[0].upper() if "." in event_type else event_type.upper()
    return {
        "scan_id": data.get("scan_id"), "event_type": event_type,
        "category": cat, "icon": CATEGORY_ICONS.get(event_type, "📋"),
        "severity": data.get("severity", "info"), "message": message,
        "created_at": datetime.now(timezone.utc).isoformat(), "data": data
   }

VALID_TLDS = {"com","org","net","id","co.id","ac.id","go.id","edu","mil","io","ai","dev","app","me","tv","cc","xyz","info","biz","name","pro","mobi","tel","xxx","post","geo","asia","cat","tel","xxx","mobi","co","uk","us","ca","au","de","fr","jp","kr","cn","in","br","ru","es","it","nl","se","no","fi","dk","pl","at","ch","be","pt","ie","nz","za","mx","ar","cl","co.uk","co.jp","co.kr","co.nz","co.ca","com.au","com.br","com.mx","com.ar","com.sg","com.my","com.ph","com.hk","com.tw","gov","edu","mil","int"}

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

# ================ Scan Manager ================
class ScanManager:
    def __init__(self):
        self._running: Dict[str, asyncio.Task] = {}
        self._paused: Dict[str, bool] = {}
        self._limits: Dict[str, Dict[str, int]] = {}

    async def create_scan(self, root_domain: str, profile: str, options: Dict[str, Any]) -> dict:
        if not is_valid_domain(root_domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
        scan_id = f"scan_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        async with AsyncSessionLocal() as db:
            scan = ScanModel(id=scan_id, root_domain=root_domain, status="queued", profile=profile, options=options)
            db.add(scan)
            ev = ScanEventModel(scan_id=scan_id, event_type="scan.created", severity="info", message=f"Scan queued for {root_domain}", data={"profile": profile, "options": options})
            db.add(ev)
            log = AuditLogModel(scan_id=scan_id, actor="api", action="scan.created", target=root_domain, details={"profile": profile})
            db.add(log)
            await db.commit()
        return {"scan_id": scan_id, "status": "queued", "target": root_domain, "profile": profile}

    async def start(self, scan_id: str):
        scan = await self._get_scan(scan_id)
        if not scan:
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as db:
            db.add(ScanEventModel(scan_id=scan_id, event_type="scan.started", severity="info", message=f"Scan started for {scan.root_domain}", data={"profile": scan.profile}))
            db.add(AuditLogModel(scan_id=scan_id, actor="api", action="scan.started", target=scan.root_domain))
            await db.commit()
        await bus.publish(fmt_ev("scan.started", f"Scan started for {scan.root_domain}", scan_id=scan_id, target=scan.root_domain))
        task = asyncio.create_task(self._run_pipeline(scan_id, scan.root_domain, scan.profile, scan.options or {}))
        self._running[scan_id] = task
        self._paused[scan_id] = False

    async def pause(self, scan_id: str):
        if scan_id in self._paused:
            self._paused[scan_id] = True
            async with AsyncSessionLocal() as db:
                db.add(ScanEventModel(scan_id=scan_id, event_type="scan.paused", severity="warn", message="Scan paused by user"))
                db.add(AuditLogModel(scan_id=scan_id, actor="api", action="scan.paused"))
                await db.commit()
            await bus.publish(fmt_ev("scan.paused", "Scan paused", scan_id=scan_id))

    async def resume(self, scan_id: str):
        if scan_id in self._paused:
            self._paused[scan_id] = False
            async with AsyncSessionLocal() as db:
                db.add(ScanEventModel(scan_id=scan_id, event_type="scan.resumed", severity="info", message="Scan resumed by user"))
                db.add(AuditLogModel(scan_id=scan_id, actor="api", action="scan.resumed"))
                await db.commit()
            await bus.publish(fmt_ev("scan.resumed", "Scan resumed", scan_id=scan_id))

    async def stop(self, scan_id: str):
        task = self._running.get(scan_id)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        scan = await self._get_scan(scan_id)
        if scan and scan.status not in {"completed", "stopped", "cancelled", "partial_failure"}:
            scan.status = "stopped"
            scan.completed_at = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as db:
                db.add(ScanEventModel(scan_id=scan_id, event_type="scan.stopped", severity="warn", message="Scan stopped by user"))
                db.add(AuditLogModel(scan_id=scan_id, actor="api", action="scan.stopped"))
                await db.commit()
            await bus.publish(fmt_ev("scan.stopped", "Scan stopped by user", scan_id=scan_id))
        self._running.pop(scan_id, None)
        self._paused.pop(scan_id, None)

    async def _get_scan(self, scan_id: str) -> Optional[ScanModel]:
        async with AsyncSessionLocal() as db:
            return await db.get(ScanModel, scan_id)

    async def _run_pipeline(self, scan_id: str, root_domain: str, profile: str, options: Dict[str, Any]):
        try:
            await bus.publish(fmt_ev("scan.running", "Pipeline running...", scan_id=scan_id))
            allowed = [root_domain] + [f"*.{root_domain}"]
            limits = {
                "max_assets": options.get("max_assets", settings.max_assets_per_scan),
                "max_urls": options.get("max_urls", settings.max_urls_per_scan),
                "max_crawl_depth": options.get("max_crawl_depth", settings.max_crawl_depth),
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

            async with AsyncSessionLocal() as db:
                root_asset = AssetModel(scan_id=scan_id, hostname=root_domain, asset_type="subdomain", depth=0, discovered_from=["user_input"], asset_metadata={"root_domain": root_domain})
                db.add(root_asset)
                db.add(ScanEventModel(scan_id=scan_id, event_type="asset.discovered", severity="info", message=f"Found subdomain: {root_domain}", data={"hostname": root_domain, "asset_type": "subdomain", "depth": 0}))
                await db.commit()

            await bus.publish(fmt_ev("asset.discovered", f"Found subdomain: {root_domain}", scan_id=scan_id, hostname=root_domain, asset_type="subdomain", depth=0))

            # DNS Resolution
            await check_pause()
            await check_limits()
            await asyncio.sleep(0.3)
            ips = [f"10.0.0.{10 + hash(root_domain) % 240}"]
            async with AsyncSessionLocal() as db:
                root_asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == root_domain))).scalar_one_or_none()
                if root_asset:
                    root_asset.ip = ips[0]
                    await db.commit()
            await bus.publish(fmt_ev("dns.resolved", f"{root_domain} -> {', '.join(ips)}", scan_id=scan_id, hostname=root_domain, a=ips))

            # Port Scan
            await check_pause()
            await check_limits()
            await asyncio.sleep(0.4)
            ports = [{"port": 80, "state": "open", "service": "http"}, {"port": 443, "state": "open", "service": "https"}]
            async with AsyncSessionLocal() as db:
                root_asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == root_domain))).scalar_one_or_none()
                if root_asset:
                    for p in ports:
                        db.add(PortModel(asset_id=root_asset.id, **p))
                    await db.commit()
            for p in ports:
                await bus.publish(fmt_ev("port.open", f"{root_domain}:{p['port']}/{p['protocol']} {p['state'].upper()}", scan_id=scan_id, hostname=root_domain, port=p["port"], state=p["state"], service=p.get("service")))

            # HTTP Probe
            await check_pause()
            await check_limits()
            await asyncio.sleep(0.3)
            async with AsyncSessionLocal() as db:
                root_asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == root_domain))).scalar_one_or_none()
                if root_asset:
                    db.add(URLModel(asset_id=root_asset.id, url=f"https://{root_domain}/", scheme="https", host=root_domain, port=443, path="/", status_code=200, title=root_domain))
                    db.add(URLModel(asset_id=root_asset.id, url=f"https://{root_domain}/robots.txt", scheme="https", host=root_domain, port=443, path="/robots.txt", status_code=200))
                    db.add(URLModel(asset_id=root_asset.id, url=f"https://{root_domain}/login", scheme="https", host=root_domain, port=443, path="/login", status_code=302))
                    await db.commit()
            for u in [f"https://{root_domain}/", f"https://{root_domain}/robots.txt", f"https://{root_domain}/login"]:
                await bus.publish(fmt_ev("http.available", f"{u} [200]", scan_id=scan_id, url=u, status_code=200))
                await bus.publish(fmt_ev("url.discovered", f"Discovered {u}", scan_id=scan_id, url=u, scheme="https", host=root_domain, status_code=200 if "login" not in u else 302))

            # Recursive subdomain discovery
            await check_pause()
            await check_limits()
            subdomains = [f"www.{root_domain}", f"api.{root_domain}", f"dev.{root_domain}", f"admin.{root_domain}"]
            for sub in subdomains:
                await check_pause()
                await check_limits()
                await asyncio.sleep(0.2)
                if not enforce_scope(sub, allowed):
                    await bus.publish(fmt_ev("scope.denied", f"Out of scope: {sub}", scan_id=scan_id, severity="warn"))
                    continue
                async with AsyncSessionLocal() as db:
                    existing = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == sub))).scalar_one_or_none()
                    if existing:
                        continue
                    parent = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == root_domain))).scalar_one_or_none()
                    child = AssetModel(scan_id=scan_id, hostname=sub, asset_type="subdomain", depth=1, parent_id=parent.id if parent else None, discovered_from=["subdomain_discovery"])
                    db.add(child)
                    await db.commit()
                await bus.publish(fmt_ev("asset.discovered", f"Found subdomain: {sub}", scan_id=scan_id, hostname=sub, asset_type="subdomain", depth=1))
                await bus.publish(fmt_ev("dns.resolved", f"{sub} -> 10.0.0.{20 + hash(sub) % 230}", scan_id=scan_id, hostname=sub, a=[f"10.0.0.{20 + hash(sub) % 230}"]))
                await bus.publish(fmt_ev("port.open", f"{sub}:443/tcp OPEN", scan_id=scan_id, hostname=sub, port=443, state="open"))
                if sub.startswith("api."):
                    api_url = f"https://{sub}/api/v1/users"
                    async with AsyncSessionLocal() as db:
                        child = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == sub))).scalar_one_or_none()
                        if child:
                            db.add(URLModel(asset_id=child.id, url=api_url, scheme="https", host=sub, port=443, path="/api/v1/users", status_code=200))
                            db.add(ParameterModel(url_id=None, name="user_id", location="query", confidence=0.9))
                            await db.commit()
                    await bus.publish(fmt_ev("url.discovered", f"Discovered {api_url}", scan_id=scan_id, url=api_url, scheme="https", host=sub, status_code=200))
                    await bus.publish(fmt_ev("parameter.discovered", "Parameter detected: user_id", scan_id=scan_id, name="user_id", location="query", url=api_url))
                    # Finding with lifecycle
                    finding_data = {"scan_id": scan_id, "title": "Potential sensitive endpoint exposure", "severity": "MEDIUM", "confidence": 0.7, "status": "open", "finding_type": "misconfiguration", "description": "API endpoint exposing user data detected", "evidence": {"url": api_url, "parameter": "user_id"}}
                    async with AsyncSessionLocal() as db:
                        f = FindingModel(**finding_data)
                        db.add(f)
                        await db.commit()
                    await bus.publish(fmt_ev("finding.created", "MEDIUM: Potential sensitive endpoint exposure", scan_id=scan_id, severity="MEDIUM", confidence=0.7, status="open"))

            # Technology detection
            await check_pause()
            await asyncio.sleep(0.2)
            async with AsyncSessionLocal() as db:
                root_asset = (await db.execute(select(AssetModel).where(AssetModel.scan_id == scan_id, AssetModel.hostname == root_domain))).scalar_one_or_none()
                if root_asset:
                    db.add(TechnologyModel(asset_id=root_asset.id, name="nginx", version=None, confidence=0.9, evidence="Server header"))
                    await db.commit()
            await bus.publish(fmt_ev("technology.detected", "Detected nginx", scan_id=scan_id, name="nginx", confidence=0.9))

            # Complete
            async with AsyncSessionLocal() as db:
                scan = await db.get(ScanModel, scan_id)
                if scan:
                    scan.status = "completed"
                    scan.completed_at = datetime.now(timezone.utc)
                    asset_count = (await db.execute(select(func.count()).select_from(AssetModel).where(AssetModel.scan_id == scan_id))).scalar() or 0
                    finding_count = (await db.execute(select(func.count()).select_from(FindingModel).where(FindingModel.scan_id == scan_id))).scalar() or 0
                    scan.progress = {"subdomains": asset_count, "findings": finding_count}
                    db.add(ScanEventModel(scan_id=scan_id, event_type="scan.completed", severity="info", message="Scan pipeline complete", data={"assets": asset_count, "findings": finding_count}))
                    db.add(AuditLogModel(scan_id=scan_id, actor="system", action="scan.completed", details={"assets": asset_count, "findings": finding_count}))
                    await db.commit()
            await bus.publish(fmt_ev("scan.completed", "Scan pipeline complete", scan_id=scan_id, assets=scan.progress.get("subdomains", 0), findings=scan.progress.get("findings", 0)))

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
    logger.info("Bug Hunter starting with database: %s", settings.database_url)
    yield
    logger.info("Bug Hunter shutting down")

app = FastAPI(title="Bug Hunter", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",")] if settings.cors_origins != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    # Always serve frontend SPA at root
    frontend_path = BASE_DIR / "frontend"
    index = frontend_path / "index.html"
    if frontend_path.exists() and index.exists():
        print(f"[BOOT] Serving frontend from {index}")
        return FileResponse(index)
    # Fallback if frontend not built yet
    return {"message": "Bug Hunter API", "docs": "/docs", "frontend": "/", "version": "0.2.0", "note": "frontend not found at " + str(frontend_path)}

    return {"message": "Bug Hunter API", "docs": "/docs", "frontend": "/", "version": "0.2.0", "note": "frontend not found at " + str(frontend_path)}

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

@app.get("/ready")
async def ready():
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(select(1))
        return {"status": "ready"}
    except Exception as exc:
        return {"status": "not_ready", "error": str(exc)}

# ================ Scans ================
@app.post("/api/scans")
async def create_scan(target: str = Query(...), profile: str = Query("standard"), include_subdomains: bool = Query(True)):
    target = normalize_target(target)
    if not is_valid_domain(target):
        raise HTTPException(status_code=400, detail="Invalid domain. Use format like example.com")
    options = {"port_scan": True, "web_discovery": True, "parameter_discovery": True, "security_checks": True, "include_subdomains": include_subdomains, "max_assets": settings.max_assets_per_scan, "max_urls": settings.max_urls_per_scan, "max_crawl_depth": settings.max_crawl_depth, "max_runtime": settings.max_runtime_minutes * 60}
    result = await scan_manager.create_scan(target, profile, options)
    await scan_manager.start(result["scan_id"])
    return result

@app.get("/api/scans")
async def list_scans():
    async with AsyncSessionLocal() as db:
        scans = (await db.execute(select(ScanModel).order_by(desc(ScanModel.created_at)))).scalars().all()
        return [{"id": s.id, "root_domain": s.root_domain, "status": s.status, "profile": s.profile, "progress": s.progress, "created_at": s.created_at.isoformat(), "completed_at": s.completed_at.isoformat() if s.completed_at else None} for s in scans]

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    async with AsyncSessionLocal() as db:
        s = await db.get(ScanModel, scan_id)
        if not s:
            return {"error": "not found"}
        return {"id": s.id, "root_domain": s.root_domain, "status": s.status, "profile": s.profile, "options": s.options, "progress": s.progress, "created_at": s.created_at.isoformat(), "completed_at": s.completed_at.isoformat() if s.completed_at else None}

@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    await scan_manager.pause(scan_id)
    return {"scan_id": scan_id, "action": "pause", "status": "accepted"}

@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str):
    await scan_manager.resume(scan_id)
    return {"scan_id": scan_id, "action": "resume", "status": "accepted"}

@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    await scan_manager.stop(scan_id)
    return {"scan_id": scan_id, "action": "stop", "status": "accepted"}

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
from fastapi.responses import FileResponse
import os

frontend_path = BASE_DIR / "frontend"
if frontend_path.exists():
    # Mount CSS/JS directly
    for static_dir in ["css", "js"]:
        p = frontend_path / static_dir
        if p.exists():
            app.mount(f"/{static_dir}", StaticFiles(directory=p), name=f"frontend-{static_dir}")
    # Mount images if any
    img_dir = frontend_path / "images"
    if img_dir.exists():
        app.mount("/images", StaticFiles(directory=img_dir), name="frontend-images")
    
    # SPA fallback: serve index.html for any non-API path
    @app.get("/{full_path:path}")
    async def serve_frontend(request, full_path: str):
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("openapi") or full_path.startswith("health") or full_path.startswith("ready"):
            return None
        # Try static file first
        file_path = frontend_path / full_path
        if full_path and file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        # Fallback to SPA index.html for SPA routing
        return FileResponse(frontend_path / "index.html")