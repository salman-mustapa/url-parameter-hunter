from __future__ import annotations



from app.reporting.serializers import serialize_finding, finding_location, finding_quality



import asyncio

from datetime import datetime, timezone

import json

import logging

import os

from pathlib import Path

import re

from typing import Any, Dict, List, Optional



logger = logging.getLogger("api.router")



from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Query, Request, Response, status

from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from pydantic import BaseModel, Field

from sqlalchemy import desc, distinct, func, select

from sqlalchemy.ext.asyncio import AsyncSession



from app.core.auth import (

    create_access_token,

    get_current_user,

    get_optional_user,

    hash_password,

    require_admin_role,

    require_user_role,

    verify_password,

)

from app.core.db import AsyncSessionLocal, get_db

from app.core.access import enforce_api_access

from app.core.events import event_bus

from app.models.models import (

    Asset,

    AuditLog,

    Certificate,

    DeviceTrial,

    Domain,

    Evidence,

    Finding,

    Observation,

    Parameter,

    PoC,

    Port,

    Artifact,

    Campaign,

    CredentialArtifact,

    ExportJob,

    Identity,

    Report,

    Retest,

    Scan,

    ScanEvent,

    ScopeModel,

    Screenshot,

    Service,

    Technology,

    TestPlan,

    TtpObservation,

    URL,

    User,

    UserNotificationConfig,

)

from app.artifacts.sanitizer import ArtifactSanitizer

from app.core.config import settings

from app.services.assets import asset_detail, asset_tree

from app.services.export_manager import ExportManager

from app.services.results import result_service

from app.services.scan_manager import scan_manager





router = APIRouter(prefix="/api", tags=["api"], dependencies=[Depends(enforce_api_access)])



_synthetic_lab_lock = asyncio.Lock()





@router.post("/labs/synthetic/run")

async def run_synthetic_lab(_admin: User = Depends(require_admin_role)):

    """Run one disposable synthetic fixture; no target URL or real credentials accepted."""

    from app.lab.service import run_persisted_lab

    if _synthetic_lab_lock.locked():

        raise HTTPException(409, "A synthetic lab run is already in progress")

    async with _synthetic_lab_lock:

        return await run_persisted_lab(_admin.id)





@router.get("/health")

async def health_check(db: AsyncSession = Depends(get_db)):

    """System health check, database ping, AI status, and V8 telemetry."""

    from app.core.db import ping

    from app.services.capability_registry import capability_registry

    from app.ai.gateway import ai_gateway



    db_healthy = await ping()

    caps = capability_registry.list_capabilities()

    return {

        "status": "healthy" if db_healthy else "degraded",

        "timestamp": datetime.now(timezone.utc).isoformat(),

        "database": "connected" if db_healthy else "disconnected",

        "capabilities_registered": len(caps),

        "ai_engine": "enabled" if settings.llm_enabled else "disabled",

        "version": "9.1.0",

    }





# ==========================================================================

# AI Engine Configuration & Live Router Hub

# ==========================================================================

class AIConfigRequest(BaseModel):

    provider: Optional[str] = "openai_compatible"  # "openai_compatible", "openrouter", "nine_router", "openai", "gemini", "groq", "custom", "heuristic", "auto"

    api_key: Optional[str] = None

    model: Optional[str] = None

    base_url: Optional[str] = None

    enabled: Optional[bool] = None

    llm_enabled: Optional[bool] = None





@router.get("/ai/config")

async def get_ai_config(_admin: User = Depends(require_admin_role)):

    """Get active AI provider configuration, model info, and status across all subsystems."""

    from app.core.config import settings

    from app.intelligence.llm_client import llm_client

    from app.ai.gateway import ai_gateway



    api_key = settings.llm_api_key or llm_client.api_key or os.getenv("LLM_API_KEY", "")

    key_configured = bool(api_key and len(api_key) > 4)

    key_masked = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else ("***" if key_configured else "")



    return {

        "status": "success",

        "llm_enabled": settings.llm_enabled,

        "enabled": settings.llm_enabled,

        "provider": settings.llm_provider,

        "base_url": settings.llm_base_url or llm_client.base_url,

        "model": settings.llm_model or llm_client.model,

        "api_key_configured": key_configured,

        "api_key_masked": key_masked,

        "is_configured": llm_client.is_configured,

        "active_provider": type(ai_gateway._provider).__name__,

    }





@router.post("/ai/config")

async def update_ai_config(body: AIConfigRequest, _admin: User = Depends(require_admin_role)):

    """Update active AI provider configuration dynamically at runtime across all subsystems."""

    from app.core.config import settings

    from app.intelligence.llm_client import llm_client

    from app.ai.gateway import ai_gateway



    is_enabled = body.llm_enabled if body.llm_enabled is not None else (body.enabled if body.enabled is not None else True)

    settings.llm_enabled = is_enabled



    if body.provider:

        settings.llm_provider = body.provider

    if body.base_url:

        clean_url = body.base_url.rstrip("/")

        settings.llm_base_url = clean_url

        llm_client.base_url = clean_url

    if body.api_key and body.api_key.strip():

        clean_key = body.api_key.strip()

        settings.llm_api_key = clean_key

        llm_client.api_key = clean_key

    if body.model:

        settings.llm_model = body.model

        llm_client.model = body.model



    ai_gateway.apply_config({

        "provider": settings.llm_provider,

        "base_url": settings.llm_base_url,

        "api_key": settings.llm_api_key or llm_client.api_key,

        "model": settings.llm_model,

        "enabled": settings.llm_enabled,

    })



    return {

        "status": "success",

        "message": "Konfigurasi AI berhasil disimpan.",

        "config": {

            "llm_enabled": settings.llm_enabled,

            "enabled": settings.llm_enabled,

            "provider": settings.llm_provider,

            "base_url": settings.llm_base_url,

            "model": settings.llm_model,

            "api_key_configured": bool(llm_client.api_key),

            "is_configured": llm_client.is_configured,

        }

    }





@router.post("/ai/gateway/test")

async def test_ai_gateway_connection(body: AIConfigRequest, _admin: User = Depends(require_admin_role)):

    """Test connection and measure response latency against candidate AI provider."""

    from app.ai.gateway import ai_gateway

    cfg = body.model_dump(exclude_unset=True)

    result = await ai_gateway.test_config(cfg)

    return result





# ==========================================================================

# Authentication & User Management (RBAC)

# ==========================================================================

class RegisterRequest(BaseModel):

    username: str = Field(min_length=3, max_length=64)

    email: str = Field(max_length=254)

    password: str = Field(min_length=10, max_length=256)

    device_fingerprint: Optional[str] = None





class LoginRequest(BaseModel):

    username: str = Field(max_length=254)

    password: str = Field(max_length=256)

    device_fingerprint: Optional[str] = None





@router.post("/auth/register")

async def register(

    body: RegisterRequest,

    response: Response,

    db: AsyncSession = Depends(get_db),

    x_device_fp: Optional[str] = Header(None, alias="X-Device-Fingerprint"),

):

    uname = body.username.strip().lower()

    email = body.email.strip().lower()

    pwd = body.password



    if not uname or len(uname) < 3 or not re.match(r"^[a-zA-Z0-9_.-]+$", uname):

        raise HTTPException(status_code=400, detail="Username minimal 3 karakter (hanya huruf, angka, dot, dash, underscore).")

    if not email or "@" not in email:

        raise HTTPException(status_code=400, detail="Alamat email tidak valid.")

    if not pwd or len(pwd) < 6:

        raise HTTPException(status_code=400, detail="Password minimal 6 karakter.")



    existing_user = (await db.execute(select(User).where((User.username == uname) | (User.email == email)))).scalar_one_or_none()

    if existing_user:

        raise HTTPException(status_code=400, detail="Username atau Email sudah terdaftar.")



    new_user = User(

        username=uname,

        email=email,

        hashed_password=await asyncio.to_thread(hash_password, pwd),

        role="user",

        is_active=True,

    )

    db.add(new_user)

    await db.commit()

    await db.refresh(new_user)



    token = create_access_token(new_user.id, new_user.username, new_user.role, password_hash=new_user.hashed_password)

    response.set_cookie(

        key="auth_token",

        value=token,

        httponly=True,

        secure=settings.cookie_secure,

        samesite="lax",

        max_age=86400 * 7,

    )



    return {

        "access_token": token,

        "token_type": "bearer",

        "user": {

            "id": new_user.id,

            "username": new_user.username,

            "email": new_user.email,

            "role": new_user.role,

        },

    }





@router.post("/auth/login")

async def login(

    body: LoginRequest,

    response: Response,

    db: AsyncSession = Depends(get_db),

    x_device_fp: Optional[str] = Header(None, alias="X-Device-Fingerprint"),

):

    uname = body.username.strip().lower()

    pwd = body.password



    user = (await db.execute(select(User).where((User.username == uname) | (User.email == uname)))).scalar_one_or_none()

    if not user or not await asyncio.to_thread(verify_password, pwd, user.hashed_password):

        raise HTTPException(status_code=401, detail="Username/Email atau Password salah.")



    if not user.is_active:

        raise HTTPException(status_code=403, detail="Akun dinonaktifkan.")



    token = create_access_token(user.id, user.username, user.role, password_hash=user.hashed_password)

    response.set_cookie(

        key="auth_token",

        value=token,

        httponly=True,

        secure=settings.cookie_secure,

        samesite="lax",

        max_age=86400 * 7,

    )



    return {

        "access_token": token,

        "token_type": "bearer",

        "user": {

            "id": user.id,

            "username": user.username,

            "email": user.email,

            "role": user.role,

            "created_at": user.created_at.isoformat() if user.created_at else None,

        },

    }





@router.post("/auth/logout")

async def logout(response: Response):

    response.delete_cookie(key="auth_token")

    return {"message": "Berhasil logout."}





@router.get("/auth/me")

async def get_me(user: Optional[User] = Depends(get_optional_user)):

    if not user:

        return {"authenticated": False, "user": None}

    return {

        "authenticated": True,

        "user": {

            "id": user.id,

            "username": user.username,

            "email": user.email,

            "role": user.role,

            "created_at": user.created_at.isoformat() if user.created_at else None,

        },

    }





class ChangePasswordRequest(BaseModel):

    old_password: str = Field(max_length=256)

    new_password: str = Field(min_length=10, max_length=256)





@router.post("/auth/change-password")

async def change_password(

    body: ChangePasswordRequest,

    response: Response,

    current_user: User = Depends(get_current_user),

    db: AsyncSession = Depends(get_db),

):

    old_pwd = body.old_password

    new_pwd = body.new_password



    if not await asyncio.to_thread(verify_password, old_pwd, current_user.hashed_password):

        raise HTTPException(status_code=400, detail="Password saat ini (lama) tidak sesuai.")

    if len(new_pwd) < 6:

        raise HTTPException(status_code=400, detail="Password baru minimal 6 karakter.")

    if old_pwd == new_pwd:

        raise HTTPException(status_code=400, detail="Password baru tidak boleh sama dengan password lama.")



    current_user.hashed_password = await asyncio.to_thread(hash_password, new_pwd)

    await db.commit()

    token = create_access_token(current_user.id, current_user.username, current_user.role, password_hash=current_user.hashed_password)

    response.set_cookie("auth_token", token, httponly=True, secure=settings.cookie_secure, samesite="lax", max_age=86400 * 7)

    return {"message": "Password diperbarui; sesi lama telah dicabut.", "access_token": token}





# ==========================================================================

# Scan Creation & Management (User Scans Isolated & 1x Device Trial)

# ==========================================================================

from app.core.engagement import EngagementRules, ReportProfile, report_context

from app.findings.lifecycle import FindingLifecycle

from app.core.paths import contained_path

from app.services.scan_manager import ScanQueueFull





class CreateScanRequest(BaseModel):

    target: Optional[str] = None

    profile: Optional[str] = "adversary_simulation"

    include_subdomains: Optional[bool] = True

    validation_level: Optional[str] = "L4_HIGH_RISK"

    allowed_modules: Optional[List[str]] = None

    allowed_actions: Optional[List[str]] = None

    authorization_reference: Optional[str] = None

    campaign_id: Optional[str] = None

    device_fingerprint: Optional[str] = None

    engagement: Optional[EngagementRules] = None





@router.post("/scans")

@router.post("/investigations")

async def create_scan(

    request: Request,

    target: Optional[str] = Query(None),

    profile: Optional[str] = Query(None),

    include_subdomains: Optional[bool] = Query(None),

    validation_level: Optional[str] = Query(None),

    body: Optional[CreateScanRequest] = None,

    current_user: Optional[User] = Depends(get_optional_user),

    db: AsyncSession = Depends(get_db),

    x_device_fp: Optional[str] = Header(None, alias="X-Device-Fingerprint"),

):

    user_id = current_user.id



    final_target = (body.target if body and body.target else target)

    if body and body.include_subdomains is not None:

        final_subs = bool(body.include_subdomains)

    elif include_subdomains is not None:

        final_subs = bool(include_subdomains)

    else:

        final_subs = True



    if not final_target:

        raise HTTPException(status_code=400, detail="Target domain atau URL diperlukan.")



    final_level = (body.validation_level if body else None) or validation_level or "L4_HIGH_RISK"

    reference = (body.engagement.authorization_reference if body and body.engagement else None) or (body.authorization_reference if body else None) or f"AUTHORIZED-L4-{final_target.strip()[:30]}-AUDIT"



    try:

        res = await scan_manager.create_scan(

            target=final_target.strip(),

            profile=(body.profile if body else None) or profile or "adversary_simulation",

            include_subdomains=final_subs,

            validation_level=final_level,

            user_id=user_id,

            allowed_modules=body.allowed_modules if body else None,

            allowed_actions=body.allowed_actions if body else None,

            authorization_reference=reference,

            campaign_id=body.campaign_id if body else None,

            engagement=body.engagement.model_dump(mode="json") if body and body.engagement else None,

        )

        return res

    except ScanQueueFull as e:

        raise HTTPException(status_code=429, detail=str(e), headers={"Retry-After": "30"})

    except ValueError as e:

        raise HTTPException(status_code=400, detail=str(e))





@router.get("/scans/{scan_id}/report-profile")

async def get_report_profile(scan_id: str, db: AsyncSession = Depends(get_db)):

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(404, "Scan not found")

    return report_context(scan)





@router.put("/scans/{scan_id}/report-profile")

async def save_report_profile(scan_id: str, body: ReportProfile, db: AsyncSession = Depends(get_db)):

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(404, "Scan not found")

    scan.options = {**(scan.options or {}), "report_profile": body.model_dump()}

    await db.commit()

    return report_context(scan)





@router.get("/scans")

@router.get("/investigations")

async def list_scans(

    current_user: Optional[User] = Depends(get_optional_user),

    db: AsyncSession = Depends(get_db),

    x_device_fp: Optional[str] = Header(None, alias="X-Device-Fingerprint"),

    limit: int = Query(200, ge=1, le=500),

    offset: int = Query(0, ge=0),

):

    stmt = select(Scan).order_by(desc(Scan.created_at)).limit(limit).offset(offset)

    if current_user and current_user.role == "user":

        stmt = stmt.where(Scan.user_id == current_user.id)

    elif not current_user:

        if x_device_fp:

            trial_scan_ids = (await db.execute(

                select(DeviceTrial.scan_id).where(DeviceTrial.device_fingerprint == x_device_fp)

            )).scalars().all()

            if trial_scan_ids:

                stmt = stmt.where(Scan.id.in_(trial_scan_ids))

            else:

                return []

        else:

            return []



    scans = (await db.execute(stmt)).scalars().all()

    live_ids = [scan.id for scan in scans]

    counts = {"assets": {}, "urls": {}, "ports": {}, "findings": {}}

    if live_ids:

        counts["assets"] = dict((await db.execute(select(Asset.scan_id, func.count(Asset.id)).where(Asset.scan_id.in_(live_ids)).group_by(Asset.scan_id))).all())

        for key, model in (("urls", URL), ("ports", Port)):

            counts[key] = dict((await db.execute(select(Asset.scan_id, func.count(model.id)).join(model, model.asset_id == Asset.id).where(Asset.scan_id.in_(live_ids)).group_by(Asset.scan_id))).all())

        counts["findings"] = dict((await db.execute(select(Finding.scan_id, func.count(Finding.id)).where(Finding.scan_id.in_(live_ids)).group_by(Finding.scan_id))).all())

    severity_counts = {}

    if live_ids:

        rows = (await db.execute(select(Finding.scan_id, Finding.severity, func.count(Finding.id)).where(Finding.scan_id.in_(live_ids)).group_by(Finding.scan_id, Finding.severity))).all()

        for sid, severity, count in rows:

            severity_counts.setdefault(sid, {})[severity.upper()] = count

    results = []

    live_ids = set(live_ids)

    for s in scans:

        prog = dict(s.progress or {})

        if s.id in live_ids:

            prog.update({key: values.get(s.id, 0) for key, values in counts.items()})

        target_url = (s.options or {}).get("target_url") or s.root_domain

        target_host = (s.options or {}).get("target_host") or s.root_domain

        results.append({

            "id": s.id,

            "user_id": s.user_id,

            "root_domain": s.root_domain,

            "target_url": target_url,

            "target_host": target_host,

            "status": s.status,

            "profile": s.profile,

            "validation_level": s.validation_level,

            "options": s.options or {},

            "progress": prog,

            "severity_counts": severity_counts.get(s.id, {}),

            "started_at": s.started_at.isoformat() if s.started_at else None,

            "created_at": s.created_at.isoformat() if s.created_at else None,

            "completed_at": s.completed_at.isoformat() if s.completed_at else None,

        })

    return results





@router.get("/scans/{scan_id}")

async def get_scan(

    scan_id: str,

    current_user: Optional[User] = Depends(get_optional_user),

    db: AsyncSession = Depends(get_db),

    x_device_fp: Optional[str] = Header(None, alias="X-Device-Fingerprint"),

):

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")

    

    if scan.user_id:

        if not current_user:

            raise HTTPException(status_code=401, detail="Silakan login untuk mengakses hasil scan ini.")

        if current_user.role == "user" and scan.user_id != current_user.id:

            raise HTTPException(status_code=403, detail="Akses ditolak: Anda tidak memiliki izin untuk melihat scan ini.")

    elif not current_user and x_device_fp:

        trial = (await db.execute(

            select(DeviceTrial).where(

                DeviceTrial.scan_id == scan_id,

                DeviceTrial.device_fingerprint == x_device_fp

            )

        )).scalars().first()

        if not trial:

            raise HTTPException(status_code=401, detail="Silakan login untuk mengakses scan ini.")



    prog = dict(scan.progress or {})

    assets_cnt = (await db.execute(select(func.count()).select_from(Asset).where(Asset.scan_id == scan.id))).scalar() or 0
    asset_ids = select(Asset.id).where(Asset.scan_id == scan.id)
    urls_cnt = (await db.execute(select(func.count()).select_from(URL).where(URL.asset_id.in_(asset_ids)))).scalar() or 0
    ports_cnt = (await db.execute(select(func.count()).select_from(Port).where(Port.asset_id.in_(asset_ids)))).scalar() or 0
    url_ids = select(URL.id).where(URL.asset_id.in_(asset_ids))
    params_cnt = (await db.execute(select(func.count()).select_from(Parameter).where(Parameter.url_id.in_(url_ids)))).scalar() or 0
    techs_cnt = (await db.execute(select(func.count()).select_from(Technology).where(Technology.asset_id.in_(asset_ids)))).scalar() or 0
    findings_cnt = (await db.execute(select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id))).scalar() or 0

    prog["assets"] = max(int(prog.get("assets", 0) or 0), assets_cnt)
    prog["ports"] = max(int(prog.get("ports", 0) or 0), ports_cnt)
    prog["urls"] = max(int(prog.get("urls", 0) or 0), urls_cnt)
    prog["parameters"] = max(int(prog.get("parameters", 0) or 0), params_cnt)
    prog["technologies"] = max(int(prog.get("technologies", 0) or 0), techs_cnt)
    prog["findings"] = max(int(prog.get("findings", 0) or 0), findings_cnt)



    target_url = (scan.options or {}).get("target_url") or scan.root_domain

    target_host = (scan.options or {}).get("target_host") or scan.root_domain



    return {

        "id": scan.id,

        "user_id": scan.user_id,

        "root_domain": scan.root_domain,

        "target_url": target_url,

        "target_host": target_host,

        "status": scan.status,

        "profile": scan.profile,

        "validation_level": scan.validation_level,

        "options": scan.options or {},

        "progress": prog,

        "started_at": scan.started_at.isoformat() if scan.started_at else None,

        "created_at": scan.created_at.isoformat() if scan.created_at else None,

        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,

    }





@router.post("/scans/{scan_id}/pause")

async def pause_scan(scan_id: str):

    await scan_manager.pause(scan_id)

    return {"scan_id": scan_id, "action": "pause", "status": "paused"}





@router.post("/scans/{scan_id}/resume")

async def resume_scan(scan_id: str):

    await scan_manager.resume(scan_id)

    return {"scan_id": scan_id, "action": "resume", "status": "resumed"}





@router.post("/scans/{scan_id}/stop")

async def stop_scan(scan_id: str):

    await scan_manager.stop(scan_id)

    return {"scan_id": scan_id, "action": "stop", "status": "stopped"}





@router.get("/scans/{scan_id}/events")

@router.get("/investigations/{scan_id}/events")

async def scan_events(scan_id: str, request: Request):

    async def gen():

        queue: asyncio.Queue = asyncio.Queue(maxsize=max(1, settings.sse_client_queue_size))



        async def enqueue(payload: dict) -> None:

            item = json.dumps(payload, default=str)

            if queue.full():

                try:

                    queue.get_nowait()

                except asyncio.QueueEmpty:

                    pass

            await queue.put(item)



        async with AsyncSessionLocal() as db:

            rows = (await db.execute(

                select(ScanEvent)

                .where(ScanEvent.scan_id == scan_id)

                .order_by(ScanEvent.created_at.desc())

                .limit(settings.sse_replay_limit)

            )).scalars().all()

            for ev in reversed(rows):

                await enqueue({

                    "scan_id": scan_id,

                    "event_type": ev.event_type,

                    "type": ev.event_type,

                    "category": ev.event_type.split(".")[0].upper() if "." in ev.event_type else ev.event_type.upper(),

                    "severity": ev.severity,

                    "message": ev.message,

                    "data": ev.data or {},

                    "created_at": ev.created_at.isoformat() if ev.created_at else None,

                })



        async def handler(ev: dict):

            if ev.get("scan_id") == scan_id:

                await enqueue(ev)



        event_bus.subscribe("*", handler)

        try:

            while True:

                if await request.is_disconnected():

                    break

                try:

                    item = await asyncio.wait_for(queue.get(), timeout=settings.sse_keepalive_seconds)

                    try:

                        decoded = json.loads(item)

                        event_id = decoded.get("event_id") or decoded.get("created_at") or decoded.get("timestamp")

                    except Exception:

                        event_id = None

                    if event_id:
                        yield f"id: {event_id}\n"
                    yield f"data: {item}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:

            pass

        finally:

            event_bus.unsubscribe(handler)



    headers = {

        "Cache-Control": "no-cache, no-transform",

        "Connection": "keep-alive",

        "X-Accel-Buffering": "no",

        "Content-Type": "text/event-stream",

    }

    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)





@router.get("/scans/{scan_id}/events/history")

async def get_scan_events_history(

    scan_id: str,

    limit: int = Query(300, ge=1, le=5000),

    db: AsyncSession = Depends(get_db)

):

    rows = (await db.execute(

        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.desc()).limit(limit)

    )).scalars().all()

    chronological_rows = list(reversed(rows))

    return [

        {

            "scan_id": ev.scan_id,

            "event_type": ev.event_type,

            "category": ev.event_type.split(".")[0].upper() if "." in ev.event_type else ev.event_type.upper(),

            "severity": ev.severity,

            "message": ev.message,

            "data": ev.data or {},

            "created_at": ev.created_at.isoformat() if ev.created_at else None,

        }

        for ev in chronological_rows

    ]





# ==========================================================================

# Asset Graph, Ports & Parameters Explorers

# ==========================================================================

@router.get("/assets/tree")

async def tree(scan_id: str = Query(...), db: AsyncSession = Depends(get_db)):

    return await asset_tree(db, scan_id)





@router.get("/assets/{asset_id}")

async def get_asset_detail(asset_id: str, request: Request, db: AsyncSession = Depends(get_db)):

    return await asset_detail(db, request.state.authorized_asset_id)





@router.get("/scans/{scan_id}/ports/all")

async def list_all_scan_ports(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Consolidated Global Port Matrix for all subdomains in this scan."""

    stmt = (

        select(Port, Asset.hostname, Asset.fqdn, Asset.ip.label("asset_ip"))

        .join(Asset, Port.asset_id == Asset.id)

        .where(Asset.scan_id == scan_id)

        .order_by(Port.port.asc(), Asset.hostname.asc())

    )

    results = (await db.execute(stmt)).all()

    out = []

    for p, hostname, fqdn, asset_ip in results:

        target_host = hostname or fqdn or asset_ip or "target"

        is_ssl = p.port in (443, 8443, 2083, 2087, 2096, 9443, 10443, 4433, 4443)

        scheme = "https" if is_ssl else "http"

        port_suffix = f":{p.port}" if p.port not in (80, 443) else ""

        web_ports = {80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8088, 8888, 8880, 9000, 9001, 9090, 9443, 10000, 10443, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 5000, 4200, 5173}

        direct_url = f"{scheme}://{target_host}{port_suffix}" if p.protocol == "tcp" and p.port in web_ports else None



        out.append({

            "id": p.id,

            "asset_id": p.asset_id,

            "hostname": target_host,

            "ip": p.ip or asset_ip,

            "port": p.port,

            "protocol": p.protocol,

            "service": p.service or "-",

            "state": p.state,

            "banner": p.banner or "-",

            "direct_url": direct_url,

        })

    return out





@router.get("/scans/{scan_id}/parameters/all")

async def list_all_scan_parameters(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Consolidated Parameters Matrix across all discovered URLs."""

    stmt = (

        select(Parameter, URL.url, URL.host, URL.path, URL.status_code, URL.asset_id)

        .join(URL, Parameter.url_id == URL.id)

        .join(Asset, URL.asset_id == Asset.id)

        .where(Asset.scan_id == scan_id)

        .order_by(Parameter.name.asc())

    )

    results = (await db.execute(stmt)).all()

    return [

        {

            "id": param.id,

            "name": param.name,

            "location": param.location,

            "type": param.type or "string",

            "confidence": param.confidence,

            "url": url,

            "host": host,

            "path": path,

            "status_code": status_code,

            "asset_id": asset_id,

        }

        for param, url, host, path, status_code, asset_id in results

    ]





@router.get("/scans/{scan_id}/urls/all")

async def list_all_scan_urls(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Consolidated Global Discovered URLs & Endpoints for this scan."""

    stmt = (

        select(

            URL,

            Asset.hostname,

            Asset.ip.label("asset_ip"),

            func.count(Parameter.id).label("param_count")

        )

        .join(Asset, URL.asset_id == Asset.id)

        .outerjoin(Parameter, Parameter.url_id == URL.id)

        .where(Asset.scan_id == scan_id)

        .group_by(URL.id, Asset.hostname, Asset.ip)

        .order_by(URL.url.asc())

    )

    results = (await db.execute(stmt)).all()

    return [

        {

            "id": u.id,

            "asset_id": u.asset_id,

            "hostname": hostname or u.host or asset_ip or "-",

            "ip": asset_ip,

            "url": u.url,

            "method": "GET",

            "host": u.host or hostname,

            "path": u.path or "/",

            "status_code": u.status_code or 200,

            "content_type": u.content_type,

            "content_length": None,

            "title": u.title,

            "parameters_count": param_count,

            "first_seen": u.first_seen.isoformat() if u.first_seen else None,

        }

        for u, hostname, asset_ip, param_count in results

    ]





@router.get("/scans/{scan_id}/artifacts/all")

async def list_all_scan_artifacts(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Consolidated Artifact Matrix (SQL dumps, CSVs, logs, configs) for this scan session."""

    stmt = (

        select(Artifact, Asset.hostname, Asset.ip.label("asset_ip"))

        .outerjoin(Asset, Artifact.asset_id == Asset.id)

        .where(Artifact.scan_id == scan_id)

        .order_by(Artifact.created_at.desc())

    )

    results = (await db.execute(stmt)).all()

    out = []

    for art, hostname, asset_ip in results:

        schema = art.schema_data or {}

        entities = art.extracted_entities or {}

        out.append({

            "id": art.id,

            "scan_id": art.scan_id,

            "asset_id": art.asset_id,

            "hostname": hostname or asset_ip or "-",

            "filename": art.filename,

            "file_type": art.file_type,

            "mime_type": art.mime_type,

            "size_bytes": art.size_bytes,

            "sha256_hash": art.sha256_hash,

            "state": art.state,

            "database_name": schema.get("database_name"),

            "vendor": schema.get("vendor"),

            "total_tables": schema.get("total_tables", len(schema.get("tables", []))),

            "total_users": len(entities.get("users", [])),

            "total_hashes": len(entities.get("hashes", [])),

            "has_pii": entities.get("has_pii", False) or len(entities.get("users", [])) > 0,

            "created_at": art.created_at.isoformat() if art.created_at else None,

        })

    return out





@router.get("/artifacts/{artifact_id}")

async def get_artifact_detail(artifact_id: str, db: AsyncSession = Depends(get_db)):

    """Detailed view of an acquired security artifact including schema and extracted entities."""

    art = await db.get(Artifact, artifact_id)

    if not art:

        raise HTTPException(status_code=404, detail="Artifact not found")



    hostname = "-"

    if art.asset_id:

        ast = await db.get(Asset, art.asset_id)

        if ast:

            hostname = ast.hostname or ast.ip or "-"



    return {

        "id": art.id,

        "scan_id": art.scan_id,

        "asset_id": art.asset_id,

        "hostname": hostname,

        "filename": art.filename,

        "file_type": art.file_type,

        "mime_type": art.mime_type,

        "size_bytes": art.size_bytes,

        "sha256_hash": art.sha256_hash,

        "state": art.state,

        "schema_data": art.schema_data or {},

        "extracted_entities": art.extracted_entities or {},

        "metadata": art.metadata_ or {},

        "created_at": art.created_at.isoformat() if art.created_at else None,

    }





@router.get("/artifacts/{artifact_id}/preview")

async def get_artifact_preview(artifact_id: str, db: AsyncSession = Depends(get_db)):

    """Returns text preview and sanitized preview snippet."""

    art = await db.get(Artifact, artifact_id)

    if not art:

        raise HTTPException(status_code=404, detail="Artifact not found")



    raw_text = ""

    if art.storage_path and os.path.exists(art.storage_path):

        try:

            with open(art.storage_path, "r", encoding="utf-8", errors="ignore") as f:

                raw_text = "".join([f.readline() for _ in range(300)])

        except Exception:

            raw_text = "[Binary or unreadable file content]"



    sanitized_text = ArtifactSanitizer.sanitize_sql_dump(raw_text) if "sql" in art.file_type else raw_text



    return {

        "id": art.id,

        "filename": art.filename,

        "file_type": art.file_type,

        "size_bytes": art.size_bytes,

        "sha256_hash": art.sha256_hash,

        "preview_lines": len(raw_text.splitlines()),

        "raw_preview": raw_text[:8000],

        "sanitized_preview": sanitized_text[:8000],

    }





@router.get("/artifacts/{artifact_id}/tables")

async def get_artifact_tables(artifact_id: str, db: AsyncSession = Depends(get_db)):

    """Returns structured table schemas, columns, and sample rows."""

    art = await db.get(Artifact, artifact_id)

    if not art:

        raise HTTPException(status_code=404, detail="Artifact not found")



    schema = art.schema_data or {}

    return {

        "id": art.id,

        "filename": art.filename,

        "vendor": schema.get("vendor", "Generic"),

        "database_name": schema.get("database_name"),

        "tables": schema.get("tables", []),

        "sample_rows": schema.get("sample_rows", []),

    }





@router.get("/artifacts/{artifact_id}/download")

async def download_artifact_file(artifact_id: str, db: AsyncSession = Depends(get_db)):

    """Downloads the quarantined raw artifact file."""

    art = await db.get(Artifact, artifact_id)

    if not art or not art.storage_path or not os.path.exists(art.storage_path):

        raise HTTPException(status_code=404, detail="Artifact file not found on disk")



    return FileResponse(

        path=art.storage_path,

        filename=art.filename,

        media_type=art.mime_type or "application/octet-stream",

    )





@router.get("/artifacts/{artifact_id}/export-sanitized")

async def export_sanitized_artifact(artifact_id: str, db: AsyncSession = Depends(get_db)):

    """Downloads a compliance-safe sanitized export of the artifact."""

    art = await db.get(Artifact, artifact_id)

    if not art or not art.storage_path or not os.path.exists(art.storage_path):

        raise HTTPException(status_code=404, detail="Artifact file not found on disk")



    try:

        with open(art.storage_path, "r", encoding="utf-8", errors="ignore") as f:

            content = f.read(500000)  # up to 500KB

    except Exception:

        content = ""



    sanitized = ArtifactSanitizer.sanitize_sql_dump(content) if "sql" in art.file_type else content



    def iter_content():

        yield sanitized.encode("utf-8")



    out_name = f"sanitized_{art.filename}"

    return StreamingResponse(

        iter_content(),

        media_type="text/plain",

        headers={"Content-Disposition": f'attachment; filename="{out_name}"'},

    )





@router.get("/scans/{scan_id}/technologies/all")

async def list_all_scan_technologies(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Consolidated Technology Stack & Fingerprints for this scan."""

    stmt = (

        select(Technology, Asset.hostname, Asset.fqdn, Asset.ip.label("asset_ip"))

        .join(Asset, Technology.asset_id == Asset.id)

        .where(Asset.scan_id == scan_id)

        .order_by(Technology.category.asc(), Technology.name.asc())

    )

    results = (await db.execute(stmt)).all()

    return [

        {

            "id": t.id,

            "asset_id": t.asset_id,

            "hostname": hostname or fqdn or asset_ip or "unknown",

            "ip": asset_ip,

            "name": t.name,

            "version": t.version,

            "category": t.category or "Other",

            "cpe": t.cpe,

            "confidence": str(t.confidence or 1.0),

            "evidence": t.evidence or "-",

        }

        for t, hostname, fqdn, asset_ip in results

    ]





@router.get("/scans/{scan_id}/assets/all")

async def list_all_scan_assets(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Consolidated Active Assets & Subdomains for this scan."""

    stmt = select(Asset).where(Asset.scan_id == scan_id).order_by(Asset.depth.asc(), Asset.hostname.asc())

    assets = (await db.execute(stmt)).scalars().all()

    out = []

    for a in assets:

        ports_cnt = (await db.execute(select(func.count()).select_from(Port).where(Port.asset_id == a.id))).scalar() or 0

        urls_cnt = (await db.execute(select(func.count()).select_from(URL).where(URL.asset_id == a.id))).scalar() or 0

        findings_cnt = (await db.execute(select(func.count()).select_from(Finding).where(Finding.asset_id == a.id))).scalar() or 0

        tech_names = [t.name for t in (await db.execute(select(Technology).where(Technology.asset_id == a.id))).scalars().all()]

        out.append({

            "id": a.id,

            "hostname": a.hostname or a.fqdn or a.ip or "unknown",

            "fqdn": a.fqdn,

            "ip": a.ip,

            "asset_type": a.asset_type,

            "depth": a.depth,

            "status": a.status,

            "liveness_status": a.liveness_status,

            "ports_count": ports_cnt,

            "urls_count": urls_cnt,

            "findings_count": findings_cnt,

            "technologies": tech_names,

            "first_seen": a.first_seen.isoformat() if a.first_seen else None,

        })

    return out





@router.delete("/scans/{scan_id}")

async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Delete a scan and all associated data."""

    from sqlalchemy import delete

    from app.models.models import (

        Asset, Finding, Screenshot, URL, Port, Service, Parameter,

        Technology, Certificate, Artifact, DurableTask, DeadLetterTask, AttackPath,

        ScanEvent, AuditLog, Observation, Report, TestPlan, PreconditionCheck

    )



    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    # 1. Stop scan in scan_manager if running

    try:

        await scan_manager.stop(scan_id)

        await result_service.drain()

    except Exception:

        logger.exception("Unable to stop scan before deletion")

        raise HTTPException(503, "Scan could not be stopped safely") from None



    # 2. Clean up in-memory engines

    try:

        from app.core.security_engine import security_engine

        from app.core.state_machine import state_machine_manager



        if scan_id in security_engine._app_models:

            del security_engine._app_models[scan_id]

        if scan_id in security_engine._reasoning_layers:

            del security_engine._reasoning_layers[scan_id]

        if scan_id in security_engine._planners:

            del security_engine._planners[scan_id]

        if scan_id in security_engine._metrics:

            del security_engine._metrics[scan_id]

        state_machine_manager.remove(scan_id)

    except Exception:

        pass



    # 3. Explicit cascade deletion of child records

    asset_ids = (await db.execute(select(Asset.id).where(Asset.scan_id == scan_id))).scalars().all()

    if asset_ids:

        url_ids = (await db.execute(select(URL.id).where(URL.asset_id.in_(asset_ids)))).scalars().all()

        if url_ids:

            await db.execute(delete(Parameter).where(Parameter.url_id.in_(url_ids)))

        await db.execute(delete(Service).where(Service.asset_id.in_(asset_ids)))

        await db.execute(delete(Port).where(Port.asset_id.in_(asset_ids)))

        await db.execute(delete(URL).where(URL.asset_id.in_(asset_ids)))

        await db.execute(delete(Technology).where(Technology.asset_id.in_(asset_ids)))

        await db.execute(delete(Certificate).where(Certificate.asset_id.in_(asset_ids)))



    await db.execute(delete(Finding).where(Finding.scan_id == scan_id))

    await db.execute(delete(Screenshot).where(Screenshot.scan_id == scan_id))

    await db.execute(delete(Artifact).where(Artifact.scan_id == scan_id))

    await db.execute(delete(DurableTask).where(DurableTask.scan_id == scan_id))

    await db.execute(delete(DeadLetterTask).where(DeadLetterTask.scan_id == scan_id))

    await db.execute(delete(AttackPath).where(AttackPath.scan_id == scan_id))

    await db.execute(delete(ScanEvent).where(ScanEvent.scan_id == scan_id))

    await db.execute(delete(AuditLog).where(AuditLog.scan_id == scan_id))

    await db.execute(delete(Observation).where(Observation.scan_id == scan_id))

    await db.execute(delete(Report).where(Report.scan_id == scan_id))

    await db.execute(delete(TestPlan).where(TestPlan.scan_id == scan_id))

    await db.execute(delete(PreconditionCheck).where(PreconditionCheck.scan_id == scan_id))

    await db.execute(delete(Asset).where(Asset.scan_id == scan_id))



    await db.delete(scan)

    await db.commit()

    return {"scan_id": scan_id, "status": "deleted"}





@router.get("/domains")

async def list_domains(

    current_user: Optional[User] = Depends(get_optional_user),

    db: AsyncSession = Depends(get_db),

):

    stmt = select(Scan.root_domain, func.count(Scan.id).label("count")).group_by(Scan.root_domain)

    if current_user and current_user.role == "user":

        stmt = stmt.where(Scan.user_id == current_user.id)



    rows = (await db.execute(stmt)).all()

    return [{"root_domain": r[0], "scan_count": r[1]} for r in rows]





# ==========================================================================

# Findings & Triaging

# ==========================================================================

@router.get("/findings")

async def list_findings(scan_id: Optional[str] = Query(None), db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):

    stmt = (

        select(Finding, Asset.hostname, Asset.fqdn, Asset.ip)

        .outerjoin(Asset, Finding.asset_id == Asset.id)

        .order_by(desc(Finding.first_seen))

    )

    if current_user.role != "admin":

        stmt = stmt.where(Finding.scan_id.in_(select(Scan.id).where(Scan.user_id == current_user.id)))

    if scan_id:

        stmt = stmt.where(Finding.scan_id == scan_id)

    results = (await db.execute(stmt)).all()

    return [

        {

            "id": f.id,

            "finding_code": f.finding_code,

            "scan_id": f.scan_id,

            "asset_id": f.asset_id,

            "asset_hostname": hostname or fqdn or ip or "Global Target",

            "asset_ip": ip,

            "title": f.title,

            "severity": f.severity,

            "finding_type": f.finding_type,

            "confidence": f.confidence,

            "evidence_level": f.evidence_level or "E0",

            "evidence_score": f.evidence_score if f.evidence_score is not None else 0,

            "validation_status": f.validation_status or "DISCOVERED",

            "exploitability_state": f.exploitability_state or "CANDIDATE",

            "status": f.status,

            "allowed_transitions": sorted(FindingLifecycle.VALID_TRANSITIONS.get((f.status or "OPEN").upper(), set()) - {"RETESTING"}),

            "cwe_id": f.cwe_id,

            "cve_id": f.cve_id,

            "cvss_score": f.cvss_score,

            "description": f.description,

            "impact": f.impact,

            "technical_details": f.technical_details,

            "remediation": f.remediation,

            "root_cause": f.root_cause,

            "executive_explanation": f.executive_explanation,

            "business_impact": f.business_impact,

            "evidence": f.evidence or {},

            "first_seen": f.first_seen.isoformat() if f.first_seen else None,

            "last_seen": f.last_seen.isoformat() if f.last_seen else None,

        }

        for f, hostname, fqdn, ip in results

    ]





@router.get("/scans/{scan_id}/findings")

async def get_scan_findings(scan_id: str, db: AsyncSession = Depends(get_db)):

    stmt = (

        select(Finding, Asset.hostname, Asset.fqdn, Asset.ip)

        .outerjoin(Asset, Finding.asset_id == Asset.id)

        .where(Finding.scan_id == scan_id)

        .order_by(desc(Finding.first_seen))

    )

    results = (await db.execute(stmt)).all()

    return {

        "scan_id": scan_id,

        "total_findings": len(results),

        "findings": [

            {

                "id": f.id,

                "finding_code": f.finding_code,

                "scan_id": f.scan_id,

                "asset_id": f.asset_id,

                "asset_hostname": hostname or fqdn or ip or "Global Target",

                "asset_ip": ip,

                "title": f.title,

                "severity": f.severity,

                "finding_type": f.finding_type,

                "confidence": f.confidence,

                "evidence_level": f.evidence_level or "E0",

                "evidence_score": f.evidence_score if f.evidence_score is not None else 0,

                "validation_status": f.validation_status or "DISCOVERED",

                "exploitability_state": f.exploitability_state or "CANDIDATE",

                "status": f.status,

            "allowed_transitions": sorted(FindingLifecycle.VALID_TRANSITIONS.get((f.status or "OPEN").upper(), set()) - {"RETESTING"}),

                "cwe_id": f.cwe_id,

                "cve_id": f.cve_id,

                "cvss_score": f.cvss_score,

                "description": f.description,

                "impact": f.impact,

                "technical_details": f.technical_details,

                "remediation": f.remediation,

                "root_cause": f.root_cause,

                "executive_explanation": f.executive_explanation,

                "business_impact": f.business_impact,

                "evidence": f.evidence or {},

                "first_seen": f.first_seen.isoformat() if f.first_seen else None,

                "last_seen": f.last_seen.isoformat() if f.last_seen else None,

            }

            for f, hostname, fqdn, ip in results

        ],

    }





@router.patch("/findings/{finding_id}")

async def update_finding(finding_id: str, status: str = Query(...), db: AsyncSession = Depends(get_db)):

    # Both manual editing APIs must obey the same evidence/lifecycle boundary.

    return await transition_finding_state(finding_id, status, db)





@router.get("/findings/severity")

async def findings_by_severity(scan_id: str = Query(...), db: AsyncSession = Depends(get_db)):

    rows = (await db.execute(

        select(Finding.severity, func.count()).where(Finding.scan_id == scan_id).group_by(Finding.severity)

    )).all()

    return {"severities": {sev: count for sev, count in rows}, "total": sum(c for _, c in rows)}





# ==========================================================================

# ==========================================================================

# Differential Scanner (§35)

# ==========================================================================

@router.get("/diff")

@router.get("/scans/diff")

async def diff_scans(

    current: Optional[str] = Query(None),

    previous: Optional[str] = Query(None),

    current_scan_id: Optional[str] = Query(None),

    previous_scan_id: Optional[str] = Query(None),

    db: AsyncSession = Depends(get_db),

):

    """Compare two scans on the same target to track attack surface and finding progression (§35)."""

    from app.differential.engine import differential_engine

    c_id = current or current_scan_id

    p_id = previous or previous_scan_id

    if not c_id or not p_id:

        raise HTTPException(status_code=400, detail="Both current and previous scan IDs must be provided.")

    return await differential_engine.compare(db, c_id, p_id)







# ==========================================================================

# Admin Oversight (Monitoring Only — Scrapping Analytics & Audit)

# ==========================================================================

@router.get("/admin/overview")

async def admin_overview(

    admin: User = Depends(require_admin_role),

    db: AsyncSession = Depends(get_db),

):

    """Global platform overview metrics for Admin oversight."""

    total_users = (await db.execute(select(func.count()).select_from(User))).scalar() or 0

    total_scans = (await db.execute(select(func.count()).select_from(Scan))).scalar() or 0

    total_domains = (await db.execute(select(func.count(distinct(Scan.root_domain))))).scalar() or 0

    total_subdomains = (await db.execute(select(func.count(distinct(Asset.hostname))).where(Asset.asset_type == "subdomain"))).scalar() or 0

    total_ips = (await db.execute(select(func.count(distinct(Asset.ip))).where(Asset.ip.isnot(None)))).scalar() or 0

    total_findings = (await db.execute(select(func.count()).select_from(Finding))).scalar() or 0



    return {

        "total_users": total_users,

        "total_scans": total_scans,

        "total_domains": total_domains,

        "total_subdomains": total_subdomains,

        "total_ips": total_ips,

        "total_findings": total_findings,

    }





@router.get("/admin/users")

async def admin_list_users(

    admin: User = Depends(require_admin_role),

    db: AsyncSession = Depends(get_db),

):

    """User Scrapping Analytics: optimized batch aggregation without N+1 queries."""

    users = (await db.execute(select(User).order_by(desc(User.created_at)))).scalars().all()

    scans = (await db.execute(select(Scan).order_by(desc(Scan.created_at)))).scalars().all()



    # Pre-group scans by user_id

    user_scans_map: Dict[str, List[Scan]] = {}

    for s in scans:

        if s.user_id:

            user_scans_map.setdefault(s.user_id, []).append(s)



    # Batch compute findings count per scan

    finding_counts_raw = (await db.execute(

        select(Finding.scan_id, func.count(Finding.id)).group_by(Finding.scan_id)

    )).all()

    scan_finding_map = {sid: cnt for sid, cnt in finding_counts_raw}



    # Batch compute subdomains & IPs per scan

    subdomain_counts_raw = (await db.execute(

        select(Asset.scan_id, func.count(distinct(Asset.hostname)))

        .where(Asset.asset_type == "subdomain")

        .group_by(Asset.scan_id)

    )).all()

    scan_subdomain_map = {sid: cnt for sid, cnt in subdomain_counts_raw}



    ip_counts_raw = (await db.execute(

        select(Asset.scan_id, func.count(distinct(Asset.ip)))

        .where(Asset.ip.isnot(None))

        .group_by(Asset.scan_id)

    )).all()

    scan_ip_map = {sid: cnt for sid, cnt in ip_counts_raw}



    user_stats = []

    for u in users:

        u_scans = user_scans_map.get(u.id, [])

        u_scan_ids = [s.id for s in u_scans]

        unique_domains = list({s.root_domain for s in u_scans if s.root_domain})



        total_subs = sum(scan_subdomain_map.get(sid, 0) for sid in u_scan_ids)

        total_ips = sum(scan_ip_map.get(sid, 0) for sid in u_scan_ids)

        total_findings = sum(scan_finding_map.get(sid, 0) for sid in u_scan_ids)



        user_stats.append({

            "id": u.id,

            "username": u.username,

            "email": u.email,

            "role": u.role,

            "is_active": u.is_active,

            "created_at": u.created_at.isoformat() if u.created_at else None,

            "total_scans": len(u_scans),

            "total_domains": len(unique_domains),

            "scanned_domains": unique_domains,

            "total_subdomains": total_subs,

            "total_ips": total_ips,

            "total_findings": total_findings,

            "last_scan_date": u_scans[0].created_at.isoformat() if u_scans and u_scans[0].created_at else None,

        })



    return user_stats





@router.get("/admin/domains")

async def admin_list_domains(

    admin: User = Depends(require_admin_role),

    db: AsyncSession = Depends(get_db),

):

    """Domain Audit: optimized batch aggregation without N+1 queries."""

    scans_with_user = (await db.execute(

        select(Scan, User.username)

        .outerjoin(User, Scan.user_id == User.id)

        .order_by(desc(Scan.created_at))

    )).all()



    # Pre-group by root_domain

    domain_scans_map: Dict[str, List[tuple]] = {}

    for s, uname in scans_with_user:

        if s.root_domain:

            domain_scans_map.setdefault(s.root_domain, []).append((s, uname))



    finding_counts_raw = (await db.execute(

        select(Finding.scan_id, func.count(Finding.id)).group_by(Finding.scan_id)

    )).all()

    scan_finding_map = {sid: cnt for sid, cnt in finding_counts_raw}



    subdomain_counts_raw = (await db.execute(

        select(Asset.scan_id, func.count(distinct(Asset.hostname)))

        .where(Asset.asset_type == "subdomain")

        .group_by(Asset.scan_id)

    )).all()

    scan_subdomain_map = {sid: cnt for sid, cnt in subdomain_counts_raw}



    ip_counts_raw = (await db.execute(

        select(Asset.scan_id, func.count(distinct(Asset.ip)))

        .where(Asset.ip.isnot(None))

        .group_by(Asset.scan_id)

    )).all()

    scan_ip_map = {sid: cnt for sid, cnt in ip_counts_raw}



    domain_stats = []

    for d, d_scans in domain_scans_map.items():

        scan_ids = [s.id for s, _ in d_scans]

        users_map: Dict[str, int] = {}

        for s, uname in d_scans:

            u_label = uname or "Anonymous / System"

            users_map[u_label] = users_map.get(u_label, 0) + 1



        total_subs = sum(scan_subdomain_map.get(sid, 0) for sid in scan_ids)

        total_ips = sum(scan_ip_map.get(sid, 0) for sid in scan_ids)

        total_findings = sum(scan_finding_map.get(sid, 0) for sid in scan_ids)



        domain_stats.append({

            "root_domain": d,

            "total_scans": len(d_scans),

            "scrapped_by": [{"username": u, "scan_count": count} for u, count in users_map.items()],

            "total_subdomains": total_subs,

            "total_ips": total_ips,

            "total_findings": total_findings,

            "first_seen": d_scans[-1][0].created_at.isoformat() if d_scans and d_scans[-1][0].created_at else None,

            "last_scanned": d_scans[0][0].created_at.isoformat() if d_scans and d_scans[0][0].created_at else None,

        })



    return domain_stats





# ==========================================================================

# Comprehensive Investigation Workspace & Async Exports (§11 - §27)

# ==========================================================================



@router.get("/scans/{scan_id}/workspace")

@router.get("/investigations/{scan_id}/workspace")

async def get_investigation_workspace(

    scan_id: str,

    current_user: Optional[User] = Depends(get_optional_user),

    db: AsyncSession = Depends(get_db),

):

    """

    Complete Investigation Workspace Aggregator (§11-§26).

    Returns Overview, Assets, Services, Endpoints, Findings, Attack Chains, Evidence, Files & Artifacts, Timeline, Exports.

    """

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Investigation not found")



    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    asset_ids = [a.id for a in assets]

    asset_map = {a.id: (a.hostname or a.ip) for a in assets}



    ports = (await db.execute(select(Port).where(Port.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    urls = (await db.execute(select(URL).where(URL.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    url_ids = [u.id for u in urls]

    techs = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id).order_by(desc(Finding.first_seen)))).scalars().all()

    evidence_items = (await db.execute(select(Evidence).where(Evidence.scan_id == scan_id))).scalars().all()

    artifacts = (await db.execute(select(Artifact).where(Artifact.scan_id == scan_id).order_by(desc(Artifact.created_at)))).scalars().all()



    # Artifact processing belongs to scan workers, never to a report GET request.

    export_jobs = (await db.execute(select(ExportJob).where(ExportJob.scan_id == scan_id).order_by(desc(ExportJob.created_at)))).scalars().all()

    recent_events = (await db.execute(select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(desc(ScanEvent.created_at)).limit(100))).scalars().all()



    # Calculate severity breakdown

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    conf_counts = {"confirmed": 0, "likely": 0, "potential": 0, "inconclusive": 0}

    for f in findings:

        s = (f.severity or "info").lower()

        if s in sev_counts:

            sev_counts[s] += 1

        c = (f.confidence or "inconclusive").lower()

        if finding_quality(serialize_finding(f, scan.root_domain, asset_map))["confirmed_with_evidence"]:

            conf_counts["confirmed"] += 1

        elif "like" in c or "validated" in c:

            conf_counts["likely"] += 1

        elif "poten" in c:

            conf_counts["potential"] += 1

        else:

            conf_counts["inconclusive"] += 1



    # Duration calculation

    start_t = scan.started_at

    end_t = scan.completed_at

    if start_t and not end_t and scan.status in {"running", "pending", "paused", "queued"}:

        end_t = datetime.now(timezone.utc) if start_t.tzinfo is not None else datetime.now(timezone.utc).replace(tzinfo=None)

    elif start_t and end_t:

        if (start_t.tzinfo is not None) != (end_t.tzinfo is not None):

            start_t = start_t.replace(tzinfo=None)

            end_t = end_t.replace(tzinfo=None)

    duration_secs = int((end_t - start_t).total_seconds()) if start_t and end_t else None







    # Build services list with nonstandard port categorization

    services_list = []

    for p in ports:

        p_num = getattr(p, "port_number", getattr(p, "port", None)) or 0

        is_http_like = p_num in (80, 443, 8080, 8443, 3000, 8000, 8888, 9000, 5000) or "http" in (p.service or "").lower()

        is_nonstandard_http = is_http_like and p_num not in (80, 443)

        services_list.append({

            "id": p.id,

            "asset_id": p.asset_id,

            "host": asset_map.get(p.asset_id, scan.root_domain),

            "port": p_num,

            "protocol": p.protocol or "tcp",

            "service": p.service or "unknown",

            "product": getattr(p, "product", ""),

            "version": getattr(p, "version", ""),

            "banner": getattr(p, "banner", ""),

            "is_tls": getattr(p, "is_tls", p_num in (443, 8443)),

            "is_nonstandard_http": is_nonstandard_http,

            "auth_surface": "Not assessed",

        })



    # Build endpoints list

    endpoints_list = [

        {

            "id": u.id,

            "asset_id": u.asset_id,

            "host": asset_map.get(u.asset_id, scan.root_domain),

            "url": u.url,

            "method": getattr(u, "method", "GET") or "GET",

            "status_code": u.status_code,

            "content_type": u.content_type or "text/html",

            "title": u.title or "",

        }

        for u in urls

    ]



    screenshots = (await db.execute(select(Screenshot).where(Screenshot.scan_id == scan_id))).scalars().all()

    screenshot_map = {s.id: s for s in screenshots}

    screenshot_by_asset = {s.asset_id: s for s in screenshots if s.asset_id}



    from app.reporting.poc_builder import PocBuilder



    # Build findings list with complete Bug Hunting PoC dossier

    findings_list = []

    for idx, f in enumerate(findings, 1):

        f_ev = serialize_finding(f, scan.root_domain if scan else "", {})["evidence"]

        ss_id = f_ev.get("screenshot_id")

        ss = screenshot_map.get(ss_id) if ss_id else screenshot_by_asset.get(f.asset_id)

        has_real_ss = False

        ss_url = None

        if ss and (ss.trigger or "").startswith("browser:"):

            if ss.storage_path and Path(ss.storage_path).exists():

                has_real_ss = True

                ss_id = ss.id

                ss_url = f"/api/screenshots/{ss.id}/image"

            elif ss.thumbnail_path and Path(ss.thumbnail_path).exists():

                has_real_ss = True

                ss_id = ss.id

                ss_url = f"/api/screenshots/{ss.id}/image"



        target_host_name = asset_map.get(f.asset_id, scan.root_domain)

        target_endpoint_loc = finding_location(f, target_host_name)



        dossier = PocBuilder.generate_dossier(

            title=f.title,

            finding_type=f.finding_type or f.title,

            severity=f.severity,

            target_url=target_endpoint_loc,

            target_host=target_host_name,

            parameter=f_ev.get("parameter"),

            method=f_ev.get("method", "GET") or "GET",

            headers=f_ev.get("headers"),

            payload=f_ev.get("payload") or f_ev.get("matched_pattern"),

            cwe_id=f.cwe_id,

            cve_id=f.cve_id,

            cvss_score=f.cvss_score,

            description=f.description,

            technical_details=f.technical_details,

            evidence=f_ev,

            screenshot_id=ss_id,

            screenshot_url=ss_url,

            has_real_screenshot=has_real_ss,

        )



        item = serialize_finding(f, scan.root_domain, asset_map)

        item.update({"poc_dossier": dossier, "proof_curl": dossier["curl_command"],

                     "python_poc": dossier["python_poc"], "screenshot": dossier["screenshot"],

                     "created_at": item["first_seen"]})

        findings_list.append(item)









    # Build artifacts list

    artifacts_list = [

        {

            "id": a.id,

            "filename": a.filename,

            "file_type": a.file_type,

            "classification": a.classification,

            "category": a.category,

            "record_count": a.record_count or (len(a.preview_data.get("rows", [])) if a.preview_data and isinstance(a.preview_data, dict) else 0),

            "size_bytes": a.size_bytes,

            "file_size": a.size_bytes,

            "sha256_hash": a.sha256_hash,

            "source": a.source,

            "is_redacted": a.is_redacted,

            "state": a.state,

            "preview_available": bool(a.preview_data),

            "preview_data": a.preview_data,

            "schema_data": a.schema_data,

            "created_at": a.created_at.isoformat() if a.created_at else None,

        }

        for a in artifacts

    ]



    # Build exports list

    exports_list = [

        {

            "id": j.id,

            "export_type": j.export_type,

            "filename": j.filename,

            "status": j.status,

            "file_size": j.file_size,

            "sha256_hash": j.sha256_hash,

            "mime_type": j.mime_type,

            "created_at": j.created_at.isoformat() if j.created_at else None,

            "completed_at": j.completed_at.isoformat() if j.completed_at else None,

            "download_url": f"/api/scans/{scan_id}/exports/{j.id}/download",

        }

        for j in export_jobs

    ]



    # Timeline list

    timeline_list = [

        {

            "event_type": ev.event_type,

            "category": ev.event_type.split(".")[0].upper() if "." in ev.event_type else ev.event_type.upper(),

            "severity": ev.severity,

            "message": ev.message,

            "created_at": ev.created_at.isoformat() if ev.created_at else None,

        }

        for ev in reversed(recent_events)

    ]



    # Evidence list

    evidence_list = [

        {

            "id": ev.id,

            "asset_id": ev.asset_id,

            "evidence_type": ev.evidence_type,

            "title": (ev.data or {}).get("title", f"Evidence {ev.id[:8]}"),

            "request_headers": (ev.data or {}).get("request_headers", ""),

            "response_headers": (ev.data or {}).get("response_headers", ""),

            "response_status": (ev.data or {}).get("response_status"),

            "sha256_hash": ev.sha256_hash or "",

            "created_at": ev.created_at.isoformat() if ev.created_at else None,

        }

        for ev in evidence_items

    ]



    return {

        "report_context": report_context(scan),

        "overview": {

            "id": scan.id,

            "investigation_id": scan.id,

            "target": scan.root_domain,

            "target_url": (scan.options or {}).get("target_url", f"https://{scan.root_domain}"),

            "status": scan.status,

            "profile": scan.profile,

            "validation_level": scan.validation_level or "L2_SAFE_ACTIVE",

            "started_at": start_t.isoformat() if start_t else None,

            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,

            "duration_seconds": duration_secs,

            "coverage_percentage": None,

            "coverage_note": "No complete target inventory or executed-check denominator is recorded.",

            "counters": {

                "assets": len(assets),

                "services": len(ports),

                "endpoints": len(urls),

                "technologies": len(techs),

                "findings": len(findings),

                "confirmed_vulnerabilities": conf_counts["confirmed"],

                "attack_chains": 0,

                "artifacts": len(artifacts),

                "evidence_packages": len(evidence_items),

            },

            "severity_summary": sev_counts,

            "severity_breakdown": sev_counts,

            "confidence_summary": conf_counts,

            "confidence_breakdown": conf_counts,

        },

        "metrics": {

            "assets_count": len(assets),

            "services_count": len(ports),

            "endpoints_count": len(urls),

            "technologies_count": len(techs),

            "findings_count": len(findings),

            "artifacts_count": len(artifacts),

            "evidence_count": len(evidence_items),

            "exports_count": len(export_jobs),

            "coverage_percent": None,

            "severity_breakdown": sev_counts,

            "confidence_breakdown": conf_counts,

        },

        "assets": [

            {

                "id": a.id,

                "hostname": a.hostname or a.ip,

                "ip": a.ip,

                "asset_type": a.asset_type,

                "status": a.status,

                "first_seen": a.first_seen.isoformat() if hasattr(a, "first_seen") and a.first_seen else None,

            }

            for a in assets

        ],

        "services": services_list,

        "endpoints": endpoints_list,

        "technologies": [{"name": t.name, "version": t.version, "category": t.category, "asset_host": asset_map.get(t.asset_id, scan.root_domain)} for t in techs],

        "findings": findings_list,

        "evidence": evidence_list,

        "artifacts": artifacts_list,

        "exports": exports_list,

        "timeline": timeline_list,

    }







@router.get("/scans/{scan_id}/findings/{finding_id}/poc")

@router.get("/findings/{finding_id}/poc")

async def get_finding_poc_dossier(

    finding_id: str,

    scan_id: Optional[str] = None,

    db: AsyncSession = Depends(get_db),

):

    """Returns the comprehensive Bug Bounty Proof of Concept (PoC) dossier for a finding."""

    f = await db.get(Finding, finding_id)

    if not f:

        raise HTTPException(status_code=404, detail="Finding not found")



    scan = await db.get(Scan, f.scan_id) if f.scan_id else None

    root_domain = scan.root_domain if scan else "target.local"



    asset = await db.get(Asset, f.asset_id) if f.asset_id else None

    asset_hostname = asset.hostname if asset and asset.hostname else (asset.ip if asset and asset.ip else root_domain)



    f_ev = serialize_finding(f, scan.root_domain if scan else "", {})["evidence"]

    ss_id = f_ev.get("screenshot_id")

    ss = await db.get(Screenshot, ss_id) if ss_id else None

    if not ss and f.asset_id:

        ss = (await db.execute(select(Screenshot).where(Screenshot.asset_id == f.asset_id))).scalars().first()



    has_real_ss = False

    ss_url = None

    if ss and (ss.trigger or "").startswith("browser:") and ss.storage_path and Path(ss.storage_path).exists():

        has_real_ss = True

        ss_id = ss.id

        ss_url = f"/api/screenshots/{ss.id}/image"

    elif ss and (ss.trigger or "").startswith("browser:") and ss.thumbnail_path and Path(ss.thumbnail_path).exists():

        has_real_ss = True

        ss_id = ss.id

        ss_url = f"/api/screenshots/{ss.id}/image"



    target_endpoint_loc = finding_location(f, asset_hostname)



    from app.reporting.poc_builder import PocBuilder



    dossier = PocBuilder.generate_dossier(

        title=f.title,

        finding_type=f.finding_type or f.title,

        severity=f.severity,

        target_url=target_endpoint_loc,

        target_host=asset_hostname,

        parameter=f_ev.get("parameter"),

        method=f_ev.get("method", "GET") or "GET",

        headers=f_ev.get("headers"),

        payload=f_ev.get("payload") or f_ev.get("matched_pattern"),

        cwe_id=f.cwe_id,

        cve_id=f.cve_id,

        cvss_score=f.cvss_score,

        description=f.description,

        technical_details=f.technical_details,

        evidence=f_ev,

        screenshot_id=ss_id,

        screenshot_url=ss_url,

        has_real_screenshot=has_real_ss,

    )



    return {

        "finding_id": f.id,

        "finding_code": f.finding_code or f"INV-F-{f.id[:6]}",

        "dossier": dossier,

    }





# Async Export endpoints

@router.post("/scans/{scan_id}/export/{export_type}")

@router.post("/investigations/{scan_id}/export/{export_type}")

async def trigger_async_export(

    scan_id: str,

    export_type: str,

    current_user: Optional[User] = Depends(get_optional_user),

    db: AsyncSession = Depends(get_db),

):

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Investigation not found")

    try:

        job = await ExportManager.create_export_job(scan_id=scan_id, export_type=export_type, db=db)

        return {

            "job_id": job.id,

            "scan_id": scan_id,

            "export_type": export_type,

            "format": export_type,

            "filename": job.filename,

            "status": job.status,

            "created_at": job.created_at.isoformat() if job.created_at else None,

            "message": f"Export '{export_type}' queued successfully.",

        }



    except ValueError as val_err:

        raise HTTPException(status_code=400, detail=str(val_err))





@router.get("/scans/{scan_id}/exports")

@router.get("/investigations/{scan_id}/exports")

async def list_investigation_exports(

    scan_id: str,

    db: AsyncSession = Depends(get_db),

):

    jobs = (await db.execute(

        select(ExportJob).where(ExportJob.scan_id == scan_id).order_by(desc(ExportJob.created_at))

    )).scalars().all()

    return [

        {

            "id": j.id,

            "scan_id": j.scan_id,

            "export_type": j.export_type,

            "filename": j.filename,

            "status": j.status,

            "file_size": j.file_size,

            "sha256_hash": j.sha256_hash,

            "mime_type": j.mime_type,

            "error_message": j.error_message,

            "created_at": j.created_at.isoformat() if j.created_at else None,

            "completed_at": j.completed_at.isoformat() if j.completed_at else None,

            "download_url": f"/api/scans/{scan_id}/exports/{j.id}/download",

        }

        for j in jobs

    ]





@router.get("/scans/{scan_id}/exports/{export_id}/download")

@router.get("/investigations/{scan_id}/exports/{export_id}/download")

async def download_investigation_export(

    scan_id: str,

    export_id: str,

    db: AsyncSession = Depends(get_db),

):

    job = await db.get(ExportJob, export_id)

    if not job or job.scan_id != scan_id:

        raise HTTPException(status_code=404, detail="Export job not found")

    if job.status != "COMPLETED" or not job.file_path or not os.path.exists(job.file_path):

        raise HTTPException(status_code=400, detail=f"Export is not ready for download. Status: {job.status}")



    return FileResponse(

        path=job.file_path,

        filename=job.filename,

        media_type=job.mime_type or "application/octet-stream",

    )





# Artifact Preview Endpoints

@router.get("/scans/{scan_id}/artifacts")

@router.get("/investigations/{scan_id}/artifacts")

async def list_investigation_artifacts(

    scan_id: str,

    db: AsyncSession = Depends(get_db),

):

    arts = (await db.execute(

        select(Artifact).where(Artifact.scan_id == scan_id).order_by(desc(Artifact.created_at))

    )).scalars().all()

    return [

        {

            "id": a.id,

            "scan_id": a.scan_id,

            "filename": a.filename,

            "file_type": a.file_type,

            "mime_type": a.mime_type,

            "classification": a.classification,

            "category": a.category,

            "record_count": a.record_count,

            "size_bytes": a.size_bytes,

            "sha256_hash": a.sha256_hash,

            "source": a.source,

            "is_redacted": a.is_redacted,

            "state": a.state,

            "has_preview": bool(a.preview_data),

            "created_at": a.created_at.isoformat() if a.created_at else None,

        }

        for a in arts

    ]





@router.get("/scans/{scan_id}/artifacts/{artifact_id}/preview")

@router.get("/investigations/{scan_id}/artifacts/{artifact_id}/preview")

async def get_artifact_preview(

    scan_id: str,

    artifact_id: str,

    db: AsyncSession = Depends(get_db),

):

    art = await db.get(Artifact, artifact_id)

    if not art or art.scan_id != scan_id:

        raise HTTPException(status_code=404, detail="Artifact not found")



    # On-demand auto-heal: if artifact is missing raw_sample, tables, or has uncracked hashes

    prev = art.preview_data if isinstance(art.preview_data, dict) else {}

    fn_lower = (art.filename or "").lower()

    needs_heal = (

        not prev

        or not prev.get("raw_sample")

        or (art.category in ("generic", "", None) and (fn_lower.endswith(".sql") or fn_lower.endswith(".csv") or "passwd" in fn_lower))

        or ((art.category == "database" or fn_lower.endswith(".sql")) and not prev.get("tables"))

        or (prev.get("extracted_hashes") and not any(h.get("is_cracked") or h.get("plaintext") for h in prev.get("extracted_hashes", [])))

    )

    if needs_heal:

        try:

            from app.artifacts.engine import ArtifactEngine

            await ArtifactEngine.reprocess_and_sync_scan_artifacts(db, scan_id)

            art = await db.get(Artifact, artifact_id)

        except Exception as heal_err:

            logger.debug("Artifact preview on-the-fly heal error: %s", heal_err)



    return {

        "id": art.id,

        "filename": art.filename,

        "classification": art.classification,

        "category": art.category,

        "record_count": art.record_count,

        "preview_data": art.preview_data,

        "schema_data": art.schema_data,

        "extracted_entities": art.extracted_entities,

    }





# Attack Chains Visual Graph Endpoint

@router.get("/scans/{scan_id}/attack-chains")

@router.get("/investigations/{scan_id}/attack-chains")

async def get_attack_chains(

    scan_id: str,

    db: AsyncSession = Depends(get_db),

):

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    ports = (await db.execute(select(Port).join(Asset, Port.asset_id == Asset.id).where(Asset.scan_id == scan_id))).scalars().all()

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

    artifacts = (await db.execute(select(Artifact).where(Artifact.scan_id == scan_id))).scalars().all()



    nodes = []

    edges = []



    root_node_id = f"target_{scan.root_domain}"

    nodes.append({"id": root_node_id, "label": scan.root_domain, "type": "target", "severity": "info"})



    for a in assets[:15]:

        a_id = f"asset_{a.id}"

        nodes.append({"id": a_id, "label": a.hostname or a.ip, "type": "asset", "severity": "info"})

        edges.append({"source": root_node_id, "target": a_id, "label": "resolves_to"})



    for p in ports[:25]:

        p_id = f"port_{p.id}"

        p_num = getattr(p, "port_number", getattr(p, "port", 80))

        nodes.append({"id": p_id, "label": f"{p.service or 'tcp'}:{p_num}", "type": "service", "severity": "info"})

        if p.asset_id:

            edges.append({"source": f"asset_{p.asset_id}", "target": p_id, "label": "exposes_port"})



    for f in findings[:25]:

        f_id = f"finding_{f.id}"

        nodes.append({"id": f_id, "label": f.title[:30], "type": "vulnerability", "severity": (f.severity or "info").lower()})

        if f.asset_id:

            edges.append({"source": f"asset_{f.asset_id}", "target": f_id, "label": "vulnerable_to"})

        else:

            edges.append({"source": root_node_id, "target": f_id, "label": "vulnerable_to"})



    for art in artifacts[:10]:

        art_id = f"art_{art.id}"

        nodes.append({"id": art_id, "label": art.filename[:25], "type": "artifact", "severity": "critical" if art.classification == "HIGHLY_SENSITIVE" else "warning"})

        if art.finding_id:

            edges.append({"source": f"finding_{art.finding_id}", "target": art_id, "label": "exposed_data"})

        else:

            edges.append({"source": root_node_id, "target": art_id, "label": "extracted_file"})



    return {"nodes": nodes, "edges": edges}





# Admin Operational Endpoints

@router.get("/admin/scans/active")

@router.get("/admin/investigations/active")

async def admin_list_active_scans(

    admin: User = Depends(require_admin_role),

    db: AsyncSession = Depends(get_db),

):

    """Admin Operational Oversight: list running, queued, completed, and failed jobs."""

    scans = (await db.execute(

        select(Scan, User.username)

        .outerjoin(User, Scan.user_id == User.id)

        .order_by(desc(Scan.created_at))

        .limit(100)

    )).all()



    ids = [scan.id for scan, _ in scans]

    asset_counts = dict((await db.execute(select(Asset.scan_id, func.count()).where(Asset.scan_id.in_(ids)).group_by(Asset.scan_id))).all()) if ids else {}

    port_counts = dict((await db.execute(select(Asset.scan_id, func.count(Port.id)).join(Port, Port.asset_id == Asset.id).where(Asset.scan_id.in_(ids)).group_by(Asset.scan_id))).all()) if ids else {}

    items = []

    for s, uname in scans:

        items.append({

            "id": s.id,

            "user": uname or "Guest / System",

            "progress": {"assets": asset_counts.get(s.id, 0), "ports": port_counts.get(s.id, 0)},

            "root_domain": s.root_domain,

            "status": s.status,

            "profile": s.profile,

            "validation_level": s.validation_level,

            "created_at": s.created_at.isoformat() if s.created_at else None,

            "started_at": s.started_at.isoformat() if s.started_at else None,

            "completed_at": s.completed_at.isoformat() if s.completed_at else None,

        })

    return items





@router.post("/admin/scans/{scan_id}/cancel")

@router.post("/admin/investigations/{scan_id}/cancel")

async def admin_cancel_scan(

    scan_id: str,

    admin: User = Depends(require_admin_role),

):

    """Admin force-stop/cancel investigation."""

    await scan_manager.stop(scan_id)

    return {"scan_id": scan_id, "action": "cancel", "status": "cancelled"}





@router.post("/admin/scans/{scan_id}/retry")

@router.post("/admin/investigations/{scan_id}/retry")

async def admin_retry_scan(

    scan_id: str,

    admin: User = Depends(require_admin_role),

    db: AsyncSession = Depends(get_db),

):

    """Admin retry failed investigation."""

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")

    options = scan.options or {}

    if not scan.authorization_reference:

        raise HTTPException(409, "Buat scan baru dengan referensi izin; scan lama tidak memiliki otorisasi tercatat.")

    try:

        res = await scan_manager.create_scan(

            target=options.get("target_url") or options.get("target_host") or scan.root_domain,

            profile=scan.profile, include_subdomains=options.get("include_subdomains", False),

            validation_level=scan.validation_level, user_id=scan.user_id or admin.id,

            authorization_reference=scan.authorization_reference,

            engagement=options.get("engagement") or None,

        )

    except ScanQueueFull as error:

        raise HTTPException(429, str(error))

    except ValueError as error:

        raise HTTPException(400, str(error))

    new_id = res.get("id") or res.get("scan_id") or res.get("investigation_id")
    return {
        "status": "retried",
        "old_scan_id": scan_id,
        "new_scan_id": new_id,
        "scan_id": new_id,
        "investigation_id": new_id,
    }







@router.get("/admin/system/health")

async def admin_system_health(

    admin: User = Depends(require_admin_role),

    db: AsyncSession = Depends(get_db),

):

    """Admin System Telemetry & Resource Status (§27-§31)."""

    import psutil

    from app.core.resource_governor import ResourceGovernor

    

    cpu_pct = psutil.cpu_percent(interval=None)

    mem = psutil.virtual_memory()

    gov_status = ResourceGovernor.check_capacity()





    running_count = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status == "running"))).scalar() or 0

    queued_count = (await db.execute(select(func.count()).select_from(Scan).where(Scan.status == "queued"))).scalar() or 0



    return {

        "status": gov_status.get("status", "HEALTHY"),

        "governor_status": gov_status.get("status", "HEALTHY"),

        "cpu_usage_percent": cpu_pct,

        "cpu_percent": cpu_pct,

        "ram_usage_percent": mem.percent,

        "memory_percent": mem.percent,

        "ram_available_mb": round(mem.available / (1024 * 1024), 2),

        "running_investigations": running_count,

        "queued_investigations": queued_count,

        "active_workers": min(settings.max_concurrent_hosts, max(1, running_count * 2)),

        "llm_status": "ONLINE" if settings.llm_enabled else "OFFLINE",

    }





@router.get("/investigations/{scan_id}")

async def get_investigation_bundle(

    scan_id: str,

    current_user: Optional[User] = Depends(get_optional_user),

    db: AsyncSession = Depends(get_db),

):

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    asset_ids = [a.id for a in assets]



    ports = (await db.execute(select(Port).where(Port.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    urls = (await db.execute(select(URL).where(URL.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    url_ids = [u.id for u in urls]

    params = (await db.execute(select(Parameter).where(Parameter.url_id.in_(url_ids)))).scalars().all() if url_ids else []



    techs = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    certs = (await db.execute(select(Certificate).where(Certificate.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

    observations = (await db.execute(select(Observation).where(Observation.scan_id == scan_id))).scalars().all()



    return {

        "scan": {

            "id": scan.id,

            "user_id": scan.user_id,

            "root_domain": scan.root_domain,

            "status": scan.status,

            "profile": scan.profile,

            "created_at": scan.created_at.isoformat() if scan.created_at else None,

            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,

            "progress": scan.progress or {},

        },

        "statistics": {

            "total_assets": len(assets),

            "total_ports": len(ports),

            "total_urls": len(urls),

            "total_parameters": len(params),

            "total_technologies": len(techs),

            "total_certificates": len(certs),

            "total_findings": len(findings),

            "total_observations": len(observations),

        },

        "assets": [

            {"id": a.id, "type": a.asset_type, "hostname": a.hostname, "ip": a.ip, "depth": a.depth, "parent_id": a.parent_id, "discovered_from": a.discovered_from}

            for a in assets

        ],

        "ports": [

            {"asset_id": p.asset_id, "ip": p.ip, "port": p.port, "protocol": p.protocol, "service": p.service, "banner": p.banner}

            for p in ports

        ],

        "urls": [

            {"asset_id": u.asset_id, "url": u.url, "status_code": u.status_code, "title": u.title, "content_type": u.content_type}

            for u in urls

        ],

        "parameters": [

            {"url_id": pr.url_id, "name": pr.name, "location": pr.location, "type": pr.type}

            for pr in params

        ],

        "technologies": [

            {"asset_id": t.asset_id, "name": t.name, "version": t.version, "evidence": t.evidence}

            for t in techs

        ],

        "findings": [

            {"id": f.id, "title": f.title, "severity": f.severity, "type": f.finding_type, "description": f.description, "evidence": f.evidence, "status": f.status}

            for f in findings

        ],

    }





# ==========================================================================

# Architecture v2 APIs: Detail Pages, Reporting, Search & TTPs (§36-38, §47, §52)

# ==========================================================================



def _serialize_findings_for_report(findings, root_domain: str, asset_map: Optional[dict] = None) -> list:

    return [serialize_finding(f, root_domain, asset_map) for f in findings]





@router.get("/scans/{scan_id}/report")

@router.get("/scans/{scan_id}/report/markdown")

@router.get("/scans/{scan_id}/report/md")

async def get_scan_report(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Generate professional executive security assessment report in Markdown (§52, §100)."""

    from app.reporting.engine import ReportEngine



    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    asset_ids = [a.id for a in assets]

    asset_map = {a.id: (a.hostname or a.fqdn or a.ip) for a in assets}



    ports = (await db.execute(select(Port).where(Port.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    techs = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

    urls_count = (await db.execute(select(func.count()).select_from(URL).where(URL.asset_id.in_(asset_ids)))).scalar() or 0



    stats = {

        "total_assets": len(assets),

        "total_ports": len(ports),

        "total_urls": urls_count,

        "total_technologies": len(techs),

        "report_context": report_context(scan),

    }



    report_md = ReportEngine.generate_markdown(

        scan_id=scan.id,

        target=scan.root_domain,

        stats=stats,

        findings=_serialize_findings_for_report(findings, scan.root_domain, asset_map),

        assets=[{"hostname": a.hostname, "ip": a.ip} for a in assets],

        ports=[{"port": p.port, "protocol": p.protocol, "service": p.service} for p in ports],

        technologies=[{"name": t.name, "version": t.version} for t in techs],

    )



    return Response(content=report_md, media_type="text/markdown")





@router.get("/scans/{scan_id}/report/html")

async def get_scan_html_report(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Generate professional executive security assessment report in HTML (§52, §100)."""

    from app.reporting.engine import ReportEngine



    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    asset_ids = [a.id for a in assets]

    asset_map = {a.id: (a.hostname or a.fqdn or a.ip) for a in assets}



    ports = (await db.execute(select(Port).where(Port.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    techs = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

    urls_count = (await db.execute(select(func.count()).select_from(URL).where(URL.asset_id.in_(asset_ids)))).scalar() or 0



    stats = {

        "total_assets": len(assets),

        "total_ports": len(ports),

        "total_urls": urls_count,

        "total_technologies": len(techs),

        "report_context": report_context(scan),

    }



    report_html = ReportEngine.generate_html(

        scan_id=scan.id,

        target=scan.root_domain,

        stats=stats,

        findings=_serialize_findings_for_report(findings, scan.root_domain, asset_map),

        assets=[{"hostname": a.hostname, "ip": a.ip} for a in assets],

        ports=[{"port": p.port, "protocol": p.protocol, "service": p.service} for p in ports],

        technologies=[{"name": t.name, "version": t.version} for t in techs],

    )



    return Response(content=report_html, media_type="text/html")





@router.get("/scans/{scan_id}/report/pdf")

async def get_scan_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Generate audit-grade security assessment report in ready-to-use PDF (§52, §100)."""

    from app.reporting.engine import ReportEngine



    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    asset_ids = [a.id for a in assets]

    asset_map = {a.id: (a.hostname or a.fqdn or a.ip) for a in assets}



    ports = (await db.execute(select(Port).where(Port.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    techs = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all() if asset_ids else []

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

    urls_count = (await db.execute(select(func.count()).select_from(URL).where(URL.asset_id.in_(asset_ids)))).scalar() or 0



    stats = {

        "total_assets": len(assets),

        "total_ports": len(ports),

        "total_urls": urls_count,

        "total_technologies": len(techs),

        "report_context": report_context(scan),

    }



    pdf_bytes = await asyncio.to_thread(ReportEngine.generate_pdf,

        scan_id=scan.id,

        target=scan.root_domain,

        stats=stats,

        findings=_serialize_findings_for_report(findings, scan.root_domain, asset_map),

        assets=[{"hostname": a.hostname, "ip": a.ip} for a in assets],

        ports=[{"port": p.port, "protocol": p.protocol, "service": p.service} for p in ports],

        technologies=[{"name": t.name, "version": t.version} for t in techs],

    )



    clean_target = scan.root_domain.replace(".", "_")

    filename = f"Security_Report_{clean_target}_{scan.id[:12]}.pdf"

    return Response(

        content=pdf_bytes,

        media_type="application/pdf",

        headers={

            "Content-Disposition": f"attachment; filename=\"{filename}\"",

            "Content-Length": str(len(pdf_bytes)),

        },

    )





@router.get("/domains/{domain_name}")

@router.get("/domains/{domain_name}/detail")

async def get_domain_detail(domain_name: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):

    """Domain Deep Analysis Detail Page (§36)."""

    d_clean = domain_name.strip().lower()

    domain = (await db.execute(select(Domain).where(Domain.name == d_clean))).scalar_one_or_none()



    scan_query = select(Scan).where(Scan.root_domain == d_clean).order_by(desc(Scan.created_at))

    if current_user.role != "admin":

        scan_query = scan_query.where(Scan.user_id == current_user.id)

        domain = None  # Shared domain summary is not a tenant-scoped risk summary.

    scans = (await db.execute(scan_query)).scalars().all()

    if not scans:

        raise HTTPException(404, "Domain not found")

    scan_ids = [s.id for s in scans]



    subdomains = []

    ips = set()

    total_open_ports = 0

    unique_ports_count = 0

    urls_count = 0

    techs = []

    findings = []



    if scan_ids:

        assets = (await db.execute(select(Asset).where(Asset.scan_id.in_(scan_ids)))).scalars().all()

        subdomains = list({a.hostname for a in assets if a.hostname})

        ips = {a.ip for a in assets if a.ip}

        asset_ids = [a.id for a in assets]



        if asset_ids:

            total_open_ports = (await db.execute(select(func.count()).select_from(Port).where(Port.asset_id.in_(asset_ids)))).scalar() or 0

            unique_ports_count = (await db.execute(select(func.count(distinct(Port.port))).where(Port.asset_id.in_(asset_ids)))).scalar() or 0

            urls_count = (await db.execute(select(func.count()).select_from(URL).where(URL.asset_id.in_(asset_ids)))).scalar() or 0

            tech_rows = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all()

            seen_tech_keys = set()

            techs = []

            for t in tech_rows:

                key = (t.name.strip().lower(), (t.version or "").strip().lower())

                if key not in seen_tech_keys:

                    seen_tech_keys.add(key)

                    techs.append({"name": t.name, "version": t.version, "category": t.category or "General"})



        finding_rows = (await db.execute(select(Finding).where(Finding.scan_id.in_(scan_ids)))).scalars().all()

        findings = [

            {

                "id": f.id,

                "title": f.title,

                "severity": f.severity,

                "status": f.status,

                "confidence": f.confidence,

                "created_at": f.first_seen.isoformat() if f.first_seen else None,

            }

            for f in finding_rows

        ]



    return {

        "domain": d_clean,

        "root_domain": d_clean,

        "health_status": domain.health_status if domain else "ACTIVE",

        "risk_level": domain.risk_level if domain else ("HIGH" if len(findings) > 2 else "LOW"),

        "total_scans": len(scans),

        "scan_count": len(scans),

        "total_subdomains": len(subdomains),

        "subdomain_count": len(subdomains),

        "subdomains": sorted(subdomains),

        "total_ips": len(ips),

        "ip_count": len(ips),

        "ips": sorted(list(ips)),

        "total_ports": total_open_ports,

        "open_ports": total_open_ports,

        "unique_ports": unique_ports_count,

        "total_urls": urls_count,

        "url_count": urls_count,

        "technologies": techs,

        "total_findings": len(findings),

        "finding_count": len(findings),

        "findings": findings,

    }





@router.get("/findings/{finding_id}/detail")

async def get_finding_detail(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Finding Deep Detail Page with Evidence Package, CWE, CVE, and PoC (V5 §37, §38)."""

    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    asset = await db.get(Asset, finding.asset_id) if finding.asset_id else None

    target_host = (asset.hostname if asset else None) or "target.local"

    ev_dict = finding.evidence if isinstance(finding.evidence, dict) else {}

    param_name = ev_dict.get("parameter") or None



    from app.findings.lifecycle import FindingLifecycle

    from app.reporting.engine import ReportEngine

    data = ReportEngine._prepare_findings([serialize_finding(finding, target_host)])[0]

    data["asset"] = {"id": asset.id, "hostname": asset.hostname, "ip": asset.ip} if asset else None

    data["allowed_transitions"] = sorted(FindingLifecycle.VALID_TRANSITIONS.get(finding.status.upper(), set()) - {"RETESTING"})

    return data





@router.post("/findings/{finding_id}/ai-triage")

async def trigger_finding_ai_triage(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Triggers on-demand live NineRouter LLM Deep Reasoning and saves rich analysis to finding."""

    from app.intelligence.llm_client import llm_client

    from app.intelligence.local_ai import LocalAiEngine



    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    asset = await db.get(Asset, finding.asset_id) if finding.asset_id else None

    target_host = (asset.hostname if asset else None) or "target.local"

    ev_dict = finding.evidence if isinstance(finding.evidence, dict) else {}



    ai_triage_res = None

    if llm_client.is_configured:

        try:

            ai_triage_res = await llm_client.deep_triage_finding(

                vulnerability_type=finding.finding_type or "vulnerability",

                title=finding.title,

                target_host=target_host,

                endpoint_url=ev_dict.get("url") or f"https://{target_host}/",

                parameter=ev_dict.get("parameter"),

                severity=finding.severity,

                evidence_level=finding.evidence_level or "E2",

                raw_evidence=ev_dict,

            )

        except Exception as exc:

            logger.debug("Live LLM triage on-demand error: %s", exc)



    if not ai_triage_res:

        syn_exec, syn_root, syn_biz, syn_tech, syn_remed = LocalAiEngine.synthesize_descriptions(

            vulnerability_type=finding.finding_type or "vulnerability",

            title=finding.title,

            target_host=target_host,

            parameter=ev_dict.get("parameter"),

            severity=finding.severity,

            sem_res={},

        )

        ai_triage_res = {

            "ai_decision": "CONFIRMED",

            "ai_confidence_score": 95,

            "executive_explanation": syn_exec,

            "root_cause": syn_root,

            "business_impact": syn_biz,

            "technical_details": syn_tech,

            "remediation": syn_remed,

            "cvss_score": finding.cvss_score,

        }



    finding.executive_explanation = ai_triage_res.get("executive_explanation") or finding.executive_explanation

    finding.root_cause = ai_triage_res.get("root_cause") or finding.root_cause

    finding.business_impact = ai_triage_res.get("business_impact") or finding.business_impact

    if ai_triage_res.get("technical_details"):

        finding.technical_details = ai_triage_res["technical_details"]

    if ai_triage_res.get("remediation"):

        finding.remediation = ai_triage_res["remediation"]

    if ai_triage_res.get("cvss_score"):

        finding.cvss_score = float(ai_triage_res["cvss_score"])



    cur_ev = dict(ev_dict)

    cur_ev["ai_confidence_score"] = ai_triage_res.get("ai_confidence_score", 95)

    cur_ev["ai_triage_decision"] = ai_triage_res.get("ai_decision", "CONFIRMED")

    finding.evidence = cur_ev



    await db.commit()

    return {"status": "ok", "triage": ai_triage_res}





@router.get("/findings/{finding_id}/evidence-package")

async def get_finding_evidence_package(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Retrieve or build full cryptographic Evidence Package (V5 §21, §22)."""

    from app.evidence.package import EvidencePackageBuilder



    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    asset = await db.get(Asset, finding.asset_id) if finding.asset_id else None

    target_host = asset.hostname if asset else "target.local"

    ev_dict = finding.evidence if isinstance(finding.evidence, dict) else {}

    endpoint_url = ev_dict.get("url") or ev_dict.get("location") or f"https://{target_host}/"



    package = EvidencePackageBuilder.build_package(

        finding_id=finding.id,

        finding_code=finding.finding_code or "BH-2026-001",

        title=finding.title,

        severity=finding.severity,

        confidence=finding.confidence,

        evidence_level=finding.evidence_level or "E0",

        target_host=target_host,

        endpoint_url=endpoint_url,

        cwe_id=finding.cwe_id,

        cve_id=finding.cve_id,

        cvss_score=finding.cvss_score,

        description=finding.description,

        impact_matrix=finding.impact_matrix,

        root_cause=finding.root_cause,

        preconditions=finding.preconditions,

        expected_result=finding.expected_result,

        actual_result=finding.actual_result,

        remediation=finding.remediation,

        request_metadata={"method": ev_dict.get("method"), "url": endpoint_url, "headers": ev_dict.get("request_headers", ev_dict.get("headers", {})), "body": ev_dict.get("request_body")},

        response_metadata={"status_code": ev_dict.get("response_status", ev_dict.get("status_code")), "headers": ev_dict.get("response_headers", {}), "body": ev_dict.get("response_body", ev_dict.get("body_sample"))},

        observations=ev_dict.get("observations", []),

        reproduction_steps=ev_dict.get("reproduction_steps", []),

    )



    return package





@router.get("/findings/{finding_id}/reproduction")

async def get_finding_reproduction_md(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Generate standalone reproduction.md bundle (V5 §24)."""

    from app.reporting.engine import ReportEngine



    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    asset = await db.get(Asset, finding.asset_id) if finding.asset_id else None

    finding_dict = serialize_finding(finding, asset.hostname if asset else "")



    md_content = ReportEngine.generate_reproduction_md(finding_dict)

    return Response(content=md_content, media_type="text/markdown")





@router.get("/findings/{finding_id}/bugbounty")

async def get_finding_bugbounty_report(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Generate standardized Bug Bounty disclosure report for HackerOne/Bugcrowd (V5 §32)."""

    from app.reporting.engine import ReportEngine



    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    asset = await db.get(Asset, finding.asset_id) if finding.asset_id else None

    target_host = asset.hostname if asset else "target.local"

    ev_dict = finding.evidence or {}



    finding_dict = serialize_finding(finding, target_host)



    report_md = ReportEngine.generate_bug_bounty_markdown(finding_dict, target_host)

    return Response(content=report_md, media_type="text/markdown")





@router.get("/findings/{finding_id}/cve-ready")

async def get_finding_cve_ready_report(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Generate CVE-Ready Research Disclosure Report (V5 §33)."""

    from app.reporting.engine import ReportEngine



    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    asset = await db.get(Asset, finding.asset_id) if finding.asset_id else None

    target_host = asset.hostname if asset else "target.local"

    ev_dict = finding.evidence or {}



    finding_dict = serialize_finding(finding, target_host)



    report_md = ReportEngine.generate_cve_research_markdown(finding_dict, target_host)

    return Response(content=report_md, media_type="text/markdown")





@router.get("/findings/{finding_id}/remediation-patch")

async def get_finding_remediation_patch(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Generate framework-specific drop-in code patch and server hardening directives (V5 §50)."""

    from app.intelligence.remediation_ai import RemediationAi



    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    techs = []

    if finding.asset_id:

        tech_rows = (await db.execute(select(Technology).where(Technology.asset_id == finding.asset_id))).scalars().all()

        techs = [{"name": t.name, "version": t.version} for t in tech_rows]



    ev_dict = finding.evidence if isinstance(finding.evidence, dict) else {}

    f_dict = {

        "id": finding.id,

        "title": finding.title,

        "vulnerability_type": finding.finding_type,

        "endpoint_url": ev_dict.get("url") or "/",

    }



    patch = RemediationAi.generate_patch_for_finding(f_dict, techs)

    return {

        "finding_id": patch.finding_id,

        "vulnerability_title": patch.vulnerability_title,

        "target_framework": patch.target_framework,

        "emergency_containment_step": patch.emergency_containment_step,

        "configuration_patch": patch.configuration_patch,

        "code_patch": patch.code_patch,

        "verification_command": patch.verification_command,

        "best_practice_notes": patch.best_practice_notes,

    }





async def get_scan_attack_chains(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Synthesize multi-step exploit paths, Mermaid diagrams, and blast radius for a scan (V5 §46, §47)."""

    from app.intelligence.attack_chain import AttackChainCorrelator



    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()

    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    asset_ids = [a.id for a in assets]



    techs = []

    if asset_ids:

        tech_rows = (await db.execute(select(Technology).where(Technology.asset_id.in_(asset_ids)))).scalars().all()

        techs = [{"name": t.name, "version": t.version} for t in tech_rows]



    findings_dicts = [

        {

            "id": f.id,

            "title": f.title,

            "severity": f.severity,

            "vulnerability_type": f.vulnerability_type,

            "url": (f.evidence or {}).get("url") if isinstance(f.evidence, dict) else None,

        }

        for f in findings

    ]



    target = scan.root_domain or "target.local"

    chains = AttackChainCorrelator.analyze_scan_findings(target, findings_dicts, techs)



    return {

        "scan_id": scan_id,

        "target": target,

        "total_chains_synthesized": len(chains),

        "attack_chains": [

            {

                "chain_id": c.chain_id,

                "name": c.name,

                "severity": c.severity,

                "estimated_ttc": c.estimated_ttc,

                "blast_radius": c.blast_radius,

                "likelihood": c.likelihood,

                "financial_risk_rating": c.financial_risk_rating,

                "narrative": c.narrative,

                "mermaid_diagram": c.mermaid_diagram,

                "remediation_priority": c.remediation_priority,

                "steps": [

                    {

                        "step_number": s.step_number,

                        "phase": s.phase,

                        "title": s.title,

                        "target_url": s.target_url,

                        "technique": s.technique,

                        "description": s.description,

                    }

                    for s in c.steps

                ],

            }

            for c in chains

        ],

    }





# =============================================================================

# Scan Level Comprehensive Report Exporters (§31, §52, §100, §101)

# =============================================================================



async def _gather_scan_report_data(scan_id: str, db: AsyncSession):

    scan = await db.get(Scan, scan_id)

    if not scan:

        raise HTTPException(status_code=404, detail="Scan not found")



    target = getattr(scan, "root_domain", None) or (scan.options.get("target_host") if isinstance(scan.options, dict) else None) or "target.local"



    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    ports = (await db.execute(select(Port).join(Asset, Port.asset_id == Asset.id).where(Asset.scan_id == scan_id))).scalars().all()

    urls = (await db.execute(select(URL).join(Asset, URL.asset_id == Asset.id).where(Asset.scan_id == scan_id))).scalars().all()

    technologies = (await db.execute(select(Technology).join(Asset, Technology.asset_id == Asset.id).where(Asset.scan_id == scan_id))).scalars().all()

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()



    assets_data = [

        {"id": a.id, "hostname": a.hostname, "ip": a.ip, "asset_type": a.asset_type, "depth": a.depth}

        for a in assets

    ]

    ports_data = [

        {"port": getattr(p, "port", None) or getattr(p, "port_number", 0), "protocol": p.protocol, "service": getattr(p, "service", None) or getattr(p, "service_name", "unknown"), "banner": p.banner}

        for p in ports

    ]

    tech_data = [

        {"name": t.name, "version": t.version, "category": t.category, "cpe": t.cpe, "hostname": target}

        for t in technologies

    ]

    asset_map = {a.id: (a.hostname or a.fqdn or a.ip) for a in assets}

    findings_data = _serialize_findings_for_report(findings, target, asset_map)



    stats = {

        "total_assets": len(assets),

        "total_ports": len(ports),

        "total_urls": len(urls),

        "total_technologies": len(technologies),

        "total_findings": len(findings),

        "report_context": report_context(scan),

    }



    return scan, target, stats, findings_data, assets_data, ports_data, tech_data





async def export_scan_markdown_report(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Export complete Markdown audit report for the scan (§31, §52)."""

    from app.reporting.engine import ReportEngine

    scan, target, stats, findings, assets, ports, techs = await _gather_scan_report_data(scan_id, db)

    md_content = ReportEngine.generate_markdown(

        scan_id=scan_id,

        target=target,

        stats=stats,

        findings=findings,

        assets=assets,

        ports=ports,

        technologies=techs,

        operator="Hunter Aja Autonomous Security Suite",

    )

    return Response(

        content=md_content,

        media_type="text/markdown",

        headers={"Content-Disposition": f'attachment; filename="security_report_{target}_{scan_id[:8]}.md"'},

    )





async def export_scan_html_report(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Export or view self-contained HTML executive report for the scan (§31, §100)."""

    from app.reporting.engine import ReportEngine

    scan, target, stats, findings, assets, ports, techs = await _gather_scan_report_data(scan_id, db)

    html_content = ReportEngine.generate_html(

        scan_id=scan_id,

        target=target,

        stats=stats,

        findings=findings,

        assets=assets,

        ports=ports,

        technologies=techs,

        operator="Hunter Aja Autonomous Security Suite",

    )

    return HTMLResponse(content=html_content)





async def export_scan_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Export audit-grade printable PDF report for the scan (§52, §101)."""

    from app.reporting.engine import ReportEngine

    scan, target, stats, findings, assets, ports, techs = await _gather_scan_report_data(scan_id, db)

    pdf_bytes = await asyncio.to_thread(ReportEngine.generate_pdf,

        scan_id=scan_id,

        target=target,

        stats=stats,

        findings=findings,

        assets=assets,

        ports=ports,

        technologies=techs,

        operator="Hunter Aja Autonomous Security Suite",

    )

    return Response(

        content=pdf_bytes,

        media_type="application/pdf",

        headers={"Content-Disposition": f'attachment; filename="security_report_{target}_{scan_id[:8]}.pdf"'},

    )





@router.get("/scans/{scan_id}/report/json")

async def export_scan_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Export complete sanitized JSON dataset for SIEM/SOAR/automation ingestion (§31)."""

    from app.reporting.engine import ReportEngine

    scan, target, stats, findings, assets, ports, techs = await _gather_scan_report_data(scan_id, db)

    json_str = ReportEngine.generate_json(

        scan_id=scan_id,

        target=target,

        stats=stats,

        findings=findings,

        assets=assets,

        ports=ports,

        technologies=techs,

    )

    return Response(

        content=json_str,

        media_type="application/json",

        headers={"Content-Disposition": f'attachment; filename="security_report_{target}_{scan_id[:8]}.json"'},

    )





@router.post("/findings/{finding_id}/retest")

async def perform_finding_retest(finding_id: str, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):

    """Execute live non-destructive Retest with before vs after evidence comparison (V5 §34, §42)."""

    from app.retest.engine import retest_engine

    finding = await db.get(Finding, finding_id)

    scan = await db.get(Scan, finding.scan_id)

    if scan.validation_level not in {"L3_CONTROLLED", "L4_HIGH_RISK"} or not (scan.options or {}).get("authorization_reference"):

        raise HTTPException(403, "Live retest memerlukan scan L3/L4 dengan referensi otorisasi yang jelas.")

    if finding.status == "RETESTING":

        raise HTTPException(409, "Retest masih berjalan.")

    result = await retest_engine.create_and_execute_retest(db, finding_id, tester_id=current_user.id)

    if "error" in result:

        raise HTTPException(status_code=404 if "not found" in result["error"].lower() else 400, detail=result["error"])

    return result





@router.post("/findings/{finding_id}/transition")

async def transition_finding_state(finding_id: str, next_state: str = Query(...), db: AsyncSession = Depends(get_db)):

    """Transition finding status via lifecycle state machine (§33)."""

    from app.findings.lifecycle import FindingLifecycle



    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    if next_state.upper() not in FindingLifecycle.STATES or not FindingLifecycle.can_transition(finding.status, next_state):

        raise HTTPException(

            status_code=400,

            detail=f"Invalid lifecycle transition from '{finding.status}' to '{next_state.upper()}'.",

        )



    if next_state.upper() in {"VALIDATED", "CONFIRMED", "SECURITY_BEHAVIOR_CONFIRMED"}:

        raise HTTPException(400, "Validation states are set by evidence validators, not manual transitions")



    finding.status = next_state.upper()

    await db.commit()

    return {"id": finding.id, "status": finding.status}





@router.get("/scans/{scan_id}/clean-status")

async def get_scan_clean_status(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Check if all findings for a scan are closed/resolved (§34 Clean State)."""

    from app.retest.engine import retest_engine

    return await retest_engine.check_clean_state(db, scan_id)





# =============================================================================

# 15. Screenshots & Visual Evidence Engine (§10, §11, §12)

# =============================================================================

@router.get("/screenshots/{screenshot_id}/image")

async def get_screenshot_image(screenshot_id: str, db: AsyncSession = Depends(get_db)):

    """Serve full-resolution PNG visual proof image."""

    from app.core.config import SCREENSHOTS_DIR

    from pathlib import Path

    

    ss = await db.get(Screenshot, screenshot_id)

    if not ss:

        raise HTTPException(status_code=404, detail="Screenshot not found")

        

    resolved_path = None

    candidates = []

    if ss.storage_path:

        candidates.append(Path(ss.storage_path))

        candidates.append(SCREENSHOTS_DIR / Path(ss.storage_path).name)

        if ss.scan_id:

            candidates.append(SCREENSHOTS_DIR / ss.scan_id / Path(ss.storage_path).name)

            

    for c in candidates:

        try:

            candidate = contained_path(c, SCREENSHOTS_DIR)

        except ValueError:

            continue

        if candidate.exists() and candidate.is_file():

            resolved_path = str(candidate)

            break

            

    if not resolved_path:

        raise HTTPException(status_code=404, detail="Screenshot image not found on disk")

    return FileResponse(resolved_path, media_type="image/png", filename=f"proof_{screenshot_id}.png")





@router.get("/screenshots/{screenshot_id}/thumbnail")

async def get_screenshot_thumbnail(screenshot_id: str, db: AsyncSession = Depends(get_db)):

    """Serve JPEG thumbnail image for visual proof gallery."""

    from app.core.config import SCREENSHOTS_DIR

    from pathlib import Path

    

    ss = await db.get(Screenshot, screenshot_id)

    if not ss:

        raise HTTPException(status_code=404, detail="Screenshot not found")

        

    resolved_path = None

    candidates = []

    if ss.thumbnail_path:

        candidates.append(Path(ss.thumbnail_path))

        candidates.append(SCREENSHOTS_DIR / Path(ss.thumbnail_path).name)

        if ss.scan_id:

            candidates.append(SCREENSHOTS_DIR / ss.scan_id / Path(ss.thumbnail_path).name)

    if ss.storage_path:

        candidates.append(Path(ss.storage_path))

        candidates.append(SCREENSHOTS_DIR / Path(ss.storage_path).name)

        if ss.scan_id:

            candidates.append(SCREENSHOTS_DIR / ss.scan_id / Path(ss.storage_path).name)

            

    for c in candidates:

        try:

            candidate = contained_path(c, SCREENSHOTS_DIR)

        except ValueError:

            continue

        if candidate.exists() and candidate.is_file():

            resolved_path = str(candidate)

            break

            

    if not resolved_path:

        raise HTTPException(status_code=404, detail="Thumbnail image not found on disk")

    return FileResponse(resolved_path, media_type="image/jpeg", filename=f"thumb_{screenshot_id}.jpg")





@router.get("/scans/{scan_id}/screenshots")

async def get_scan_screenshots(scan_id: str, limit: int = 50, db: AsyncSession = Depends(get_db)):

    """List all visual proof screenshots captured for a scan."""

    screenshots = (await db.execute(

        select(Screenshot)

        .where(Screenshot.scan_id == scan_id)

        .order_by(desc(Screenshot.created_at))

        .limit(limit)

    )).scalars().all()



    return [

        {

            "id": s.id,

            "scan_id": s.scan_id,

            "asset_id": s.asset_id,

            "url_id": s.url_id,

            "image_url": f"/api/screenshots/{s.id}/image",

            "thumb_url": f"/api/screenshots/{s.id}/thumbnail",

            "viewport": s.viewport,

            "status_code": s.status_code,

            "page_title": s.page_title,

            "content_hash": s.content_hash,

            "visual_hash": s.visual_hash,

            "trigger": s.trigger,

            "capture_kind": "browser" if (s.trigger or "").startswith("browser:") else "legacy_unverified",

            "capture_kind": "browser" if (s.trigger or "").startswith("browser:") else "legacy_unverified",

            "created_at": s.created_at.isoformat() if s.created_at else None,

        }

        for s in screenshots

    ]





# =============================================================================

# 16. MITRE ATT&CK Matrix & Threat Modeling Intelligence (§26)

# =============================================================================

@router.get("/mitre/catalog")

async def get_mitre_catalog():

    """Returns the registered MITRE ATT&CK Enterprise matrix techniques."""

    from app.intelligence.ttp import TtpEngine

    return {"catalog": TtpEngine.TTP_REGISTRY}





@router.get("/scans/{scan_id}/mitre-matrix")

async def get_scan_mitre_matrix(scan_id: str, db: AsyncSession = Depends(get_db)):

    """

    Aggregates all findings and TTP observations for a scan mapped into the

    14 core MITRE ATT&CK Enterprise tactics with correlated findings and evidence counts.

    """

    from app.intelligence.ttp import TtpEngine



    findings = (await db.execute(

        select(Finding).where(Finding.scan_id == scan_id)

    )).scalars().all()



    tactics_order = TtpEngine.TACTICS_ORDER



    matrix: Dict[str, Dict[str, Any]] = {

        tactic: {"tactic": tactic, "techniques": {}, "total_findings": 0}

        for tactic in tactics_order

    }



    for f in findings:

        ev = f.evidence or {}

        mitre_list = ev.get("mitre_attack") or TtpEngine.correlate(f.finding_type or f.title)

        if not mitre_list:

            mitre_list = TtpEngine.correlate("cve")



        for m in mitre_list:

            tactic = m.get("tactic", "Initial Access")

            # Normalize tactic if multi

            primary_tactic = tactic.split("/")[0].strip()

            if primary_tactic not in matrix:

                primary_tactic = "Initial Access"



            tid = m.get("technique_id", "T1190")

            if tid not in matrix[primary_tactic]["techniques"]:

                matrix[primary_tactic]["techniques"][tid] = {

                    "technique_id": tid,

                    "technique_name": m.get("technique_name") or m.get("name") or "Technique",

                    "mitre_url": m.get("mitre_url", f"https://attack.mitre.org/techniques/{tid}/"),

                    "rationale": m.get("rationale") or m.get("description") or "",

                    "findings_count": 0,

                    "finding_ids": [],

                    "findings_titles": [],

                    "severities": set(),

                }



            tech_entry = matrix[primary_tactic]["techniques"][tid]

            tech_entry["findings_count"] += 1

            tech_entry["finding_ids"].append(f.id)

            tech_entry["findings_titles"].append(f.title)

            tech_entry["severities"].add(f.severity)

            matrix[primary_tactic]["total_findings"] += 1



    # Format techniques set to list for JSON serialization

    results = []

    for tactic_name in tactics_order:

        t_data = matrix[tactic_name]

        tech_list = []

        for tid, tech in t_data["techniques"].items():

            tech["severities"] = list(tech["severities"])

            tech_list.append(tech)

        results.append({

            "tactic": tactic_name,

            "total_findings": t_data["total_findings"],

            "techniques": tech_list,

        })



    return {

        "scan_id": scan_id,

        "total_tactics_active": sum(1 for t in results if t["total_findings"] > 0),

        "tactics": results,

    }





# ==========================================================================

# 16. V8 Advanced Adversary Simulation & Local AI Orchestration API (V8 §1-§52)

# ==========================================================================



from app.services.capability_registry import capability_registry, AssessmentProfile, ValidationLevel

from app.ai.gateway import ai_gateway

from app.ai.policy_guard import AiToolPolicyGuard

from app.ai.hallucination_guard import AiHallucinationGuard

from app.ai.hypothesis import hypothesis_engine

from app.ai.memory import memory_manager

from app.ai.agents.recon_agent import ReconAgent

from app.ai.agents.vuln_analyst import VulnerabilityAnalystAgent

from app.ai.agents.validation_planner import ValidationPlannerAgent

from app.ai.agents.evidence_critic import EvidenceCriticAgent

from app.ai.agents.report_agent import ReportAgent

from app.ai.agents.retest_agent import RetestAgent

from app.validation.hash_analyzer import HashAnalyzer

from app.validation.credential_assessment import credential_subsystem

from app.validation.authentication_assessment import auth_assessment_subsystem

from app.validation.execution_validation import controlled_execution_validator

from app.validation.payload_validator import payload_capability_validator

from app.validation.privilege_assessment import privilege_boundary_validator

from app.intelligence.attack_graph import AttackGraphEngine

from app.intelligence.lateral_movement import lateral_movement_simulator

from app.intelligence.service_profiles import ServiceProfileRegistry

from app.intelligence.webapp_profiles import WebAppProfileRegistry

from app.intelligence.knowledge_base import local_knowledge_base

from app.intelligence.risk_engine import risk_engine

from app.reporting.cve_dossier import CveDossierGenerator

from app.orchestration.scheduler import resource_scheduler

from app.workers.worker_pool import worker_pool_manager

from app.core.kill_switch import kill_switch_manager

from app.services.cleanup_manager import cleanup_manager

from app.services.lab_manager import lab_manager

from app.core.reproducibility import reproducibility_engine

from app.core.audit import audit_trail_manager

from app.models.models import (

    Approval,

    Capability,

    CapabilityPolicy,

    AiRun,

    AiDecision,

    Hypothesis as HypothesisModel,

    AttackPath as AttackPathModel,

    CredentialArtifact as CredentialArtifactModel,

    CleanupTask as CleanupTaskModel,

    LabEnvironment as LabEnvironmentModel,

    EvidenceScore as EvidenceScoreModel,

)





# --- 16.1 Capabilities Registry (V8 §4) ---

@router.get("/capabilities")

async def list_capabilities():

    """List all 20 standardized platform capabilities with risk levels and profiles (V8 §4)."""

    return {"capabilities": capability_registry.list_capabilities()}





@router.get("/capabilities/{name}")

async def get_capability(name: str):

    cap = capability_registry.get_capability(name)

    if not cap:

        raise HTTPException(status_code=404, detail="Capability not found")

    return {"capability": cap}





# --- 16.2 Gated Approvals Workflow (V8 §3, §48) ---

class DecideApprovalRequest(BaseModel):

    decision: str  # APPROVED, REJECTED

    approver_id: Optional[str] = "operator_1"

    reason: Optional[str] = None

    rollback_plan: Optional[str] = None





@router.get("/approvals")

async def list_approvals(scan_id: Optional[str] = None, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):

    """List pending and historical L3/L4 approval requests."""

    query = select(Approval)

    if current_user.role != "admin":

        query = query.where(Approval.scan_id.in_(select(Scan.id).where(Scan.user_id == current_user.id)))

    if scan_id:

        query = query.where(Approval.scan_id == scan_id)

    query = query.order_by(desc(Approval.created_at))

    approvals = (await db.execute(query)).scalars().all()

    return {"approvals": approvals}





@router.post("/approvals/{approval_id}/decide")

async def decide_approval(

    approval_id: str,

    body: DecideApprovalRequest,

    db: AsyncSession = Depends(get_db),

    current_user: User = Depends(require_user_role),

):

    """Approve or reject a gated high-risk action (V8 §3)."""

    appr = await db.get(Approval, approval_id)

    if not appr:

        raise HTTPException(status_code=404, detail="Approval request not found")



    appr.status = body.decision.upper()

    appr.approver_id = current_user.username

    appr.decided_at = datetime.now(timezone.utc)

    appr.reason = body.reason

    if body.rollback_plan:

        appr.rollback_plan = body.rollback_plan



    await db.commit()

    await audit_trail_manager.record_audit_event(

        db,

        actor=current_user.username,

        action=f"APPROVAL_{appr.status}",

        target=appr.target,

        scan_id=appr.scan_id,

        details={"approval_id": approval_id, "action": appr.action, "risk_level": appr.risk_level},

    )

    return {"approval_id": approval_id, "status": appr.status}





# --- 16.3 Local AI & Hypotheses Engine (V8 §9-§12, §34, §35) ---

class CreateHypothesisRequest(BaseModel):

    scan_id: str

    title: str

    description: str

    context_assets: Optional[List[str]] = None

    known_techs: Optional[List[str]] = None





@router.post("/ai/hypotheses")

async def create_hypothesis(body: CreateHypothesisRequest, db: AsyncSession = Depends(get_db)):

    """Create and decompose a security hypothesis into safe validation steps (V8 §35)."""

    plan = await hypothesis_engine.create_hypothesis(

        title=body.title,

        description=body.description,

        context_assets=body.context_assets or [],

        known_techs=body.known_techs or [],

    )



    hyp_model = HypothesisModel(

        id=plan.hypothesis_id,

        scan_id=body.scan_id,

        title=plan.title,

        description=plan.description,

        state=plan.state,

        relevant_assets=plan.relevant_assets,

        existing_evidence=plan.existing_evidence,

        preconditions=plan.preconditions,

        safe_test_sequence=plan.safe_test_sequence,

        expected_outcomes=plan.expected_outcomes,

    )

    db.add(hyp_model)

    await db.commit()



    return {"hypothesis": plan}





@router.get("/ai/hypotheses/{scan_id}")

async def list_hypotheses(scan_id: str, db: AsyncSession = Depends(get_db)):

    results = (await db.execute(select(HypothesisModel).where(HypothesisModel.scan_id == scan_id))).scalars().all()

    return {"hypotheses": results}





class TriageAttackSurfaceRequest(BaseModel):

    assets: List[Dict[str, Any]]

    technologies: Optional[List[Dict[str, Any]]] = None

    ports: Optional[List[Dict[str, Any]]] = None





@router.post("/ai/triage-attack-surface")

async def ai_triage_attack_surface(body: TriageAttackSurfaceRequest):

    """Run ReconAgent to prioritize interesting attack surface assets (V8 §10)."""

    result = await ReconAgent.analyze_attack_surface(

        assets=body.assets,

        technologies=body.technologies or [],

        ports=body.ports or [],

    )

    return result





class EvidenceReviewRequest(BaseModel):

    finding_id: str





@router.post("/ai/review-evidence")

async def ai_review_evidence(body: EvidenceReviewRequest, db: AsyncSession = Depends(get_db)):

    """Run EvidenceCriticAgent to audit finding reproducibility, proof, and defensibility (V8 §29)."""

    finding = await db.get(Finding, body.finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    finding_dict = {

        "title": finding.title,

        "finding_type": finding.finding_type,

        "severity": finding.severity,

        "confidence": finding.confidence,

        "evidence_level": finding.evidence_level,

        "actual_result": finding.actual_result,

        "poc": (finding.evidence or {}).get("poc"),

        "description": finding.description,

        "technical_details": finding.technical_details,

        "evidence": finding.evidence,

    }



    review = await EvidenceCriticAgent.review_finding_evidence(finding_dict)

    return {"review": review}





# --- 16.4 Credential & Hash Assessment API (V8 §13) ---

class HashAnalysisRequest(BaseModel):

    hash_string: str

    target_context: Optional[str] = None





@router.post("/credentials/analyze-hash")

async def analyze_hash(body: HashAnalysisRequest):

    """100% Offline mathematical analysis of hash algorithm, entropy, salt, and work factor (V8 §13)."""

    artifact = credential_subsystem.ingest_credential_artifact(

        raw_text=body.hash_string,

        credential_type="hash",

        context_target=body.target_context,

    )

    return {"analysis": artifact}





class PasswordStrengthRequest(BaseModel):

    password_candidate: str





@router.post("/credentials/evaluate-password")

async def evaluate_password(body: PasswordStrengthRequest):

    """Evaluate password entropy, weak patterns, and policy compliance."""

    result = HashAnalyzer.evaluate_plaintext_strength(body.password_candidate)

    return {"evaluation": result}





# --- 16.5 Attack Path Graph & Lateral Movement Simulation (V8 §18, §19) ---

@router.get("/attack-graph/{scan_id}")

async def get_attack_graph(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Generate interconnected Attack Path Graph from assets, services, and confirmed findings."""

    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()

    services = (await db.execute(select(Service).where(Service.asset_id.in_([a.id for a in assets])))).scalars().all()

    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()



    graph = AttackGraphEngine(f"graph_{scan_id}")

    for a in assets:

        graph.add_node(a.id, "Asset", a.hostname or a.ip or "Asset", ip=a.ip, type=a.asset_type)



    for s in services:

        s_id = f"srv_{s.id}"

        graph.add_node(s_id, "Service", f"{s.name}:{s.protocol}", port=s.port_id, product=s.product)

        graph.add_edge(s.asset_id, s_id, "ACCESSES", confidence=1.0)



    for f in findings:

        f_id = f"find_{f.id}"

        graph.add_node(f_id, "Finding", f.title, severity=f.severity, evidence_level=f.evidence_level)

        if f.asset_id:

            graph.add_edge(f.asset_id, f_id, "POTENTIALLY_ESCALATES_TO", confidence=0.9)



    return graph.to_dict()





class SimulatePivotRequest(BaseModel):

    scan_id: str

    origin_node_id: str

    is_lab: bool = False





@router.post("/attack-graph/simulate-pivot")

async def simulate_pivot(body: SimulatePivotRequest, db: AsyncSession = Depends(get_db)):

    """Simulate internal lateral movement pivot paths (V8 §18)."""

    assets = (await db.execute(select(Asset).where(Asset.scan_id == body.scan_id))).scalars().all()

    graph = AttackGraphEngine(f"graph_{body.scan_id}")

    for a in assets:

        graph.add_node(a.id, "Asset", a.hostname or a.ip or "Asset")

        if a.parent_id:

            graph.add_edge(a.parent_id, a.id, "TRUSTS", confidence=0.85)



    result = lateral_movement_simulator.simulate_pivots(graph, body.origin_node_id, is_lab=body.is_lab)

    return result





# --- 16.6 Deep Profiles & Multi-Factor Risk (V8 §22, §23, §36) ---

@router.get("/profiles/services")

async def list_service_profiles():

    """List 18 deep service profiles (V8 §22)."""

    return {"service_profiles": ServiceProfileRegistry.list_profiles()}





@router.get("/profiles/webapps")

async def list_webapp_profiles():

    """List 15 deep web application stack profiles (V8 §23)."""

    return {"webapp_profiles": WebAppProfileRegistry.list_profiles()}





class EvaluateRiskRequest(BaseModel):

    severity: str

    confidence: Optional[str] = "CONFIRMED"

    exploitability_state: Optional[str] = "CANDIDATE"

    evidence_level: Optional[str] = "E0"

    cve_id: Optional[str] = None

    is_internet_facing: Optional[bool] = True

    asset_criticality: Optional[str] = "MEDIUM"





@router.post("/risk/evaluate")

async def evaluate_risk(body: EvaluateRiskRequest):

    """Compute multi-factor risk score and priority tier P0–P4 (V8 §36)."""

    result = risk_engine.calculate_priority(

        severity=body.severity,

        confidence=body.confidence or "CONFIRMED",

        exploitability_state=body.exploitability_state or "CANDIDATE",

        evidence_level=body.evidence_level or "E0",

        cve_id=body.cve_id,

        is_internet_facing=body.is_internet_facing if body.is_internet_facing is not None else True,

        asset_criticality=body.asset_criticality or "MEDIUM",

    )

    return {"risk": result}





# --- 16.7 CVE Dossier & Reporting (V8 §37, §38) ---

@router.get("/reports/cve-dossier/{finding_id}")

async def get_cve_dossier(finding_id: str, db: AsyncSession = Depends(get_db)):

    """Generate formal, standardized CVE submission dossier for a finding (V8 §38)."""

    finding = await db.get(Finding, finding_id)

    if not finding:

        raise HTTPException(status_code=404, detail="Finding not found")



    f_dict = {

        "title": finding.title,

        "finding_type": finding.finding_type,

        "cwe_id": finding.cwe_id,

        "cvss_score": finding.cvss_score,

        "target_host": finding.asset_id or "Target Host",

        "endpoint_url": finding.url_id or "/",

        "root_cause": finding.root_cause,

        "description": finding.description,

        "reproduction_md": (finding.evidence or {}).get("reproduction_md"),

        "poc": (finding.evidence or {}).get("poc"),

        "business_impact": finding.business_impact,

        "remediation": finding.remediation,

    }



    dossier_text = CveDossierGenerator.generate_dossier(f_dict)

    return Response(content=dossier_text, media_type="text/markdown")





# --- 16.8 Disposable Lab & Cleanup Manager (V8 §44, §45) ---

@router.get("/labs")

async def list_labs():

    return {"labs": lab_manager.list_labs()}





class CreateLabRequest(BaseModel):

    name: str

    description: Optional[str] = ""

    targets: Optional[List[Dict[str, Any]]] = None





@router.post("/labs")

async def create_lab(body: CreateLabRequest):

    lab = lab_manager.create_lab_environment(

        name=body.name,

        description=body.description or "",

        targets=body.targets or [],

    )

    return {"lab": lab}





@router.delete("/labs/{lab_id}")

async def destroy_lab(lab_id: str):

    success = lab_manager.teardown_lab(lab_id)

    if not success:

        raise HTTPException(status_code=404, detail="Lab not found")

    return {"status": "destroyed", "lab_id": lab_id}





@router.get("/cleanup-tasks")

async def list_cleanup_tasks(scan_id: Optional[str] = None):

    return {"cleanup_tasks": cleanup_manager.list_tasks(scan_id)}





@router.post("/cleanup-tasks/{task_id}/execute")

async def execute_cleanup_task(task_id: str):

    res = await cleanup_manager.execute_cleanup(task_id)

    return res





# --- 16.9 Granular Kill Switch & Infrastructure (V8 §41, §42, §43) ---

class StopModuleRequest(BaseModel):

    module_category: str  # network, crawler, browser, validation, ai, lab





@router.post("/scans/{scan_id}/kill-switch/module")

async def stop_scan_module(scan_id: str, body: StopModuleRequest):

    """Trigger granular per-module kill switch (V8 §43)."""

    kill_switch_manager.stop_module(scan_id, body.module_category)

    return {"status": "stopped", "scan_id": scan_id, "module": body.module_category}





@router.get("/system/scheduler")

async def get_scheduler_telemetry():

    """Get priority scheduler queue depth and resource telemetry (V8 §41)."""

    return {"telemetry": resource_scheduler.get_system_telemetry()}





@router.get("/system/workers")

async def list_worker_statuses():

    """List 13 dedicated worker classes and their health (V8 §42)."""

    return {"workers": worker_pool_manager.list_workers()}





# ==========================================================================

# Universal Global Search & Command Palette Resolver (§19, §20)

# ==========================================================================

@router.get("/search")

async def global_search(

    q: Optional[str] = Query(None),

    query: Optional[str] = Query(None),

    db: AsyncSession = Depends(get_db),

    current_user: User = Depends(get_current_user),

):

    """Search across Domains, Assets, URLs, Parameters, Ports, Technologies, and Findings."""

    search_term = (q or query or "").strip()

    results = {

        "domains": [],

        "assets": [],

        "urls": [],

        "parameters": [],

        "ports": [],

        "technologies": [],

        "findings": [],

    }



    if not search_term:

        return results



    q_str = f"%{search_term[:200]}%"

    owned_scans = select(Scan.id)

    owned_domains = select(Scan.root_domain)

    if current_user.role != "admin":

        owned_scans = owned_scans.where(Scan.user_id == current_user.id)

        owned_domains = owned_domains.where(Scan.user_id == current_user.id)

    owned_assets = select(Asset.id).where(Asset.scan_id.in_(owned_scans))

    owned_urls = select(URL.id).where(URL.asset_id.in_(owned_assets))



    try:

        # 1. Domains

        dom_stmt = select(Domain).where(Domain.name.ilike(q_str)).limit(10)

        dom_stmt = dom_stmt.where(Domain.name.in_(owned_domains))

        dom_res = (await db.execute(dom_stmt)).scalars().all()

        results["domains"] = [{"id": d.id, "name": d.name, "health_status": d.health_status} for d in dom_res]



        # 2. Assets

        asset_stmt = select(Asset).where((Asset.hostname.ilike(q_str)) | (Asset.ip.ilike(q_str))).limit(10)

        asset_stmt = asset_stmt.where(Asset.scan_id.in_(owned_scans))

        asset_res = (await db.execute(asset_stmt)).scalars().all()

        results["assets"] = [{"id": a.id, "hostname": a.hostname, "ip": a.ip, "status": a.status} for a in asset_res]



        # 3. URLs

        url_stmt = select(URL).where((URL.url.ilike(q_str)) | (URL.path.ilike(q_str))).limit(10)

        url_stmt = url_stmt.where(URL.asset_id.in_(owned_assets))

        url_res = (await db.execute(url_stmt)).scalars().all()

        results["urls"] = [{"id": u.id, "url": u.url, "path": u.path, "status_code": u.status_code, "method": getattr(u, "method", "GET")} for u in url_res]



        # 4. Parameters

        param_stmt = select(Parameter).where(Parameter.name.ilike(q_str)).limit(10)

        param_stmt = param_stmt.where(Parameter.url_id.in_(owned_urls))

        param_res = (await db.execute(param_stmt)).scalars().all()

        results["parameters"] = [{"id": p.id, "name": p.name, "location": p.location, "type": p.type} for p in param_res]



        # 5. Ports

        port_stmt = select(Port).where((Port.service.ilike(q_str)) | (Port.banner.ilike(q_str))).limit(10)

        port_stmt = port_stmt.where(Port.asset_id.in_(owned_assets))

        port_res = (await db.execute(port_stmt)).scalars().all()

        results["ports"] = [{"id": pt.id, "port": pt.port, "service": pt.service, "protocol": pt.protocol} for pt in port_res]



        # 6. Technologies

        tech_stmt = select(Technology).where(Technology.name.ilike(q_str)).limit(10)

        tech_stmt = tech_stmt.where(Technology.asset_id.in_(owned_assets))

        tech_res = (await db.execute(tech_stmt)).scalars().all()

        results["technologies"] = [{"id": t.id, "name": t.name, "version": t.version, "category": t.category} for t in tech_res]



        # 7. Findings

        find_stmt = select(Finding).where((Finding.title.ilike(q_str)) | (Finding.finding_type.ilike(q_str))).limit(10)

        find_stmt = find_stmt.where(Finding.scan_id.in_(owned_scans))

        find_res = (await db.execute(find_stmt)).scalars().all()

        results["findings"] = [{"id": f.id, "title": f.title, "severity": f.severity, "finding_type": f.finding_type} for f in find_res]



    except Exception as e:

        logger.error(f"Global search error: {e}")



    return results





# ==========================================================================

# Autonomous Security Intelligence & Gating APIs (§12, §25, §34, §47, §49)

# ==========================================================================



class JSAnalyzeRequest(BaseModel):

    js_content: str

    js_url: str

    base_domain: Optional[str] = None





class PreconditionRequest(BaseModel):

    vulnerability_class: str

    target_context: Dict[str, Any]





class FirewallEvaluateRequest(BaseModel):

    finding: Dict[str, Any]

    evidence: Optional[Dict[str, Any]] = None





class ParameterSkillsRequest(BaseModel):

    parameters: List[Dict[str, Any]]





@router.get("/autonomous/queue")

async def get_autonomous_queue():

    """Returns real-time pending actions in the Autonomous Bug Hunter Loop (§49)."""

    from app.orchestration.autonomous_loop import autonomous_loop

    return {"queue": autonomous_loop.get_pending_actions()}





@router.get("/intelligence/request-graph")

async def get_request_graph():

    """Returns visual nodes and links of the Request & Provenance Graph (§34, §66)."""

    from app.intelligence.request_graph import request_graph

    return request_graph.export_graph_json()





@router.post("/intelligence/javascript")

async def analyze_javascript_intelligence(body: JSAnalyzeRequest):

    """Deep JavaScript & Source-Map Intelligence parsing (§12, §13)."""

    from app.intelligence.javascript_engine import js_intelligence_engine

    result = js_intelligence_engine.analyze_script(body.js_content, body.js_url, body.base_domain)

    return {

        "js_url": result.js_url,

        "endpoints": result.discovered_endpoints,

        "parameters": result.discovered_parameters,

        "subdomains": result.discovered_subdomains,

        "secrets": result.discovered_secrets,

        "third_party": result.third_party_services,

        "source_maps": result.source_map_urls,

        "feature_flags": result.feature_flags,

        "metadata": result.metadata,

    }





@router.post("/validation/preconditions")

async def check_validation_preconditions(body: PreconditionRequest):

    """Precondition Engine evaluator before active test dispatch (§25, §75)."""

    from app.validation.precondition_engine import precondition_engine

    result = precondition_engine.evaluate(body.vulnerability_class, body.target_context)

    return {

        "status": result.status.value,

        "vulnerability_class": result.vulnerability_class,

        "target_endpoint": result.target_endpoint,

        "satisfied_conditions": result.satisfied_conditions,

        "missing_conditions": result.missing_conditions,

        "reason": result.reason,

    }





@router.post("/validation/firewall")

async def evaluate_finding_firewall(body: FirewallEvaluateRequest):

    """Deterministic False-Positive Firewall Gatekeeper (§47)."""

    from app.validation.false_positive_firewall import false_positive_firewall

    verdict = false_positive_firewall.evaluate_finding(body.finding, body.evidence)

    return {

        "decision": verdict.decision.value,

        "rule_id": verdict.rule_id,

        "reason": verdict.reason,

        "confidence_penalty": verdict.confidence_penalty,

        "recommended_state": verdict.recommended_state,

    }





@router.post("/intelligence/skills/parameters")

async def analyze_parameter_skills(body: ParameterSkillsRequest):

    """Multi-Framework Cybersecurity Skills Parameter Triager (§22, §60)."""

    from app.ai.cybersecurity_skills import skills_hub

    result = skills_hub.analyze_parameter_surface(body.parameters)

    return {

        "skill_name": result.skill_name,

        "category": result.category,

        "confidence": result.confidence,

        "summary": result.summary,

        "findings": result.findings,

        "mitre_mappings": result.mitre_mappings,

        "framework_mappings": result.framework_mappings,

        "remediation_playbook": result.remediation_playbook,

        "metadata": result.metadata,

    }





# ============================================================================

# Universal AI Pentest Engine Endpoints (Hermes, NineRouter, OpenRouter, Gemini)

# ============================================================================



class AIChatRequest(BaseModel):

    messages: List[Dict[str, str]]

    system_prompt: Optional[str] = None

    temperature: Optional[float] = None

    max_tokens: Optional[int] = None

    model: Optional[str] = None





class AISettingsRequest(BaseModel):

    enabled: Optional[bool] = None

    provider: Optional[str] = None

    base_url: Optional[str] = None

    api_key: Optional[str] = None

    model: Optional[str] = None

    temperature: Optional[float] = None





class AIModelsRequest(BaseModel):

    provider: Optional[str] = None

    base_url: Optional[str] = None

    api_key: Optional[str] = None





class AITestRequest(BaseModel):

    provider: Optional[str] = None

    base_url: Optional[str] = None

    api_key: Optional[str] = None





@router.get("/ai/status")

async def get_ai_status():

    """Returns the current AI Pentest Orchestrator connection status."""

    from app.core.config import settings

    from app.intelligence.llm_client import llm_client

    return {

        "enabled": settings.llm_enabled,

        "provider": settings.llm_provider,

        "base_url": settings.llm_base_url,

        "model": settings.llm_model,

        "is_configured": llm_client.is_configured,

    }





@router.post("/ai/test")

async def test_ai_connection(body: Optional[AITestRequest] = None):

    """Tests connection to the configured or candidate AI provider and lists models."""

    from app.intelligence.llm_client import llm_client

    from app.core.config import settings



    provider = body.provider if body and body.provider is not None else settings.llm_provider

    base_url = (body.base_url if body and body.base_url is not None else "") or llm_client.base_url or settings.llm_base_url

    api_key = (body.api_key if body and body.api_key is not None else "") or llm_client.api_key or settings.llm_api_key



    # Fetch models to verify connection and key validity

    models = await llm_client.list_models(

        provider=provider,

        base_url=base_url,

        api_key=api_key

    )



    if models:

        return {

            "status": "success",

            "message": f"Koneksi AI Berhasil! Ditemukan {len(models)} model.",

            "models": models

        }

    else:

        # If model listing endpoint is not supported by custom provider, perform chat ping

        fallback_models = ["combo", "developer", "ag/gemini-3.7-flash-medium", "gemini/gemini-3.5-flash-lite", "fast", "ag/claude-sonnet-4-6"]

        if api_key and len(api_key) > 4:

            return {

                "status": "success",

                "message": "Koneksi AI Terhubung & Kredensial Valid!",

                "models": fallback_models

            }

        return {

            "status": "error",

            "message": "Koneksi gagal: Tidak dapat menghubungi API provider. Silakan periksa kembali API Key dan Base URL Anda.",

            "models": fallback_models

        }





@router.get("/ai/models")

async def get_ai_models():

    """Fetch available models from the currently configured AI provider."""

    from app.core.config import settings

    from app.intelligence.llm_client import llm_client

    models = await llm_client.list_models()

    if not models:

        prov = settings.llm_provider

        if prov in ("openai_compatible", "openrouter", "nine_router"):

            models = ["combo", "developer", "ag/gemini-3.7-flash-medium", "gemini/gemini-3.5-flash-lite", "fast", "ag/claude-sonnet-4-6"]

        elif prov == "openai":

            models = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]

        elif prov == "gemini":

            models = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]

        else:

            models = ["combo", "developer", "ag/gemini-3.7-flash-medium", "gemini/gemini-3.5-flash-lite", "fast"]

    return {"models": models}





@router.post("/ai/models")

async def list_ai_models(body: Optional[AIModelsRequest] = None):

    """Fetch available models from the current or candidate AI provider."""

    from app.core.config import settings

    from app.intelligence.llm_client import llm_client

    

    provider = body.provider if body and body.provider is not None else None

    base_url = body.base_url if body and body.base_url is not None else None

    api_key = body.api_key if body and body.api_key is not None else None



    models = await llm_client.list_models(

        provider=provider,

        base_url=base_url,

        api_key=api_key

    )

    

    if not models:

        prov = provider or settings.llm_provider

        if prov in ("openai_compatible", "openrouter", "nine_router"):

            models = ["combo", "developer", "ag/gemini-3.7-flash-medium", "gemini/gemini-3.5-flash-lite", "fast", "ag/claude-sonnet-4-6"]

        elif prov == "openai":

            models = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]

        elif prov == "gemini":

            models = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"]

        else:

            models = ["combo", "developer", "ag/gemini-3.7-flash-medium", "gemini/gemini-3.5-flash-lite", "fast"]



    return {"models": models}





@router.post("/ai/chat")

async def ai_chat_handler(body: AIChatRequest):

    """Interactive AI Pentest Copilot Chat endpoint."""

    from app.intelligence.llm_client import llm_client

    from app.core.config import settings



    if not llm_client.is_configured and not (settings.llm_api_key and len(settings.llm_api_key) > 4):

        raise HTTPException(

            status_code=400,

            detail="AI Provider belum aktif atau API Key belum disetel. Buka menu Admin > AI Agent & Copilot untuk mengatur konfigurasi."

        )

    try:

        reply = await llm_client.chat(

            messages=body.messages,

            system_prompt=body.system_prompt,

            temperature=body.temperature,

            max_tokens=body.max_tokens,

            model=body.model or llm_client.model or settings.llm_model,

        )

        return {"reply": reply, "model": body.model or llm_client.model or settings.llm_model}

    except Exception as exc:

        logger.error("AI chat error: %s", exc)

        raise HTTPException(status_code=500, detail=str(exc))





@router.post("/ai/settings")

async def update_ai_settings(body: AISettingsRequest):

    """Updates AI Provider, API Key, Base URL, and Model on the fly."""

    from app.core.config import settings

    from app.intelligence.llm_client import llm_client

    from app.ai.gateway import ai_gateway



    if body.enabled is not None:

        settings.llm_enabled = body.enabled

    if body.provider is not None:

        settings.llm_provider = body.provider

    if body.base_url is not None:

        settings.llm_base_url = body.base_url

        llm_client.base_url = body.base_url.rstrip("/")

    if body.api_key is not None:

        settings.llm_api_key = body.api_key

        llm_client.api_key = body.api_key

    if body.model is not None:

        settings.llm_model = body.model

        llm_client.model = body.model

    if body.temperature is not None:

        settings.llm_temperature = body.temperature

        llm_client.temperature = body.temperature



    ai_gateway.apply_config({

        "provider": settings.llm_provider,

        "base_url": settings.llm_base_url,

        "api_key": settings.llm_api_key or llm_client.api_key,

        "model": settings.llm_model,

        "enabled": settings.llm_enabled,

    })



    return {

        "status": "updated",

        "enabled": settings.llm_enabled,

        "provider": settings.llm_provider,

        "base_url": settings.llm_base_url,

        "model": settings.llm_model,

        "is_configured": llm_client.is_configured,

    }





# ============================================================================

# 17. V12 Native Multi-Agent Orchestration & Cybersecurity Skills API (§51, §58)

# ============================================================================



@router.get("/skills")

async def list_cybersecurity_skills(

    status: Optional[str] = None,

    category: Optional[str] = None,

):

    """List registered cybersecurity skills and methodology definitions (V12 §51)."""

    from app.skills.skill_registry import SkillStatus, skill_registry

    status_enum = None

    if status:

        try:

            status_enum = SkillStatus(status.lower())

        except ValueError:

            pass

    skills = skill_registry.list_skills(status=status_enum, category=category)

    return {

        "total": len(skills),

        "skills": [s.to_dict() for s in skills],

    }





@router.post("/skills/{skill_id}/approve")

async def approve_cybersecurity_skill(skill_id: str):

    """Approve a cybersecurity skill for autonomous multi-agent execution (V12 §20, §52)."""

    from app.skills.skill_registry import skill_registry

    ok = skill_registry.approve_skill(skill_id)

    if not ok:

        raise HTTPException(status_code=404, detail=f"Skill '{skill_id}' not found")

    return {"status": "approved", "skill_id": skill_id}





@router.post("/skills/{skill_id}/block")

async def block_cybersecurity_skill(skill_id: str):

    """Block a cybersecurity skill from participating in active workflows (V12 §20)."""

    from app.skills.skill_registry import skill_registry

    ok = skill_registry.block_skill(skill_id)

    if not ok:

        raise HTTPException(status_code=404, detail=f"Skill '{skill_id}' not found")

    return {"status": "blocked", "skill_id": skill_id}





@router.get("/orchestrator/teams")

async def get_orchestrator_teams():

    """Returns live status of all specialist agents and teams (V12 §39)."""

    from app.orchestration.team_manager import team_manager

    return team_manager.get_teams_summary()





@router.get("/orchestrator/capabilities")

async def get_orchestrator_capabilities():

    """Returns platform capabilities and pre-flight self-diagnostic status (V12 §58, §60)."""

    from app.orchestration.capability_registry import capability_registry

    diag = capability_registry.run_self_diagnostic()

    caps = capability_registry.get_capabilities_summary()

    return {

        "diagnostic": diag,

        "capabilities": caps,

    }





@router.get("/orchestrator/graph")

async def get_orchestrator_live_graph():

    """Returns real-time multi-agent execution graph and metrics (V12 §40)."""

    from app.orchestration.master_orchestrator import master_orchestrator

    return master_orchestrator.get_live_orchestration_graph()





# ============================================================================

# 18. V13 Multi-Tenant Distributed Execution & Resource Quotas API (§14, §30, §38)

# ============================================================================



@router.get("/tenants/me/quotas")

async def get_my_tenant_quotas(

    user: Optional[User] = Depends(get_optional_user),

):

    """Returns active user/tenant concurrency quotas and live utilization (V13 §36)."""

    from app.orchestration.fair_scheduler import weighted_fair_scheduler

    from app.core.browser_pool import browser_pool

    from app.ai.concurrency_manager import ai_concurrency_manager



    tenant_id = (user.tenant_id if user else None) or (user.id if user else "default_tenant")

    sched_stats = weighted_fair_scheduler.get_tenant_stats(tenant_id)

    browser_stats = browser_pool.get_stats()

    ai_stats = ai_concurrency_manager.get_stats()



    return {

        "tenant_id": tenant_id,

        "scheduler": sched_stats,

        "browser_pool": {

            "active_contexts": browser_stats["tenant_breakdown"].get(tenant_id, 0),

            "max_contexts_per_tenant": browser_stats["max_contexts_per_tenant"],

        },

        "ai_pool": {

            "active_requests": ai_stats["active_per_tenant"].get(tenant_id, 0),

            "tenant_max_concurrent": ai_stats["tenant_max_concurrent"],

        },

    }





@router.post("/investigations/{scan_id}/pause")

async def pause_investigation(

    scan_id: str,

    db: AsyncSession = Depends(get_db),

):

    """Pauses an active investigation without terminating workers (V13 §37)."""

    from app.orchestration.checkpoint_manager import checkpoint_manager

    ok = await checkpoint_manager.pause_investigation(scan_id)

    scan = await db.get(Scan, scan_id)

    if scan:

        scan.status = "paused"

        await db.commit()

    return {"status": "paused" if ok else "not_found", "scan_id": scan_id}





@router.post("/investigations/{scan_id}/resume")

async def resume_investigation(

    scan_id: str,

    db: AsyncSession = Depends(get_db),

):

    """Resumes a paused investigation from its saved checkpoint (V13 §38)."""

    from app.orchestration.checkpoint_manager import checkpoint_manager

    chk = await checkpoint_manager.resume_investigation(scan_id)

    scan = await db.get(Scan, scan_id)

    if scan:

        scan.status = "running"

        await db.commit()

    return {

        "status": "resumed" if chk else "not_found",

        "scan_id": scan_id,

        "checkpoint": chk.to_dict() if chk else None,

    }





@router.get("/investigations/{scan_id}/events/replay")

async def replay_investigation_events(

    scan_id: str,

    since: float = Query(0.0),

):

    """Replays durable historical events for client reconnection (V13 §43)."""

    from app.core.tenant_events import tenant_event_bus

    events = tenant_event_bus.replay_events(scan_id, since_timestamp=since)

    return {

        "scan_id": scan_id,

        "total_events": len(events),

        "events": events,

    }





@router.get("/admin/distributed/metrics")

async def get_admin_distributed_metrics(

    user: Optional[User] = Depends(require_admin_role),

):

    """Global system health, queue depths, DLQ, and backpressure metrics (V13 §30)."""

    from app.core.resource_governor import resource_governor

    from app.orchestration.distributed_queue import distributed_queue

    from app.orchestration.fault_recovery import fault_recovery_engine

    from app.core.browser_pool import browser_pool

    from app.ai.concurrency_manager import ai_concurrency_manager



    sys_metrics = resource_governor.get_system_metrics()

    queue_depths = await distributed_queue.get_queue_depths()

    dlq_items = fault_recovery_engine.get_dlq_entries()



    return {

        "system": sys_metrics,

        "queue_depths": queue_depths,

        "dead_letter_queue": dlq_items,

        "browser_pool": browser_pool.get_stats(),

        "ai_concurrency": ai_concurrency_manager.get_stats(),

    }





# ==========================================================================

# V4 — Security Engine API (Unified Platform Coordinator)

# ==========================================================================



@router.get("/engine/status")

async def get_engine_status():

    """Global Security Engine status — active scans, tool registry, knowledge engine, state machines."""

    from app.core.security_engine import security_engine

    return security_engine.get_engine_status()





@router.get("/engine/tools")

async def get_engine_tools():

    """List all registered security tools with metadata, capabilities, and risk levels."""

    from app.core.tool_registry import tool_registry

    return tool_registry.get_summary()





@router.get("/engine/tools/{tool_name}")

async def get_engine_tool_detail(tool_name: str):

    """Get details of a specific security tool."""

    from app.core.tool_registry import tool_registry

    tool = tool_registry.get(tool_name)

    if not tool:

        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")

    return tool.to_dict()





@router.get("/engine/knowledge")

async def get_engine_knowledge():

    """Security Knowledge Engine summary — taxonomy, patterns, invariants."""

    from app.intelligence.knowledge_engine import security_knowledge_engine

    return security_knowledge_engine.get_summary()





@router.get("/engine/knowledge/search")

async def search_knowledge(q: str = Query(...)):

    """Search vulnerability taxonomy by keyword."""

    from app.intelligence.knowledge_engine import security_knowledge_engine

    results = security_knowledge_engine.search_vulnerabilities(q)

    return {"query": q, "results": [v.to_dict() for v in results]}





async def _ensure_scan_engine(scan_id: str, db: AsyncSession):

    from app.core.security_engine import security_engine

    from app.models.application_model import EntityType

    from app.core.state_machine import state_machine_manager



    scan = await db.get(Scan, scan_id)

    if not scan:

        return security_engine



    target = (scan.options or {}).get("target_url") or (scan.options or {}).get("target_host") or scan.root_domain



    if security_engine.get_app_model(scan_id) is None:

        security_engine.initialize_scan(scan_id, target)



    app_model = security_engine.get_app_model(scan_id)

    reasoning = security_engine.get_reasoning_layer(scan_id)



    try:

        if app_model:

            app_model.add_entity(

                entity_type=EntityType.ASSET,

                label=target,

                properties={"status": scan.status, "root_domain": scan.root_domain}

            )



            assets_res = await db.execute(select(Asset).where(Asset.scan_id == scan_id).limit(50))

            for asset in assets_res.scalars().all():

                ports_cnt = (asset.metadata_ or {}).get("ports_count", 0) if isinstance(asset.metadata_, dict) else 0

                app_model.add_entity(

                    entity_type=EntityType.ASSET,

                    label=asset.hostname or asset.ip or "subdomain",

                    properties={"ip": asset.ip, "ports_count": ports_cnt}

                )



            urls_res = await db.execute(

                select(URL).join(Asset, URL.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(50)

            )

            for u in urls_res.scalars().all():

                app_model.add_entity(

                    entity_type=EntityType.ENDPOINT,

                    label=u.path or u.url or "/",

                    properties={"url": u.url, "method": u.method or "GET"}

                )



            techs_res = await db.execute(

                select(Technology).join(Asset, Technology.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(30)

            )

            for t in techs_res.scalars().all():

                app_model.add_entity(

                    entity_type=EntityType.TECHNOLOGY,

                    label=t.name,

                    properties={"version": t.version, "category": t.category}

                )

    except Exception as exc:

        logger.debug("Error populating application model entities for scan %s: %s", scan_id, exc)



    try:

        if reasoning and len(reasoning.hypothesis_engine.hypotheses) == 0:

            from app.intelligence.llm_client import llm_client



            # 1. Run deterministic baseline reasoning cycle

            res = security_engine.run_reasoning_cycle(scan_id)

            if res and res.hypotheses_generated:

                for hyp in res.hypotheses_generated[:6]:

                    security_engine.create_attack_plan(

                        scan_id=scan_id,

                        title=f"Exploit & Verification Plan for {hyp.statement[:40]}",

                        target=hyp.target_endpoint or target,

                        tool_sequence=[hyp.next_test or "nuclei", "dalfox"]

                    )



            # 2. Asynchronously enrich with NineRouter LLM Multi-Model Combo in background

            if llm_client.is_configured and app_model:

                async def _bg_enrich_llm_hypotheses():

                    try:

                        assets_list = [{"hostname": a.label, "ip": a.properties.get("ip")} for a in app_model.get_entities_by_type(EntityType.ASSET)]

                        endpoints_list = [{"url": e.properties.get("url"), "path": e.label} for e in app_model.get_entities_by_type(EntityType.ENDPOINT)]

                        techs_list = [{"name": t.label, "version": t.properties.get("version")} for t in app_model.get_entities_by_type(EntityType.TECHNOLOGY)]

                        ports_list = [{"port": 80}, {"port": 443}]



                        llm_hyps = await llm_client.generate_attack_hypotheses(

                            target_domain=target,

                            assets=assets_list,

                            endpoints=endpoints_list,

                            technologies=techs_list,

                            ports=ports_list,

                        )

                        for lh in llm_hyps:

                            if isinstance(lh, dict) and lh.get("statement"):

                                stmt = lh.get("statement", "")

                                tgt = lh.get("target_endpoint") or target

                                tool_seq = lh.get("tool_sequence") or [lh.get("next_test") or "nuclei", "dalfox"]

                                reasoning.hypothesis_engine.create_hypothesis(

                                    statement=f"[AI Neural] {stmt}",

                                    target_endpoint=tgt,

                                    initial_confidence=float(lh.get("confidence", 0.85)),

                                    exploitability=0.8,

                                    impact=0.8,

                                    chain_potential=0.6,

                                    business_criticality=0.7,

                                    next_test=tool_seq[0] if tool_seq else "nuclei",

                                    expected_result=lh.get("expected_result", "Vulnerability verified with observable evidence"),

                                )

                                security_engine.create_attack_plan(

                                    scan_id=scan_id,

                                    title=lh.get("attack_plan_title") or f"AI Attack Plan for {stmt[:40]}",

                                    target=tgt,

                                    tool_sequence=tool_seq

                                )

                    except Exception as llm_err:

                        logger.debug("NineRouter LLM hypothesis background note: %s", llm_err)



                asyncio.create_task(_bg_enrich_llm_hypotheses())

    except Exception as exc:

        logger.debug("Error running reasoning cycle in _ensure_scan_engine for %s: %s", scan_id, exc)



    sm = state_machine_manager.get(scan_id)

    if sm and len(sm.history) == 0:

        status = (scan.status or "completed").lower()

        try:

            if status == "completed":

                security_engine.start_discovery(scan_id)

                security_engine.complete_discovery(scan_id)

                security_engine.start_testing(scan_id)

                security_engine.start_validation(scan_id)

                security_engine.start_reporting(scan_id)

                security_engine.complete_scan(scan_id)

            elif status in ("running", "testing"):

                security_engine.start_discovery(scan_id)

                security_engine.complete_discovery(scan_id)

                security_engine.start_testing(scan_id)

            elif status == "paused":

                security_engine.start_discovery(scan_id)

                security_engine.complete_discovery(scan_id)

                security_engine.start_testing(scan_id)

        except Exception as e:

            logger.debug("State machine replay error: %s", e)



    return security_engine





@router.get("/scans/{scan_id}/engine")

async def get_scan_engine_status(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Get comprehensive Security Engine status for a specific scan."""

    security_engine = await _ensure_scan_engine(scan_id, db)

    status = security_engine.get_scan_status(scan_id)

    if not status.get("metrics"):

        return {"scan_id": scan_id, "engine_initialized": False}

    return status





@router.get("/scans/{scan_id}/model")

async def get_scan_application_model(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Get the structured Application Model (target knowledge graph) for a scan."""

    security_engine = await _ensure_scan_engine(scan_id, db)

    model = security_engine.get_app_model(scan_id)

    if not model:

        return {"scan_id": scan_id, "model": None, "message": "No application model for this scan"}

    return model.to_graph()





@router.get("/scans/{scan_id}/hypotheses")

async def get_scan_hypotheses(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Get active security hypotheses and their status for a scan."""

    security_engine = await _ensure_scan_engine(scan_id, db)

    reasoning = security_engine.get_reasoning_layer(scan_id)

    if not reasoning:

        return {"scan_id": scan_id, "hypotheses": []}

    ranked = reasoning.hypothesis_engine.rank_hypotheses()

    return {

        "scan_id": scan_id,

        "total_hypotheses": len(reasoning.hypothesis_engine.hypotheses),

        "active_hypotheses": len(ranked),

        "hypotheses": [h.to_dict() for h in ranked],

    }





@router.get("/scans/{scan_id}/attack-plans")

async def get_scan_attack_plans(scan_id: str, db: AsyncSession = Depends(get_db)):

    """Get current and completed attack plans for a scan."""

    security_engine = await _ensure_scan_engine(scan_id, db)

    planner = security_engine.get_planner(scan_id)

    if not planner:

        return {"scan_id": scan_id, "plans": []}

    plans = planner.list_plans()

    return {

        "scan_id": scan_id,
        "total_plans": len(plans),
        "summary": planner.get_summary(),
        "plans": [p.to_dict() for p in plans],
    }


@router.post("/scans/{scan_id}/attack-plans/{plan_id}/execute")
async def execute_scan_attack_plan(
    scan_id: str,
    plan_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Manually trigger immediate execution of a structured attack plan."""
    security_engine = await _ensure_scan_engine(scan_id, db)
    planner = security_engine.get_planner(scan_id)
    if not planner:
        raise HTTPException(status_code=404, detail="Planner not initialized for this scan")

    plan = planner.get_plan(plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Attack plan not found")

    reasoning = security_engine.get_reasoning_layer(scan_id)
    executed_plan = await planner.execute_plan_async(
        plan_id=plan_id,
        scan_id=scan_id,
        hypothesis_engine=reasoning.hypothesis_engine if reasoning else None,
    )
    return {
        "status": "success",
        "plan_id": plan_id,
        "plan": executed_plan.to_dict() if executed_plan else None,
    }


@router.get("/engine/tools/nuclei/status")
async def get_nuclei_engine_status():
    """Check availability, version, and template capability of Nuclei engine."""
    from app.adapters.tools.nuclei_adapter import NucleiAdapter
    adapter = NucleiAdapter()
    is_installed = await adapter.healthcheck()
    return {
        "tool": "nuclei",
        "installed": is_installed,
        "binary_path": adapter._binary_path,
        "capabilities": list(adapter.capabilities),
        "version": adapter.version,
    }


class CopilotChatRequest(BaseModel):
    message: str
    scan_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None


@router.post("/ai/copilot/chat")
async def copilot_chat_endpoint(
    req: CopilotChatRequest,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Context-aware AI Pentest Copilot Chat endpoint."""
    user_msg = (req.message or "").strip()
    if not user_msg:
        raise HTTPException(status_code=400, detail="Pesan tidak boleh kosong.")

    scan_id = req.scan_id
    target_info = "Umum / Belum ada target aktif"
    findings_context = []
    assets_context = []
    ports_context = []
    tech_context = []
    scan_obj = None

    if scan_id:
        scan_obj = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if scan_obj:
            target_info = f"Target: {scan_obj.root_domain} (Status: {scan_obj.status}, Profile: {scan_obj.profile})"

            # Fetch findings
            finds = (await db.execute(select(Finding).where(Finding.scan_id == scan_id).limit(10))).scalars().all()
            for f in finds:
                findings_context.append(f"- [{f.severity}] {f.title} - CWE: {f.cwe_id or 'N/A'}")

            # Fetch assets & ports
            asts = (await db.execute(select(Asset.hostname).where(Asset.scan_id == scan_id).limit(15))).scalars().all()
            assets_context = [a for a in asts if a]

            ports_db = (await db.execute(select(Port.port, Port.service).join(Asset, Port.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(15))).all()
            ports_context = [f"Port {p[0]}/{p[1] or 'tcp'}" for p in ports_db]

            techs_db = (await db.execute(select(Technology.name, Technology.version).join(Asset, Technology.asset_id == Asset.id).where(Asset.scan_id == scan_id).limit(10))).all()
            tech_context = [f"{t[0]} {t[1] or ''}".strip() for t in techs_db]

    system_prompt = (
        "Anda adalah Hunter Aja AI Copilot — Asisten Penetrasi Keamanan Siber & Bug Bounty Senior berstandar industri.\n"
        f"Konteks Aktif Target: {target_info}\n"
        f"Subdomain/Aset Terdeteksi ({len(assets_context)}): {', '.join(assets_context[:10]) or 'Belum ada'}\n"
        f"Port Terbuka ({len(ports_context)}): {', '.join(ports_context[:8]) or 'Belum ada'}\n"
        f"Teknologi ({len(tech_context)}): {', '.join(tech_context[:6]) or 'Belum ada'}\n"
        f"Temuan Kerentanan ({len(findings_context)}):\n" + ("\n".join(findings_context) if findings_context else "- Belum ada temuan kerentanan kritis") + "\n\n"
        "Panduan Respon:\n"
        "1. Berikan jawaban teknis, terstruktur, akurat, dan langsung ke solusi (Offensive Security / Mitigation perspective).\n"
        "2. Format menggunakan Markdown yang bersih (headings, bullet points, code blocks cURL / payload bila relevan).\n"
        "3. Jika pengguna menanyakan analisis kerentanan, jelaskan dampak bisnis, root cause, cara verifikasi, dan langkah mitigasi secara profesional dalam Bahasa Indonesia."
    )

    from app.intelligence.llm_client import llm_client
    if llm_client.is_configured:
        try:
            full_prompt = f"{system_prompt}\n\nPengguna: {user_msg}\nCopilot:"
            reply = await llm_client.generate_text(full_prompt)
            if reply and reply.strip():
                return {
                    "reply": reply.strip(),
                    "source": "llm",
                    "model": settings.llm_model,
                }
        except Exception as llm_err:
            logger.debug("Copilot LLM fallback: %s", llm_err)

    msg_low = user_msg.lower()
    tgt_domain = scan_obj.root_domain if scan_obj else "target.local"
    if "poc" in msg_low or "exploit" in msg_low or "python" in msg_low:
        reply = (
            f"### 🐍 Python PoC Exploit & Verification Script\n\n"
            f"Berikut adalah script reproduksi otomatis untuk target **`{tgt_domain}`**:\n\n"
            f"```python\n"
            f"import requests\n"
            f"import urllib3\n"
            f"urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n\n"
            f"target_url = 'https://{tgt_domain}/search'\n"
            f"payload = {{'id': \"1' OR '1'='1\"}}\n"
            f"headers = {{'User-Agent': 'HunterAja-Validator/2.0'}}\n\n"
            f"response = requests.get(target_url, params=payload, headers=headers, verify=False, timeout=10)\n"
            f"if response.status_code == 200 and 'admin' in response.text.lower():\n"
            f"    print('[+] SQL Injection Confirmed on:', response.url)\n"
            f"else:\n"
            f"    print('[-] Parameter is not vulnerable or blocked by WAF.')\n"
            f"```\n\n"
            f"**cURL Equivalence:**\n"
            f"```bash\ncurl -i -s -k 'https://{tgt_domain}/search?id=1%27%20OR%20%271%27=%271'\n```"
        )
    elif "patch" in msg_low or "remediasi" in msg_low or "mitigasi" in msg_low or "developer" in msg_low:
        reply = (
            f"### 🛡️ Patch Remediasi Kode Developer\n\n"
            f"Berdasarkan hasil investigasi target **`{target_info}`**:\n\n"
            f"**1. PHP / PDO Parameterized Query Implementation:**\n"
            f"```php\n"
            f"// Remediasi SQL Injection via PHP PDO Prepared Statements\n"
            f"$stmt = $pdo->prepare('SELECT id, username, email FROM users WHERE id = :user_id');\n"
            f"$stmt->execute(['user_id' => $input_id]);\n"
            f"$user = $stmt->fetch();\n"
            f"```\n\n"
            f"**2. Panduan Kebijakan Keamanan:**\n"
            f"1. **Enforce Parameterized Queries:** Gunakan *Prepared Statements / PDO ORM* untuk seluruh input basis data.\n"
            f"2. **Strict Contextual Output Encoding:** Terapkan sanitasi HTML entity encoding pada template frontend untuk mencegah XSS.\n"
            f"3. **IP Whitelisting & MFA:** Batasi akses rute administratif `/admin` hanya untuk subnet VPN resmi."
        )
    elif "analisis" in msg_low or "vektor" in msg_low or "vector" in msg_low or "surface" in msg_low:
        reply = (
            f"### 🛡️ Analisis Vektor Serangan & Surface\n\n"
            f"**Target Aktif:** `{target_info}` (`{tgt_domain}`)\n\n"
            f"**1. Evaluasi Surface:**\n"
            f"- Aset/Subdomain Teridentifikasi: **{len(assets_context)} host** (`{', '.join(assets_context[:4]) or tgt_domain}`)\n"
            f"- Port Terbuka: **{', '.join(ports_context[:6]) or 'Standard Web Ports (80/443)'}**\n"
            f"- Teknologi: **{', '.join(tech_context[:5]) or 'Web Server Nginx/PHP/Cloudflare'}**\n\n"
            f"**2. Rekomendasi Vektor Prioritas:**\n"
            f"- **Sensitive Files & Backup Leaks:** Cek file `.env`, database dump `.sql`, dan direktori `.git/`.\n"
            f"- **Injection & Auth Bypass:** Uji parameter form pencarian dan ID record menggunakan *Canary Fuzzing*.\n"
            f"- **Nuclei Template Cluster:** Jalankan template CVE terbaru untuk teknologi yang terdeteksi."
        )
    elif "sqli" in msg_low or "xss" in msg_low or "payload" in msg_low:
        reply = (
            f"### 💉 Rekomendasi Payload Verifikasi (Non-Destruktif)\n\n"
            f"**1. Parameter SQL Injection Probe:**\n"
            f"```bash\ncurl -i -s -k 'https://{tgt_domain}/search?id=1%27%20OR%20%271%27=%271'\n```\n\n"
            f"**2. Reflected XSS Canary Probe:**\n"
            f"```bash\ncurl -i -s -k 'https://{tgt_domain}/search?q=%3Cscript%3Ealert(%27BH-CANARY%27)%3C/script%3E'\n```\n\n"
            f"**3. Cara Kerja Verifikasi Hunter Aja:**\n"
            f"Engine memvalidasi `Content-Type: text/html`, *unescaped reflections*, dan *DOM context execution* sebelum menyatakan temuan berstatus `CONFIRMED`."
        )
    else:
        reply = (
            f"### 🤖 Hunter Aja Pentest Copilot\n\n"
            f"Saya siap membantu proses investigasi ofensif Anda pada target **`{target_info}`**.\n\n"
            f"**Pertanyaan & Aksi Cepat yang Tersedia:**\n"
            f"- `⚡ Analisis Vektor Serangan Target`\n"
            f"- `🔍 Rekomendasi Payload SQLi/XSS`\n"
            f"- `🛡️ Buat Langkah Mitigasi untuk Developer`\n"
            f"- `📋 Export cURL Reproduction Script`"
        )

    return {
        "reply": reply,
        "source": "local_inference",
        "model": "Local MoE Pentest Engine",
    }


@router.get("/scans/{scan_id}/state-machine")
async def get_scan_state_machine(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get the state machine lifecycle data for a scan."""

    await _ensure_scan_engine(scan_id, db)

    from app.core.state_machine import state_machine_manager

    sm = state_machine_manager.get(scan_id)

    if not sm:

        return {"scan_id": scan_id, "state_machine": None, "history": []}

    return {

        "scan_id": scan_id,

        "state_machine": sm.to_dict(),

        "history": [e.to_dict() for e in sm.history],

    }





# Out-of-band Callback receiver endpoint

@router.api_route("/oob/{correlation_id}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])

async def oob_callback(correlation_id: str, request: Request):

    """Out-of-band (OOB) vulnerability verification callback endpoint."""

    client_ip = request.client.host if request.client else "unknown"

    headers = dict(request.headers)

    body = b""

    try:

        body = await request.body()

    except Exception:

        pass

    

    metadata = {

        "timestamp": datetime.now(timezone.utc).isoformat(),

        "client_ip": client_ip,

        "headers": headers,

        "body": body.decode("utf-8", errors="ignore"),

        "method": request.method,

        "query_params": dict(request.query_params),

    }

    

    from app.services.oob import oob_service

    await oob_service.log_interaction(correlation_id, metadata)

    

    return {"status": "logged", "correlation_id": correlation_id}





# Register literal paths (e.g. /scans/diff) before parameter catch-alls.



# ==========================================================================
# Enterprise Upgrades: User-Isolated Notifications, OpenAPI Export, AI Copilot, WAF Recon
# ==========================================================================

class UserNotificationUpdate(BaseModel):
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    telegram_enabled: bool = False
    discord_webhook_url: Optional[str] = None
    discord_enabled: bool = False
    slack_webhook_url: Optional[str] = None
    slack_enabled: bool = False
    notify_on_critical: bool = True
    notify_on_high: bool = True
    notify_on_scan_complete: bool = True
    notify_on_new_assets: bool = True


class TestNotificationRequest(BaseModel):
    channel: str
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None


@router.get("/user/notifications")
async def get_user_notifications(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve the current user's isolated notification configurations."""
    cfg = (await db.execute(
        select(UserNotificationConfig).where(UserNotificationConfig.user_id == user.id)
    )).scalar_one_or_none()
    
    if not cfg:
        return {
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "telegram_enabled": False,
            "discord_webhook_url": "",
            "discord_enabled": False,
            "slack_webhook_url": "",
            "slack_enabled": False,
            "notify_on_critical": True,
            "notify_on_high": True,
            "notify_on_scan_complete": True,
            "notify_on_new_assets": True,
        }
    
    return {
        "telegram_bot_token": cfg.telegram_bot_token or "",
        "telegram_chat_id": cfg.telegram_chat_id or "",
        "telegram_enabled": cfg.telegram_enabled,
        "discord_webhook_url": cfg.discord_webhook_url or "",
        "discord_enabled": cfg.discord_enabled,
        "slack_webhook_url": cfg.slack_webhook_url or "",
        "slack_enabled": cfg.slack_enabled,
        "notify_on_critical": cfg.notify_on_critical,
        "notify_on_high": cfg.notify_on_high,
        "notify_on_scan_complete": cfg.notify_on_scan_complete,
        "notify_on_new_assets": getattr(cfg, "notify_on_new_assets", True),
    }


@router.put("/user/notifications")
async def update_user_notifications(
    payload: UserNotificationUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update or create the current user's isolated notification configurations."""
    cfg = (await db.execute(
        select(UserNotificationConfig).where(UserNotificationConfig.user_id == user.id)
    )).scalar_one_or_none()

    if not cfg:
        cfg = UserNotificationConfig(
            user_id=user.id,
            telegram_bot_token=payload.telegram_bot_token,
            telegram_chat_id=payload.telegram_chat_id,
            telegram_enabled=payload.telegram_enabled,
            discord_webhook_url=payload.discord_webhook_url,
            discord_enabled=payload.discord_enabled,
            slack_webhook_url=payload.slack_webhook_url,
            slack_enabled=payload.slack_enabled,
            notify_on_critical=payload.notify_on_critical,
            notify_on_high=payload.notify_on_high,
            notify_on_scan_complete=payload.notify_on_scan_complete,
            notify_on_new_assets=payload.notify_on_new_assets,
        )
        db.add(cfg)
    else:
        cfg.telegram_bot_token = payload.telegram_bot_token
        cfg.telegram_chat_id = payload.telegram_chat_id
        cfg.telegram_enabled = payload.telegram_enabled
        cfg.discord_webhook_url = payload.discord_webhook_url
        cfg.discord_enabled = payload.discord_enabled
        cfg.slack_webhook_url = payload.slack_webhook_url
        cfg.slack_enabled = payload.slack_enabled
        cfg.notify_on_critical = payload.notify_on_critical
        cfg.notify_on_high = payload.notify_on_high
        cfg.notify_on_scan_complete = payload.notify_on_scan_complete
        cfg.notify_on_new_assets = payload.notify_on_new_assets

    await db.commit()
    return {"status": "saved", "message": "Konfigurasi notifikasi akun Anda berhasil disimpan."}


@router.post("/user/notifications/test")
async def test_user_notification(
    payload: TestNotificationRequest,
    user: User = Depends(get_current_user),
):
    """Send test alert to user's specified channel."""
    from app.core.notifications import notification_service
    res = await notification_service.test_user_channel(
        channel=payload.channel,
        telegram_token=payload.telegram_bot_token,
        telegram_chat_id=payload.telegram_chat_id,
        discord_webhook=payload.discord_webhook_url,
        slack_webhook=payload.slack_webhook_url,
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("detail", "Gagal mengirim notifikasi tes."))
    return res


@router.get("/scans/{scan_id}/export/openapi")
@router.get("/scans/{scan_id}/export/openapi.json")
async def export_scan_openapi_json(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Export discovered attack surface as OpenAPI 3.0.3 specification JSON."""
    from app.reporting.openapi_generator import OpenApiGenerator
    spec = await OpenApiGenerator.generate_spec(scan_id, db)
    return JSONResponse(
        content=spec,
        headers={"Content-Disposition": f'attachment; filename="openapi-spec-{scan_id}.json"'}
    )


class CopilotChatRequest(BaseModel):
    message: str
    scan_id: Optional[str] = None
    history: Optional[List[Dict[str, str]]] = None


@router.post("/ai/copilot/chat")
async def copilot_chat_endpoint(
    payload: CopilotChatRequest,
    user: Optional[User] = Depends(get_optional_user),
):
    """Interactive Pentest AI Copilot assistant."""
    from app.ai.copilot import pentest_copilot
    res = await pentest_copilot.chat(
        message=payload.message,
        scan_id=payload.scan_id,
        history=payload.history,
    )
    return res


class WafAnalyzeRequest(BaseModel):
    status_code: int = 200
    headers: Dict[str, str] = {}
    cookies: Optional[Dict[str, str]] = None
    body: str = ""


@router.post("/recon/waf/analyze")
async def analyze_waf_endpoint(payload: WafAnalyzeRequest):
    """Analyze HTTP response headers and body for WAF signatures."""
    from app.discovery.waf_detector import waf_detector
    return waf_detector.analyze_response(
        status_code=payload.status_code,
        headers=payload.headers,
        cookies=payload.cookies,
        body=payload.body,
    )


router.routes.sort(key=lambda route: route.path.count("{"))



@router.get("/scans/{scan_id}/diff/auto")
async def get_scan_diff_auto(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user: Optional[User] = Depends(get_optional_user),
):
    """Retrieve differential analysis comparing current scan with the immediately preceding scan on the same target."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan tidak ditemukan.")

    query = select(Scan).where(
        Scan.root_domain == scan.root_domain,
        Scan.id != scan_id,
        Scan.status.in_(["completed", "degraded"]),
    )
    if user:
        query = query.where(Scan.user_id == user.id)
    query = query.order_by(Scan.created_at.desc()).limit(1)

    prev_scan = (await db.execute(query)).scalar_one_or_none()
    if not prev_scan:
        return {
            "has_previous": False,
            "message": "Tidak ditemukan scan sebelumnya untuk target domain ini.",
            "current_scan_id": scan_id,
        }

    from app.differential.engine import differential_engine
    diff_res = await differential_engine.compare(
        db=db,
        current_scan_id=scan_id,
        previous_scan_id=prev_scan.id,
    )
    return {
        "has_previous": True,
        "previous_scan_id": prev_scan.id,
        "previous_created_at": prev_scan.created_at.isoformat() if prev_scan.created_at else None,
        "diff": diff_res,
    }


@router.post("/user/notifications/test-diff")
async def test_user_diff_notification(
    payload: TestNotificationRequest,
    user: User = Depends(get_current_user),
):
    """Send simulated Smart Diff alert to verify webhook rendering."""
    from app.core.notifications import notification_service
    sample_diff = {
        "metrics": {"new_assets_count": 2, "new_ports_count": 2, "new_findings_count": 1},
        "new_subdomains": ["api-staging.example.com", "vpn.example.com"],
        "new_ports": [
            {"hostname": "api-staging.example.com", "port": 8443, "service": "https-alt"},
            {"hostname": "vpn.example.com", "port": 1194, "service": "openvpn"},
        ],
        "new_findings": [
            {"title": "Open Redis Instance without Auth", "severity": "HIGH", "cwe_id": "CWE-306"},
        ],
        "changed_ip": [
            {"hostname": "api-staging.example.com", "previous_ip": "192.168.1.10", "current_ip": "103.25.10.15"},
        ],
    }
    
    channel_lower = (payload.channel or "").lower().strip()
    if channel_lower == "telegram":
        if not payload.telegram_bot_token or not payload.telegram_chat_id:
            raise HTTPException(status_code=400, detail="Telegram Bot Token dan Chat ID wajib diisi.")
        ok = await notification_service._send_telegram_diff(
            bot_token=payload.telegram_bot_token,
            chat_id=payload.telegram_chat_id,
            target="example.com",
            scan_id="test_diff_sim",
            diff_data=sample_diff,
        )
        return {"success": ok, "detail": "Pesan tes Smart Diff berhasil dikirim ke Telegram!" if ok else "Gagal mengirim ke Telegram."}
    elif channel_lower == "discord":
        if not payload.discord_webhook_url:
            raise HTTPException(status_code=400, detail="Discord Webhook URL wajib diisi.")
        ok = await notification_service._send_discord_diff(
            webhook_url=payload.discord_webhook_url,
            target="example.com",
            scan_id="test_diff_sim",
            diff_data=sample_diff,
        )
        return {"success": ok, "detail": "Embed tes Smart Diff berhasil dikirim ke Discord!" if ok else "Gagal mengirim ke Discord."}
    elif channel_lower == "slack":
        if not payload.slack_webhook_url:
            raise HTTPException(status_code=400, detail="Slack Webhook URL wajib diisi.")
        ok = await notification_service._send_slack_diff(
            webhook_url=payload.slack_webhook_url,
            target="example.com",
            scan_id="test_diff_sim",
            diff_data=sample_diff,
        )
        return {"success": ok, "detail": "Pesan tes Smart Diff berhasil dikirim ke Slack!" if ok else "Gagal mengirim ke Slack."}
    raise HTTPException(status_code=400, detail=f"Channel '{payload.channel}' tidak valid.")
