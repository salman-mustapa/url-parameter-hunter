"""API authentication and ownership checks shared by every API route."""
import json
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_optional_user
from app.core.db import get_db
from app.models.models import Approval, Artifact, Asset, ExportJob, Finding, Scan, Screenshot, User

PUBLIC_ROUTES = {
    "/api/health", "/api/auth/login", "/api/auth/register", "/api/auth/logout",
    "/api/auth/me", "/api/oob/{correlation_id}",
}
ADMIN_ENDPOINTS = {
    "perform_finding_retest", "get_ai_config", "update_ai_config", "test_ai_gateway_connection",
    "get_ai_status", "test_ai_connection", "get_ai_models", "list_ai_models",
    "update_ai_settings", "list_labs", "create_lab", "destroy_lab",
    "list_cleanup_tasks", "execute_cleanup_task", "get_scheduler_telemetry",
    "list_worker_statuses", "get_autonomous_queue", "get_request_graph",
    "approve_cybersecurity_skill", "block_cybersecurity_skill",
    "get_orchestrator_teams", "get_orchestrator_live_graph", "get_engine_status",
}
RESOURCE_MODELS = {
    "asset_id": Asset, "finding_id": Finding, "artifact_id": Artifact,
    "screenshot_id": Screenshot, "approval_id": Approval, "export_id": ExportJob,
}


async def require_scan_access(scan_id: str, user: User, db: AsyncSession) -> Scan:
    scan = await db.get(Scan, scan_id)
    if not scan or (user.role != "admin" and scan.user_id != user.id):
        # Do not reveal whether another user's resource exists.
        raise HTTPException(404, "Scan not found")
    return scan


async def enforce_api_access(
    request: Request,
    user: User | None = Depends(get_optional_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    route = request.scope["route"]
    if route.path in PUBLIC_ROUTES:
        return
    if not user:
        raise HTTPException(401, "Silakan login terlebih dahulu.", headers={"WWW-Authenticate": "Bearer"})
    if user.role not in {"user", "admin"}:
        raise HTTPException(403, "Role tidak diizinkan.")
    if (route.path.startswith("/api/admin/") or route.name in ADMIN_ENDPOINTS) and user.role != "admin":
        raise HTTPException(403, "Akses administrator diperlukan.")

    refs = dict(request.path_params)
    scan_ids = set()
    if refs.get("scan_id"):
        scan_ids.add(refs["scan_id"])
    for key in ("scan_id", "current", "previous", "current_scan_id", "previous_scan_id"):
        scan_ids.update(value for value in request.query_params.getlist(key) if value)

    # These endpoints reference stored resources in JSON instead of their URL.
    if route.name in {"create_hypothesis", "ai_review_evidence", "simulate_pivot"}:
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(422, "Malformed JSON body") from None
        if isinstance(body, dict):
            for key in ("scan_id", "finding_id"):
                value = body.get(key)
                if value is not None and not isinstance(value, str):
                    raise HTTPException(422, f"{key} must be a string")
                if value:
                    refs[key] = value
                    if key == "scan_id":
                        scan_ids.add(value)
    for key, model in RESOURCE_MODELS.items():
        if not refs.get(key):
            continue
        resource = await db.get(model, refs[key])
        if not resource and key == "asset_id" and route.name == "get_asset_detail":
            query = select(Asset).join(Scan, Asset.scan_id == Scan.id).where(
                (Asset.hostname == refs[key]) | (Asset.fqdn == refs[key]) | (Asset.ip == refs[key])
            ).order_by(Asset.last_seen.desc()).limit(1)
            if user.role != "admin":
                query = query.where(Scan.user_id == user.id)
            resource = (await db.execute(query)).scalars().first()
        if not resource:
            raise HTTPException(404, "Resource not found")
        resource_scan_id = resource.scan_id
        if refs.get("scan_id") and resource_scan_id != refs["scan_id"]:
            raise HTTPException(404, "Resource not found")
        if not resource_scan_id:
            if user.role != "admin":
                raise HTTPException(404, "Resource not found")
        else:
            scan_ids.add(resource_scan_id)
        if key == "asset_id":
            request.state.authorized_asset_id = resource.id
    for scan_id in scan_ids:
        await require_scan_access(scan_id, user, db)
