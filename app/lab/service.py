"""Persist the disposable local investigation through the real application services."""

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.core.db import AsyncSessionLocal
from app.core.events import event_bus
from app.lab.runtime import local_lab
from app.lab.workflow import investigate_local_lab
from app.models.models import Asset, Scan, URL
from app.services.results import result_service
from app.validation.engine import EvidenceValidationEngine


async def run_persisted_lab(user_id: str) -> dict:
    async with AsyncSessionLocal() as db:
        scan = Scan(user_id=user_id, root_domain="127.0.0.1", status="queued",
                    profile="synthetic_lab", validation_level="L3_CONTROLLED",
                    authorization_reference="disposable synthetic local lab",
                    options={"synthetic_lab": True, "include_subdomains": False})
        db.add(scan)
        await db.commit()
        scan_id = scan.id

    async def progress(stage, data):
        async with AsyncSessionLocal() as db:
            record = await db.get(Scan, scan_id)
            record.progress = {**(record.progress or {}), "stage": stage, **data}
            await db.commit()
        await event_bus.publish(result_service.make_event(
            scan_id, f"lab.{stage}", f"Synthetic local lab: {stage}", **data))

    await progress("queued", {})
    try:
        async with asyncio.timeout(30), local_lab() as (base, state):
            async with AsyncSessionLocal() as db:
                record = await db.get(Scan, scan_id)
                record.status = "running"
                record.started_at = datetime.now(timezone.utc)
                record.options = {**record.options, "authorized_origins": [base]}
                asset = Asset(scan_id=scan_id, asset_type="domain", hostname="127.0.0.1",
                              fingerprint=base, discovered_from=["synthetic_lab"])
                db.add(asset)
                await db.flush()
                asset_id = asset.id
                await db.commit()
            await progress("running", {"assets": 1})

            async def persist(result):
                async with AsyncSessionLocal() as db:
                    parts = urlsplit(result.endpoint_url)
                    db.add(URL(asset_id=asset_id, url=result.endpoint_url, scheme=parts.scheme,
                               host=parts.hostname, port=parts.port, path=parts.path))
                    await db.flush()
                    finding = await EvidenceValidationEngine().persist(db, scan_id, result, asset_id)
                    await db.commit()
                    return finding.id if finding else None

            report = await investigate_local_lab(base, state, persist=persist, progress=progress)
        async with AsyncSessionLocal() as db:
            record = await db.get(Scan, scan_id)
            record.status = "completed"
            record.completed_at = datetime.now(timezone.utc)
            record.progress = {**record.progress, "stage": "completed",
                               "findings": len(report["finding_ids"]), "urls": 1}
            await db.commit()
        await progress("completed", {"findings": len(report["finding_ids"])})
        await result_service.drain()
        return {**report, "scan_id": scan_id,
                "report_url": f"/api/scans/{scan_id}/report/markdown"}
    except BaseException as error:
        async with AsyncSessionLocal() as db:
            record = await db.get(Scan, scan_id)
            record.status = "stopped" if isinstance(error, asyncio.CancelledError) else "failed"
            record.last_error = type(error).__name__
            record.completed_at = datetime.now(timezone.utc)
            await db.commit()
        raise
