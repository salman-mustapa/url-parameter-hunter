"""Bounded asynchronous exports: database snapshot, worker rendering, atomic publish."""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import logging
import uuid
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import STORAGE_DIR
from app.core.db import AsyncSessionLocal
from app.core.events import event_bus
from app.core.engagement import report_context
from app.core.paths import contained_path
from app.models.models import Artifact, Asset, Evidence, ExportJob, Finding, Port, Scan, Technology, URL
from app.reporting.export_formats import render_export
from app.reporting.serializers import serialize_finding

logger = logging.getLogger("export_manager")


class ExportQueueFull(ValueError):
    pass


class ExportManager:
    SUPPORTED_TYPES = {
        "full_pdf": ("application/pdf", ".pdf"),
        "executive_pdf": ("application/pdf", ".pdf"),
        "technical_pdf": ("application/pdf", ".pdf"),
        "findings_csv": ("text/csv", ".csv"),
        "findings_xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"),
        "investigation_json": ("application/json", ".json"),
        "assets_csv": ("text/csv", ".csv"),
        "services_csv": ("text/csv", ".csv"),
        "evidence_index_json": ("application/json", ".json"),
        "artifact_manifest_json": ("application/json", ".json"),
    }
    _slots = asyncio.Semaphore(2)
    _admission = asyncio.Lock()
    _tasks: set[asyncio.Task] = set()

    @classmethod
    async def create_export_job(cls, scan_id: str, export_type: str, db: AsyncSession) -> ExportJob:
        if export_type not in cls.SUPPORTED_TYPES:
            raise ValueError(f"Unsupported export type: {export_type}")
        async with cls._admission:
            pending = select(ExportJob).where(ExportJob.status.in_(("QUEUED", "PROCESSING")))
            existing = (await db.execute(pending.where(ExportJob.scan_id == scan_id, ExportJob.export_type == export_type))).scalars().first()
            if existing:
                return existing
            count = (await db.execute(select(func.count()).select_from(ExportJob).where(ExportJob.status.in_(("QUEUED", "PROCESSING"))))).scalar() or 0
            if count >= 20:
                raise ExportQueueFull("Export queue is busy. Retry after existing jobs finish.")
            mime, ext = cls.SUPPORTED_TYPES[export_type]
            filename = f"{export_type}_{scan_id}_{uuid.uuid4().hex[:12]}{ext}"
            job = ExportJob(scan_id=scan_id, export_type=export_type, filename=filename, status="QUEUED", mime_type=mime)
            db.add(job)
            await db.commit()
            await db.refresh(job)
            task = asyncio.create_task(cls._execute_generation(job.id, scan_id, export_type, filename))
            cls._tasks.add(task)
            task.add_done_callback(cls._tasks.discard)
            return job

    @classmethod
    async def _execute_generation(cls, job_id: str, scan_id: str, export_type: str, filename: str):
        root = STORAGE_DIR.resolve()
        async with cls._slots:
            async with AsyncSessionLocal() as db:
                job = await db.get(ExportJob, job_id)
                if not job:
                    return
                try:
                    job.status = "PROCESSING"
                    await db.commit()
                    scan = await db.get(Scan, scan_id)
                    if not scan:
                        raise ValueError("Scan no longer exists")
                    assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()
                    ports = (await db.execute(select(Port).join(Asset).where(Asset.scan_id == scan_id))).scalars().all()
                    techs = (await db.execute(select(Technology).join(Asset).where(Asset.scan_id == scan_id))).scalars().all()
                    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.first_seen, Finding.id))).scalars().all()
                    evidence = (await db.execute(select(Evidence).where(Evidence.scan_id == scan_id))).scalars().all()
                    artifacts = (await db.execute(select(Artifact).where(Artifact.scan_id == scan_id))).scalars().all()
                    url_count = (await db.execute(select(func.count()).select_from(URL).join(Asset).where(Asset.scan_id == scan_id))).scalar() or 0
                    hosts = {a.id: a.hostname or a.fqdn or a.ip for a in assets}
                    snapshot = {
                        "schema_version": "1.0", "investigation_id": scan_id, "target": scan.root_domain,
                        "status": scan.status, "profile": scan.profile, "validation_level": scan.validation_level,
                        "engagement": report_context(scan),
                        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "statistics": {"report_context": report_context(scan), "total_assets": len(assets), "total_ports": len(ports), "total_urls": url_count,
                                       "total_technologies": len(techs), "total_findings": len(findings), "total_artifacts": len(artifacts)},
                        "findings": [serialize_finding(f, scan.root_domain, hosts) for f in findings],
                        "assets": [{"id": a.id, "hostname": hosts[a.id], "ip": a.ip, "asset_type": a.asset_type, "status": a.status} for a in assets],
                        "services": [{"id": p.id, "asset_id": p.asset_id, "host": hosts.get(p.asset_id), "port": p.port,
                                      "protocol": p.protocol, "service": p.service, "banner": p.banner} for p in ports],
                        "technologies": [{"name": t.name, "version": t.version, "category": t.category, "hostname": hosts.get(t.asset_id)} for t in techs],
                        "evidence": [{"id": e.id, "asset_id": e.asset_id, "evidence_type": e.evidence_type, "data": e.data,
                                      "sha256_hash": e.sha256_hash, "created_at": e.created_at.isoformat() if e.created_at else None} for e in evidence],
                        "artifacts": [{"id": a.id, "filename": a.filename, "classification": a.classification,
                                       "category": a.category, "size_bytes": a.size_bytes, "sha256_hash": a.sha256_hash,
                                       "is_redacted": a.is_redacted} for a in artifacts],
                    }
                    file_bytes = await asyncio.to_thread(render_export, export_type, snapshot)
                    directory = contained_path(root / "investigations" / scan_id / "exports", root)
                    output = directory / filename
                    def write_file():
                        directory.mkdir(parents=True, exist_ok=True)
                        temporary = output.with_suffix(output.suffix + ".part")
                        temporary.write_bytes(file_bytes)
                        temporary.replace(output)
                    await asyncio.to_thread(write_file)
                    job.status = "COMPLETED"
                    job.file_path = str(output)
                    job.file_size = len(file_bytes)
                    job.sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                    job.completed_at = datetime.datetime.now(datetime.timezone.utc)
                    await db.commit()
                except Exception as error:
                    await db.rollback()
                    logger.exception("Export failed: %s %s", scan_id, export_type)
                    job = await db.get(ExportJob, job_id)
                    if job:
                        job.status = "FAILED"
                        job.error_message = "Export generation failed. Review server logs and retry."
                        await db.commit()
                    return
                try:
                    await event_bus.publish({"scan_id": scan_id, "event_type": "export.completed", "data": {"job_id": job_id},
                                             "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()})
                except Exception:
                    logger.warning("Export saved; completion event could not be published", exc_info=True)
