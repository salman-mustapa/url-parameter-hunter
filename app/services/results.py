from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import AsyncSessionLocal
from app.models.models import Asset, AuditLog, Finding, Observation, Scan, ScanEvent


from app.core.sanitizer import sanitize_text


class ResultService:
    def __init__(self, dialect: str = "postgresql"):
        self.dialect = dialect
        self._asset_cache: dict[tuple[str, str, str], str] = {}
        self._lock = asyncio.Lock()

    def make_event(self, scan_id: str, event_type: str, message: str, **data) -> dict:
        cat = event_type.split(".")[0].upper() if "." in event_type else event_type.upper()
        return {
            "scan_id": scan_id,
            "event_type": event_type,
            "category": cat,
            "severity": data.pop("severity", "info"),
            "message": sanitize_text(message),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "data": sanitize_text(data),
        }

    async def persist_event(self, event: dict) -> None:
        async with AsyncSessionLocal() as db:
            ev = ScanEvent(
                scan_id=event["scan_id"],
                event_type=event["event_type"],
                severity=event.get("severity", "info"),
                message=sanitize_text(event.get("message", "")),
                data=sanitize_text(event.get("data", {})),
            )
            db.add(ev)
            await db.commit()


    async def upsert_asset(
        self,
        db: AsyncSession,
        *,
        scan_id: str,
        asset_type: str,
        fingerprint: str,
        parent_id: Optional[str] = None,
        hostname: Optional[str] = None,
        fqdn: Optional[str] = None,
        ip: Optional[str] = None,
        depth: int = 0,
        discovered_from: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Asset:
        clean_fp = sanitize_text(fingerprint)
        clean_host = sanitize_text(hostname)
        clean_fqdn = sanitize_text(fqdn)
        clean_ip = sanitize_text(ip)
        clean_meta = sanitize_text(metadata or {})
        clean_srcs = sanitize_text(discovered_from or [])

        existing = (await db.execute(
            select(Asset).where(Asset.scan_id == scan_id, Asset.asset_type == asset_type, Asset.fingerprint == clean_fp)
        )).scalar_one_or_none()
        if existing:
            if parent_id and not existing.parent_id:
                existing.parent_id = parent_id
            if clean_ip and not existing.ip:
                existing.ip = clean_ip
            if clean_srcs:
                srcs = list(existing.discovered_from or [])
                for src in clean_srcs:
                    if src not in srcs:
                        srcs.append(src)
                existing.discovered_from = srcs
            return existing
        asset = Asset(
            scan_id=scan_id,
            asset_type=asset_type,
            fingerprint=clean_fp,
            parent_id=parent_id,
            hostname=clean_host,
            fqdn=clean_fqdn,
            ip=clean_ip,
            depth=depth,
            discovered_from=clean_srcs,
            metadata_=clean_meta,
        )
        db.add(asset)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return (await db.execute(
                select(Asset).where(Asset.scan_id == scan_id, Asset.asset_type == asset_type, Asset.fingerprint == clean_fp)
            )).scalar_one()
        return asset

    async def upsert_finding(
        self, db: AsyncSession, *, scan_id: str, asset_id: Optional[str], finding_type: str, title: str,
        severity: str = "INFO", confidence: float = 0.5, description: str | None = None, evidence: dict | None = None,
        status: str = "OPEN",
    ) -> Finding | None:
        clean_title = sanitize_text(title)
        clean_desc = sanitize_text(description)
        clean_ev = sanitize_text(evidence or {})
        existing = (await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id, Finding.asset_id == asset_id, Finding.finding_type == finding_type, Finding.title == clean_title,
            )
        )).scalar_one_or_none()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            return existing
        finding = Finding(
            scan_id=scan_id, asset_id=asset_id, finding_type=finding_type, title=clean_title,
            severity=severity, confidence=confidence, description=clean_desc,
            evidence=clean_ev, status=status,
        )
        db.add(finding)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return None
        return finding

    async def upsert_observation(
        self, db: AsyncSession, *, scan_id: str, asset_id: Optional[str], observation_type: str, title: str,
        evidence: dict | None = None, confidence: float = 0.5,
    ) -> Observation | None:
        clean_title = sanitize_text(title)
        clean_ev = sanitize_text(evidence or {})
        existing = (await db.execute(
            select(Observation).where(
                Observation.scan_id == scan_id, Observation.asset_id == asset_id,
                Observation.observation_type == observation_type, Observation.title == clean_title,
            )
        )).scalar_one_or_none()
        if existing:
            return existing
        obs = Observation(
            scan_id=scan_id, asset_id=asset_id, observation_type=observation_type, title=clean_title,
            evidence=clean_ev, confidence=confidence,
        )
        db.add(obs)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return None
        return obs

    async def audit(self, db: AsyncSession, scan_id: str, action: str, actor: str = "system", target: str | None = None, details: dict | None = None):
        db.add(AuditLog(
            scan_id=scan_id,
            actor=sanitize_text(actor),
            action=sanitize_text(action),
            target=sanitize_text(target),
            details=sanitize_text(details or {}),
        ))
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()


result_service = ResultService()