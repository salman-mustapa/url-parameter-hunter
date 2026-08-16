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
            "message": message,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }

    async def persist_event(self, event: dict) -> None:
        async with AsyncSessionLocal() as db:
            ev = ScanEvent(
                scan_id=event["scan_id"],
                event_type=event["event_type"],
                severity=event.get("severity", "info"),
                message=event.get("message", ""),
                data=event.get("data", {}),
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
        existing = (await db.execute(
            select(Asset).where(Asset.scan_id == scan_id, Asset.asset_type == asset_type, Asset.fingerprint == fingerprint)
        )).scalar_one_or_none()
        if existing:
            if parent_id and not existing.parent_id:
                existing.parent_id = parent_id
            if ip and not existing.ip:
                existing.ip = ip
            if discovered_from:
                srcs = list(existing.discovered_from or [])
                for src in discovered_from:
                    if src not in srcs:
                        srcs.append(src)
                existing.discovered_from = srcs
            return existing
        asset = Asset(
            scan_id=scan_id,
            asset_type=asset_type,
            fingerprint=fingerprint,
            parent_id=parent_id,
            hostname=hostname,
            fqdn=fqdn,
            ip=ip,
            depth=depth,
            discovered_from=discovered_from or [],
            metadata_=metadata or {},
        )
        db.add(asset)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return (await db.execute(
                select(Asset).where(Asset.scan_id == scan_id, Asset.asset_type == asset_type, Asset.fingerprint == fingerprint)
            )).scalar_one()
        return asset

    async def upsert_finding(
        self, db: AsyncSession, *, scan_id: str, asset_id: Optional[str], finding_type: str, title: str,
        severity: str = "INFO", confidence: float = 0.5, description: str | None = None, evidence: dict | None = None,
        status: str = "OPEN",
    ) -> Finding | None:
        existing = (await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id, Finding.asset_id == asset_id, Finding.finding_type == finding_type, Finding.title == title,
            )
        )).scalar_one_or_none()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            return existing
        finding = Finding(
            scan_id=scan_id, asset_id=asset_id, finding_type=finding_type, title=title,
            severity=severity, confidence=confidence, description=description,
            evidence=evidence or {}, status=status,
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
        existing = (await db.execute(
            select(Observation).where(
                Observation.scan_id == scan_id, Observation.asset_id == asset_id,
                Observation.observation_type == observation_type, Observation.title == title,
            )
        )).scalar_one_or_none()
        if existing:
            return existing
        obs = Observation(
            scan_id=scan_id, asset_id=asset_id, observation_type=observation_type, title=title,
            evidence=evidence or {}, confidence=confidence,
        )
        db.add(obs)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return None
        return obs

    async def audit(self, db: AsyncSession, scan_id: str, action: str, actor: str = "system", target: str | None = None, details: dict | None = None):
        db.add(AuditLog(scan_id=scan_id, actor=actor, action=action, target=target, details=details or {}))
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()


result_service = ResultService()