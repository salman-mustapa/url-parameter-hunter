from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import AsyncSessionLocal
from app.core.config import settings
from app.core.sanitizer import sanitize_text
from app.findings.dedup import FindingDedup
from app.models.models import Asset, AuditLog, Finding, Observation, Scan, ScanEvent

logger = logging.getLogger("services.results")


class ResultService:
    def __init__(self, dialect: str = "postgresql"):
        self.dialect = dialect
        self._asset_cache: dict[tuple[str, str, str], str] = {}
        self._lock = asyncio.Lock()
        self._event_queue: asyncio.Queue = asyncio.Queue(maxsize=max(100, settings.result_event_queue_size))
        self._flush_task: Optional[asyncio.Task] = None
        self._dropped_events = 0
        self._failed_events = 0

    def _ensure_worker(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            if self._flush_task is None or self._flush_task.done():
                self._flush_task = loop.create_task(self._event_flusher())
        except RuntimeError:
            pass

    async def _event_flusher(self) -> None:
        """Background worker that batches scan events to prevent DB pool exhaustion."""
        while True:
            batch = []
            try:
                item = await self._event_queue.get()
                batch.append(item)
                while len(batch) < 50:
                    try:
                        batch.append(self._event_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                for attempt in range(3):
                    try:
                        await self._flush_batch(batch)
                        break
                    except Exception:
                        if attempt == 2:
                            self._failed_events += len(batch)
                            logger.exception("Event persistence failed after three attempts (%d events)", len(batch))
                        else:
                            await asyncio.sleep(0.05 * (attempt + 1))
            except asyncio.CancelledError:
                raise
            finally:
                for _ in batch:
                    self._event_queue.task_done()

    async def _flush_batch(self, events: list[dict]) -> None:
        if not events:
            return
        from app.reporting.redaction import RedactionEngine
        async with AsyncSessionLocal() as db:
            scan_ids = {item.get("scan_id") for item in events} - {None}
            existing = set((await db.execute(select(Scan.id).where(Scan.id.in_(scan_ids)))).scalars())
            for ev_dict in events:
                if ev_dict.get("scan_id") not in existing:
                    continue  # The scan may have been deleted before its last event drained.
                db.add(ScanEvent(
                    id=ev_dict.get("event_id"),
                    scan_id=ev_dict["scan_id"],
                    event_type=ev_dict.get("event_type", "system.event"),
                    severity=ev_dict.get("severity", "info"),
                    message=RedactionEngine.redact_text(sanitize_text(ev_dict.get("message", ""))),
                    data=RedactionEngine.redact_dict(sanitize_text(ev_dict.get("data", {}))),
                    created_at=ev_dict.get("created_at") or datetime.now(timezone.utc),
                ))
            await db.commit()

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
        if not isinstance(event, dict):
            return

        scan_id = event.get("scan_id")
        if not scan_id:
            data = event.get("data")
            if isinstance(data, dict):
                scan_id = data.get("scan_id")
        if not scan_id:
            return  # Ignore events that do not belong to a specific scan table record

        event_type = event.get("event_type") or event.get("type") or "system.event"
        severity = event.get("severity") or (event.get("status", "info").lower() if isinstance(event.get("status"), str) else "info")
        message = event.get("message") or ""
        event_data = event.get("data") if isinstance(event.get("data"), dict) else {}
        raw_time = event.get("created_at") or event.get("timestamp")
        try:
            created_at = datetime.fromisoformat(raw_time) if isinstance(raw_time, str) else datetime.now(timezone.utc)
        except ValueError:
            created_at = datetime.now(timezone.utc)

        self._ensure_worker()
        try:
            self._event_queue.put_nowait({
                "event_id": event.get("event_id"),
                "created_at": created_at,
                "scan_id": scan_id,
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "data": event_data,
            })
        except asyncio.QueueFull:
            self._dropped_events += 1
            try:
                self._event_queue.get_nowait()
                self._event_queue.task_done()
                self._event_queue.put_nowait({
                    "event_id": event.get("event_id"),
                    "created_at": created_at,
                    "scan_id": scan_id,
                    "event_type": event_type,
                    "severity": severity,
                    "message": message,
                    "data": event_data,
                })
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass
            if self._dropped_events == 1 or self._dropped_events % 100 == 0:
                logger.warning(
                    "Result event queue saturated; dropped %d oldest event(s).",
                    self._dropped_events,
                )

    async def close(self) -> None:
        """Flush queued events and terminate the background writer cleanly."""
        task = self._flush_task
        if task and not task.done():
            await self.drain()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._flush_task = None

    async def drain(self) -> None:
        """Acknowledge events only after commit, and expose persistence failures."""
        if not self._event_queue.empty():
            self._ensure_worker()
        await asyncio.wait_for(self._event_queue.join(), timeout=15)
        if self._failed_events:
            raise RuntimeError(f"{self._failed_events} events could not be persisted")

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
        **kwargs: Any,
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
        self,
        db: AsyncSession,
        *,
        scan_id: str,
        asset_id: Optional[str],
        finding_type: str,
        title: str,
        severity: str = "INFO",
        confidence: str = "OBSERVED",
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        description: str | None = None,
        impact: str | None = None,
        technical_details: str | None = None,
        remediation: str | None = None,
        business_impact: str | None = None,
        root_cause: str | None = None,
        preconditions: list | None = None,
        expected_result: str | None = None,
        actual_result: str | None = None,
        executive_explanation: str | None = None,
        evidence_level: str = "E0",
        evidence_score: int = 10,
        exploitability_state: str = "CANDIDATE",
        priority: str = "P2",
        rule_version: str = "v8.0.0",
        impact_matrix: dict | None = None,
        validation_status: str = "DISCOVERED",
        evidence: dict | None = None,
        reproducibility_meta: dict | None = None,
        status: str = "OPEN",
        **kwargs: Any,
    ) -> Finding | None:
        from app.validation.context import has_verified_proof
        from app.reporting.redaction import RedactionEngine
        validated_result = kwargs.get("validated_result")
        if confidence == "CONFIRMED" or validation_status == "CONFIRMED" or exploitability_state in {"CONFIRMED", "EXPLOITABLE"}:
            if not validated_result or not has_verified_proof(validated_result) or validated_result.status != "CONFIRMED":
                confidence, validation_status, exploitability_state = "SUSPECTED", "INCONCLUSIVE", "INCONCLUSIVE"
                evidence_level, evidence_score = "E0", min(evidence_score, 30)
        evidence = RedactionEngine.redact_dict(evidence or kwargs.get("evidence_data") or {})
        clean_title = sanitize_text(title)
        clean_desc = sanitize_text(description)
        clean_ev = sanitize_text(evidence or {})
        clean_impact = sanitize_text(impact)
        clean_tech = sanitize_text(technical_details)
        clean_remed = sanitize_text(remediation)
        clean_biz = sanitize_text(business_impact)
        clean_root = sanitize_text(root_cause)
        clean_exp = sanitize_text(expected_result)
        clean_act = sanitize_text(actual_result)
        clean_exec = sanitize_text(executive_explanation)

        dedup_key = FindingDedup.generate_dedup_key(
            asset_identifier=asset_id or scan_id,
            vulnerability_type=finding_type,
            location=clean_title,
        )

        existing = (await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.asset_id == asset_id,
                Finding.finding_type == finding_type,
                Finding.title == clean_title,
            )
        )).scalar_one_or_none()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            if clean_ev:
                cur_ev = dict(existing.evidence or {})
                cur_ev.update(clean_ev)
                existing.evidence = cur_ev
            if clean_impact:
                existing.impact = clean_impact
            if clean_tech:
                existing.technical_details = clean_tech
            if clean_remed:
                existing.remediation = clean_remed
            if clean_root:
                existing.root_cause = clean_root
            if clean_exec:
                existing.executive_explanation = clean_exec
            if clean_biz:
                existing.business_impact = clean_biz
            if clean_exp:
                existing.expected_result = clean_exp
            if clean_act:
                existing.actual_result = clean_act
            if impact_matrix:
                existing.impact_matrix = impact_matrix
            if validation_status:
                existing.validation_status = validation_status
                existing.confidence = str(confidence)
            if cvss_score:
                existing.cvss_score = cvss_score
            if evidence_level and existing.evidence_level in ("E0", "E1") and evidence_level in ("E2", "E3", "E4"):
                existing.evidence_level = evidence_level
            if evidence_score > (existing.evidence_score or 0):
                existing.evidence_score = evidence_score
            if exploitability_state:
                existing.exploitability_state = exploitability_state
            if priority:
                existing.priority = priority
            return existing

        count = (await db.execute(
            select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
        )).scalar() or 0
        finding_code = f"BH-{count + 1:03d}"

        finding = Finding(
            scan_id=scan_id,
            asset_id=asset_id,
            finding_code=finding_code,
            finding_type=finding_type,
            title=clean_title,
            severity=severity,
            confidence=str(confidence),
            evidence_level=evidence_level,
            evidence_score=evidence_score,
            exploitability_state=exploitability_state,
            priority=priority,
            rule_version=rule_version,
            impact_matrix=impact_matrix or {},
            validation_status=validation_status,
            root_cause=clean_root,
            preconditions=preconditions or [],
            expected_result=clean_exp,
            actual_result=clean_act,
            executive_explanation=clean_exec,
            business_impact=clean_biz,
            cwe_id=cwe_id,
            cve_id=cve_id,
            cvss_score=cvss_score,
            dedup_key=dedup_key,
            description=clean_desc,
            impact=clean_impact,
            technical_details=clean_tech,
            remediation=clean_remed,
            evidence=clean_ev,
            reproducibility_meta=reproducibility_meta or {},
            status=status,
        )
        db.add(finding)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return None
        return finding

    async def upsert_observation(
        self,
        db: AsyncSession,
        *,
        scan_id: str,
        asset_id: Optional[str],
        observation_type: str,
        title: str,
        evidence: dict | None = None,
        confidence: float = 0.5,
        **kwargs: Any,
    ) -> Observation | None:
        clean_title = sanitize_text(title)
        clean_ev = sanitize_text(evidence or {})
        existing = (await db.execute(
            select(Observation).where(
                Observation.scan_id == scan_id,
                Observation.asset_id == asset_id,
                Observation.observation_type == observation_type,
                Observation.title == clean_title,
            )
        )).scalar_one_or_none()
        if existing:
            return existing
        obs = Observation(
            scan_id=scan_id,
            asset_id=asset_id,
            observation_type=observation_type,
            title=clean_title,
            evidence=clean_ev,
            confidence=confidence,
        )
        db.add(obs)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            return None
        return obs

    async def audit(
        self,
        db: AsyncSession,
        scan_id: str,
        action: str,
        actor: str = "system",
        target: str | None = None,
        details: dict | None = None,
    ):
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
