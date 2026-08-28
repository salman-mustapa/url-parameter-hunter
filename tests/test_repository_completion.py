"""Completion gates using real SQLite constraints, HTTP fixtures and persistence."""

import asyncio
import logging
import uuid

import httpx
import pytest
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError

from app.core.db import AsyncSessionLocal, engine, init_db
from app.core.events import event_bus
from app.core.logging import RedactingFormatter
from app.main import app
from app.models.models import Asset, Evidence, EvidencePackage, Finding, Scan, ScanEvent, User
from app.services.results import ResultService, result_service


async def account(role="admin"):
    from app.core.auth import create_access_token
    suffix = uuid.uuid4().hex
    async with AsyncSessionLocal() as db:
        user = User(username=suffix, email=f"{suffix}@example.invalid",
                    hashed_password="synthetic-hash", role=role)
        db.add(user)
        await db.commit()
    return user, {"Authorization": "Bearer " + create_access_token(
        user.id, user.username, user.role, password_hash=user.hashed_password)}


@pytest.mark.anyio
async def test_migrations_are_idempotent_and_constraints_enforced():
    await init_db()
    await init_db()
    async with engine.connect() as connection:
        assert (await connection.execute(text("PRAGMA foreign_keys"))).scalar() == 1
        assert (await connection.execute(text("SELECT count(*) FROM schema_migrations"))).scalar() == 1
        indexes = await connection.run_sync(lambda sync: inspect(sync).get_indexes("scans"))
        assert "ix_scans_user_id" in {index["name"] for index in indexes}
    async with AsyncSessionLocal() as db:
        db.add(Asset(scan_id="missing-parent", asset_type="domain", fingerprint="orphan"))
        with pytest.raises(IntegrityError):
            await db.commit()
        await db.rollback()


@pytest.mark.anyio
async def test_full_real_lab_api_evidence_report_and_delete():
    _, headers = await account()
    event_bus.set_persister(result_service.persist_event)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver",
                                    headers=headers, timeout=30) as client:
            run = await client.post("/api/labs/synthetic/run")
            assert run.status_code == 200, run.text
            report = run.json()
            assert report["status"] == "CONFIRMED"
            scan_id, finding_id = report["scan_id"], report["finding_ids"][0]
            assert report["request_count"] <= 80
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                finding = await db.get(Finding, finding_id)
                assert scan.status == "completed" and scan.completed_at
                assert finding.validation_status == "CONFIRMED"
                assert (await db.execute(select(func.count()).select_from(Evidence).where(Evidence.scan_id == scan_id))).scalar() >= 4
                package = (await db.execute(select(EvidencePackage).where(EvidencePackage.finding_id == finding_id))).scalar_one()
                assert package.validation_data["evidence_ids"]
                events = (await db.execute(select(ScanEvent.event_type).where(ScanEvent.scan_id == scan_id))).scalars().all()
                assert set(events) >= {"lab.queued", "lab.running", "lab.discovery", "lab.validating", "lab.finding", "lab.completed"}
            for path in (f"/api/scans/{scan_id}", f"/api/scans/{scan_id}/workspace",
                         f"/api/findings/{finding_id}/evidence-package", report["report_url"],
                         f"/api/scans/{scan_id}/report/html", f"/api/scans/{scan_id}/report/json"):
                response = await client.get(path)
                assert response.status_code == 200, (path, response.text)
            assert (await client.delete(f"/api/scans/{scan_id}")).status_code == 200
            async with AsyncSessionLocal() as db:
                assert await db.get(Finding, finding_id) is None
                assert (await db.execute(select(func.count()).select_from(Evidence).where(Evidence.scan_id == scan_id))).scalar() == 0
                assert await db.get(EvidencePackage, package.id) is None
    finally:
        await result_service.close()
        event_bus.set_persister(None)


@pytest.mark.anyio
async def test_manual_patch_cannot_mint_validation_and_bad_json_is_422():
    user, headers = await account("user")
    async with AsyncSessionLocal() as db:
        scan = Scan(user_id=user.id, root_domain="example.invalid")
        db.add(scan)
        await db.flush()
        finding = Finding(scan_id=scan.id, title="Observed only", finding_type="sqli", status="OPEN")
        db.add(finding)
        await db.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver", headers=headers) as client:
        for state in ("CONFIRMED", "VALIDATED", "invented"):
            assert (await client.patch(f"/api/findings/{finding.id}", params={"status": state})).status_code == 400
        assert (await client.patch(f"/api/findings/{finding.id}", params={"status": "TRIAGED"})).status_code == 200
        for path in ("/api/ai/hypotheses", "/api/ai/review-evidence", "/api/attack-graph/simulate-pivot"):
            assert (await client.post(path, content=b'{broken', headers={"Content-Type": "application/json"})).status_code == 422
        assert (await client.post("/api/labs/synthetic/run")).status_code == 403


@pytest.mark.anyio
async def test_event_drain_waits_for_commit_and_failures_are_visible(monkeypatch):
    service = ResultService()
    started, release = asyncio.Event(), asyncio.Event()
    committed = []

    async def flush(batch):
        started.set()
        await release.wait()
        committed.extend(batch)

    monkeypatch.setattr(service, "_flush_batch", flush)
    await service.persist_event({"scan_id": "synthetic", "event_type": "test"})
    await started.wait()
    draining = asyncio.create_task(service.drain())
    await asyncio.sleep(0)
    assert not draining.done()
    release.set()
    await draining
    assert len(committed) == 1
    await service.close()

    async def failure(batch):
        raise RuntimeError("synthetic database outage")

    service = ResultService()
    monkeypatch.setattr(service, "_flush_batch", failure)
    await service.persist_event({"scan_id": "synthetic"})
    with pytest.raises(RuntimeError, match="could not be persisted"):
        await service.drain()
    service._failed_events = 0  # Acknowledge the deliberately injected failure for cleanup.
    await service.close()


def test_logs_redact_credentials_and_ai_rejects_unexecutable_tests():
    record = logging.LogRecord("test", logging.ERROR, "", 1,
                               "redis://user:synthetic-password@localhost token=synthetic-token", (), None)
    rendered = RedactingFormatter().format(record)
    assert "synthetic-password" not in rendered and "synthetic-token" not in rendered
    from app.ai.evidence_reasoning import EvidenceReasoner, ReasoningInput
    payload = ReasoningInput(evidence=[{"id": "e1", "observation": "HTTP response"}])
    with pytest.raises(ValueError, match="not executable"):
        EvidenceReasoner.validate_output(payload, {
            "hypotheses": [], "recommended_tests": ["invented_shell_action"],
            "required_evidence": [], "confidence": 0.1, "reasoning": "hypothesis only",
            "evidence_ids": ["e1"],
        })
