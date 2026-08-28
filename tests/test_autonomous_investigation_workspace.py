"""Comprehensive Test Suite for Autonomous Engine, Investigation Workspace,
Sensitive Document Classification, Async Exports, and Admin Operations.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from app.main import app
from app.core.db import AsyncSessionLocal
from app.models.models import (
    User, Scan, Asset, Port, Service, URL, Finding, Technology, Artifact, Evidence, ExportJob
)
from app.core.auth import create_access_token
from app.artifacts.engine import DocumentClassifier, ArtifactEngine


def test_document_classifier():
    """Verify automatic classification of sensitive records into correct categories and sensitivity tiers."""
    classifier = DocumentClassifier()

    # 1. Indonesian NIK (16 digits) -> HIGHLY_SENSITIVE, identity_documents
    nik_sample = "NIK: 3201234567890123, Nama: Budi Santoso, Alamat: Jakarta"
    cls, cat, tags = classifier.classify("user_nik.txt", nik_sample)
    assert cls == "HIGHLY_SENSITIVE"
    assert cat == "identity_documents"

    # 2. RSA Private Key -> HIGHLY_SENSITIVE, private_keys
    key_sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    cls, cat, tags = classifier.classify("id_rsa", key_sample)
    assert cls == "HIGHLY_SENSITIVE"
    assert cat == "private_keys"

    # 3. SQL Database Dump with Passwords -> HIGHLY_SENSITIVE, database
    sql_sample = "CREATE TABLE users (id INT PRIMARY KEY, password VARCHAR(255));\nINSERT INTO users VALUES (1, '$2b$12$e...');"
    cls, cat, tags = classifier.classify("backup.sql", sql_sample, "sql_dump")
    assert cls == "HIGHLY_SENSITIVE"
    assert cat == "database"

    # 4. Credentials / Password Leaks -> HIGHLY_SENSITIVE, credentials
    pwd_sample = "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=SuperSecretPass"
    cls, cat, tags = classifier.classify(".env", pwd_sample)
    assert cls == "HIGHLY_SENSITIVE"
    assert cat == "credentials"

    # 5. Public Static File -> PUBLIC, generic
    pub_sample = "<html><body><h1>Hello World</h1></body></html>"
    cls, cat, tags = classifier.classify("index.html", pub_sample)
    assert cls == "PUBLIC"
    assert cat == "generic"


def test_report_dossier_never_fabricates_missing_proof():
    from app.reporting.engine import ReportEngine
    from app.reporting.poc_builder import PocBuilder
    from app.reporting.serializers import finding_quality
    dossier = PocBuilder.generate_dossier(title="Potential SQL injection", finding_type="sqli",
                                         severity="HIGH", target_url="https://example.invalid/search?q=one",
                                         target_host="example.invalid", evidence={})
    assert "Response not captured" in dossier["raw_http_response"]
    assert "200 OK" not in dossier["raw_http_response"]
    assert "vulnerability_demonstrated" not in dossier["raw_http_response"]
    assert dossier["cwe_id"] is None
    assert "VULNERABILITY DEMONSTRATION SUCCESSFUL" not in dossier["python_poc"]
    assert "requests.request(METHOD" in dossier["python_poc"]
    assert finding_quality({"confidence": "CONFIRMED", "evidence_level": "E0"})["confirmed_with_evidence"] is False
    md = ReportEngine.generate_bug_bounty_markdown({"title": "Candidate", "severity": "HIGH"}, "example.invalid")
    assert "NEEDS_REVIEW" in md
    assert "HTTP/1.1 200" not in md
    assert "CWE-200" not in md


def test_export_sanitization_and_spreadsheet_formulas():
    from app.reporting.export_formats import spreadsheet_cell
    from app.reporting.redaction import RedactionEngine
    assert spreadsheet_cell("  =HYPERLINK(\"https://example.invalid\")").startswith("'")
    assert spreadsheet_cell("@SUM(1,2)").startswith("'")
    assert spreadsheet_cell(-42) == -42
    value = RedactionEngine.redact_dict({"headers": {"Authorization": "Bearer secret-value", "Cookie": "session=secret"},
                                        "password": "test-secret", "body": '{"access_token":"secret-token"}'})
    assert "secret" not in str(value)


def test_evidence_hashes_cover_redacted_content_without_invented_observations():
    from app.evidence.package import EvidencePackageBuilder
    package = EvidencePackageBuilder.build_package(
        finding_id="fixture", finding_code="FIXTURE", title="Unverified candidate",
        severity="INFO", confidence="OBSERVED", evidence_level="E0",
        target_host="example.invalid", endpoint_url="https://example.invalid/",
        request_metadata={"headers": {"Authorization": "Bearer fixture-secret"}},
    )
    assert "fixture-secret" not in str(package)
    assert package["response_metadata"] == {}
    assert package["validation"]["observations"] == []
    assert package["timeline"] == []
    assert package["hashes"]["request_metadata_sha256"] == EvidencePackageBuilder.hash_content(package["request_metadata"])


def test_frontend_modals_are_independent_and_ids_unique():
    from pathlib import Path
    from bs4 import BeautifulSoup
    document = BeautifulSoup((Path(__file__).parents[1] / "frontend/index.html").read_text(encoding="utf-8"), "html.parser")
    ids = [node["id"] for node in document.select("[id]")]
    assert len(ids) == len(set(ids))
    for modal in document.select(".modal-backdrop"):
        assert modal.find_parent(class_="modal-backdrop") is None, modal.get("id")


def test_program_scope_and_logo_validation():
    import base64
    import io
    from PIL import Image
    from app.core.engagement import EngagementRules, ReportProfile
    from app.core.scope_engine import ScopeEngine
    scope = ScopeEngine("example.com", scope_hosts=["*.example.com"], excluded_hosts=["critical.example.com"])
    assert scope.host_allowed("app.example.com")
    assert not scope.host_allowed("example.com")
    assert not scope.host_allowed("sub.critical.example.com")
    assert not scope.url_allowed("https://app.example.com:bad/")
    assert not scope.url_allowed("https://user:password@app.example.com/")
    assert not ScopeEngine("example.com", allowed_ports=[443]).url_allowed("http://example.com/")
    assert ScopeEngine("example.com", allowed_ports=[443]).url_allowed("https://example.com/")
    for ports in ([], [0], [65536], [80.5]):
        with pytest.raises(ValueError):
            EngagementRules(authorization_reference="EXAMPLE", authorization_acknowledged=True, allowed_ports=ports)
    rules = EngagementRules(authorization_reference="EXAMPLE", authorization_acknowledged=True, allowed_ports=[443, 80, 443])
    assert rules.allowed_ports == [80, 443]
    with pytest.raises(ValueError):
        EngagementRules(authorization_reference="EXAMPLE", authorization_acknowledged=False)
    with pytest.raises(ValueError):
        EngagementRules(authorization_reference="EXAMPLE", authorization_acknowledged=True, ends_at="2026-01-01T00:00:00")
    for logo in ("https://example.com/logo.png", "data:image/svg+xml;base64,AAA", "data:image/png;base64,AAAA"):
        with pytest.raises(ValueError):
            ReportProfile(logo_data_url=logo)
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), "blue").save(buf, "PNG")
    profile = ReportProfile(logo_data_url="data:image/png;base64," + base64.b64encode(buf.getvalue()).decode())
    assert profile.logo_data_url.startswith("data:image/png;base64,")


def test_storage_containment_and_windows_device_prefix(tmp_path):
    from pathlib import Path
    from app.core.paths import contained_path, _ordinary_path
    assert contained_path(tmp_path / "reports" / "report.pdf", tmp_path).name == "report.pdf"
    with pytest.raises(ValueError):
        contained_path(tmp_path / ".." / "outside.txt", tmp_path)
    if os.name == "nt":
        assert _ordinary_path(Path(r"\\?\C:\reports\test.pdf")) == Path(r"C:\reports\test.pdf")
        assert _ordinary_path(Path(r"\\?\UNC\server\share\test.pdf")) == Path(r"\\server\share\test.pdf")


@pytest.mark.anyio
async def test_scan_slots_serialize_same_domain_and_bound_parallelism(monkeypatch):
    import asyncio
    from app.core.config import settings
    from app.services.scan_manager import ScanManager
    monkeypatch.setattr(settings, "max_concurrent_scans", 2)
    manager = ScanManager()
    active, seen, peak = set(), [], 0
    entered = asyncio.Event()
    release = asyncio.Event()
    async def execute(scan_id, domain, profile, options):
        nonlocal peak
        assert domain not in active
        active.add(domain)
        peak = max(peak, len(active))
        seen.append(scan_id)
        if len(active) == 2:
            entered.set()
        await release.wait()
        active.remove(domain)
    monkeypatch.setattr(manager, "_execute_with_timeout", execute)
    tasks = [asyncio.create_task(manager._run_with_timeout(str(i), domain, "bug_hunt", {}))
             for i, domain in enumerate(["one.invalid", "one.invalid", "two.invalid", "three.invalid"])]
    await asyncio.wait_for(entered.wait(), 2)
    assert len(seen) == 2
    release.set()
    await asyncio.wait_for(asyncio.gather(*tasks), 2)
    assert peak == 2 and len(seen) == 4
    assert not manager._active


@pytest.mark.anyio
async def test_opportunity_queues_are_isolated_and_bounded():
    from app.orchestration.attack_opportunity import AttackOpportunity, OpportunityBus
    first = OpportunityBus(use_distributed=False, scan_id="first", max_opportunities=1)
    second = OpportunityBus(use_distributed=False, scan_id="second")
    a = AttackOpportunity(target="https://same.example.invalid/")
    b = AttackOpportunity(target=a.target)
    assert await first.publish(a)
    assert await second.publish(b)
    assert a.fingerprint() != b.fingerprint()
    assert not await first.publish(AttackOpportunity(target="https://extra.example.invalid/"))
    assert not await first.publish(b)
    assert (await first.get_next(timeout=.1)).metadata["scan_id"] == "first"
    assert (await second.get_next(timeout=.1)).metadata["scan_id"] == "second"
    first.task_done()
    second.task_done()


@pytest.mark.anyio
async def test_screenshot_failure_never_substitutes_generated_image(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from app.core.config import settings
    from app.scanners.screenshot import ScreenshotEngine
    monkeypatch.setattr(settings, "browser_capture_enabled", True)
    monkeypatch.setattr(ScreenshotEngine, "_capture_browser", AsyncMock(side_effect=RuntimeError("No browser installed")))
    db = SimpleNamespace(add=lambda _: pytest.fail("No screenshot may be stored after capture failure"))
    ctx = SimpleNamespace(emit=AsyncMock())
    assert await ScreenshotEngine.capture_url(db, "local", None, None, "https://example.invalid/", ctx=ctx) is None
    assert ctx.emit.await_args.args[0] == "screenshot.unavailable"


def test_cve_version_match_is_a_candidate_not_validation():
    from app.intelligence.cve import CveIntelligence
    candidates = CveIntelligence.match_candidates("Apache", "2.4.49")
    assert candidates
    assert all(c["confidence"] == "CANDIDATE" and c["requires_applicability_review"] for c in candidates)
    assert all(c["source_last_verified"] is None and c["references"] for c in candidates)


@pytest.mark.anyio
@pytest.mark.parametrize("raise_error", [False, True])
async def test_retest_missing_response_preserves_status(monkeypatch, raise_error):
    from app.retest import engine as retest_module
    async def unavailable(*args, **kwargs):
        if raise_error:
            raise TimeoutError("fixture timeout")
        return None
    monkeypatch.setattr(retest_module, "fetch_http", unavailable)
    async with AsyncSessionLocal() as db:
        scan = Scan(id=f"retest-{uuid.uuid4().hex}", root_domain="retest.example.invalid", status="completed")
        db.add(scan)
        await db.flush()
        finding = Finding(scan_id=scan.id, finding_type="generic", title="Unreachable fixture",
                          status="OPEN", evidence={"url": "https://retest.example.invalid/"})
        db.add(finding)
        await db.commit()
        result = await retest_module.retest_engine.create_and_execute_retest(db, finding.id)
        assert result["retest_result"] == "INCONCLUSIVE"
        assert result["after_status"] == "OPEN"
        assert result["is_still_vulnerable"] is None


@pytest.mark.anyio
async def test_investigation_workspace_and_export_lifecycle(monkeypatch, tmp_path):
    """Verify the full end-to-end lifecycle for Workspace, Async Exports, and Admin Controls."""
    # Exercise scan creation without starting outbound workers on fixture targets.
    from app.services.scan_manager import scan_manager
    from app.services import export_manager
    import asyncio
    import hashlib
    monkeypatch.setattr(export_manager, "STORAGE_DIR", tmp_path)
    monkeypatch.setattr(scan_manager, "_run", lambda *args, **kwargs: None)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        scan_id = f"inv_{uuid.uuid4().hex[:10]}"
        asset_id = f"asset_{uuid.uuid4().hex[:8]}"
        target = "adversary-test.com"

        admin_user_id = f"adm_{uuid.uuid4().hex[:6]}"

        # Seed Database
        async with AsyncSessionLocal() as db:
            admin = User(
                id=admin_user_id,
                username=f"admin_{uuid.uuid4().hex[:4]}",
                email=f"admin_{uuid.uuid4().hex[:4]}@test.local",
                hashed_password="hash",
                role="admin",
                is_active=True,
            )
            db.add(admin)
            await db.flush()

            token = create_access_token(admin.id, admin.username, admin.role, password_hash=admin.hashed_password)
            headers = {"Authorization": f"Bearer {token}"}

            scan = Scan(
                id=scan_id,
                user_id=admin.id,
                root_domain=target,
                status="running",
                profile="autonomous",
                authorization_reference="LOCAL-MOCK-ONLY",
                options={"target_url": f"https://{target}", "validation_level": "L4_HIGH_RISK"},
                started_at=datetime.now(timezone.utc),
                progress={"assets": 1, "ports": 2, "urls": 2, "findings": 2, "artifacts": 1},
            )
            db.add(scan)
            await db.flush()

            asset = Asset(
                id=asset_id,
                scan_id=scan_id,
                hostname=target,
                fqdn=target,
                ip="10.0.0.99",
                fingerprint=f"domain:{target}",
                asset_type="domain",
                status="ACTIVE",
            )
            db.add(asset)
            await db.flush()

            port_http = Port(id=f"p1_{uuid.uuid4().hex[:6]}", asset_id=asset_id, port=8080, protocol="tcp", state="open", service="http-alt")
            db.add(port_http)
            await db.flush()

            svc = Service(
                id=f"s1_{uuid.uuid4().hex[:6]}",
                asset_id=asset_id,
                port_id=port_http.id,
                name="http-alt",
                product="Apache Tomcat",
                version="9.0.45",
                banner="Apache Tomcat/9.0.45",
                tls_enabled=False,
            )
            db.add(svc)

            u1 = URL(id=f"u1_{uuid.uuid4().hex[:6]}", asset_id=asset_id, url=f"http://{target}:8080/manager/html", scheme="http", host=target, path="/manager/html", status_code=401)
            db.add(u1)


            finding = Finding(
                id=f"f1_{uuid.uuid4().hex[:6]}",
                scan_id=scan_id,
                asset_id=asset_id,
                finding_type="tomcat_auth_bypass",
                title="Apache Tomcat Manager Panel Exposed",
                severity="HIGH",
                confidence="CONFIRMED",
                cwe_id="CWE-306",
                cvss_score=7.5,
                status="CONFIRMED",
                technical_details=f"http://{target}:8080/manager/html",
                evidence={"cve_ids": ["CVE-2020-1938"], "curl": f"curl -i http://{target}:8080/manager/html"},
            )
            db.add(finding)

            evidence_item = Evidence(
                id=f"ev1_{uuid.uuid4().hex[:6]}",
                scan_id=scan_id,
                asset_id=asset_id,
                evidence_type="HTTP_OBSERVATION",
                data={
                    "title": "Tomcat 401 Response Proof",
                    "request_headers": "GET /manager/html HTTP/1.1\r\nHost: adversary-test.local:8080\r\n",
                    "response_status": 401,
                    "response_headers": "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Tomcat Manager Application\"\r\n",
                },
                sha256_hash="abc123def4567890",
            )
            db.add(evidence_item)

            artifact_item = Artifact(
                id=f"art1_{uuid.uuid4().hex[:6]}",
                scan_id=scan_id,
                asset_id=asset_id,
                file_type="csv_export",
                filename="customers_masked.csv",
                storage_path=f"storage/investigations/{scan_id}/extracted/customers_masked.csv",
                size_bytes=1024,
                sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                classification="CONFIDENTIAL",
                category="database_dump",
                record_count=25,
                preview_data={
                    "columns": ["id", "username", "nik", "email"],
                    "rows": [
                        {"id": "1", "username": "admin", "nik": "3201************", "email": "a***@target.com"},
                        {"id": "2", "username": "johndoe", "nik": "3275************", "email": "j***@target.com"},
                    ]
                }
            )
            db.add(artifact_item)
            await db.commit()


        # 1. Test Investigation Workspace Aggregator
        res = await client.get(f"/api/investigations/{scan_id}/workspace", headers=headers)
        assert res.status_code == 200
        ws = res.json()
        assert ws["overview"]["id"] == scan_id
        assert ws["metrics"]["assets_count"] == 1
        assert ws["metrics"]["services_count"] >= 1
        assert len(ws["findings"]) >= 1
        assert len(ws["artifacts"]) >= 1
        assert len(ws["evidence"]) >= 1

        # Test /api/investigations endpoint alias
        res_inv_list = await client.get("/api/investigations", headers=headers)
        assert res_inv_list.status_code == 200
        invs = res_inv_list.json()
        assert isinstance(invs, list)
        assert any(i["id"] == scan_id for i in invs)

        # Test workspace breakdown and metrics fields
        assert "severity_breakdown" in ws["metrics"]
        assert "confidence_breakdown" in ws["metrics"]
        assert "technologies_count" in ws["metrics"]
        assert ws["metrics"]["coverage_percent"] is None
        assert ws["overview"]["counters"]["attack_chains"] == 0

        # Verify Bug Hunting PoC Structure
        finding_item = ws["findings"][0]
        assert "poc_dossier" in finding_item
        assert "python_poc" in finding_item
        assert "reproduction_steps" in finding_item
        assert finding_item["poc_dossier"]["provenance"]["reproduction_steps"] == "review_checklist"
        assert "import requests" in finding_item["python_poc"]
        assert "curl" in finding_item["proof_curl"].lower()

        # 2. Test Dedicated Finding PoC Endpoint
        res_poc = await client.get(f"/api/scans/{scan_id}/findings/{finding.id}/poc", headers=headers)
        assert res_poc.status_code == 200
        poc_data = res_poc.json()
        assert "dossier" in poc_data
        assert poc_data["dossier"]["title"] == finding.title
        assert len(poc_data["dossier"]["reproduction_steps"]) >= 1
        assert "import requests" in poc_data["dossier"]["python_poc"]
        assert "expected_behavior" in poc_data["dossier"]
        assert "actual_behavior" in poc_data["dossier"]

        # 3. Test Artifact Preview API
        res_preview = await client.get(f"/api/scans/{scan_id}/artifacts/{artifact_item.id}/preview", headers=headers)
        assert res_preview.status_code == 200
        preview = res_preview.json()
        assert preview["classification"] == "CONFIDENTIAL"
        assert preview["record_count"] == 25
        assert len(preview["preview_data"]["columns"]) == 4

        # 4. Test Attack Chains Graph Endpoint
        res_chains = await client.get(f"/api/scans/{scan_id}/attack-chains", headers=headers)
        assert res_chains.status_code == 200
        chains = res_chains.json()
        assert "nodes" in chains or isinstance(chains, list)

        # 5. Test Async Export Triggers
        for fmt in export_manager.ExportManager.SUPPORTED_TYPES:
            res_exp = await client.post(f"/api/scans/{scan_id}/export/{fmt}", headers=headers)
            assert res_exp.status_code == 200
            job = res_exp.json()
            assert job["format"] == fmt
            assert job["status"] in ["QUEUED", "PROCESSING", "COMPLETED"]

        await asyncio.wait_for(asyncio.gather(*export_manager.ExportManager._tasks), timeout=60)

        # 6. Test Exports List
        res_job_list = await client.get(f"/api/scans/{scan_id}/exports", headers=headers)
        assert res_job_list.status_code == 200
        jobs = res_job_list.json()
        assert len(jobs) == len(export_manager.ExportManager.SUPPORTED_TYPES)
        for job in jobs:
            assert job["status"] == "COMPLETED", job
            download = await client.get(job["download_url"], headers=headers)
            assert download.status_code == 200
            assert hashlib.sha256(download.content).hexdigest() == job["sha256_hash"]
            if job["export_type"].endswith("_pdf"):
                assert download.content.startswith(b"%PDF-")
            if job["export_type"] == "findings_xlsx":
                assert download.content.startswith(b"PK")
        for action in ("bugbounty", "cve-ready", "reproduction", "remediation-patch"):
            response = await client.get(f"/api/findings/{finding.id}/{action}", headers=headers)
            assert response.status_code == 200, (action, response.text[:200])

        # 7. Test Admin Operational Controls & Health
        res_health = await client.get("/api/admin/system/health", headers=headers)
        assert res_health.status_code == 200
        health = res_health.json()
        assert "cpu_percent" in health
        assert health["status"] in ["accepting", "throttled", "saturated", "HEALTHY"]

        res_active = await client.get("/api/admin/scans/active", headers=headers)
        assert res_active.status_code == 200
        active_list = res_active.json()
        assert any(s["id"] == scan_id for s in active_list)

        # 8. Test Admin Cancel & Retry
        res_cancel = await client.post(f"/api/admin/scans/{scan_id}/cancel", headers=headers)
        assert res_cancel.status_code == 200
        assert res_cancel.json()["status"] == "cancelled"

        res_retry = await client.post(f"/api/admin/scans/{scan_id}/retry", headers=headers)
        assert res_retry.status_code == 200
        new_scan_id = res_retry.json()["new_scan_id"]
        assert new_scan_id is not None
        assert new_scan_id != scan_id
