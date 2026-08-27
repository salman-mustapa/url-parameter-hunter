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


@pytest.mark.anyio
async def test_investigation_workspace_and_export_lifecycle():
    """Verify the full end-to-end lifecycle for Workspace, Async Exports, and Admin Controls."""
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

            token = create_access_token(admin.id, admin.username, admin.role)
            headers = {"Authorization": f"Bearer {token}"}

            scan = Scan(
                id=scan_id,
                user_id=admin.id,
                root_domain=target,
                status="running",
                profile="autonomous",
                options={"target_url": f"https://{target}", "validation_level": "L4_HIGH_RISK"},
                started_at=datetime.now(timezone.utc),
                progress={"assets": 1, "ports": 2, "urls": 2, "findings": 2, "artifacts": 1},
            )
            db.add(scan)

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

        # Verify Bug Hunting PoC Structure
        finding_item = ws["findings"][0]
        assert "poc_dossier" in finding_item
        assert "python_poc" in finding_item
        assert "reproduction_steps" in finding_item
        assert len(finding_item["reproduction_steps"]) >= 1
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
        for fmt in ["findings_csv", "investigation_json", "assets_csv", "services_csv", "evidence_index_json", "artifact_manifest_json"]:
            res_exp = await client.post(f"/api/scans/{scan_id}/export/{fmt}", headers=headers)
            assert res_exp.status_code == 200
            job = res_exp.json()
            assert job["format"] == fmt
            assert job["status"] in ["QUEUED", "PROCESSING", "COMPLETED"]

        # 6. Test Exports List
        res_job_list = await client.get(f"/api/scans/{scan_id}/exports", headers=headers)
        assert res_job_list.status_code == 200
        jobs = res_job_list.json()
        assert len(jobs) >= 1

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

