import pytest
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone
import uuid
from sqlalchemy import select

from app.main import app
from app.core.db import AsyncSessionLocal
from app.models.models import Scan, ScanEvent, Asset, Port, Service, URL, Finding, Technology
from app.core.auth import create_access_token

@pytest.mark.anyio
async def test_full_platform_api_workflows():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as async_client:
        # 1. Setup seeded test scan and assets in DB
        scan_id = f"test_e2e_{uuid.uuid4().hex[:8]}"
        asset_id = f"asset_{uuid.uuid4().hex[:8]}"
        target_host = "testtarget.local"
        target_ip = "192.168.100.50"

        async with AsyncSessionLocal() as db:
            from app.models.models import User
            admin_user = (await db.execute(select(User).where(User.username == "admin"))).scalars().first()
            if not admin_user:
                admin_user = User(
                    id="admin_user_id",
                    username="admin",
                    email="admin@test.local",
                    hashed_password="hash",
                    role="admin",
                    is_active=True
                )
                db.add(admin_user)
                await db.flush()

            token = create_access_token(admin_user.id, admin_user.username, admin_user.role)
            auth_headers = {"Authorization": f"Bearer {token}"}

            scan = Scan(
                id=scan_id,
                user_id=admin_user.id,
                root_domain=target_host,
                status="running",
                profile="deep",
                options={"target_url": f"https://{target_host}", "target_host": target_host},
                started_at=datetime.now(timezone.utc),
                progress={"assets": 1, "ports": 2, "urls": 1, "findings": 1}
            )
            db.add(scan)
            
            asset = Asset(
                id=asset_id,
                scan_id=scan_id,
                hostname=target_host,
                fqdn=target_host,
                ip=target_ip,
                asset_type="subdomain",
                fingerprint=f"subdomain:{target_host}",
                status="ACTIVE",
                metadata_={"active": True}
            )
            db.add(asset)

            port1 = Port(id=f"p1_{uuid.uuid4().hex[:6]}", asset_id=asset_id, port=80, protocol="tcp", state="open", service="http")
            port2 = Port(id=f"p2_{uuid.uuid4().hex[:6]}", asset_id=asset_id, port=443, protocol="tcp", state="open", service="https")
            db.add_all([port1, port2])

            url_obj = URL(id=f"u1_{uuid.uuid4().hex[:6]}", asset_id=asset_id, url=f"https://{target_host}/api/v1/user", scheme="https", host=target_host, path="/api/v1/user", status_code=200)
            db.add(url_obj)

            tech = Technology(id=f"t1_{uuid.uuid4().hex[:6]}", asset_id=asset_id, name="Nginx", version="1.24.0", category="Web Server")
            db.add(tech)

            finding = Finding(
                id=f"f1_{uuid.uuid4().hex[:6]}",
                scan_id=scan_id,
                asset_id=asset_id,
                finding_type="sql_injection",
                title="SQL Injection in user parameter",
                severity="HIGH",
                cwe_id="CWE-89",
                cvss_score=8.5,
                status="CONFIRMED",
                technical_details=f"https://{target_host}/api/v1/user?id=1",
                evidence={"type": "SQLI_POC", "url": f"https://{target_host}/api/v1/user?id=1", "sha256": "abcdef123456"}
            )
            db.add(finding)
            await db.commit()

        # 2. Test GET /api/scans
        res = await async_client.get("/api/scans", headers=auth_headers)
        assert res.status_code == 200
        scans = res.json()
        assert any(s["id"] == scan_id for s in scans)

        # 3. Test GET /api/scans/{scan_id}
        res = await async_client.get(f"/api/scans/{scan_id}", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == scan_id
        assert data["root_domain"] == target_host

        # 4. Test Pause, Resume, Stop scan controls
        res = await async_client.post(f"/api/scans/{scan_id}/pause", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["status"] == "paused"

        res = await async_client.post(f"/api/scans/{scan_id}/resume", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["status"] == "resumed"

        res = await async_client.post(f"/api/scans/{scan_id}/stop", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["status"] == "stopped"

        # 5. Test Asset Lookup by ID, IP, and Hostname
        res = await async_client.get(f"/api/assets/{asset_id}", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["hostname"] == target_host
        assert len(res.json()["ports"]) == 2

        # Lookup by IP
        res_ip = await async_client.get(f"/api/assets/{target_ip}", headers=auth_headers)
        assert res_ip.status_code == 200
        assert res_ip.json()["hostname"] == target_host

        # Lookup by Hostname
        res_host = await async_client.get(f"/api/assets/{target_host}", headers=auth_headers)
        assert res_host.status_code == 200
        assert res_host.json()["ip"] == target_ip

        # 6. Test Domain Summary & Detail
        res_domains = await async_client.get("/api/domains", headers=auth_headers)
        assert res_domains.status_code == 200

        res_domain_detail = await async_client.get(f"/api/domains/{target_host}", headers=auth_headers)
        assert res_domain_detail.status_code == 200
        d_data = res_domain_detail.json()
        assert d_data["root_domain"] == target_host
        assert d_data["total_ports"] >= 2

        # 7. Test AI Graph, Hypotheses & State Machine
        res_tree = await async_client.get(f"/api/assets/tree?scan_id={scan_id}", headers=auth_headers)
        assert res_tree.status_code == 200

        res_hypo = await async_client.get(f"/api/scans/{scan_id}/hypotheses", headers=auth_headers)
        assert res_hypo.status_code == 200

        res_plans = await async_client.get(f"/api/scans/{scan_id}/attack-plans", headers=auth_headers)
        assert res_plans.status_code == 200

        res_sm = await async_client.get(f"/api/scans/{scan_id}/state-machine", headers=auth_headers)
        assert res_sm.status_code == 200

        # 8. Test Global Search
        res_search = await async_client.get(f"/api/search?q={target_host}", headers=auth_headers)
        assert res_search.status_code == 200

        # 9. Test Report Downloads (Markdown, JSON, HTML, PDF)
        for fmt in ["json", "markdown", "html", "pdf"]:
            res_rep = await async_client.get(f"/api/scans/{scan_id}/report/{fmt}", headers=auth_headers)
            assert res_rep.status_code == 200

        # 10. Clean up test scan
        res_del = await async_client.delete(f"/api/scans/{scan_id}", headers=auth_headers)
        assert res_del.status_code == 200
