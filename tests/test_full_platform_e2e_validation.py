import pytest
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone
import uuid
from unittest.mock import AsyncMock
from sqlalchemy import select

from app.main import app
from app.core.db import AsyncSessionLocal
from app.models.models import Scan, ScanEvent, Asset, Port, Service, URL, Finding, Technology
from app.core.auth import create_access_token


async def _access_fixture():
    from app.models.models import User
    suffix = uuid.uuid4().hex[:10]
    users, scans, assets, findings = [], [], [], []
    async with AsyncSessionLocal() as db:
        for role in ("user", "user", "admin"):
            index = len(users)
            user = User(username=f"access_{suffix}_{index}", email=f"{suffix}_{index}@example.invalid", hashed_password="test-hash", role=role)
            db.add(user)
            await db.flush()
            users.append(user)
        for index in range(2):
            scan = Scan(user_id=users[index].id, root_domain=f"access-{suffix}-{index}.example.invalid", status="completed", progress={"assets": 1, "urls": 0})
            db.add(scan)
            await db.flush()
            asset = Asset(scan_id=scan.id, hostname=scan.root_domain, fingerprint=f"access-{suffix}-{index}", asset_type="domain")
            db.add(asset)
            await db.flush()
            finding = Finding(scan_id=scan.id, asset_id=asset.id, title=f"access-finding-{suffix}-{index}", finding_type="test", severity="INFO")
            db.add(finding)
            await db.flush()
            scans.append(scan)
            assets.append(asset)
            findings.append(finding)
        await db.commit()
    headers = [{"Authorization": f"Bearer {create_access_token(u.id, u.username, u.role, password_hash=u.hashed_password)}"} for u in users]
    return users, scans, assets, findings, headers


@pytest.mark.anyio
async def test_api_requires_login_and_contains_static_paths():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        for method, path in [("GET", "/api/scans"), ("POST", "/api/scans"), ("GET", "/api/findings"), ("GET", "/api/scans/unknown/events"), ("POST", "/api/scans/unknown/stop"), ("POST", "/api/ai/settings"), ("GET", "/api/search?q=test")]:
            response = await client.request(method, path)
            assert response.status_code == 401, (path, response.text)
        assert (await client.get("/api/auth/me")).status_code == 200
        for path in ("/%2e%2e%2fpyproject.toml", "/%2e%2e%5c.env"):
            assert (await client.get(path)).status_code == 404
        response = await client.get("/")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"


@pytest.mark.anyio
async def test_resource_ownership_on_reads_controls_search_and_json():
    users, scans, assets, findings, headers = await _access_fixture()
    own, other = scans
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver", headers=headers[0]) as client:
        assert (await client.get(f"/api/scans/{own.id}")).status_code == 200
        for method, path in [
            ("GET", f"/api/scans/{other.id}"), ("POST", f"/api/scans/{other.id}/stop"),
            ("GET", f"/api/scans/{other.id}/events"), ("DELETE", f"/api/scans/{other.id}"),
            ("GET", f"/api/scans/{other.id}/report/html"), ("GET", f"/api/scans/{other.id}/workspace"),
            ("GET", f"/api/assets/{assets[1].id}"), ("GET", f"/api/assets/{assets[1].hostname}"),
            ("GET", f"/api/findings/{findings[1].id}/detail"),
            ("GET", f"/api/findings?scan_id={other.id}"), ("GET", f"/api/assets/tree?scan_id={other.id}"),
            ("GET", f"/api/diff?current={own.id}&previous={other.id}"),
            ("GET", f"/api/scans/{own.id}/findings/{findings[1].id}/poc"),
        ]:
            response = await client.request(method, path)
            assert response.status_code == 404, (path, response.text)
        assert (await client.get(f"/api/assets/{assets[0].hostname}")).json()["id"] == assets[0].id
        response = await client.post("/api/ai/review-evidence", json={"finding_id": findings[1].id})
        assert response.status_code == 404
        response = await client.post("/api/attack-graph/simulate-pivot", json={"scan_id": other.id, "origin_node_id": "x"})
        assert response.status_code == 404
        assert (await client.post("/api/ai/settings", json={})).status_code == 403
        assert (await client.post("/api/labs", json={})).status_code == 403
        assert (await client.get(f"/api/domains/{other.root_domain}")).status_code == 404
        assert other.id not in {row["id"] for row in (await client.get("/api/scans")).json()}
        assert findings[1].id not in {row["id"] for row in (await client.get("/api/findings")).json()}
        results = (await client.get("/api/search?q=access-")).json()
        assert assets[1].id not in {row["id"] for row in results["assets"]}
        assert findings[1].id not in {row["id"] for row in results["findings"]}
        assert (await client.get(f"/api/scans/diff?current={own.id}&previous={own.id}")).status_code == 200
        assert (await client.get("/api/scans?limit=0")).status_code == 422
        assert len((await client.get("/api/scans?limit=1")).json()) <= 1
        # Admin can inspect another operator's scan through the same guard.
        assert (await client.get(f"/api/scans/{other.id}", headers=headers[2])).status_code == 200


@pytest.mark.anyio
async def test_scan_defaults_do_not_escalate_validation(monkeypatch):
    from app.services.scan_manager import scan_manager
    users, scans, assets, findings, headers = await _access_fixture()
    monkeypatch.setattr(scan_manager, "_run", lambda *args: None)
    monkeypatch.setattr("app.services.scan_manager.event_bus.publish", AsyncMock())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver", headers=headers[0]) as client:
        response = await client.post("/api/scans", json={"target": "example.com", "include_subdomains": False, "authorization_reference": "LOCAL-MOCK-ONLY"})
        assert response.status_code == 200, response.text
        assert response.json()["validation_level"] == "L4_HIGH_RISK"
        scan_id = response.json().get("id") or response.json().get("scan_id")
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            assert scan.user_id == users[0].id
            assert scan.options["authorized_high_risk"] is True
            assert scan.options["security_checks"] is True


@pytest.mark.anyio
async def test_engagement_scope_dates_identity_and_queue(monkeypatch):
    from app.services.scan_manager import scan_manager
    from app.core.config import settings
    users, scans, assets, findings, headers = await _access_fixture()
    monkeypatch.setattr(scan_manager, "_run", lambda *args: None)
    monkeypatch.setattr("app.services.scan_manager.event_bus.publish", AsyncMock())
    rules = {"authorization_reference": "LOCAL-TEST-ONLY", "authorization_acknowledged": True,
             "scope_hosts": ["*.example.com"], "excluded_hosts": ["excluded.example.com"],
             "report": {"organization": "Example Agency", "assessor": "Local Tester"}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver", headers=headers[0]) as client:
        assert (await client.post("/api/scans", json={"target": "app.example.com"})).status_code == 200
        for target in ("example.com", "excluded.example.com", "example.com.attacker.invalid", "https://app.example.com:8080", "app.example.com:8080", "https://app.example.com:bad"):
            response = await client.post("/api/scans", json={"target": target, "engagement": rules})
            assert response.status_code == 400, response.text
        response = await client.post("/api/scans", json={"target": "app.example.com", "engagement": {**rules, "ends_at": "2020-01-01T00:00:00Z"}})
        assert response.status_code == 400
        response = await client.post("/api/scans", json={"target": "app.example.com", "engagement": rules})
        assert response.status_code == 200, response.text
        scan_id = response.json().get("id") or response.json().get("scan_id")
        workspace = (await client.get(f"/api/scans/{scan_id}/workspace")).json()
        assert workspace["overview"]["started_at"] is None
        assert workspace["overview"]["duration_seconds"] is None
        context = (await client.get(f"/api/scans/{scan_id}/report-profile")).json()
        assert context["report"]["organization"] == "Example Agency"
        response = await client.put(f"/api/scans/{scan_id}/report-profile", json={"organization": "Updated Agency", "classification": "INTERNAL"})
        assert response.status_code == 200
        assert response.json()["rules"]["excluded_hosts"] == ["excluded.example.com"]
        response = await client.put(f"/api/scans/{scan_id}/report-profile", json={"authorization_reference": "rewrite-history"})
        assert response.status_code == 422
        response = await client.put(f"/api/scans/{scans[1].id}/report-profile", json={"organization": "Unwanted"})
        assert response.status_code == 404
        for kind in ("md", "html", "json"):
            response = await client.get(f"/api/scans/{scan_id}/report/{kind}")
            assert response.status_code == 200, response.text[:200]
            assert "Updated Agency" in response.text
        monkeypatch.setattr(settings, "max_pending_scans", 1)
        response = await client.post("/api/scans", json={"target": "other.example.com", "engagement": rules})
        assert response.status_code == 429
        assert response.headers["retry-after"] == "30"


@pytest.mark.anyio
async def test_http_request_limits_and_cross_origin_rejection():
    transport = ASGITransport(app=app, client=("rate-limit-fixture", 123))
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/api/auth/login", headers={"Origin": "https://untrusted.example"}, json={"username": "none", "password": "none"})
        assert response.status_code == 403
        response = await client.post("/api/auth/login", content=b"x" * 17000)
        assert response.status_code == 413
        for _ in range(21):
            response = await client.post("/api/auth/login", json={"username": "rate-fixture-nonexistent", "password": "invalid"})
        assert response.status_code == 429
        assert response.headers["retry-after"] == "60"


def test_jwt_rejects_malformed_claims_and_fixed_fallback():
    import hashlib
    import hmac
    import json
    import time
    from app.core.auth import SECRET_KEY, _b64_encode, decode_access_token
    assert SECRET_KEY != "development-only-change-me"
    for header, payload in [({"alg": "none"}, {"sub": "x", "exp": time.time() + 60}), ({"alg": "HS256"}, {"sub": "x", "exp": float("nan")}), ({"alg": "HS256"}, {"sub": 42, "exp": time.time() + 60}), ({"alg": "HS256"}, {"sub": "x", "exp": "never"})]:
        message = f"{_b64_encode(json.dumps(header).encode())}.{_b64_encode(json.dumps(payload).encode())}"
        signature = _b64_encode(hmac.new(SECRET_KEY.encode(), message.encode(), hashlib.sha256).digest())
        assert decode_access_token(f"{message}.{signature}") is None


@pytest.mark.anyio
async def test_password_change_revokes_existing_sessions():
    from app.models.models import User
    users, scans, assets, findings, headers = await _access_fixture()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver", headers=headers[0]) as client:
        assert (await client.get("/api/scans")).status_code == 200
        async with AsyncSessionLocal() as db:
            user = await db.get(User, users[0].id)
            user.hashed_password = "changed-test-password-hash"
            await db.commit()
        assert (await client.get("/api/scans")).status_code == 401

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

            token = create_access_token(admin_user.id, admin_user.username, admin_user.role, password_hash=admin_user.hashed_password)
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
            await db.flush()
            
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
            await db.flush()

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
