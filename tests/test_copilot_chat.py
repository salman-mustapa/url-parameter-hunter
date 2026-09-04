"""Test suite for Context-Aware AI Copilot Chat Endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.db import AsyncSessionLocal
from app.models.models import Scan, Finding, Asset, Domain, User
from app.core.auth import create_access_token, hash_password
import uuid


@pytest.mark.asyncio
async def test_copilot_chat_general_query():
    """Verify copilot responds intelligently to general offensive security inquiries."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/ai/copilot/chat", json={
            "message": "Bagaimana cara melakukan analisis vektor serangan pada target web?",
            "scan_id": None,
        })
        assert res.status_code == 200
        data = res.json()
        assert "reply" in data
        assert len(data["reply"]) > 20
        assert "source" in data


@pytest.mark.asyncio
async def test_copilot_chat_with_active_scan_context():
    """Verify copilot ingests active scan context (subdomains, ports, findings) into analysis."""
    scan_id = f"scan_copilot_{uuid.uuid4().hex[:8]}"
    root_domain = f"pentest-{uuid.uuid4().hex[:6]}.internal"

    async with AsyncSessionLocal() as db:
        user = User(
            id=f"usr_{uuid.uuid4().hex[:8]}",
            username=f"copilot_{uuid.uuid4().hex[:8]}",
            email=f"copilot_{uuid.uuid4().hex[:8]}@example.invalid",
            hashed_password=hash_password("Copilot-Test-Only-2026!"),
            role="user",
            is_active=True,
        )
        db.add(user)
        await db.flush()
        domain = Domain(id=f"dom_{uuid.uuid4().hex[:8]}", name=root_domain)
        db.add(domain)
        await db.flush()

        scan = Scan(
            id=scan_id,
            user_id=user.id,
            domain_id=domain.id,
            root_domain=root_domain,
            status="running",
            profile="adversary_simulation",
        )
        db.add(scan)
        await db.flush()

        asset = Asset(
            id=f"ast_{uuid.uuid4().hex[:8]}",
            scan_id=scan_id,
            domain_id=domain.id,
            asset_type="subdomain",
            fingerprint=f"fp_{uuid.uuid4().hex[:8]}",
            hostname=f"admin.{root_domain}",
            ip="10.0.0.15",
        )
        db.add(asset)
        await db.flush()

        finding = Finding(
            id=f"fnd_{uuid.uuid4().hex[:8]}",
            scan_id=scan_id,
            domain_id=domain.id,
            asset_id=asset.id,
            finding_type="sqli",
            title="SQL Injection in Admin Search Parameter",
            severity="CRITICAL",
            cwe_id="CWE-89",
            status="CONFIRMED",
        )
        db.add(finding)
        await db.commit()

    token = create_access_token(user.id, user.username, user.role, password_hash=user.hashed_password)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unauthenticated = await client.post("/api/ai/copilot/chat", json={
            "message": "Tampilkan konteks scan",
            "scan_id": scan_id,
        })
        assert unauthenticated.status_code == 401
        res = await client.post("/api/ai/copilot/chat", json={
            "message": "Tolong jelaskan celah SQLi dan rekomendasikan payload verifikasi",
            "scan_id": scan_id,
        }, headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        data = res.json()
        assert "reply" in data
        assert "sql injection" in data["reply"].lower() or "curl" in data["reply"].lower()
        assert "\\n" not in data["reply"]


def test_openapi_operation_ids_are_unique():
    """Every documented operation must have one stable, unique identifier."""
    schema = app.openapi()
    methods = {"get", "post", "put", "patch", "delete", "options", "head"}
    operation_ids = [
        operation["operationId"]
        for path in schema["paths"].values()
        for method, operation in path.items()
        if method in methods and "operationId" in operation
    ]
    assert len(operation_ids) == len(set(operation_ids))
