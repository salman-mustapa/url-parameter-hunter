"""Comprehensive Integration & Unit Test Suite for Autonomous Multi-Stage Attack Chaining Architecture.

Validates the full 7-stage lifecycle:
1. Reconnaissance / Database Artifact Exposure
2. Data-to-Input Action Correlation (semantic field matching & date permutations)
3. Controlled Stateful Authentication & Session Acquisition
4. Differential Authenticated Surface Crawling (Delta Surface)
5. File Upload Security Assessment & Non-Destructive Canary Generation
6. Safe Execution Verification Probing (MD5 Echo Validation)
7. Multi-Node Attack Path Lineage Graph & Unified Bounty Report Generation
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pytest
from typing import Any, Dict, List

from app.attacks.auth.module import AuthAttackModule
from app.attacks.upload.module import UploadAttackModule
from app.core.events import event_bus
from app.core.session_context import SessionContext, SessionIdentity
from app.discovery.authenticated_crawler import AuthenticatedCrawlerEngine, authenticated_crawler
from app.orchestration.attack_opportunity import AttackOpportunity, opportunity_bus
from app.orchestration.attack_path_engine import AttackPathEngine, AttackPathStage, attack_path_engine
from app.orchestration.data_action_correlator import DataToInputActionCorrelator, data_action_correlator
from app.reporting.bounty_template import BugBountyReportGenerator, bug_bounty_generator


# =========================================================================
# 1. Unit Tests for DataToInputActionCorrelator
# =========================================================================
class TestDataActionCorrelator:
    def test_date_permutations(self):
        """Verify Indonesian date permutations from standard YYYY-MM-DD."""
        raw_date = "1998-05-12"
        perms = DataToInputActionCorrelator.generate_date_permutations(raw_date)

        assert "1998-05-12" in perms
        assert "12-05-1998" in perms
        assert "12051998" in perms
        assert "19980512" in perms
        assert "12/05/1998" in perms
        assert len(perms) >= 5

    def test_semantic_field_recognition(self):
        """Verify semantic identification for student/user identifiers and secrets."""
        assert DataToInputActionCorrelator.is_identity_field("nim")
        assert DataToInputActionCorrelator.is_identity_field("nip")
        assert DataToInputActionCorrelator.is_identity_field("username")
        assert DataToInputActionCorrelator.is_identity_field("user_email")

        assert DataToInputActionCorrelator.is_secret_field("tanggal_lahir")
        assert DataToInputActionCorrelator.is_secret_field("tgl_lahir")
        assert DataToInputActionCorrelator.is_secret_field("password")
        assert DataToInputActionCorrelator.is_secret_field("dob")

    def test_form_and_table_correlation(self):
        """Verify table m_mahasiswa with (nim, tanggal_lahir) matches login form."""
        html_login = """
        <form action="/login" method="POST">
            <input type="text" name="nim" placeholder="Nomor Induk Mahasiswa">
            <input type="password" name="tanggal_lahir" placeholder="Tanggal Lahir">
            <input type="hidden" name="csrf_token" value="abc123token">
            <input type="submit" value="Login">
        </form>
        """
        forms = DataToInputActionCorrelator.extract_form_inputs_from_html(html_login, base_url="http://testapp.local")
        assert len(forms) == 1
        assert forms[0]["action"] == "http://testapp.local/login"

        sample_tables = [
            {
                "name": "m_mahasiswa",
                "columns": [{"name": "id"}, {"name": "nim"}, {"name": "nama"}, {"name": "tanggal_lahir"}],
                "sample_records": [
                    {"id": 1, "nim": "531420001", "nama": "Ahmad", "tanggal_lahir": "1998-05-12"},
                    {"id": 2, "nim": "531420002", "nama": "Budi", "tanggal_lahir": "1999-10-24"},
                ],
            }
        ]

        hypotheses = data_action_correlator.correlate_artifact_data_to_forms(
            forms=forms,
            tables=sample_tables,
            target_url="http://testapp.local/login",
        )

        assert len(hypotheses) == 1
        hypo = hypotheses[0]
        assert hypo.endpoint == "http://testapp.local/login"
        assert "nim" in hypo.field_mapping
        assert "tanggal_lahir" in hypo.field_mapping
        assert len(hypo.candidates) >= 2

        # Convert to opportunity
        opp = hypo.to_attack_opportunity(priority=98)
        assert opp.attack_type == "auth"
        assert opp.priority == 98
        assert len(opp.metadata["credentials"]) >= 2


# =========================================================================
# 2. Unit Tests for AuthAttackModule with Multi-Field Credentials
# =========================================================================
class TestAuthAttackModule:
    @pytest.mark.anyio
    async def test_auth_validation_success_and_event_emission(self, monkeypatch):
        auth_module = AuthAttackModule()
        session = SessionContext(base_url="http://testapp.local")

        # Mock GET form response
        form_html = """
        <form action="/login" method="POST">
            <input type="text" name="nim">
            <input type="password" name="tanggal_lahir">
        </form>
        """
        async def mock_get(url, **kwargs):
            from app.core.session_context import NetworkClassification, SessionResponse
            return SessionResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                text=form_html,
                content=form_html.encode(),
                url=url,
                elapsed_ms=10.0,
                classification=NetworkClassification.SUCCESS,
            )

        # Mock POST auth response (Redirect to /dashboard with session cookie)
        async def mock_post(url, data=None, **kwargs):
            from app.core.session_context import NetworkClassification, SessionResponse
            if data and data.get("nim") == "531420001" and data.get("tanggal_lahir") in ("1998-05-12", "12-05-1998"):
                return SessionResponse(
                    status_code=302,
                    headers={"location": "/dashboard", "set-cookie": "PHPSESSID=auth_token_secret_123"},
                    text="Redirecting to Dashboard...",
                    content=b"Redirecting to Dashboard...",
                    url=url,
                    elapsed_ms=15.0,
                    classification=NetworkClassification.SUCCESS,
                )
            return SessionResponse(
                status_code=200,
                headers={},
                text="Gagal login: data tidak cocok.",
                content=b"Gagal login",
                url=url,
                elapsed_ms=15.0,
                classification=NetworkClassification.SUCCESS,
            )

        monkeypatch.setattr(session, "get", mock_get)
        monkeypatch.setattr(session, "post", mock_post)

        received_events = []
        async def event_collector(event_data):
            received_events.append(event_data)
        event_bus.subscribe("AuthenticationSucceeded", event_collector)

        opp = AttackOpportunity(
            target="http://testapp.local/login",
            endpoint="http://testapp.local/login",
            attack_type="auth",
            metadata={
                "credentials": [
                    {"nim": "531420001", "tanggal_lahir": "1998-05-12"},
                    {"nim": "531420002", "tanggal_lahir": "1999-10-24"},
                ]
            },
        )

        result = await auth_module.validate(opp, session)
        assert result.is_vulnerable is True
        assert result.severity in ("HIGH", "CRITICAL")
        assert result.confidence >= 0.95
        assert result.evidence["valid_credentials"]["nim"] == "531420001"
        assert session.has_authenticated_session() is True

        # Check event published
        await asyncio.sleep(0.05)
        assert any(ev.get("type") == "AuthenticationSucceeded" for ev in received_events)


# =========================================================================
# 3. Unit Tests for AuthenticatedCrawlerEngine & Surface Differencing
# =========================================================================
class TestAuthenticatedCrawler:
    @pytest.mark.anyio
    async def test_crawler_differential_surface_and_upload_discovery(self, monkeypatch):
        crawler = AuthenticatedCrawlerEngine()
        crawler.register_unauthenticated_url("http://testapp.local/login")
        crawler.register_unauthenticated_url("http://testapp.local/")

        session = SessionContext(base_url="http://testapp.local")
        session.register_identity(
            SessionIdentity(
                id="authenticated_session",
                name="Student",
                role="user",
                cookies={"PHPSESSID": "valid_token"},
            )
        )
        session.switch_identity("authenticated_session")

        # Mock dashboard containing link to /kuesioner and upload form
        dashboard_html = """
        <html>
            <body>
                <h1>Welcome, Mahasiswa!</h1>
                <a href="/kuesioner">Isi Kuesioner</a>
                <a href="/profile">Lihat Profil</a>
            </body>
        </html>
        """
        kuesioner_html = """
        <html>
            <body>
                <h2>Upload Berkas Skripsi</h2>
                <form action="/kuesioner/upload" method="POST" enctype="multipart/form-data">
                    <input type="file" name="berkas_file" accept=".pdf,.doc">
                    <input type="text" name="judul" value="Skripsi Final">
                    <input type="submit" value="Upload">
                </form>
            </body>
        </html>
        """

        async def mock_get(url, **kwargs):
            from app.core.session_context import NetworkClassification, SessionResponse
            text = ""
            if "kuesioner" in url:
                text = kuesioner_html
            else:
                text = dashboard_html
            return SessionResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                text=text,
                content=text.encode(),
                url=url,
                elapsed_ms=10.0,
                classification=NetworkClassification.SUCCESS,
            )

        monkeypatch.setattr(session, "get", mock_get)

        endpoints = await crawler.crawl_authenticated_surface(
            session=session,
            base_url="http://testapp.local",
            start_urls=["http://testapp.local/dashboard"],
            max_depth=2,
            max_pages=10,
        )

        assert len(endpoints) >= 2
        delta = crawler.get_delta_surface()
        assert len(delta) >= 1

        # Check second-stage opportunities generated
        opps = crawler.generate_second_stage_opportunities(endpoints)
        upload_opps = [o for o in opps if o.attack_type == "upload"]
        assert len(upload_opps) >= 1
        assert upload_opps[0].priority >= 90


# =========================================================================
# 4. Unit Tests for FileUploadSecurityEngine (Benign Canary & RCE Proof)
# =========================================================================
class TestUploadAttackModule:
    @pytest.mark.anyio
    async def test_canary_generation_and_execution_verification(self, monkeypatch):
        upload_module = UploadAttackModule()
        session = SessionContext(base_url="http://testapp.local")

        canary_name, canary_token, val_hash, code = upload_module.generate_canary()
        assert "BH_CANARY" in canary_token
        assert val_hash == hashlib.md5(f"VALIDATE_{canary_token}".encode()).hexdigest()
        assert val_hash in hashlib.md5(f"VALIDATE_{canary_token}".encode()).hexdigest()

        # Mock GET form
        async def mock_get(url, **kwargs):
            from app.core.session_context import NetworkClassification, SessionResponse
            # If probing uploaded canary, return the executed MD5 hash!
            if "canary" in url:
                return SessionResponse(
                    status_code=200,
                    headers={"content-type": "text/html"},
                    text=val_hash,  # Server executed the PHP script!
                    content=val_hash.encode(),
                    url=url,
                    elapsed_ms=5.0,
                    classification=NetworkClassification.SUCCESS,
                )
            return SessionResponse(
                status_code=200,
                headers={"content-type": "text/html"},
                text='<form action="/upload" method="POST" enctype="multipart/form-data"><input type="file" name="file"></form>',
                content=b"form",
                url=url,
                elapsed_ms=5.0,
                classification=NetworkClassification.SUCCESS,
            )

        # Mock POST upload
        async def mock_request(method, url, files=None, **kwargs):
            from app.core.session_context import NetworkClassification, SessionResponse
            if method.upper() == "POST" and files:
                fn = next(iter(files.values()))[0]
                resp_body = json.dumps({"status": "success", "url": f"/uploads/{fn}"})
                return SessionResponse(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=resp_body,
                    content=resp_body.encode(),
                    url=url,
                    elapsed_ms=12.0,
                    classification=NetworkClassification.SUCCESS,
                )
            return await mock_get(url, **kwargs)

        monkeypatch.setattr(session, "get", mock_get)
        monkeypatch.setattr(session, "request", mock_request)

        # Ensure generator returns predictable canary for test
        monkeypatch.setattr(upload_module, "generate_canary", lambda: (canary_name, canary_token, val_hash, code))

        opp = AttackOpportunity(
            target="http://testapp.local/upload",
            endpoint="http://testapp.local/upload",
            attack_type="upload",
        )

        val_result = await upload_module.validate(opp, session)
        assert val_result.is_vulnerable is True
        assert val_result.severity == "CRITICAL"
        assert val_result.evidence["execution_confirmed"] is True
        assert val_result.evidence["validation_hash"] == val_hash
        assert "curl" in val_result.poc_curl


# =========================================================================
# 5. Unit Tests for AttackPathEngine & Chained Bounty Reporting
# =========================================================================
class TestAttackPathAndReporting:
    def test_build_autonomous_attack_chain_and_mermaid(self):
        chain = attack_path_engine.build_autonomous_attack_chain(
            target="http://testapp.local",
            stages_data={
                "database_artifact": "skpi_trc.sql",
                "matched_fields": "nim + tanggal_lahir",
                "user_identity": "531420001",
                "upload_endpoint": "http://testapp.local/kuesioner/upload",
                "canary_file": "canary.phtml",
                "rce_url": "http://testapp.local/uploads/canary.phtml",
            },
        )

        assert chain.total_steps == 7
        assert chain.impact_level == "CRITICAL"
        assert chain.steps[0].stage == AttackPathStage.INITIAL_EXPOSURE
        assert chain.steps[2].stage == AttackPathStage.AUTHENTICATION_VALIDATION
        assert chain.steps[4].stage == AttackPathStage.FILE_UPLOAD_ASSESSMENT
        assert chain.steps[6].stage == AttackPathStage.REMOTE_CODE_EXECUTION

        mermaid = chain.to_mermaid()
        assert "graph TD" in mermaid
        assert "Step 1:" in mermaid
        assert "Step 7:" in mermaid

    def test_generate_chained_attack_report(self):
        report_md = bug_bounty_generator.generate_chained_attack_report(
            target="http://testapp.local",
            custom_details={
                "database_artifact": "skpi_trc.sql",
                "user_identity": "531420001",
            },
        )

        assert "# [CRITICAL] Autonomous Multi-Stage Exploit Chain" in report_md
        assert "```mermaid" in report_md
        assert "Stage 1: Database Artifact Exposure" in report_md
        assert "Stage 5 & 6: Safe Benign Canary Upload" in report_md
        assert "Tailored Remediation Playbook" in report_md


# =========================================================================
# 6. Full End-to-End Autonomous Chaining Workflow Test
# =========================================================================
@pytest.mark.anyio
async def test_full_autonomous_attack_chain_e2e(monkeypatch):
    """
    End-to-End test verifying the complete chain:
    Recon Database Discovery -> Data-to-Action Correlation -> Auth Success ->
    Authenticated Spidering -> File Upload Discovery -> Benign Canary Execution -> Unified Report.
    """
    target = "http://university-portal.local"
    session = SessionContext(base_url=target)

    # 1. Simulate Discovered Database Artifact
    sql_tables = [
        {
            "name": "m_mahasiswa",
            "columns": [{"name": "id"}, {"name": "nim"}, {"name": "nama"}, {"name": "tanggal_lahir"}],
            "sample_records": [
                {"id": 1, "nim": "531420001", "nama": "Siswa A", "tanggal_lahir": "1998-05-12"}
            ],
        }
    ]

    # 2. Simulate Target Login Form
    login_html = """
    <form action="/login" method="POST">
        <input type="text" name="nim" placeholder="NIM">
        <input type="password" name="tanggal_lahir" placeholder="Tanggal Lahir (YYYY-MM-DD)">
    </form>
    """
    forms = data_action_correlator.extract_form_inputs_from_html(login_html, base_url=target)
    hypotheses = data_action_correlator.correlate_artifact_data_to_forms(forms=forms, tables=sql_tables, target_url=f"{target}/login")
    assert len(hypotheses) == 1

    auth_opp = hypotheses[0].to_attack_opportunity()

    # 3. Simulate Auth Execution with Server Mock
    dashboard_html = """
    <div>
        <h2>Dashboard Mahasiswa</h2>
        <a href="/kuesioner">Kuesioner Kelulusan</a>
    </div>
    """
    upload_page_html = """
    <form action="/kuesioner/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="attachment_doc">
        <input type="submit" value="Kirim">
    </form>
    """

    canary_token = "BH_CANARY_E2E"
    val_hash = hashlib.md5(f"VALIDATE_{canary_token}".encode()).hexdigest()

    async def mock_get(url, **kwargs):
        from app.core.session_context import NetworkClassification, SessionResponse
        body = ""
        if "/login" in url:
            body = login_html
        elif "/kuesioner/upload" in url:
            body = upload_page_html
        elif "/kuesioner" in url:
            body = upload_page_html
        elif "/dashboard" in url:
            body = dashboard_html
        elif "canary" in url:
            body = val_hash
        return SessionResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            text=body,
            content=body.encode(),
            url=url,
            elapsed_ms=5.0,
            classification=NetworkClassification.SUCCESS,
        )

    async def mock_post(url, data=None, files=None, **kwargs):
        from app.core.session_context import NetworkClassification, SessionResponse
        if "/login" in url:
            return SessionResponse(
                status_code=302,
                headers={"location": "/dashboard", "set-cookie": "PHPSESSID=session_mahasiswa_active"},
                text="Redirecting to Dashboard",
                content=b"Redirecting",
                url=url,
                elapsed_ms=10.0,
                classification=NetworkClassification.SUCCESS,
            )
        elif "/kuesioner/upload" in url and files:
            fn = next(iter(files.values()))[0]
            resp_body = json.dumps({"status": "success", "file_url": f"/uploads/{fn}"})
            return SessionResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                text=resp_body,
                content=resp_body.encode(),
                url=url,
                elapsed_ms=10.0,
                classification=NetworkClassification.SUCCESS,
            )
        return await mock_get(url, **kwargs)

    async def mock_request(method, url, **kwargs):
        if method.upper() == "POST":
            return await mock_post(url, **kwargs)
        return await mock_get(url, **kwargs)

    monkeypatch.setattr(session, "get", mock_get)
    monkeypatch.setattr(session, "post", mock_post)
    monkeypatch.setattr(session, "request", mock_request)

    # 4. Execute Auth Module
    auth_module = AuthAttackModule()
    auth_res = await auth_module.validate(auth_opp, session)
    assert auth_res.is_vulnerable is True
    assert session.has_authenticated_session() is True

    # 5. Launch Authenticated Spidering
    crawler = AuthenticatedCrawlerEngine()
    auth_endpoints = await crawler.crawl_authenticated_surface(
        session=session,
        base_url=target,
        start_urls=[f"{target}/dashboard"],
    )
    second_stage_opps = crawler.generate_second_stage_opportunities(auth_endpoints)
    upload_opps = [o for o in second_stage_opps if o.attack_type == "upload"]
    assert len(upload_opps) >= 1

    # 6. Execute File Upload Security Assessment
    upload_module = UploadAttackModule()
    monkeypatch.setattr(upload_module, "generate_canary", lambda: ("canary_e2e", canary_token, val_hash, f"<?php echo md5('VALIDATE_{canary_token}'); ?>"))
    upload_res = await upload_module.validate(upload_opps[0], session)

    assert upload_res.is_vulnerable is True
    assert upload_res.severity == "CRITICAL"
    assert upload_res.evidence["execution_confirmed"] is True

    # 7. Generate Unified Attack Chain Report
    chain = attack_path_engine.build_autonomous_attack_chain(
        target=target,
        stages_data={
            "database_artifact": "skpi_trc.sql",
            "matched_fields": "nim + tanggal_lahir",
            "user_identity": "531420001",
            "upload_endpoint": f"{target}/kuesioner/upload",
            "canary_file": "canary_e2e.phtml",
            "rce_url": f"{target}/uploads/canary_e2e.phtml",
        }
    )
    assert chain.total_steps == 7
    report = bug_bounty_generator.generate_chained_attack_report(target=target, chain_candidate=chain)
    assert "Autonomous Multi-Stage Exploit Chain" in report
    assert "531420001" in report
