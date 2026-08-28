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
    async def test_auth_validation_requires_plan_and_does_not_emit_success(self, monkeypatch):
        session = SessionContext(base_url="http://testapp.local")
        opportunity = AttackOpportunity(target="http://testapp.local", endpoint="http://testapp.local/login", attack_type="auth")
        received = []
        async def collect(event):
            received.append(event)
        event_bus.subscribe("AuthenticationSucceeded", collect)
        result = await AuthAttackModule().validate(opportunity, session)
        assert not result.is_vulnerable
        assert not session.has_authenticated_session()
        assert not received


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
    async def test_upload_requires_collected_storage_and_execution_plan(self, monkeypatch):
        module = UploadAttackModule()
        session = SessionContext(base_url="http://testapp.local")
        opportunity = AttackOpportunity(target="http://testapp.local", endpoint="http://testapp.local/upload", attack_type="upload")
        result = await module.validate(opportunity, session)
        assert not result.is_vulnerable
        assert result.proof_level == "P0"
        assert "evidence plan" in result.message


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

        assert "HYPOTHESIS / REQUIRES VALIDATION" in report_md
        assert "```mermaid" in report_md
        assert "No executed chain steps" in report_md
        assert "skpi_trc.sql" in report_md
        assert "Full Remote Code Execution (RCE) confirmed" not in report_md
        assert "Remediation & Validation Follow-up" in report_md


# =========================================================================
# 6. Full End-to-End Autonomous Chaining Workflow Test
# =========================================================================
@pytest.mark.anyio
async def test_full_autonomous_attack_chain_e2e(monkeypatch):
    from app.lab.runtime import local_lab
    from app.lab.workflow import investigate_local_lab
    async with local_lab() as (base, state):
        report = await investigate_local_lab(base, state)
    assert report["status"] == "CONFIRMED"
    assert report["reasoning"]["hypotheses"][0]["kind"] == "HYPOTHESIS"
    assert report["graph"]["edges"][0]["status"] == "TARGET_VALIDATED"
    known = {e["id"] for e in report["evidence"]}
    assert set(report["findings"][0]["evidence_ids"]) <= known
