"""Non-Destructive Security Intelligence & Proof Quality Pipeline (V5 §2-§44).

Implements:
1. Anti-Noise Rules (§44): Filters out soft-404 false-positives and generic errors.
2. Content Signature Validation (§40): Strict fingerprinting for sensitive exposure (.git, .env, .sql, phpinfo).
3. Deep Validation Adapters integration (§38, §39): SQLi, XSS, SSRF, Path Traversal, Open Redirect.
4. Proof Quality Gate (§40) & Cryptographic Evidence Package assembly (§21, §22).
5. Dynamic CVE intelligence and MITRE ATT&CK correlation (§23-§26).
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import AsyncSessionLocal
from app.core.sanitizer import sanitize_text
from app.evidence.package import EvidencePackageBuilder
from app.findings.lifecycle import FindingLifecycle
from app.intelligence.cms import CmsDetector
from app.intelligence.cve import CveIntelligence
from app.intelligence.llm_client import llm_client
from app.intelligence.local_ai import LocalAiEngine
from app.intelligence.secrets import secret_scanner
from app.intelligence.ttp import TtpEngine
from app.models.models import (
    Asset,
    Certificate,
    Evidence,
    EvidencePackage,
    Finding,
    Parameter,
    Port,
    Technology,
    TtpObservation,
    URL,
)
from app.network.rdp import RdpAssessment
from app.network.ssh import SshAssessment
from app.network.tls import TlsAssessment
from app.scanners.base import ScanContext
from app.core.kill_switch import kill_switch_manager
from app.scanners.http import extract_title, fetch_http
from app.scanners.screenshot import ScreenshotEngine
from app.services.results import result_service
from app.validation.auth_bypass import auth_bypass_validator
from app.validation.file_upload import file_upload_validator
from app.validation.idor import idor_validator
from app.validation.open_redirect import open_redirect_validator
from app.validation.path_traversal import path_traversal_validator
from app.validation.quality_gate import ProofQualityGate
from app.validation.rce import rce_validator
from app.validation.result import NormalizedValidationResult
from app.artifacts.engine import ArtifactEngine
from app.validation.sensitive_files import SensitiveFileValidator, soft_404_detector
from app.validation.xss import xss_validator
from app.validation.sqli import sqli_validator
from app.validation.ssrf import ssrf_validator
from app.intelligence.wordpress import WordPressIntelligence
from app.intelligence.agentic import agentic_engine
from app.intelligence.cve_exploiter import cve_exploit_engine
from app.intelligence.cvss4 import cvss4_calculator
from app.validation.bypass_403 import bypass_403_engine
from app.validation.brute_force import controlled_brute_force_validator
from app.validation.info_disclosure import info_disclosure_validator
from app.validation.service_exploiter import service_exploit_validator

logger = logging.getLogger("scanner.security")

SENSITIVE_PATH_DEFINITIONS = [
    {
        "file_type": "env",
        "probe_paths": ["/.env", "/.env.local", "/.env.prod", "/.env.bak", "/.env.old"],
        "finding_type": "env_exposure",
        "title": "Environment Configuration File Exposed (.env)",
        "severity": "CRITICAL",
        "cwe_id": "CWE-200",
        "desc": "File konfigurasi .env terdeteksi dapat diakses publik, memuat credential basis data, API secret, dan token otentikasi internal.",
    },
    {
        "file_type": "backup_sql",
        "probe_paths": [
            "/database/backup.sql", "/database/db.sql", "/database/dump.sql",
            "/database/data.sql", "/database/database.sql", "/database/schema.sql",
            "/database/users.sql", "/database/export.sql", "/backup.sql", "/db.sql",
            "/dump.sql", "/data.sql", "/database.sql", "/backup.dump", "/db.dump"
        ],
        "finding_type": "db_exposure",
        "title": "Database SQL Backup Archive Exposed",
        "severity": "CRITICAL",
        "cwe_id": "CWE-200",
        "desc": "File arsip cadangan basis data (.sql) terdeteksi dapat diakses publik dan diverifikasi memuat skema serta sintaks DDL/DML tabel.",
    },
    {
        "file_type": "csv",
        "probe_paths": [
            "/data.csv", "/export.csv", "/exports.csv", "/users.csv", "/user.csv",
            "/database/data.csv", "/database/export.csv", "/database/users.csv",
            "/backup.csv", "/report.csv", "/accounts.csv", "/customers.csv"
        ],
        "finding_type": "data_exposure",
        "title": "Exposed Tabular CSV / PII Data Export",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "desc": "File ekspor data tabular (.csv) terdeteksi dapat diakses secara publik tanpa otentikasi, memuat rekaman data internal / PII.",
    },
    {
        "file_type": "git_head",
        "probe_paths": ["/.git/HEAD", "/.git/config", "/.git/index"],
        "finding_type": "git_exposure",
        "title": "Git Repository Metadata Exposed (.git)",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "desc": "Direktori repositori .git terbuka ke publik. Metadata Git diverifikasi valid, memungkinkan rekonstruksi kode sumber aplikasi.",
    },
    {
        "file_type": "log_file",
        "probe_paths": [
            "/storage/logs/laravel.log", "/debug.log", "/error.log", "/app.log", "/logs/error.log",
            "/storage/logs/app.log"
        ],
        "finding_type": "log_exposure",
        "title": "Application Error & Debug Log Exposed",
        "severity": "MEDIUM",
        "cwe_id": "CWE-532",
        "desc": "Berkas log aplikasi (.log) terdeteksi dapat diakses publik, memuat jejak stack trace, query database, atau informasi sensitif sistem.",
    },
    {
        "file_type": "backup_archive",
        "probe_paths": [
            "/backup.zip", "/database.zip", "/db.tar.gz", "/site.zip", "/www.zip", "/data.zip",
            "/backup.tar.gz"
        ],
        "finding_type": "archive_exposure",
        "title": "Compressed Application Backup Archive Exposed",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "desc": "File arsip cadangan terkompresi (.zip/.tar.gz) terdeteksi dapat diunduh tanpa otentikasi.",
    },
    {
        "file_type": "phpinfo",
        "probe_paths": ["/phpinfo.php", "/info.php", "/test.php", "/php_info.php"],
        "finding_type": "info_exposure",
        "title": "PHP Info Diagnostic Page Exposed",
        "severity": "MEDIUM",
        "cwe_id": "CWE-200",
        "desc": "Halaman phpinfo() terdeteksi mengekspos detail arsitektur modul server PHP, environment variables, dan jalur sistem file.",
    },
    {
        "file_type": "swagger",
        "probe_paths": ["/swagger.json", "/openapi.json", "/api/docs", "/swagger-ui.html", "/docs"],
        "finding_type": "api_exposure",
        "title": "Interactive API Documentation Exposed",
        "severity": "LOW",
        "cwe_id": "CWE-200",
        "desc": "Dokumentasi API interaktif terbuka ke publik, mempermudah pemetaan seluruh endpoint, skema parameter, dan model otentikasi.",
    },
    {
        "file_type": "actuator",
        "probe_paths": ["/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics", "/server-status"],
        "finding_type": "info_exposure",
        "title": "Application Diagnostic & Telemetry Endpoint Exposed",
        "severity": "MEDIUM",
        "cwe_id": "CWE-200",
        "desc": "Endpoint telemetri dan status server internal terbuka, mengekspos metrik sistem, status komponen, atau pemetaan rute internal.",
    },
    {
        "file_type": "admin_surface",
        "probe_paths": [],  # V9.1: No static paths — admin portals discovered dynamically via crawler form detection
        "finding_type": "admin_portal_exposure",
        "title": "Administrative Authentication Portal Exposed",
        "severity": "MEDIUM",
        "cwe_id": "CWE-200",
        "desc": "Antarmuka otentikasi administratif terdeteksi dapat diakses langsung dari jaringan publik tanpa pembatasan IP / VPN gateway.",
    },
]


async def _process_and_save_validated_finding(
    ctx: ScanContext,
    db: AsyncSession,
    asset_id: str,
    target_host: str,
    norm_res: NormalizedValidationResult,
) -> Optional[Finding]:
    """Evaluates result via ProofQualityGate, builds EvidencePackage, and persists finding."""
    # 1. Local AI Semantic & Deep Triage Engine (V4 & V5)
    resp_meta = norm_res.response_metadata or {}
    ai_triage = LocalAiEngine.triage_finding(
        vulnerability_type=norm_res.vulnerability_type,
        title=norm_res.title,
        target_host=target_host,
        endpoint_url=norm_res.endpoint_url or f"https://{target_host}/",
        parameter=norm_res.parameter,
        severity=norm_res.severity,
        evidence_level=norm_res.evidence_level,
        status_code=resp_meta.get("status_code", 200),
        response_headers=resp_meta.get("headers", {}),
        body_sample=str(resp_meta.get("body_sample") or resp_meta.get("body") or ""),
        raw_evidence=resp_meta,
    )

    if ai_triage["ai_decision"] == "FALSE_POSITIVE":
        logger.info("Finding rejected by Local AI Anti-Noise Engine: %s (Prob: %.2f)", norm_res.title, ai_triage["false_positive_probability"])
        return None

    # 1b. Live NineRouter LLM Multi-Model Combo Deep Reasoning (if configured)
    if llm_client.is_configured:
        try:
            llm_eval = await llm_client.deep_triage_finding(
                vulnerability_type=norm_res.vulnerability_type,
                title=norm_res.title,
                target_host=target_host,
                endpoint_url=norm_res.endpoint_url or f"https://{target_host}/",
                parameter=norm_res.parameter,
                severity=norm_res.severity,
                evidence_level=norm_res.evidence_level,
                raw_evidence=resp_meta,
            )
            if llm_eval and isinstance(llm_eval, dict):
                if llm_eval.get("ai_decision") == "FALSE_POSITIVE" and float(llm_eval.get("ai_confidence_score", 0)) >= 90:
                    logger.info("Finding rejected by NineRouter LLM Critic: %s", norm_res.title)
                    return None
                # Enrich with state-of-the-art LLM insights
                if llm_eval.get("executive_explanation"):
                    ai_triage["executive_explanation"] = llm_eval["executive_explanation"]
                if llm_eval.get("root_cause"):
                    ai_triage["root_cause"] = llm_eval["root_cause"]
                if llm_eval.get("business_impact"):
                    ai_triage["business_impact"] = llm_eval["business_impact"]
                if llm_eval.get("remediation"):
                    norm_res.remediation = llm_eval["remediation"]
                if llm_eval.get("cvss_score"):
                    ai_triage["recommended_cvss"] = float(llm_eval["cvss_score"])
                if llm_eval.get("ai_confidence_score"):
                    ai_triage["ai_confidence_score"] = int(llm_eval["ai_confidence_score"])
        except Exception as llm_triage_err:
            logger.debug("LLM deep triage note: %s", llm_triage_err)

    # 2. Evaluate via Proof Quality Gate (V8 §27, §40)
    qg_res = ProofQualityGate.evaluate(norm_res, scope_decision="ALLOWED" if ctx.scope.url_allowed(norm_res.endpoint_url) else "BLOCKED")
    if len(qg_res) == 4:
        passed, final_status, exploitability_state, checklist = qg_res
    else:
        passed, final_status, checklist = qg_res[0], qg_res[1], qg_res[2]
        exploitability_state = "CONFIRMED" if passed else "NOT_EXPLOITABLE"

    if not passed and final_status == "FALSE_POSITIVE":
        logger.debug("Finding rejected by Anti-Noise / Proof Quality Gate: %s", norm_res.title)
        return None

    # 3. Determine Evidence Level & Score
    ev_level = norm_res.evidence_level
    if final_status == "CONFIRMED" and ev_level in ("E0", "E1"):
        ev_level = "E2"
    ev_score = FindingLifecycle.calculate_evidence_score(
        evidence_level=ev_level,
        has_corroboration=bool(norm_res.cve_id or norm_res.cwe_id),
        has_screenshot=bool(norm_res.screenshots),
        has_controlled_reproduction=bool(norm_res.reproduction_steps),
    )

    # 4. Multi-Factor Risk & Priority Engine (V8 §36)
    from app.intelligence.risk_engine import risk_engine
    from app.core.reproducibility import reproducibility_engine

    risk_data = risk_engine.calculate_priority(
        severity=norm_res.severity,
        confidence=norm_res.confidence,
        exploitability_state=exploitability_state,
        evidence_level=ev_level,
        cve_id=norm_res.cve_id,
    )
    priority_level = risk_data.get("priority", "P2")

    # 5. Deterministic Reproducibility Record (V8 §46)
    req_meta = norm_res.request_metadata or {}
    resp_meta_dict = norm_res.response_metadata or {}
    canary_val = None
    if isinstance(norm_res.observations, dict):
        canary_val = norm_res.observations.get("canary")
    elif isinstance(norm_res.observations, list) and norm_res.observations:
        for obs in norm_res.observations:
            if isinstance(obs, dict) and "canary" in obs:
                canary_val = obs.get("canary")
                break

    repro_record = reproducibility_engine.generate_record(
        adapter_version="v8.0.0",
        rule_version="v8.0.0",
        configuration_profile=ctx.profile,
        target_fingerprint=norm_res.endpoint_url or f"https://{target_host}/",
        evidence_hash=resp_meta_dict.get("sha256"),
    )

    poc_cmd = ai_triage.get("poc_curl") or norm_res.poc_payload or f"curl -i -s -k '{norm_res.endpoint_url}'"

    root_cause_val = ai_triage.get("root_cause") or norm_res.root_cause or "Input validation or state verification deficiency."
    exec_desc_val = ai_triage.get("executive_explanation") or norm_res.executive_explanation or f"Controlled testing confirmed {norm_res.title} on {target_host}."
    biz_impact_val = ai_triage.get("business_impact") or norm_res.business_impact or "Potential deviation in confidentiality, data security, or authorization controls."
    tech_details_val = ai_triage.get("technical_details") or f"Validation Adapter: {norm_res.adapter_name}\nAI Confidence: {ai_triage.get('ai_confidence_score', 85)}%\nQuality Gate Checklist:\n" + "\n".join(checklist)
    remed_val = ai_triage.get("remediation") or norm_res.remediation or "Apply context-aware encoding, prepared queries, and strict input validation."
    impact_matrix_val = norm_res.impact_matrix or {
        "confidentiality": "HIGH" if norm_res.severity in ("HIGH", "CRITICAL") else "MEDIUM",
        "integrity": "MEDIUM" if norm_res.severity in ("HIGH", "CRITICAL") else "LOW",
        "availability": "LOW",
        "auth_bypass": "POSSIBLE" if "auth" in norm_res.title.lower() else "NO",
        "data_exposure": "HIGH" if "exposure" in norm_res.title.lower() or "sql" in norm_res.title.lower() else "LOW",
    }

    finding = await result_service.upsert_finding(
        db,
        validated_result=norm_res,
        scan_id=ctx.scan_id,
        asset_id=asset_id,
        finding_type=norm_res.vulnerability_type,
        title=norm_res.title,
        severity=norm_res.severity,
        confidence=norm_res.confidence,
        evidence_level=ev_level,
        evidence_score=ev_score,
        exploitability_state=exploitability_state,
        priority=priority_level,
        rule_version="v8.0.0",
        cwe_id=norm_res.cwe_id,
        cve_id=norm_res.cve_id,
        cvss_score=norm_res.cvss_score or ai_triage.get("recommended_cvss"),
        description=norm_res.description,
        impact=biz_impact_val,
        technical_details=tech_details_val,
        remediation=remed_val,
        root_cause=root_cause_val,
        executive_explanation=exec_desc_val,
        business_impact=biz_impact_val,
        expected_result=norm_res.expected_result or "Server strictly enforces security boundaries and denies unauthorized state transition.",
        actual_result=norm_res.actual_result or norm_res.description,
        preconditions=norm_res.preconditions or ["Network access to target endpoint", "Authorized scope verification"],
        impact_matrix=impact_matrix_val,
        validation_status=final_status,
        reproducibility_meta=repro_record,
        evidence={
            "url": norm_res.endpoint_url,
            "parameter": norm_res.parameter,
            "observations": norm_res.observations,
            "request_metadata": norm_res.request_metadata,
            "response_metadata": norm_res.response_metadata,
            "poc": norm_res.poc_payload,
            "poc_curl": poc_cmd,
            "checklist": checklist,
            "ai_confidence_score": ai_triage.get("ai_confidence_score", 90),
            "ai_triage_decision": ai_triage.get("ai_decision", "CONFIRMED"),
            "mitre_attack": ai_triage.get("mitre_attack", []),
            "exploitation_data": norm_res.exploitation_data or {},
        },
    )

    if not finding:
        return None

    # Update V8 specialized fields
    finding.evidence_level = ev_level
    finding.evidence_score = ev_score
    finding.exploitability_state = exploitability_state
    finding.priority = priority_level
    finding.rule_version = "v8.0.0"
    finding.reproducibility_meta = repro_record
    finding.impact_matrix = impact_matrix_val
    finding.validation_status = final_status
    finding.root_cause = root_cause_val
    finding.preconditions = norm_res.preconditions or ["Network access to target endpoint", "Authorized scope verification"]
    finding.expected_result = norm_res.expected_result or "Server strictly enforces security boundaries and denies unauthorized state transition."
    finding.actual_result = norm_res.actual_result or norm_res.description
    finding.executive_explanation = exec_desc_val
    finding.business_impact = biz_impact_val
    finding.technical_details = tech_details_val
    finding.remediation = remed_val

    try:
        await db.commit()
    except Exception as commit_err:
        logger.debug("Initial finding commit note: %s", commit_err)

    # Save files read via LFI as artifacts
    expl_data = norm_res.exploitation_data or {}
    if norm_res.vulnerability_type in ("path_traversal", "traversal") and "files_read" in expl_data:
        for file_key, file_info in expl_data["files_read"].items():
            file_name = file_info.get("file", "").split("/")[-1] or f"lfi_{file_key}.txt"
            content = file_info.get("content", "")
            if content:
                try:
                    await ArtifactEngine.process_discovered_artifact(
                        ctx=ctx,
                        db=db,
                        url=file_info.get("url") or norm_res.endpoint_url or f"https://{target_host}/",
                        content_bytes=content.encode("utf-8", errors="ignore"),
                        filename=file_name,
                        file_type="passwd_file" if "passwd" in file_key else ("env_file" if "env" in file_key else "generic"),
                        mime_type="text/plain",
                        asset_id=asset_id,
                        finding_id=finding.id,
                    )
                except Exception as art_err:
                    logger.debug("Failed saving LFI artifact: %s", art_err)
        try:
            await db.commit()
        except Exception as commit_err:
            logger.debug("Artifact database commit note: %s", commit_err)

    elif norm_res.vulnerability_type in ("command_injection", "rce") and "passwd_content" in expl_data:
        passwd_content = expl_data["passwd_content"]
        if passwd_content:
            try:
                await ArtifactEngine.process_discovered_artifact(
                    ctx=ctx,
                    db=db,
                    url=norm_res.endpoint_url or f"https://{target_host}/",
                    content_bytes=passwd_content.encode("utf-8", errors="ignore"),
                    filename="passwd",
                    file_type="passwd_file",
                    mime_type="text/plain",
                    asset_id=asset_id,
                    finding_id=finding.id,
                )
                await db.commit()
            except Exception as art_err:
                logger.debug("Failed saving RCE passwd artifact: %s", art_err)

    # 3. Capture Visual Proof Screenshot (V4 §10, V5 §2, §21)
    try:
        ss = await ScreenshotEngine.capture_url(
            db=db,
            scan_id=ctx.scan_id,
            asset_id=asset_id,
            url_id=None,
            target_url=norm_res.endpoint_url or f"https://{target_host}/",
            trigger="finding",
            finding_title=finding.title,
            ctx=ctx,
        )
        if ss:
            cur_ev = dict(finding.evidence or {})
            cur_ev["screenshot_id"] = ss.id
            cur_ev["screenshot_kind"] = "browser"
            cur_ev["screenshot_url"] = f"/api/screenshots/{ss.id}/image"
            cur_ev["screenshot_thumb"] = f"/api/screenshots/{ss.id}/thumbnail"
            cur_ev["sha256"] = ss.content_hash
            finding.evidence = cur_ev
    except Exception as ss_err:
        logger.debug("Failed capturing finding visual proof: %s", ss_err)

    # 4. Assemble and persist Evidence Package (§21, §22)
    try:
        package_data = EvidencePackageBuilder.build_package(
            finding_id=finding.id,
            finding_code=finding.finding_code or f"BH-2026-{finding.id[:4]}",
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence_level=ev_level,
            target_host=target_host,
            endpoint_url=norm_res.endpoint_url or f"https://{target_host}/",
            cwe_id=finding.cwe_id,
            cve_id=finding.cve_id,
            cvss_score=finding.cvss_score,
            description=finding.description,
            impact_matrix=finding.impact_matrix,
            root_cause=finding.root_cause,
            preconditions=finding.preconditions,
            expected_result=finding.expected_result,
            actual_result=finding.actual_result,
            remediation=finding.remediation,
            request_metadata=norm_res.request_metadata,
            response_metadata=norm_res.response_metadata,
            observations=norm_res.observations,
        )

        ev_pkg = EvidencePackage(
            finding_id=finding.id,
            summary_data=package_data.get("summary_data") or package_data.get("summary") or {},
            timeline_data=package_data.get("timeline_data") or package_data.get("timeline") or [],
            request_metadata=package_data.get("request_metadata") or {},
            response_metadata=package_data.get("response_metadata") or {},
            validation_data=package_data.get("validation_data") or package_data.get("validation") or {},
            reproduction_md=package_data.get("reproduction_md") or "",
            hashes_data=package_data.get("hashes_data") or package_data.get("hashes") or {},
        )
        db.add(ev_pkg)
        await db.commit()
    except Exception as ev_err:
        logger.warning("Evidence package creation note for finding %s: %s", finding.id, ev_err)

    # Emit realtime event
    await ctx.emit(
        "finding.created",
        f"[{finding.severity}] {finding.title} on {target_host} (Evidence: {ev_level}, Score: {ev_score}/100)",
        finding_id=finding.id,
        title=finding.title,
        severity=finding.severity,
        url=norm_res.endpoint_url or target_host,
        asset_id=asset_id,
        evidence_level=ev_level,
        evidence_score=ev_score,
        confidence=0.95 if final_status == "CONFIRMED" else 0.75,
    )

    return finding


async def run(ctx: ScanContext, db: AsyncSession, root_domain: str) -> None:
    """Non-destructive Security Intelligence, Validation & Quality Gate Engine (§19-§44)."""
    if ctx.profile == "passive":
        return

    await ctx.emit("scan.security", f"Starting deep security validation and evidence correlation for {root_domain}", severity="info")

    asset_ids_query = select(Asset.id).where(Asset.scan_id == ctx.scan_id)
    assets = (await db.execute(select(Asset).where(Asset.scan_id == ctx.scan_id))).scalars().all()
    asset_map = {a.id: a for a in assets}

    # 1. Targeted Sensitive File Deep Probing with Strict Content Signature & Anti-Soft-404 (§40, §44)
    # Bounded Concurrency across all discovered assets to prevent scan timeouts
    asset_sem = asyncio.Semaphore(15)

    async def _audit_single_asset_sensitive_files(asset_obj: Asset) -> list[tuple[str, str, NormalizedValidationResult, Optional[dict]]]:
        target_host = asset_obj.hostname
        if not target_host or not ctx.scope.host_allowed(target_host):
            return []

        async with asset_sem:
            asset_url_rows = (await db.execute(
                select(URL.url).where(URL.asset_id == asset_obj.id)
            )).scalars().all()
            target_base_urls = list({urlparse(u).scheme + "://" + urlparse(u).netloc for u in asset_url_rows if urlparse(u).netloc})
            if not target_base_urls:
                target_base_urls = [f"https://{target_host}", f"http://{target_host}"]

            results: list[tuple[str, str, NormalizedValidationResult, Optional[dict]]] = []
            try:
                baseline = await soft_404_detector.get_baseline(target_host)
                is_soft = baseline.get("is_soft_404", False)
                base_len = baseline.get("content_length", 0)

                clean_h = target_host.split(":")[0].lower()
                h_parts = clean_h.split(".")
                sub = h_parts[0] if len(h_parts) > 1 else clean_h
                dom = h_parts[-2] if len(h_parts) >= 2 else clean_h

                for base_url in target_base_urls:
                    for rule in SENSITIVE_PATH_DEFINITIONS:
                        candidate_paths = list(rule.get("probe_paths") or [rule.get("probe_path", "")])
                        
                        if rule["file_type"] == "backup_sql":
                            candidate_paths.extend([
                                f"/{sub}.sql", f"/{dom}.sql", f"/database/{sub}.sql", f"/database/{dom}.sql",
                                f"/backup_{sub}.sql", f"/dump_{sub}.sql", f"/db_{sub}.sql",
                            ])
                        elif rule["file_type"] == "csv":
                            candidate_paths.extend([
                                f"/{sub}.csv", f"/{dom}.csv", f"/export_{sub}.csv", f"/database/{sub}.csv",
                                f"/data_{sub}.csv",
                            ])
                        elif rule["file_type"] == "backup_archive":
                            candidate_paths.extend([
                                f"/{sub}.zip", f"/{dom}.zip", f"/backup_{sub}.zip", f"/{sub}.tar.gz",
                            ])

                        for u_row in asset_url_rows:
                            p_path = urlparse(u_row).path
                            if p_path:
                                if p_path not in candidate_paths:
                                    if rule["file_type"] == "backup_sql" and p_path.lower().endswith((".sql", ".dump")):
                                        candidate_paths.append(p_path)
                                    elif rule["file_type"] == "csv" and p_path.lower().endswith((".csv", ".tsv")):
                                        candidate_paths.append(p_path)
                                    elif rule["file_type"] == "env_file" and "/.env" in p_path.lower():
                                        candidate_paths.append(p_path)
                                    elif rule["file_type"] == "log_file" and p_path.lower().endswith(".log"):
                                        candidate_paths.append(p_path)

                                # Component 6: Active crawl path-based probing (probe relative to subdir)
                                parts = p_path.rsplit('/', 1)
                                if len(parts) > 1 and parts[0] and parts[0] != "/":
                                    subdir = parts[0]
                                    for base_probe in rule.get("probe_paths") or [rule.get("probe_path", "")]:
                                        if base_probe:
                                            rel_path = f"{subdir}/{base_probe.lstrip('/')}"
                                            if rel_path not in candidate_paths:
                                                candidate_paths.append(rel_path)

                        for sample_path in list(dict.fromkeys(candidate_paths)):
                            if not sample_path:
                                continue

                            test_url = f"{base_url.rstrip('/')}{sample_path}"
                            resp = await fetch_http(test_url, timeout=min(6.0, settings.http_timeout_seconds))
                            if not resp or resp.status_code != 200 or not resp.text:
                                continue

                            resp_title = extract_title(resp.text) or ""

                            if is_soft:
                                curr_len = len(resp.text)
                                if abs(curr_len - base_len) < 60:
                                    continue

                            is_valid, reason, meta = SensitiveFileValidator.validate_content_signature(
                                file_type=rule["file_type"],
                                url=test_url,
                                status_code=resp.status_code,
                                content=resp.text,
                                content_type=resp.headers.get("content-type", ""),
                                title=resp_title,
                            )

                            if is_valid:
                                norm_res = NormalizedValidationResult(
                                    adapter_name="sensitive_file_validator",
                                    vulnerability_type=rule["finding_type"],
                                    title=f"{rule['title']} ({sample_path})",
                                    severity=rule["severity"],
                                    confidence="CONFIRMED",
                                    evidence_level="E3",
                                    target_host=target_host,
                                    endpoint_url=test_url,
                                    cwe_id=rule.get("cwe_id"),
                                    description=f"{rule['desc']}\n\nValidation Details: {reason}",
                                    impact_matrix={
                                        "confidentiality": "HIGH",
                                        "integrity": "HIGH" if "sql" in rule["file_type"] or "env" in rule["file_type"] else "MEDIUM",
                                        "availability": "LOW",
                                        "auth_bypass": "POSSIBLE" if any(k in rule["file_type"] for k in ["git", "env", "sql", "admin"]) else "NO",
                                        "data_exposure": "CRITICAL" if any(k in rule["file_type"] for k in ["sql", "csv", "env"]) else "HIGH",
                                    },
                                    root_cause="Inadequate access control list or public web server directory mapping configuration.",
                                    preconditions=["Network route to public web endpoint", "File readable by web server process"],
                                    expected_result="HTTP 404 Not Found or HTTP 403 Forbidden on internal configuration/metadata files.",
                                    actual_result=f"HTTP 200 OK with authentic verified content: {reason}",
                                    executive_explanation=f"A sensitive asset file ({rule['file_type']}) was verified accessible without authentication on {target_host}.",
                                    business_impact="Direct exposure of application secrets, database schemas/data, codebase metadata, or administrative authentication portals.",
                                    remediation=f"Block public access to {sample_path} in reverse proxy / web server configuration (.htaccess, nginx.conf, web.config).",
                                    poc_payload=f"curl -i -s -k '{test_url}'",
                                    reproduction_steps=[
                                        f"Send HTTP GET request to {test_url}",
                                        "Observe HTTP 200 OK response",
                                        f"Verify content signature: {reason}",
                                    ],
                                    observations=[{"type": "content_signature", "reason": reason, "metadata": meta}],
                                    request_metadata={"url": test_url, "method": "GET"},
                                    response_metadata={"status_code": 200, "headers": dict(resp.headers), "body_sample": resp.text[:400]},
                                )
                                art_meta = {
                                    "url": test_url,
                                    "content_bytes": resp.text.encode("utf-8", errors="ignore"),
                                    "filename": sample_path.split("/")[-1] or "artifact.bin",
                                    "file_type": "sql_dump" if "sql" in rule["file_type"] else ("csv_export" if "csv" in rule["file_type"] else rule["file_type"]),
                                    "asset_id": asset_obj.id,
                                }
                                results.append((asset_obj.id, target_host, norm_res, art_meta))

                    # Run Auth Bypass checks
                    try:
                        auth_test_urls = [
                            f"{base_url.rstrip('/')}/rest/user/login",
                            f"{base_url.rstrip('/')}/api/Users",
                            f"{base_url.rstrip('/')}/admin",
                            f"{base_url.rstrip('/')}/login",
                            f"{base_url.rstrip('/')}/auth/login",
                            f"{base_url.rstrip('/')}/administrator",
                            f"{base_url.rstrip('/')}/#/login",
                        ]
                        auth_cands = await auth_bypass_validator.validate(base_url, discovered_urls=auth_test_urls)
                        for cand in auth_cands:
                            is_sqli = cand.technique == "sqli_auth_bypass"
                            is_unauth = cand.technique == "unauthenticated_access"
                            f_sev = "CRITICAL" if is_sqli else ("HIGH" if is_unauth else "MEDIUM")
                            f_title = (
                                f"SQL Injection Authentication Bypass on Admin Portal ({cand.endpoint})" if is_sqli
                                else (f"Unauthenticated Administrative Access ({cand.endpoint})" if is_unauth
                                else f"Exposed Administrative Authentication Portal ({cand.endpoint})")
                            )
                            norm_res = NormalizedValidationResult(
                                adapter_name="auth_bypass_validator",
                                vulnerability_type="auth_bypass" if (is_sqli or is_unauth) else "admin_portal_exposure",
                                title=f_title,
                                severity=f_sev,
                                confidence=cand.confidence,
                                evidence_level="E3" if (is_sqli or is_unauth) else "E2",
                                target_host=target_host,
                                endpoint_url=cand.url,
                                cwe_id="CWE-89" if is_sqli else ("CWE-287" if is_unauth else "CWE-200"),
                                description=(
                                    f"The authentication portal at '{cand.endpoint}' is vulnerable to SQL injection authentication bypass, allowing unauthorized login." if is_sqli
                                    else (f"The administrative dashboard at '{cand.endpoint}' is accessible without authentication." if is_unauth
                                    else f"Administrative login portal at '{cand.endpoint}' is exposed directly on the public internet without network access controls.")
                                ),
                                impact_matrix={"confidentiality": "CRITICAL" if is_sqli else "HIGH", "integrity": "CRITICAL" if is_sqli else "MEDIUM", "availability": "MEDIUM", "auth_bypass": "CONFIRMED" if (is_sqli or is_unauth) else "POSSIBLE"},
                                remediation="Restrict administrative access to authorized VPN/IP subnets. Enforce parameterized SQL queries and Multi-Factor Authentication (MFA).",
                                poc_payload=cand.evidence.get("poc_curl") or f"curl -i -s -k '{cand.url}'",
                                reproduction_steps=[
                                    f"Send request to {cand.url}",
                                    f"Observed result: {cand.evidence.get('actual', 'Accessible endpoint')}",
                                ],
                                request_metadata={"url": cand.url},
                                response_metadata=cand.evidence,
                            )
                            results.append((asset_obj.id, target_host, norm_res, None))
                    except Exception as auth_err:
                        logger.debug("Auth validation error on %s: %s", target_host, auth_err)

                    # Phase 1b: Direct Path LFI Probing (Component 1)
                    try:
                        subdirs = []
                        for u_row in asset_url_rows:
                            p_path = urlparse(u_row).path
                            if p_path:
                                parts = p_path.rsplit('/', 1)
                                if len(parts) > 1 and parts[0] and parts[0] != "/":
                                    if parts[0] not in subdirs:
                                        subdirs.append(parts[0])
                        lfi_findings = await path_traversal_validator.validate_direct_paths(
                            base_url=base_url,
                            subdirectories=subdirs,
                            max_subdirectories=8,
                            max_requests=72,
                        )
                        for lfi in lfi_findings:
                            expl_data = getattr(lfi, "exploitation_data", {}) or {}
                            has_deep = bool(expl_data.get("files_read"))
                            files_count = expl_data.get("files_read_count", 0)
                            target_file = getattr(lfi, "target_file", "/etc/passwd")
                            technique = getattr(lfi, "technique", "direct")
                            if has_deep:
                                sev = "CRITICAL"
                                ev_level = "E4"
                                title = f"Direct Path Traversal / LFI — {files_count} Files Read ({technique})"
                                desc = f"Direct LFI vulnerability found at {lfi.url}. Allowed reading {target_file} + {files_count} additional files via {technique} technique."
                            else:
                                sev = "HIGH"
                                ev_level = "E3"
                                title = f"Direct Path Traversal LFI ({technique})"
                                desc = f"Direct LFI vulnerability found at {lfi.url}. Returned {target_file} contents."
                            norm_res = NormalizedValidationResult(
                                adapter_name="path_traversal_validator",
                                vulnerability_type="path_traversal",
                                title=title,
                                severity=sev,
                                confidence=lfi.confidence,
                                evidence_level=ev_level,
                                target_host=target_host,
                                endpoint_url=lfi.url,
                                parameter="DIRECT_PATH",
                                cwe_id="CWE-22",
                                description=desc,
                                impact_matrix=getattr(lfi, "impact_matrix", {}) or {"confidentiality": "HIGH", "integrity": "LOW", "availability": "LOW", "data_exposure": "HIGH"},
                                remediation="Ensure path requests are strictly routed within a whitelist of public files. Avoid resolving path sequences containing traversal operators.",
                                poc_payload=lfi.probe,
                                poc_command=lfi.poc_curl,
                                reproduction_steps=getattr(lfi, "reproduction_steps", []),
                                request_metadata={"url": lfi.url, "method": "GET", "payload": lfi.probe, "technique": technique},
                                response_metadata=lfi.evidence if isinstance(getattr(lfi, "evidence", None), dict) else {},
                                exploitation_data=expl_data,
                            )
                            results.append((asset_obj.id, target_host, norm_res, None))
                    except Exception as lfi_err:
                        logger.debug("Direct LFI probing error on %s: %s", base_url, lfi_err)

            except Exception as asset_err:
                logger.debug("Sensitive file audit error on %s: %s", target_host, asset_err)

            return results

    if assets:
        await ctx.emit("scan.validate", f"Auditing sensitive file exposure and configuration leaks across {len(assets)} asset(s)...", stage="SENSITIVE_FILES")
        
        # Batch assets to prevent resource starvation and descriptor leaks
        batch_size = 15
        asset_batch_results = []
        for idx in range(0, len(assets), batch_size):
            if kill_switch_manager.is_stopped(ctx.scan_id):
                break
            batch = assets[idx : idx + batch_size]
            results = await asyncio.gather(
                *[_audit_single_asset_sensitive_files(a) for a in batch],
                return_exceptions=True
            )
            asset_batch_results.extend(results)

        for res_list in asset_batch_results:
            if isinstance(res_list, list):
                for asset_id, target_host, norm_res, art_meta in res_list:
                    await _process_and_save_validated_finding(ctx, db, asset_id, target_host, norm_res)
                    if art_meta:
                        try:
                            await ArtifactEngine.process_discovered_artifact(
                                ctx=ctx,
                                db=db,
                                **art_meta,
                            )
                        except Exception as art_err:
                            logger.debug("Artifact processing error: %s", art_err)
        await db.commit()

    # 2. Secret Scan & Sensitive File Analysis on ALL Discovered URLs (§40, §85) with Bounded Concurrency
    urls = (await db.execute(
        select(URL).where(URL.asset_id.in_(asset_ids_query))
    )).scalars().all()

    if urls:
        await ctx.emit("scan.validate", f"Auditing {len(urls)} discovered URL(s) for secrets, tokens, data dumps, and exposures...", stage="SECRETS_SCAN")

    secret_sem = asyncio.Semaphore(10)

    async def _audit_single_url_for_secrets(u: URL) -> list[tuple[str, str, NormalizedValidationResult, Optional[dict]]]:
        asset_obj = asset_map.get(u.asset_id)
        target_host = asset_obj.hostname if asset_obj else root_domain
        u_path = (u.path or "").lower()
        items_found: list[tuple[str, str, NormalizedValidationResult, Optional[dict]]] = []

        # 2a. Check if discovered URL is a sensitive file (.sql, .csv, .env, .log, .zip, .kdbx, .bak, .yml, .md, .pdf)
        is_sensitive_path = (
            any(u_path.endswith(ext) for ext in [
                ".sql", ".csv", ".tsv", ".log", ".dump", ".bak", ".zip", ".tar.gz",
                ".kdbx", ".yml", ".yaml", ".json", ".md", ".pdf", ".env", ".old", ".save"
            ])
            or any(k in u_path for k in ["/.env", "/ftp/", "/backup/", "/database/", "/storage/logs", "/private/", "/order_", "/support/logs"])
        )

        if is_sensitive_path:
            async with secret_sem:
                resp = await fetch_http(u.url, timeout=settings.http_timeout_seconds)
                if resp and resp.status_code == 200 and resp.text:
                    inferred_type = (
                        "kdbx" if u_path.endswith(".kdbx")
                        else ("backup_sql" if u_path.endswith((".sql", ".dump"))
                        else ("csv" if u_path.endswith((".csv", ".tsv"))
                        else ("log_file" if u_path.endswith(".log") or "/logs" in u_path
                        else ("env" if "/.env" in u_path
                        else ("yaml" if u_path.endswith((".yml", ".yaml"))
                        else ("backup_code" if any(u_path.endswith(e) for e in [".bak", ".old", ".save", ".dist"])
                        else ("directory_leak" if "/ftp/" in u_path or "/backup/" in u_path
                        else "backup_archive")))))))
                    )
                    is_valid, reason, meta = SensitiveFileValidator.validate_content_signature(
                        file_type=inferred_type,
                        url=u.url,
                        status_code=200,
                        content=resp.text,
                        content_type=resp.headers.get("content-type", ""),
                        title=u.title or "",
                    )
                    if is_valid:
                        if inferred_type in ("backup_sql", "env", "kdbx"):
                            f_sev = "CRITICAL"
                        elif inferred_type in ("csv", "yaml", "backup_code", "directory_leak"):
                            f_sev = "HIGH"
                        else:
                            f_sev = "MEDIUM"

                        if inferred_type == "kdbx":
                            f_title = f"Exposed KeePass Password Database ({u.path})"
                        elif inferred_type == "backup_sql":
                            f_title = f"Exposed Database SQL Dump ({u.path})"
                        elif inferred_type == "csv":
                            f_title = f"Exposed Tabular CSV / PII Data Export ({u.path})"
                        elif inferred_type == "env":
                            f_title = f"Exposed Environment Secrets ({u.path})"
                        elif inferred_type == "yaml":
                            f_title = f"Exposed YAML Configuration ({u.path})"
                        elif inferred_type == "backup_code":
                            f_title = f"Exposed Source/Configuration Backup ({u.path})"
                        else:
                            f_title = f"Exposed Sensitive Document/File ({u.path})"

                        norm_res = NormalizedValidationResult(
                            adapter_name="sensitive_file_validator",
                            vulnerability_type=f"{inferred_type}_exposure",
                            title=f_title,
                            severity=f_sev,
                            confidence="CONFIRMED",
                            evidence_level="E3",
                            target_host=target_host,
                            endpoint_url=u.url,
                            cwe_id="CWE-200",
                            description=f"Sensitive file '{u.path}' was discovered during web enumeration and verified authentic.\n\nDetails: {reason}",
                            impact_matrix={"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW", "data_exposure": "CRITICAL" if f_sev == "CRITICAL" else "HIGH"},
                            remediation=f"Block public access to {u.path} in web server configuration.",
                            poc_payload=f"curl -i -s -k '{u.url}'",
                            reproduction_steps=[f"Send HTTP GET to {u.url}", f"Verify content: {reason}"],
                            request_metadata={"url": u.url, "method": "GET"},
                            response_metadata={"status_code": 200, "headers": dict(resp.headers), "body_sample": resp.text[:400]},
                        )

                        art_meta = {
                            "url": u.url,
                            "content_bytes": resp.text.encode("utf-8", errors="ignore"),
                            "filename": u_path.split("/")[-1] or "artifact.bin",
                            "file_type": "sql_dump" if inferred_type == "backup_sql" else ("csv_export" if inferred_type == "csv" else inferred_type),
                            "asset_id": u.asset_id,
                            "url_id": u.id,
                        }
                        items_found.append((u.asset_id, target_host, norm_res, art_meta))

        if u.title:
            defacement_finding = info_disclosure_validator.detect_seo_spam_defacement(u.url, html="", title=u.title)
            if defacement_finding:
                norm_res = NormalizedValidationResult(
                    adapter_name="seo_spam_detector",
                    vulnerability_type=defacement_finding.finding_type,
                    title=f"{defacement_finding.title} on {u.url}",
                    severity=defacement_finding.severity,
                    confidence=defacement_finding.confidence,
                    evidence_level=defacement_finding.evidence_level,
                    target_host=target_host,
                    endpoint_url=u.url,
                    cwe_id=defacement_finding.cwe_id,
                    description=defacement_finding.description,
                    impact_matrix=defacement_finding.impact_matrix,
                    remediation=defacement_finding.remediation,
                    poc_command=defacement_finding.poc_curl,
                    actual_result=f"Discovered webpage with compromised SEO spam / gambling title: '{u.title}'",
                    expected_result="Webpage title should reflect legitimate organization brand without third-party spam keywords.",
                )
                items_found.append((u.asset_id, target_host, norm_res, None))

        if u.title or u.url:
            secret_hits = secret_scanner.scan_text(f"{u.url} {u.title or ''}", source_url=u.url)
            for hit in secret_hits:
                norm_res = NormalizedValidationResult(
                    adapter_name="secret_scanner",
                    vulnerability_type="secret_exposure",
                    title=f"{hit['name']} Disclosed",
                    severity=hit["severity"],
                    confidence="VALIDATED",
                    evidence_level="E2",
                    target_host=target_host,
                    endpoint_url=u.url,
                    cwe_id=hit.get("cwe"),
                    description=hit["description"],
                    impact_matrix={"confidentiality": "HIGH", "integrity": "LOW", "availability": "LOW", "data_exposure": "HIGH"},
                    remediation="Revoke the exposed secret immediately and rotate API credentials.",
                    poc_payload=f"curl -s -k '{u.url}' | grep '{hit['match_redacted']}'",
                )
                items_found.append((u.asset_id, target_host, norm_res, None))

        return items_found

    if urls:
        # Process secrets audit in batches to avoid CPU/memory spikes and socket exhaustion
        batch_size = 50
        total_secrets_urls = len(urls)
        for idx in range(0, total_secrets_urls, batch_size):
            if kill_switch_manager.is_stopped(ctx.scan_id):
                break
            batch = urls[idx : idx + batch_size]
            results = await asyncio.gather(
                *[_audit_single_url_for_secrets(u) for u in batch],
                return_exceptions=True
            )
            
            # Save results immediately and clear to release memory
            for res_list in results:
                if isinstance(res_list, list):
                    for asset_id, target_host, norm_res, art_meta in res_list:
                        await _process_and_save_validated_finding(ctx, db, asset_id, target_host, norm_res)
                        if art_meta:
                            try:
                                await ArtifactEngine.process_discovered_artifact(
                                    ctx=ctx,
                                    db=db,
                                    **art_meta,
                                )
                            except Exception as art_err:
                                logger.debug("Artifact processing error: %s", art_err)
            await db.commit()

    # 3. Active Controlled Parameter Testing (§20-§22) with Bounded Async Concurrency
    if ctx.profile in ("standard", "deep", "custom", "full", "pentest", "adversary_simulation") and urls:
        all_url_ids = [u.id for u in urls]
        all_db_params = (await db.execute(
            select(Parameter).where(Parameter.url_id.in_(all_url_ids))
        )).scalars().all()

        params_by_url: dict[str, list[dict[str, str]]] = {}
        for p in all_db_params:
            params_by_url.setdefault(p.url_id, []).append({"name": p.name, "location": p.location})

        def _score_url_priority(u: URL) -> int:
            score = 0
            u_str = (u.url or "").lower()
            # Prioritize endpoints with confirmed discovered parameters
            if u.id in params_by_url and len(params_by_url[u.id]) > 0:
                score += 50 + min(len(params_by_url[u.id]) * 5, 30)
            if "?" in u_str:
                score += 25
            if u.content_type == "login_form":
                score += 35
            if any(k in u_str for k in ["search", "find", "query", "q=", "filter", "detail", "item", "view"]):
                score += 20
            if any(k in u_str for k in ["rest", "api", "products", "users", "feedback", "basket", "orders", "auth", "login", "admin"]):
                score += 15
            if any(u_str.endswith(ext) for ext in [".php", ".asp", ".aspx", ".jsp", ".json", ".action", ".do"]):
                score += 10
            return score

        sorted_urls = sorted(urls, key=_score_url_priority, reverse=True)
        max_fuzz_budget = 250 if ctx.profile in ("deep", "full", "pentest", "adversary_simulation") else 150
        target_urls = sorted_urls[:max_fuzz_budget]

        # Synthesize parameter candidates if none extracted (e.g. SPAs, REST APIs, OWASP Juice Shop)
        for u in target_urls:
            # First extract query parameters from the URL string itself if present
            parsed_u = urlparse(u.url)
            if parsed_u.query:
                qs = parse_qs(parsed_u.query, keep_blank_values=True)
                for qk in qs.keys():
                    if qk and not any(p["name"] == qk for p in params_by_url.get(u.id, [])):
                        params_by_url.setdefault(u.id, []).append({"name": qk, "location": "query"})

            if u.id not in params_by_url or not params_by_url[u.id]:
                u_path_l = (u.path or "").lower()
                if any(kw in u_path_l for kw in ["search", "product", "item", "user", "api", "rest", "find", "query", "view", "page", "feedback", "basket", "feed", "order"]):
                    params_by_url[u.id] = [
                        {"name": "q", "location": "query"},
                        {"name": "id", "location": "query"},
                        {"name": "search", "location": "query"},
                        {"name": "query", "location": "query"},
                        {"name": "name", "location": "query"},
                    ]
                elif u_path_l.endswith((".php", ".asp", ".aspx", ".jsp", ".do", ".action")) or u_path_l in ("/", ""):
                    params_by_url[u.id] = [
                        {"name": "id", "location": "query"},
                        {"name": "page", "location": "query"},
                        {"name": "file", "location": "query"},
                        {"name": "url", "location": "query"},
                    ]

        await ctx.emit(
            "scan.validate",
            f"Validating injection vulnerabilities across {len(target_urls)} endpoint(s) [SQLi, XSS, SSRF, RCE, IDOR, Traversal]...",
            stage="PARAM_VALIDATION",
        )

        param_sem = asyncio.Semaphore(12)

        async def _validate_single_url(u: URL, param_dicts: list[dict[str, str]]) -> list[tuple[str, str, NormalizedValidationResult]]:
            if not param_dicts:
                return []

            collected: list[tuple[str, str, NormalizedValidationResult]] = []
            async with param_sem:
                asset_obj = asset_map.get(u.asset_id)
                target_host = asset_obj.hostname if asset_obj else root_domain

                # Smart Parameter Heuristic Filtering & Routing
                # Goal: Avoid scanning parameters like '?action=login' or '?submit=true' with 30 traversal payloads.
                xss_sqli_params = []
                traversal_params = []
                ssrf_redirect_params = []
                rce_params = []
                idor_params = []

                parsed_url = urlparse(u.url)
                query_vals = parse_qs(parsed_url.query)

                for p in param_dicts:
                    p_name = p.get("name", "").lower()
                    p_val = query_vals.get(p["name"], [""])[0].lower() if "name" in p else ""

                    # Skip common static-like params to save requests
                    if p_name in ("submit", "btn", "_csrf", "csrf_token", "hash", "timestamp", "date", "time"):
                        continue

                    # 1. SQLi & XSS Heuristic: Exclude only strict redirection URLs, test everything else
                    if not any(k in p_name for k in ("redirect", "goto", "callback", "url_redirect")):
                        xss_sqli_params.append(p)

                    # 2. Path Traversal Heuristic
                    if any(k in p_name for k in ("file", "path", "folder", "doc", "view", "template", "include", "dir", "load", "read", "download", "src", "source", "resource", "attachment", "filename", "filepath", "img", "image", "lang", "config", "log")):
                        traversal_params.append(p)
                    elif "/" in p_val or "\\" in p_val or "." in p_val:
                        traversal_params.append(p)

                    # 3. SSRF & Open Redirect Heuristic
                    if any(k in p_name for k in ("url", "uri", "link", "href", "domain", "host", "src", "source", "callback", "webhook", "redirect", "dest", "destination", "goto", "target")):
                        ssrf_redirect_params.append(p)
                    elif p_val.startswith(("http://", "https://", "ftp://", "//")):
                        ssrf_redirect_params.append(p)

                    # 4. RCE Heuristic
                    if any(k in p_name for k in ("cmd", "command", "exec", "run", "ping", "ip", "host", "shell", "query", "id", "code", "eval", "cli", "daemon")):
                        rce_params.append(p)

                    # 5. IDOR Heuristic (Check for numeric ID, UUID format, hashes, or common IDOR parameter names)
                    is_uuid = bool(re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", p_val))
                    is_numeric = p_val.isdigit()
                    is_hash = bool(re.match(r"^[0-9a-fA-F]{32,64}$", p_val))
                    is_idor_name = any(k in p_name for k in ("id", "user", "account", "order", "invoice", "doc", "profile", "member", "customer", "transaction", "payment", "file", "download", "post", "comment"))
                    if is_numeric or is_uuid or is_hash or is_idor_name:
                        idor_params.append(p)

                # Active logs/telemetry to show filtered routing in action
                logger.debug(
                    "Param router on %s: SQLi/XSS=%d, LFI=%d, SSRF=%d, RCE=%d, IDOR=%d",
                    u.path or u.url, len(xss_sqli_params), len(traversal_params),
                    len(ssrf_redirect_params), len(rce_params), len(idor_params)
                )

                await ctx.emit(
                    "scan.validate",
                    f"Testing {len(param_dicts)} parameters on {u.path or u.url} (Routed: SQLi/XSS:{len(xss_sqli_params)} LFI:{len(traversal_params)} SSRF:{len(ssrf_redirect_params)} RCE:{len(rce_params)} IDOR:{len(idor_params)})...",
                    url=u.url,
                    stage="PARAM_TESTING",
                )

                # 3a. XSS Validation
                if xss_sqli_params:
                    try:
                        xss_cands = await xss_validator.validate_url(u.url, xss_sqli_params)
                        for cand in xss_cands:
                            # Reject pure observations without unescaped execution or dangerous context
                            if cand.confidence == "OBSERVED" and not cand.payload_executed and not cand.unescaped:
                                continue

                            if cand.payload_executed:
                                sev = "HIGH"
                                ev_level = "E3"
                                title = f"Cross-Site Scripting (XSS) Confirmed on '{cand.parameter}' ({cand.technique})"
                            elif cand.unescaped:
                                sev = "MEDIUM"
                                ev_level = "E2"
                                title = f"Unescaped HTML Reflection on '{cand.parameter}' ({cand.context}, {cand.technique})"
                            else:
                                sev = "LOW"
                                ev_level = "E1"
                                title = f"Potential Input Reflection in {cand.context} on '{cand.parameter}'"

                            norm_res = NormalizedValidationResult(
                                adapter_name="xss_validator",
                                vulnerability_type="xss_reflection",
                                title=title,
                                severity=sev,
                                confidence=cand.confidence,
                                evidence_level=cand.evidence.get("evidence_level") or ev_level,
                                target_host=target_host,
                                endpoint_url=u.url,
                                parameter=cand.parameter,
                                cwe_id="CWE-79",
                                description=f"Parameter '{cand.parameter}' {'executes injected script' if cand.payload_executed else 'reflects input unescaped'} in HTML context '{cand.context}' ({cand.technique}).",
                                impact_matrix=cand.impact_matrix if cand.impact_matrix else {"confidentiality": "MEDIUM", "integrity": "MEDIUM", "availability": "LOW"},
                                remediation="Apply contextual HTML entity encoding before reflecting user input. Implement Content-Security-Policy header.",
                                poc_payload=cand.poc_curl or cand.evidence.get("payload", u.url) if isinstance(cand.evidence, dict) else u.url,
                                reproduction_steps=cand.reproduction_steps,
                                request_metadata={"url": u.url, "parameter": cand.parameter},
                                response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                                exploitation_data=getattr(cand, 'exploitation_data', {}) or {},
                            )
                            collected.append((u.asset_id, target_host, norm_res))
                    except Exception as exc:
                        logger.debug("XSS validation error on %s: %s", u.url, exc)

                # 3b. SQL Injection Deep Validation
                if xss_sqli_params:
                    try:
                        sqli_cands = await sqli_validator.validate_url(u.url, xss_sqli_params)
                        for cand in sqli_cands:
                            db_info = f" [DB: {cand.db_engine}" + (f" v{cand.db_version}" if cand.db_version else "") + "]"
                            col_info = f" [{cand.column_count} columns]" if cand.column_count > 0 else ""
                            norm_res = NormalizedValidationResult(
                                adapter_name="sqli_validator",
                                vulnerability_type="sql_injection",
                                title=f"SQL Injection on '{cand.parameter}' ({cand.technique}){db_info}{col_info}",
                                severity="CRITICAL" if cand.column_count > 0 or getattr(cand, 'exploitation_data', {}) else "HIGH",
                                confidence=cand.confidence,
                                evidence_level="E4" if getattr(cand, 'exploitation_data', {}) else ("E3" if cand.confidence == "CONFIRMED" or cand.column_count > 0 else "E2"),
                                target_host=target_host,
                                endpoint_url=u.url,
                                parameter=cand.parameter,
                                cwe_id="CWE-89",
                                description=f"Parameter '{cand.parameter}' confirmed SQL injection ({cand.technique}-based). Database: {cand.db_engine}{(' v' + cand.db_version) if cand.db_version else ''}.{(' UNION column count: ' + str(cand.column_count)) if cand.column_count else ''}",
                                impact_matrix=cand.impact_matrix or {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM", "data_exposure": "HIGH"},
                                remediation="Use parameterized queries / prepared statements for all database interactions.",
                                poc_command=cand.poc_curl,
                                poc_payload=cand.evidence.get("probe", "") if isinstance(cand.evidence, dict) else "",
                                reproduction_steps=cand.reproduction_steps,
                                request_metadata={"url": u.url, "parameter": cand.parameter, "db_engine": cand.db_engine},
                                response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                                exploitation_data=getattr(cand, 'exploitation_data', {}) or {},
                            )
                            collected.append((u.asset_id, target_host, norm_res))
                    except Exception as exc:
                        logger.debug("SQLi validation error on %s: %s", u.url, exc)

                # 3c. SSRF Probes
                if ssrf_redirect_params:
                    try:
                        ssrf_cands = await ssrf_validator.validate_url(u.url, ssrf_redirect_params)
                        for cand in ssrf_cands:
                            norm_res = NormalizedValidationResult(
                                adapter_name="ssrf_validator",
                                vulnerability_type="ssrf",
                                title=f"Server-Side Request Forgery (SSRF) on '{cand.parameter}'",
                                severity="HIGH",
                                confidence=cand.confidence,
                                evidence_level="E3" if cand.confidence == "CONFIRMED" else "E2",
                                target_host=target_host,
                                endpoint_url=cand.url,
                                parameter=cand.parameter,
                                cwe_id="CWE-918",
                                description=f"Parameter '{cand.parameter}' executed server-side request with probe '{cand.probe}'. Internal/loopback response confirmed.",
                                impact_matrix={"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW"},
                                remediation="Validate URL scheme and host against strict whitelist. Reject private IP ranges.",
                                poc_payload=cand.probe,
                                poc_command=getattr(cand, "poc_curl", f"curl -i -s -k '{cand.url}'"),
                                reproduction_steps=getattr(cand, "reproduction_steps", [f"Send request to {cand.url} with probe {cand.probe}"]),
                                request_metadata={"url": cand.url, "parameter": cand.parameter, "probe": cand.probe},
                                response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                            )
                            collected.append((u.asset_id, target_host, norm_res))
                    except Exception as exc:
                        logger.debug("SSRF validation error on %s: %s", u.url, exc)

                # 3d. Path Traversal / LFI Probes (Nuclei-grade)
                if traversal_params:
                    try:
                        trav_cands = await path_traversal_validator.validate_url(u.url, traversal_params)
                        for cand in trav_cands:
                            cand_payload = cand.evidence.get("payload", cand.probe) if isinstance(getattr(cand, "evidence", None), dict) else cand.probe
                            cand_poc = getattr(cand, "poc_curl", "") or (cand.evidence.get("poc_curl") if isinstance(getattr(cand, "evidence", None), dict) else None)
                            expl_data = getattr(cand, "exploitation_data", {}) or {}
                            has_deep = bool(expl_data.get("files_read"))
                            files_count = expl_data.get("files_read_count", 0)
                            target_file = getattr(cand, "target_file", "/etc/passwd")
                            technique = getattr(cand, "technique", "standard")

                            if has_deep:
                                sev = "CRITICAL"
                                ev_level = "E4"
                                title = f"Path Traversal / LFI — {files_count} Files Read ({cand.parameter}, {technique})"
                                desc = f"Parameter '{cand.parameter}' allows arbitrary file read. Confirmed {target_file} + {files_count} additional files via {technique} technique."
                            else:
                                sev = "HIGH"
                                ev_level = "E3"
                                title = f"Path Traversal on '{cand.parameter}' ({technique})"
                                desc = f"Parameter '{cand.parameter}' returned {target_file} contents during directory traversal probing."

                            norm_res = NormalizedValidationResult(
                                adapter_name="path_traversal_validator",
                                vulnerability_type="path_traversal",
                                title=title,
                                severity=sev,
                                confidence=cand.confidence,
                                evidence_level=ev_level,
                                target_host=target_host,
                                endpoint_url=getattr(cand, "url", u.url),
                                parameter=cand.parameter,
                                cwe_id="CWE-22",
                                description=desc,
                                impact_matrix=getattr(cand, "impact_matrix", {}) or {"confidentiality": "HIGH", "integrity": "LOW", "availability": "LOW", "data_exposure": "HIGH"},
                                remediation="Implement path canonicalization, whitelist allowed filenames, and avoid direct filesystem path construction from parameters.",
                                poc_payload=cand_payload,
                                poc_command=cand_poc or f"curl -ksSL '{getattr(cand, 'url', u.url)}'",
                                reproduction_steps=getattr(cand, "reproduction_steps", []),
                                request_metadata={"url": getattr(cand, "url", u.url), "parameter": cand.parameter, "payload": cand_payload, "technique": technique},
                                response_metadata=cand.evidence if isinstance(getattr(cand, "evidence", None), dict) else {},
                                exploitation_data=expl_data,
                            )
                            collected.append((u.asset_id, target_host, norm_res))
                    except Exception as exc:
                        logger.debug("Path traversal validation error on %s: %s", u.url, exc)

                # 3e. Open Redirect Probes
                if ssrf_redirect_params:
                    try:
                        redir_cands = await open_redirect_validator.validate_url(u.url, ssrf_redirect_params)
                        for cand in redir_cands:
                            norm_res = NormalizedValidationResult(
                                adapter_name="open_redirect_validator",
                                vulnerability_type="open_redirect",
                                title=f"Open Redirect on Parameter '{cand.parameter}'",
                                severity="MEDIUM",
                                confidence=cand.confidence,
                                evidence_level="E2",
                                target_host=target_host,
                                endpoint_url=u.url,
                                parameter=cand.parameter,
                                cwe_id="CWE-601",
                                description=f"Parameter '{cand.parameter}' allows redirection to external domain ({cand.redirect_target}).",
                                impact_matrix={"confidentiality": "LOW", "integrity": "MEDIUM", "availability": "LOW"},
                                remediation="Use relative path redirects or strict domain whitelist.",
                                poc_payload=cand.evidence.get("poc_url") if isinstance(cand.evidence, dict) else u.url,
                                request_metadata={"url": u.url, "parameter": cand.parameter},
                            )
                            collected.append((u.asset_id, target_host, norm_res))
                    except Exception as exc:
                        logger.debug("Open redirect validation error on %s: %s", u.url, exc)

                # 3f. RCE / Command Injection Probes
                if rce_params:
                    try:
                        rce_cands = await rce_validator.validate_url(u.url, rce_params)
                        for cand in rce_cands:
                            rce_expl = getattr(cand, 'exploitation_data', {}) or {}
                            norm_res = NormalizedValidationResult(
                                adapter_name="rce_validator",
                                vulnerability_type="command_injection",
                                title=f"Command Injection on '{cand.parameter}' ({cand.technique}, {cand.os_type})",
                                severity="CRITICAL",
                                confidence=cand.confidence,
                                evidence_level="E4" if rce_expl else ("E3" if cand.confidence == "CONFIRMED" else "E2"),
                                target_host=target_host,
                                endpoint_url=u.url,
                                parameter=cand.parameter,
                                cwe_id="CWE-78",
                                description=f"Parameter '{cand.parameter}' allows OS command injection via {cand.technique}. OS: {cand.os_type}. Canary token confirmed.",
                                impact_matrix={"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "CRITICAL", "data_exposure": "CRITICAL"},
                                remediation="Never pass user input directly to shell commands. Use safe APIs and input validation.",
                                poc_command=cand.evidence.get("poc_curl", "") if isinstance(cand.evidence, dict) else "",
                                poc_payload=cand.evidence.get("probe", "") if isinstance(cand.evidence, dict) else "",
                                request_metadata={"url": u.url, "parameter": cand.parameter, "os_type": cand.os_type},
                                response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                                exploitation_data=rce_expl,
                            )
                            collected.append((u.asset_id, target_host, norm_res))
                    except Exception as exc:
                        logger.debug("RCE validation error on %s: %s", u.url, exc)

                # 3g. IDOR / Broken Access Control
                if idor_params:
                    try:
                        idor_cands = await idor_validator.validate_url(u.url, idor_params)
                        for cand in idor_cands:
                            idor_expl = getattr(cand, 'exploitation_data', {}) or {}
                            norm_res = NormalizedValidationResult(
                                adapter_name="idor_validator",
                                vulnerability_type="broken_access_control",
                                title=f"IDOR on '{cand.parameter}' (ID {cand.original_value} → {cand.modified_value})",
                                severity="CRITICAL" if idor_expl.get('sensitive_fields_exposed') else "HIGH",
                                confidence=cand.confidence,
                                evidence_level="E4" if idor_expl else "E2",
                                target_host=target_host,
                                endpoint_url=u.url,
                                parameter=cand.parameter,
                                cwe_id="CWE-639",
                                description=f"Parameter '{cand.parameter}' allows access to different objects by modifying ID. Technique: {cand.technique}.",
                                impact_matrix={"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW", "data_exposure": "HIGH"},
                                remediation="Implement server-side ownership checks and authorization on all resource lookups.",
                                poc_command=cand.evidence.get("poc_curl", "") if isinstance(cand.evidence, dict) else "",
                                request_metadata={"url": u.url, "parameter": cand.parameter},
                                response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                                exploitation_data=idor_expl,
                            )
                            collected.append((u.asset_id, target_host, norm_res))
                    except Exception as exc:
                        logger.debug("IDOR validation error on %s: %s", u.url, exc)

            return collected

        # Process target URLs in small batches to prevent starvation, support live progress updates, and check timeouts/cancellations
        batch_size = 10
        total_urls = len(target_urls)
        
        for idx in range(0, total_urls, batch_size):
            # Check if cancelled
            if kill_switch_manager.is_stopped(ctx.scan_id):
                logger.info("Scan cancelled during security validation phase.")
                await ctx.emit("scan.validate", "Security validation cancelled by operator.", severity="warn")
                break
                
            batch = target_urls[idx : idx + batch_size]
            await ctx.emit(
                "scan.validate",
                f"Testing injection vectors: batch {idx // batch_size + 1}/{(total_urls + batch_size - 1) // batch_size} ({idx}/{total_urls} URLs completed)...",
                stage="PARAM_VALIDATION",
            )
            
            # Wrap each URL task in a strict timeout to prevent any hanging validator from blocking the entire pipeline
            async def _validate_with_timeout(u: URL, p_list: list[dict[str, str]]) -> list:
                try:
                    return await asyncio.wait_for(
                        _validate_single_url(u, p_list),
                        timeout=90.0  # 90 seconds max per URL endpoint validation
                    )
                except asyncio.TimeoutError:
                    logger.warning("Timeout validating URL: %s", u.url)
                    await ctx.emit("scan.validate", f"Validation timed out for {u.url} (skipped)", severity="warn")
                    return []
                except Exception as e:
                    logger.error("Error during validation of URL %s: %s", u.url, e)
                    return []

            url_tasks = [_validate_with_timeout(u, params_by_url.get(u.id, [])) for u in batch]
            batch_results = await asyncio.gather(*url_tasks, return_exceptions=True)
            
            for res in batch_results:
                if isinstance(res, list):
                    for asset_id, target_host, norm_res in res:
                        await _process_and_save_validated_finding(ctx, db, asset_id, target_host, norm_res)
            
            await db.commit()

    # 4. Technology to CVE Intelligence (Observations only — V5 §23, §24, §40 Zero False Positive Rule)
    techs = (await db.execute(
        select(Technology).where(Technology.asset_id.in_(asset_ids_query))
    )).scalars().all()

    if techs:
        await ctx.emit("scan.cve", f"Correlating CVE and zero-day threat advisories for {len(techs)} identified component(s)...", stage="CVE_INTEL")

    for tech in techs:
        cve_candidates = CveIntelligence.match_candidates(tech.name, tech.version)
        asset_obj = asset_map.get(tech.asset_id)
        target_host = asset_obj.hostname if asset_obj else root_domain

        for cve in cve_candidates:
            await result_service.upsert_observation(
                db,
                scan_id=ctx.scan_id,
                asset_id=tech.asset_id,
                observation_type="cve_intel",
                title=f"Potential Advisory: {cve['cve_id']} ({tech.name} {tech.version or ''})".strip(),
                evidence={
                    "technology": tech.name,
                    "version": tech.version,
                    "cve_id": cve.get("cve_id"),
                    "title": cve.get("title"),
                    "cvss_score": cve.get("cvss_score"),
                    "requires_active_validation": True,
                },
                confidence=0.35,
            )

    # 5. MITRE ATT&CK TTP Correlation (§26)
    for trigger_name in ["cve", "port_scan", "web_probe", "ct_logs"]:
        ttps = TtpEngine.correlate(trigger_name)
        for ttp in ttps:
            ttp_obs = TtpObservation(
                scan_id=ctx.scan_id,
                technique_id=ttp["technique_id"],
                technique_name=ttp["technique_name"],
                tactic=ttp["tactic"],
                confidence=ttp["confidence"],
                evidence={"trigger": trigger_name},
                mitre_url=ttp.get("mitre_url"),
            )
            db.add(ttp_obs)

    # 6. Service Protocol Deep Assessments (SSH & RDP) (§16, §17)
    ports = (await db.execute(
        select(Port).where(Port.asset_id.in_(asset_ids_query))
    )).scalars().all()

    ssh_engine = SshAssessment()
    rdp_engine = RdpAssessment()
    for p in ports:
        asset_obj = asset_map.get(p.asset_id)
        target_host = asset_obj.hostname if asset_obj else root_domain
        if p.port == 22 and p.state == "open" and p.ip:
            await ctx.emit("scan.network", f"Inspecting SSH protocol security on {target_host}:22...", host=target_host, stage="SSH_AUDIT")
            ssh_result = await ssh_engine.assess(p.ip, p.port)
            for f in ssh_result.findings:
                norm_res = NormalizedValidationResult(
                    adapter_name="ssh_assessment",
                    vulnerability_type="ssh_security",
                    title=f["title"],
                    severity=f["severity"],
                    confidence="VALIDATED",
                    evidence_level=f.get("evidence_level", "E2"),
                    target_host=target_host,
                    cwe_id=f.get("cwe"),
                    cve_id=f.get("cve"),
                    description=f["description"],
                    impact_matrix={"confidentiality": "MEDIUM", "integrity": "LOW", "availability": "LOW"},
                    remediation="Update OpenSSH and disable weak KEX/cipher algorithms in sshd_config.",
                    response_metadata=f.get("evidence", {}),
                )
                await _process_and_save_validated_finding(ctx, db, p.asset_id, target_host, norm_res)
        elif p.port == 3389 and p.state == "open" and p.ip:
            await ctx.emit("scan.network", f"Inspecting RDP protocol security on {target_host}:3389...", host=target_host, stage="RDP_AUDIT")
            rdp_result = await rdp_engine.assess(p.ip, p.port)
            for f in rdp_result.findings:
                norm_res = NormalizedValidationResult(
                    adapter_name="rdp_assessment",
                    vulnerability_type="rdp_security",
                    title=f["title"],
                    severity=f["severity"],
                    confidence="VALIDATED",
                    evidence_level=f.get("evidence_level", "E2"),
                    target_host=target_host,
                    cwe_id=f.get("cwe"),
                    cve_id=f.get("cve"),
                    description=f["description"],
                    impact_matrix={"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW"},
                    remediation="Enable Network Level Authentication (NLA) and restrict RDP port 3389 via VPN gateway.",
                    response_metadata=f.get("evidence", {}),
                )
                await _process_and_save_validated_finding(ctx, db, p.asset_id, target_host, norm_res)

    # 6b. Service Exploitation Engine — Test discovered services for default creds / unauth access
    exploitable_ports = [p for p in ports if p.state == "open" and p.ip and p.port in (
        21, 3306, 33060, 6379, 9200, 9300, 11211, 27017, 27018,
    )]
    if exploitable_ports:
        await ctx.emit("scan.network", f"Testing {len(exploitable_ports)} discovered service(s) for default credentials and unauthenticated access...", stage="SERVICE_EXPLOIT")

    for p in exploitable_ports:
        asset_obj = asset_map.get(p.asset_id)
        target_host = asset_obj.hostname if asset_obj else root_domain
        service_hint = p.service or ""

        try:
            exploit_cands = await service_exploit_validator.test_port(p.ip, p.port, service_hint)
            for cand in exploit_cands:
                norm_res = NormalizedValidationResult(
                    adapter_name="service_exploit_validator",
                    vulnerability_type=f"{cand.service.lower()}_{cand.technique}",
                    title=cand.title,
                    severity=cand.severity,
                    confidence=cand.confidence,
                    evidence_level=cand.evidence_level,
                    target_host=target_host,
                    endpoint_url=f"{p.ip}:{p.port}",
                    cwe_id=cand.cwe_id,
                    description=cand.description,
                    impact_matrix=cand.impact_matrix,
                    remediation=cand.remediation,
                    poc_command=cand.poc_curl,
                    reproduction_steps=cand.reproduction_steps,
                    request_metadata={"host": p.ip, "port": p.port, "service": cand.service},
                    response_metadata=cand.evidence,
                    actual_result=f"{cand.technique} confirmed on {cand.service} service",
                    expected_result="Service should require authentication and not accept default credentials.",
                )
                await _process_and_save_validated_finding(ctx, db, p.asset_id, target_host, norm_res)
                logger.info("CONFIRMED SERVICE EXPLOIT on %s:%d: %s", target_host, p.port, cand.title)
        except Exception as svc_err:
            logger.debug("Service exploit test error on %s:%d: %s", p.ip, p.port, svc_err)

    # 7. Auth Bypass Validation (V5 §17) — test discovered URLs
    try:
        all_url_strings = [u.url for u in urls if u.url]
        for asset_id_key, asset_obj in asset_map.items():
            target_host = asset_obj.hostname if asset_obj else root_domain
            base = f"https://{target_host}"
            await ctx.emit("scan.auth", f"Evaluating authentication bypass headers on {target_host}...", host=target_host, stage="AUTH_BYPASS")
            auth_cands = await auth_bypass_validator.validate_url(base, all_url_strings[:50])
            for cand in auth_cands:
                norm_res = NormalizedValidationResult(
                    adapter_name="auth_bypass_validator",
                    vulnerability_type="authentication_bypass",
                    title=f"Authentication Bypass on {cand.endpoint}",
                    severity="HIGH",
                    confidence=cand.confidence,
                    evidence_level="E2",
                    target_host=target_host,
                    endpoint_url=cand.url,
                    cwe_id="CWE-287",
                    description=f"Endpoint '{cand.endpoint}' accessible without authentication. {cand.technique}.",
                    impact_matrix={"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW"},
                    remediation="Enforce authentication on all protected endpoints. Implement access control middleware.",
                    poc_command=cand.evidence.get("poc_curl", "") if isinstance(cand.evidence, dict) else "",
                    response_metadata=cand.evidence if isinstance(cand.evidence, dict) else {},
                )
                await _process_and_save_validated_finding(ctx, db, asset_id_key, target_host, norm_res)
            break
    except Exception as exc:
        logger.debug("Auth bypass validation error: %s", exc)

    # 8. WordPress Deep Assessment (V4 §75-77, V5 §18)
    try:
        wp_intel = WordPressIntelligence()
        for tech in techs:
            if tech.name and "wordpress" in tech.name.lower():
                asset_obj = asset_map.get(tech.asset_id)
                target_host = asset_obj.hostname if asset_obj else root_domain
                base = f"https://{target_host}"
                await ctx.emit("scan.security", f"Executing WordPress security assessment on {target_host}...", host=target_host, stage="WORDPRESS_AUDIT")
                wp_info = WordPressIntelligence.analyze_html_and_headers("", {})
                wp_info["is_wordpress"] = True
                wp_info["version"] = tech.version
                wp_result = await wp_intel.deep_assess(base, wp_info)
                for f in wp_result.get("findings", []):
                    norm_res = NormalizedValidationResult(
                        adapter_name="wordpress_intelligence",
                        vulnerability_type="wordpress_security",
                        title=f["title"],
                        severity=f["severity"],
                        confidence="VALIDATED",
                        evidence_level=f.get("evidence_level", "E1"),
                        target_host=target_host,
                        cwe_id=f.get("cwe"),
                        cve_id=f.get("cve"),
                        description=f["description"],
                        response_metadata=f.get("evidence", {}),
                        remediation=f"Update WordPress and all plugins/themes to latest versions. Restrict access to sensitive endpoints.",
                    )
                    await _process_and_save_validated_finding(ctx, db, tech.asset_id, target_host, norm_res)
    except Exception as exc:
        logger.debug("WordPress deep assessment error: %s", exc)

    # 9. Multi-Tech Deep CVE Exploitation Engine (Apache, Nginx, PHP, Next.js, Spring, Laravel, etc.)
    try:
        for asset_id_key, asset_obj in asset_map.items():
            target_host = asset_obj.hostname if asset_obj else root_domain
            asset_urls = [u.url for u in urls if u.asset_id == asset_id_key and u.url]
            discovered_bases = list({urlparse(u).scheme + "://" + urlparse(u).netloc for u in asset_urls if urlparse(u).netloc})[:3]
            if not discovered_bases:
                discovered_bases = [f"https://{target_host}", f"http://{target_host}"]

            tech_dicts = [{"name": t.name, "version": t.version or ""} for t in techs if t.asset_id == asset_id_key]
            if tech_dicts:
                await ctx.emit("scan.cve", f"Running multi-tech CVE vulnerability probes on {target_host} ({len(tech_dicts)} tech stack elements)...", host=target_host, stage="CVE_EXPLOITATION")

            for base_url in discovered_bases:
                exploit_results = await cve_exploit_engine.exploit_all(base_url, tech_dicts)
                for exp in exploit_results:
                    norm_res = NormalizedValidationResult(
                        adapter_name="cve_exploit_engine",
                        vulnerability_type=exp.impact_type,
                        title=f"{exp.cve_id} — {exp.title}",
                        severity=exp.severity,
                        confidence=exp.confidence,
                        evidence_level=exp.evidence_level,
                        target_host=target_host,
                        endpoint_url=exp.evidence.get("url") or base_url,
                        cwe_id=exp.cwe_id,
                        cve_id=exp.cve_id,
                        cvss_score=exp.cvss_score,
                        description=f"Automated controlled PoC exploitation confirmed on {target_host} ({exp.technology} {exp.version}). Technique: {exp.technique}.",
                        impact_matrix=exp.impact_matrix or {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "MEDIUM"},
                        remediation=exp.remediation or "Upgrade component to latest vendor patched release.",
                        poc_command=exp.poc_curl,
                        reproduction_steps=exp.reproduction_steps,
                        request_metadata={"url": exp.evidence.get("url") or base_url, "technique": exp.technique},
                        response_metadata=exp.evidence,
                        actual_result=f"Confirmed active exploit condition: {exp.technique}",
                        expected_result="Application/Server should reject exploit vector or return 404/403.",
                    )
                    await _process_and_save_validated_finding(ctx, db, asset_id_key, target_host, norm_res)
                    logger.info("CONFIRMED CVE EXPLOIT on %s: %s (%s)", target_host, exp.cve_id, exp.title)
    except Exception as exc:
        logger.debug("CVE exploitation engine error: %s", exc)

    # 10. 403 Access Control Bypass Engine (Path mutations, headers, method switching)
    try:
        for asset_id_key, asset_obj in asset_map.items():
            target_host = asset_obj.hostname if asset_obj else root_domain
            disc_url_strings = [u.url for u in urls if u.asset_id == asset_id_key and u.url]
            discovered_bases = list({urlparse(u).scheme + "://" + urlparse(u).netloc for u in disc_url_strings if urlparse(u).netloc})[:3]
            if not discovered_bases:
                discovered_bases = [f"https://{target_host}", f"http://{target_host}"]

            if disc_url_strings:
                await ctx.emit("scan.auth", f"Testing 403 access control bypass headers & path rewrites on {target_host}...", host=target_host, stage="ACCESS_CONTROL")

            for base_url in discovered_bases:
                bypass_results = await bypass_403_engine.scan_target(base_url, disc_url_strings)
                for bp in bypass_results:
                    norm_res = NormalizedValidationResult(
                        adapter_name="bypass_403_engine",
                        vulnerability_type="access_control_bypass",
                        title=f"403 Access Control Bypass on {bp.original_url} ({bp.technique_detail})",
                        severity="HIGH",
                        confidence=bp.confidence,
                        evidence_level=bp.evidence_level,
                        target_host=target_host,
                        endpoint_url=bp.url,
                        cwe_id="CWE-284",
                        description=f"Endpoint {bp.original_url} returned HTTP {bp.original_status} but was bypassed to HTTP 200 via {bp.technique_detail}.",
                        impact_matrix={"confidentiality": "HIGH", "integrity": "MEDIUM", "availability": "LOW", "auth_bypass": "CONFIRMED"},
                        remediation="Enforce access control uniformly at the application layer rather than relying on reverse proxy URL filtering.",
                        poc_command=bp.poc_curl,
                        reproduction_steps=bp.reproduction_steps,
                        request_metadata={"original_url": bp.original_url, "bypass_url": bp.url, "technique": bp.technique_detail},
                        response_metadata=bp.evidence,
                        actual_result=f"HTTP 200 OK returned on protected resource via {bp.technique_detail}",
                        expected_result=f"HTTP {bp.original_status} Forbidden/Unauthorized enforcement on all request variants.",
                    )
                    await _process_and_save_validated_finding(ctx, db, asset_id_key, target_host, norm_res)
                    logger.info("CONFIRMED 403 BYPASS on %s: %s", target_host, bp.technique_detail)
    except Exception as exc:
        logger.debug("403 Bypass engine error: %s", exc)

    # 11. Controlled Authentication & Credential Policy Audit (V9.1 Dynamic Crawl-Driven)
    try:
        # V9.1: Only audit URLs that were VERIFIED to contain actual login forms during crawling
        login_urls_with_forms = [
            u for u in urls
            if u.content_type == "login_form" and u.status_code == 200
        ]
        if not login_urls_with_forms:
            await ctx.emit(
                "scan.auth",
                "No active login portals discovered during crawl — skipping static auth audit. "
                "Auth endpoints will only be tested when genuine login forms are found dynamically.",
                stage="AUTH_AUDIT_SKIPPED",
            )

        # Collect discovered credentials from artifacts for credential reuse testing
        discovered_creds: list[tuple[str, str]] = []
        discovered_usernames: list[str] = []
        try:
            from app.models.models import Artifact
            scan_artifacts = (await db.execute(
                select(Artifact).where(Artifact.scan_id == ctx.scan_id)
            )).scalars().all()

            for art in scan_artifacts:
                if art.extracted_entities:
                    # Extract from SQL dump entities
                    for user_entry in (art.extracted_entities.get("users") or [])[:20]:
                        uname = user_entry.get("username") or user_entry.get("email", "")
                        pwd = user_entry.get("password", "")
                        if uname:
                            discovered_usernames.append(uname)
                            if pwd:
                                discovered_creds.append((uname, pwd))

                    # Extract from .env secrets
                    for secret in (art.extracted_entities.get("secrets") or [])[:10]:
                        key = secret.get("key", "").lower()
                        val = secret.get("value", "")
                        if val and any(k in key for k in ("password", "pwd", "pass", "secret")):
                            for admin_user in ["admin", "root", "administrator"]:
                                discovered_creds.append((admin_user, val))

                if art.schema_data:
                    # Extract from CSV PII data
                    for email in (art.schema_data.get("sample_emails") or [])[:10]:
                        if email and email not in discovered_usernames:
                            discovered_usernames.append(email)

            if discovered_creds or discovered_usernames:
                logger.info(
                    "Collected %d credential pairs and %d usernames from artifacts for auth testing",
                    len(discovered_creds), len(discovered_usernames),
                )
        except Exception as cred_exc:
            logger.debug("Credential collection from artifacts failed: %s", cred_exc)

        for u_obj in login_urls_with_forms[:5]:
            l_url = u_obj.url
            target_asset_id = u_obj.asset_id
            asset_obj = asset_map.get(target_asset_id)
            target_host = asset_obj.hostname if asset_obj else root_domain

            await ctx.emit(
                "scan.auth",
                f"🔐 Auditing authentication rate-limiting & credential policy on crawl-discovered login: {l_url}"
                + (f" (+ {len(discovered_creds)} discovered credentials)" if discovered_creds else ""),
                url=l_url,
                stage="AUTH_AUDIT_DYNAMIC",
            )
            brute_cands = await controlled_brute_force_validator.validate_login_portal(
                l_url,
                discovered_credentials=discovered_creds or None,
                discovered_usernames=discovered_usernames or None,
            )
            for cand in brute_cands:
                norm_res = NormalizedValidationResult(
                    adapter_name="controlled_brute_force",
                    vulnerability_type=cand.finding_type,
                    title=cand.title,
                    severity=cand.severity,
                    confidence=cand.confidence,
                    evidence_level=cand.evidence_level,
                    target_host=target_host,
                    endpoint_url=cand.url,
                    cwe_id="CWE-287" if cand.finding_type == "default_credentials" else "CWE-307",
                    description=f"Authentication policy validation on crawl-discovered login form {cand.url}: {cand.title}.",
                    impact_matrix=cand.impact_matrix,
                    remediation=cand.remediation,
                    poc_command=cand.poc_curl,
                    reproduction_steps=cand.reproduction_steps,
                    request_metadata={"url": cand.url, "technique": cand.technique, "discovery_method": "dynamic_crawl"},
                    response_metadata=cand.evidence,
                    actual_result=cand.title,
                    expected_result="Application should enforce rate-limiting / lockout and reject default passwords.",
                )
                await _process_and_save_validated_finding(ctx, db, target_asset_id, target_host, norm_res)
    except Exception as exc:
        logger.debug("Controlled authentication validation error: %s", exc)

    # 12. Information Disclosure & Diagnostic Endpoints (server-status, .git, etc.)
    try:
        for asset_id_key, asset_obj in asset_map.items():
            target_host = asset_obj.hostname if asset_obj else root_domain
            asset_urls = [u.url for u in urls if u.asset_id == asset_id_key and u.url]
            discovered_bases = list({urlparse(u).scheme + "://" + urlparse(u).netloc for u in asset_urls if urlparse(u).netloc})
            if not discovered_bases:
                discovered_bases = [f"https://{target_host}", f"http://{target_host}"]

            for base_url in discovered_bases:
                disc_findings = await info_disclosure_validator.scan_base_url(base_url)
                for df in disc_findings:
                    norm_res = NormalizedValidationResult(
                        adapter_name="info_disclosure_validator",
                        vulnerability_type=df.finding_type,
                        title=df.title,
                        severity=df.severity,
                        confidence=df.confidence,
                        evidence_level=df.evidence_level,
                        target_host=target_host,
                        endpoint_url=df.url,
                        cwe_id=df.cwe_id,
                        description=df.description,
                        impact_matrix=df.impact_matrix,
                        remediation=df.remediation,
                        poc_command=df.poc_curl,
                        request_metadata={"url": df.url},
                        response_metadata={"evidence_sample": df.evidence_sample},
                        actual_result=f"Accessible endpoint returning valid sensitive content signature.",
                        expected_result="HTTP 404 Not Found or HTTP 403 Forbidden.",
                    )
                    await _process_and_save_validated_finding(ctx, db, asset_id_key, target_host, norm_res)
    except Exception as exc:
        logger.debug("Info disclosure validator error: %s", exc)

    # 13. TLS Certificate Validity Checks (§18)
    certs = (await db.execute(
        select(Certificate).where(Certificate.asset_id.in_(asset_ids_query))
    )).scalars().all()

    now = datetime.now(timezone.utc)
    for cert in certs:
        if not cert.not_after:
            continue

        if cert.not_after < now:
            await ctx.emit("scan.cert", f"Expired TLS certificate detected on {cert.hostname}!", host=cert.hostname, severity="warn")
            norm_res = NormalizedValidationResult(
                adapter_name="tls_assessment",
                vulnerability_type="tls_expired",
                title=f"Expired TLS Certificate for {cert.hostname}",
                severity="HIGH",
                confidence="CONFIRMED",
                evidence_level="E3",
                target_host=cert.hostname,
                cwe_id="CWE-295",
                description=f"Sertifikat SSL/TLS untuk host {cert.hostname} telah kedaluwarsa pada {cert.not_after.strftime('%d %b %Y %H:%M:%S UTC')}.",
                impact_matrix={"confidentiality": "HIGH", "integrity": "HIGH", "availability": "LOW"},
                remediation="Perbarui sertifikat SSL/TLS dengan sertifikat baru yang valid dari Certificate Authority terpercaya.",
            )
            await _process_and_save_validated_finding(ctx, db, cert.asset_id, cert.hostname, norm_res)

    # 14. Asset-Driven Escalation Phase (V9.1 — Credential Reuse, .env Exploitation, Identity Correlation)
    try:
        from app.intelligence.escalation import escalation_engine
        from app.models.models import Artifact

        # Collect all login forms discovered during crawling
        login_form_descriptors = []
        for u in urls:
            if u.content_type == "login_form" and u.status_code == 200:
                login_form_descriptors.append({
                    "url": u.url,
                    "action_url": u.url,  # Form action resolved during crawl
                    "username_field_name": "username",  # Default; enhanced by crawler metadata
                    "password_field_name": "password",
                    "hidden_tokens": {},
                })

        # Query all artifacts from this scan
        scan_artifacts = (await db.execute(
            select(Artifact).where(Artifact.scan_id == ctx.scan_id)
        )).scalars().all()

        for artifact in scan_artifacts:
            asset_obj = asset_map.get(artifact.asset_id) if artifact.asset_id else None
            target_host = asset_obj.hostname if asset_obj else root_domain
            art_asset_id = artifact.asset_id or list(asset_map.keys())[0] if asset_map else None

            # SQL Dump Escalation
            if artifact.file_type in ("sql_dump", "backup_sql") and artifact.extracted_entities:
                await ctx.emit(
                    "scan.escalation",
                    f"🔗 Escalating from SQL dump artifact: {artifact.filename} "
                    f"({artifact.extracted_entities.get('users', []).__len__()} users, "
                    f"{artifact.extracted_entities.get('hashes', []).__len__()} hashes) "
                    f"→ credential reuse testing on {len(login_form_descriptors)} discovered login forms",
                    stage="ASSET_ESCALATION",
                )
                esc_results = await escalation_engine.escalate_from_sql_dump(
                    {
                        "sha256_hash": artifact.sha256_hash,
                        "extracted_entities": artifact.extracted_entities,
                        "schema_data": artifact.schema_data,
                        "url": artifact.metadata_.get("url", ""),
                    },
                    login_form_descriptors,
                )
                for esc in esc_results:
                    norm_res = NormalizedValidationResult(
                        adapter_name="asset_escalation_engine",
                        vulnerability_type=esc.escalation_type,
                        title=esc.title,
                        severity=esc.severity,
                        confidence=esc.confidence,
                        evidence_level=esc.evidence_level,
                        target_host=target_host,
                        endpoint_url=esc.target_url,
                        cwe_id=esc.cwe_id,
                        description=f"Asset-driven escalation from {artifact.filename}: {esc.title}",
                        impact_matrix=esc.impact_matrix,
                        remediation=esc.remediation,
                        poc_command=esc.poc_curl,
                        reproduction_steps=esc.reproduction_steps,
                        request_metadata={"source_artifact": artifact.sha256_hash, "escalation_type": esc.escalation_type},
                        response_metadata=esc.evidence,
                        actual_result=esc.title,
                        expected_result="Artifacts should not be publicly accessible and credentials should not be reusable.",
                    )
                    await _process_and_save_validated_finding(ctx, db, art_asset_id, target_host, norm_res)

            # .env File Escalation
            elif artifact.file_type in ("env_file", "env") and artifact.storage_path:
                try:
                    import pathlib
                    env_path = pathlib.Path(artifact.storage_path)
                    if env_path.exists():
                        env_content = env_path.read_text(encoding="utf-8", errors="ignore")
                        if env_content.strip():
                            await ctx.emit(
                                "scan.escalation",
                                f"🔗 Escalating from .env artifact: {artifact.filename} "
                                f"→ credential extraction & reuse testing",
                                stage="ASSET_ESCALATION",
                            )
                            esc_results = await escalation_engine.escalate_from_env(
                                env_content, login_form_descriptors,
                                artifact.sha256_hash,
                                artifact.metadata_.get("url", ""),
                            )
                            for esc in esc_results:
                                norm_res = NormalizedValidationResult(
                                    adapter_name="asset_escalation_engine",
                                    vulnerability_type=esc.escalation_type,
                                    title=esc.title,
                                    severity=esc.severity,
                                    confidence=esc.confidence,
                                    evidence_level=esc.evidence_level,
                                    target_host=target_host,
                                    endpoint_url=esc.target_url,
                                    cwe_id=esc.cwe_id,
                                    description=f"Asset-driven escalation from {artifact.filename}: {esc.title}",
                                    impact_matrix=esc.impact_matrix,
                                    remediation=esc.remediation,
                                    poc_command=esc.poc_curl,
                                    request_metadata={"source_artifact": artifact.sha256_hash, "escalation_type": esc.escalation_type},
                                    response_metadata=esc.evidence,
                                    actual_result=esc.title,
                                    expected_result="Environment files should never be publicly accessible.",
                                )
                                await _process_and_save_validated_finding(ctx, db, art_asset_id, target_host, norm_res)
                except Exception as env_exc:
                    logger.debug("ENV escalation read error: %s", env_exc)

            # CSV Identity Correlation
            elif artifact.file_type in ("csv_export", "csv", "data_export") and artifact.schema_data:
                if artifact.schema_data.get("pii_headers"):
                    await ctx.emit(
                        "scan.escalation",
                        f"🔗 Escalating from CSV artifact: {artifact.filename} "
                        f"({artifact.schema_data.get('row_count', 0)} rows, PII: {', '.join(artifact.schema_data.get('pii_headers', [])[:3])}) "
                        f"→ identity correlation",
                        stage="ASSET_ESCALATION",
                    )
                    esc_results = await escalation_engine.escalate_from_csv_identities(
                        artifact.schema_data, login_form_descriptors,
                        artifact.sha256_hash,
                        artifact.metadata_.get("url", ""),
                    )
                    for esc in esc_results:
                        norm_res = NormalizedValidationResult(
                            adapter_name="asset_escalation_engine",
                            vulnerability_type=esc.escalation_type,
                            title=esc.title,
                            severity=esc.severity,
                            confidence=esc.confidence,
                            evidence_level=esc.evidence_level,
                            target_host=target_host,
                            endpoint_url=esc.target_url,
                            cwe_id=esc.cwe_id,
                            description=f"Asset-driven escalation from {artifact.filename}: {esc.title}",
                            impact_matrix=esc.impact_matrix,
                            remediation=esc.remediation,
                            request_metadata={"source_artifact": artifact.sha256_hash, "escalation_type": esc.escalation_type},
                            response_metadata=esc.evidence,
                            actual_result=esc.title,
                            expected_result="PII data exports should not be publicly accessible.",
                        )
                        await _process_and_save_validated_finding(ctx, db, art_asset_id, target_host, norm_res)

    except Exception as exc:
        logger.debug("Asset-driven escalation phase error: %s", exc)

    await db.commit()
