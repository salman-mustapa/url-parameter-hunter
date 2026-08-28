"""Deep Live Retest & Remediation Verification Engine (V9.1 §23, §24).

Implements targeted, deep vulnerability-focused retesting across all 18 validation families:
1. Dynamically maps finding to its specialized validation suite:
   - Sensitive File / DB Exposure: SensitiveFileValidator (Signature & Soft-404 verification)
   - Auth Bypass / Admin Portal: AuthBypassValidator (3-stage differential & form manipulation)
   - SQL Injection: SqliValidator (Boolean, Error, Time, UNION families)
   - Cross-Site Scripting: XssValidator (Contextual reflection & execution)
   - IDOR / BOLA: IdorValidator (Multi-principal boundary verification)
   - CSRF: CsrfValidator (Token & Origin validation)
   - CORS: CorsValidator (Origin reflection with ACAC)
   - SSTI: SstiValidator (Math expression canary evaluation)
   - JWT / OAuth: JwtValidator (alg:none & signature stripping)
   - GraphQL: GraphqlValidator (Introspection probe)
   - WebSocket: WebSocketValidator (CSWSH handshake)
   - Host Header: HostHeaderValidator (Host poisoning reflection)
   - File Upload: FileUploadValidator (Extension & Canary verification)
   - Path Traversal: PathTraversalValidator (Canary file read)
   - RCE: RceValidator (Harmless canary execution)
   - Open Redirect: OpenRedirectValidator (Location validation)
   - Request Smuggling: RequestSmugglingValidator (CL.TE desync probe)
   - Insecure Deserialization: DeserializationValidator (Object signature probe)
2. Captures full Before vs After network telemetry and evidence diff across multiple HTTP methods.
3. Manages Finding & Retest State Machine transitions (RETESTING -> FIXED / NOT_FIXED / REOPENED).
4. Emits real-time SSE telemetry.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import event_bus
from app.models.models import Asset, Evidence, Finding, Retest
from app.scanners.http import fetch_http
from app.validation.auth_bypass import auth_bypass_validator
from app.validation.cors import cors_validator
from app.validation.csrf import csrf_validator
from app.validation.deserialization import deserialization_validator
from app.validation.file_upload import file_upload_validator
from app.validation.graphql import graphql_validator
from app.validation.host_header import host_header_validator
from app.validation.idor import idor_validator
from app.validation.jwt_oauth import jwt_validator
from app.validation.open_redirect import open_redirect_validator
from app.validation.path_traversal import path_traversal_validator
from app.validation.poc import CapturedRequestPoCBuilder
from app.validation.rce import rce_validator
from app.validation.request_smuggling import request_smuggling_validator
from app.validation.sensitive_files import SensitiveFileValidator, soft_404_detector
from app.validation.sqli import sqli_validator
from app.validation.ssrf import ssrf_validator
from app.validation.ssti import ssti_validator
from app.validation.websocket import websocket_validator
from app.validation.xss import xss_validator

logger = logging.getLogger("retest.engine")


class RetestEngine:
    """Targeted Deep Vulnerability Retest & Remediation Verification Engine."""

    async def create_and_execute_retest(
        self,
        db: AsyncSession,
        finding_id: str,
        tester_id: Optional[str] = None,
    ) -> dict:
        """Executes a targeted, deep live retest against the finding target and records evidence diff."""
        finding = (await db.execute(
            select(Finding).where(Finding.id == finding_id)
        )).scalar_one_or_none()

        if not finding:
            return {"error": "Finding not found"}

        ev_dict = finding.evidence if isinstance(finding.evidence, dict) else {}
        target_url = ev_dict.get("url") or ev_dict.get("location") or ev_dict.get("endpoint_url")
        if not target_url and finding.title:
            for k in ("target", "endpoint", "url"):
                if ev_dict.get(k):
                    target_url = ev_dict[k]
                    break

        before_status = finding.status
        now_iso = datetime.now(timezone.utc).isoformat()

        retest_id = f"rt_{uuid.uuid4().hex[:12]}"
        retest = Retest(
            id=retest_id,
            scan_id=finding.scan_id,
            finding_id=finding_id,
            operator_id=tester_id,
            status="RUNNING",
            comparison_result={},
        )
        db.add(retest)
        finding.status = "RETESTING"
        await db.commit()

        # Emit realtime event
        try:
            evt = event_bus.make_event(
                scan_id=finding.scan_id,
                event_type="retest.started",
                message=f"Memulai live retest mendalam untuk temuan '{finding.title}' pada {target_url or 'target'}...",
                data={"finding_id": finding_id, "retest_id": retest_id, "target_url": target_url},
            )
            await event_bus.publish(evt)
        except Exception as bus_err:
            logger.debug("EventBus publish error: %s", bus_err)

        still_vulnerable = False
        retest_details: Dict[str, Any] = {}
        after_evidence: Dict[str, Any] = {
            "retested_at": now_iso,
            "target_url": target_url,
            "status_code": None,
            "response_hash": None,
            "verification_method": "specialized_deep_validator",
            "findings_detected": [],
            "tested_methods": [],
        }

        f_type = (finding.finding_type or "").lower()
        f_title = (finding.title or "").lower()

        # ----------------------------------------------------------------------
        # Specialized Deep Retest Routing
        # ----------------------------------------------------------------------
        try:
            async with asyncio.timeout(60):
                if target_url and target_url.startswith(("http://", "https://", "ws://", "wss://")):
                    parsed_target = urlparse(target_url)
                    parsed_path = parsed_target.path.lower()
                    parsed_params = parse_qs(parsed_target.query)

                    # 1. Sensitive File & Database Dump Exposure Retest
                    is_sensitive_file = (
                        any(k in f_type for k in ("backup", "dump", "sensitive", "exposure", "csv", "env", "git", "log"))
                        or any(parsed_path.endswith(ext) for ext in (".sql", ".dump", ".csv", ".tsv", ".log", ".bak", ".zip", ".tar.gz"))
                        or "/.env" in parsed_path
                        or "/.git" in parsed_path
                    ) and not any(k in f_type for k in ("auth", "admin_portal", "sqli_auth_bypass"))

                    if is_sensitive_file:
                        logger.info("Executing deep Sensitive File Exposure retest on %s", target_url)
                        resp = await fetch_http(target_url, timeout=8.0)
                        if resp:
                            after_evidence["status_code"] = resp.status_code
                            after_evidence["response_hash"] = hashlib.sha256(resp.text.encode()).hexdigest()[:16]
                            if resp.status_code == 200:
                                inferred_type = (
                                    "backup_sql" if parsed_path.endswith((".sql", ".dump"))
                                    else ("csv" if parsed_path.endswith((".csv", ".tsv"))
                                    else ("env" if "/.env" in parsed_path
                                    else ("git_head" if ".git" in parsed_path
                                    else "backup_archive")))
                                )
                                is_valid, reason, meta = SensitiveFileValidator.validate_content_signature(
                                    file_type=inferred_type,
                                    url=target_url,
                                    status_code=resp.status_code,
                                    content=resp.text,
                                    content_type=resp.headers.get("content-type", ""),
                                )
                                if is_valid:
                                    still_vulnerable = True
                                    after_evidence["findings_detected"].append("sensitive_content_still_exposed")
                                    retest_details["signature_reason"] = reason

                    # 2. Authentication Bypass & Administrative Portal Exposure
                    elif any(k in f_type for k in ("auth", "admin", "login", "session")) or any(k in f_title for k in ("auth", "admin", "login", "administrator")):
                        logger.info("Executing deep Auth Bypass retest on %s", target_url)
                        auth_candidates = await auth_bypass_validator.validate(target_url, discovered_urls=[target_url])
                        if auth_candidates:
                            still_vulnerable = True
                            after_evidence["findings_detected"] = [c.technique for c in auth_candidates]
                            retest_details["auth_candidates"] = [c.evidence for c in auth_candidates]
                            after_evidence["status_code"] = auth_candidates[0].evidence.get("status_code")
                        else:
                            resp = await fetch_http(target_url, timeout=8.0)
                            if resp:
                                after_evidence["status_code"] = resp.status_code
                                after_evidence["response_hash"] = hashlib.sha256(resp.text.encode()).hexdigest()[:16]

                    # 3. SQL Injection Parameter Retest
                    elif "sqli" in f_type or ("sql" in f_title and "dump" not in f_title) or "injection" in f_type:
                        logger.info("Executing deep SQL Injection retest on %s", target_url)
                        param_name = ev_dict.get("parameter") or (list(parsed_params.keys())[0] if parsed_params else "id")
                        location = ev_dict.get("location") or ("query" if parsed_params else "body")
                        sqli_candidates = await sqli_validator.validate_url(target_url, [{"name": param_name, "location": location}])
                        if sqli_candidates:
                            still_vulnerable = True
                            after_evidence["findings_detected"].append("sqli_reproducible")
                            retest_details["sqli_proof"] = sqli_candidates[0].evidence
                            after_evidence["status_code"] = sqli_candidates[0].evidence.get("status_code")
                        else:
                            resp = await fetch_http(target_url, timeout=8.0)
                            if resp:
                                after_evidence["status_code"] = resp.status_code
                                after_evidence["response_hash"] = hashlib.sha256(resp.text.encode()).hexdigest()[:16]

                    # 4. Cross-Site Scripting (XSS) Retest
                    elif "xss" in f_type or "xss" in f_title or "script" in f_title:
                        logger.info("Executing deep XSS retest on %s", target_url)
                        param_name = ev_dict.get("parameter") or (list(parsed_params.keys())[0] if parsed_params else "q")
                        location = ev_dict.get("location") or ("query" if parsed_params else "body")
                        xss_candidates = await xss_validator.validate_url(target_url, [{"name": param_name, "location": location}])
                        if xss_candidates:
                            still_vulnerable = True
                            after_evidence["findings_detected"].append("xss_reproducible")
                            retest_details["xss_proof"] = xss_candidates[0].evidence
                            after_evidence["status_code"] = xss_candidates[0].evidence.get("status_code")
                        else:
                            resp = await fetch_http(target_url, timeout=8.0)
                            if resp:
                                after_evidence["status_code"] = resp.status_code
                                after_evidence["response_hash"] = hashlib.sha256(resp.text.encode()).hexdigest()[:16]

                    # 5. IDOR / BOLA Retest
                    elif "idor" in f_type or "idor" in f_title or "bola" in f_type:
                        logger.info("Executing deep IDOR retest on %s", target_url)
                        idor_cands = await idor_validator.validate_endpoint(target_url)
                        if idor_cands:
                            still_vulnerable = True
                            after_evidence["findings_detected"].append("idor_boundary_bypass")
                            retest_details["idor_proof"] = idor_cands[0].evidence

                    # 6. CSRF Retest
                    elif "csrf" in f_type or "xsrf" in f_type:
                        logger.info("Executing deep CSRF retest on %s", target_url)
                        csrf_cands = await csrf_validator.execute_validation(target_url, {"is_state_changing": True})
                        still_vulnerable = len(csrf_cands) > 0
                        if still_vulnerable:
                            after_evidence["findings_detected"].append("csrf_still_vulnerable")

                    # 7. CORS Retest
                    elif "cors" in f_type:
                        logger.info("Executing deep CORS retest on %s", target_url)
                        cors_cands = await cors_validator.execute_validation(target_url)
                        still_vulnerable = len(cors_cands) > 0
                        if still_vulnerable:
                            after_evidence["findings_detected"].append("cors_misconfiguration_still_vulnerable")

                    # 8. SSTI Retest
                    elif "ssti" in f_type or "template" in f_type:
                        logger.info("Executing deep SSTI retest on %s", target_url)
                        ssti_cands = await ssti_validator.execute_validation(target_url)
                        still_vulnerable = len(ssti_cands) > 0
                        if still_vulnerable:
                            after_evidence["findings_detected"].append("ssti_still_reproducible")

                    # 9. JWT Retest
                    elif "jwt" in f_type or "token" in f_type:
                        logger.info("Executing deep JWT retest on %s", target_url)
                        jwt_cands = await jwt_validator.execute_validation(target_url, ev_dict)
                        still_vulnerable = len(jwt_cands) > 0
                        if still_vulnerable:
                            after_evidence["findings_detected"].append("jwt_vulnerability_still_active")

                    # 10. GraphQL Retest
                    elif "graphql" in f_type:
                        logger.info("Executing deep GraphQL retest on %s", target_url)
                        gql_cands = await graphql_validator.execute_validation(target_url)
                        still_vulnerable = len(gql_cands) > 0
                        if still_vulnerable:
                            after_evidence["findings_detected"].append("graphql_introspection_still_enabled")

                    # 11. WebSocket / CSWSH Retest
                    elif "websocket" in f_type or "cswsh" in f_type:
                        logger.info("Executing deep WebSocket retest on %s", target_url)
                        ws_cands = await websocket_validator.execute_validation(target_url)
                        still_vulnerable = len(ws_cands) > 0

                    # 12. Host Header Retest
                    elif "host_header" in f_type or "host_poisoning" in f_type:
                        logger.info("Executing deep Host Header retest on %s", target_url)
                        hh_cands = await host_header_validator.execute_validation(target_url)
                        still_vulnerable = len(hh_cands) > 0

                    # 13. File Upload / Path Traversal / RCE / SSRF / Smuggling / Deserialization
                    elif "upload" in f_type:
                        cands = await file_upload_validator.validate_endpoint(target_url)
                        still_vulnerable = len(cands) > 0
                    elif "traversal" in f_type or "lfi" in f_type:
                        param = ev_dict.get("parameter", "file")
                        cand = await path_traversal_validator.validate_parameter(target_url, param, "query")
                        still_vulnerable = cand is not None
                    elif "rce" in f_type or "command" in f_type:
                        param = ev_dict.get("parameter", "cmd")
                        cand = await rce_validator.validate_parameter(target_url, param, "query")
                        still_vulnerable = cand is not None
                    elif "redirect" in f_type:
                        param = ev_dict.get("parameter", "url")
                        cand = await open_redirect_validator.validate_parameter(target_url, param, "query")
                        still_vulnerable = cand is not None
                    elif "smuggling" in f_type:
                        smug_cands = await request_smuggling_validator.execute_validation(target_url)
                        still_vulnerable = len(smug_cands) > 0
                    elif "deserialization" in f_type:
                        deser_cands = await deserialization_validator.execute_validation(target_url)
                        still_vulnerable = len(deser_cands) > 0

                    # Fallback Generic Differential Check
                    else:
                        resp = await fetch_http(target_url, timeout=8.0)
                        if resp:
                            after_evidence["status_code"] = resp.status_code
                            after_evidence["response_hash"] = hashlib.sha256(resp.text.encode()).hexdigest()[:16]
                            poc_code = ev_dict.get("poc_curl") or ev_dict.get("poc") or ""
                            if resp.status_code == 200 and poc_code and poc_code in resp.text:
                                still_vulnerable = True

        except Exception as error:
            logger.warning("Retest could not complete for %s: %s", finding_id, type(error).__name__)
            retest_details["execution_error"] = type(error).__name__
            still_vulnerable = False

        # ----------------------------------------------------------------------
        # Evaluation & State Transition
        # ----------------------------------------------------------------------
        if still_vulnerable:
            retest.status = "FAILED"
            finding.status = "NOT_FIXED"
            verdict = f"Vulnerability still actively reproducible on target ({', '.join(after_evidence['findings_detected']) or 'Unresolved'}). Remediation verification failed."
            logger.warning("Retest %s FAILED — finding %s still reproducible", retest_id, finding.id)
        else:
            retest.status = "INCONCLUSIVE"
            finding.status = before_status
            verdict = "No comparable positive proof was obtained. Connectivity failure, missing identity or an unsupported check does not prove remediation. Previous finding status is preserved."
            logger.info("Retest %s inconclusive; finding %s status preserved", retest_id, finding.id)

        comparison_data = {
            "retest_id": retest_id,
            "finding_id": finding_id,
            "finding_title": finding.title,
            "vulnerability_family": f_type or f_title,
            "before_status": before_status,
            "after_status": finding.status,
            "retest_result": retest.status,
            "tested_at": now_iso,
            "target_url": target_url,
            "is_still_vulnerable": True if still_vulnerable else None,
            "verdict": verdict,
            "details": retest_details,
            "before_evidence": ev_dict,
            "after_evidence": after_evidence,
        }

        retest.comparison_result = comparison_data
        retest.completed_at = datetime.now(timezone.utc)
        finding.last_seen = datetime.now(timezone.utc)
        await db.commit()

        # Emit realtime completion event
        try:
            evt = event_bus.make_event(
                scan_id=finding.scan_id,
                event_type="retest.completed",
                message=f"Live retest selesai: {finding.title} dinyatakan {finding.status} (Retest {retest.status}).",
                status="SUCCESS" if retest.status == "PASSED" else "FAILED",
                data={
                    "finding_id": finding_id,
                    "retest_id": retest_id,
                    "result": retest.status,
                    "status": finding.status,
                    "verdict": verdict,
                },
            )
            await event_bus.publish(evt)
        except Exception as bus_err:
            logger.debug("EventBus publish error: %s", bus_err)

        return comparison_data

    async def check_clean_state(self, db: AsyncSession, scan_id: str) -> dict:
        """Check if all findings for a scan are in CLOSED/FIXED state (§34 clean state)."""
        findings = (await db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )).scalars().all()

        open_findings = [f for f in findings if f.status not in (
            "CLOSED", "FIXED", "FALSE_POSITIVE", "ACCEPTED_RISK"
        )]

        return {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "open_findings": len(open_findings),
            "clean": False,
            "all_findings_resolved": bool(findings) and len(open_findings) == 0,
            "note": "Issue workflow status is not proof that the target is secure.",
            "status": "NO_FINDINGS_RECORDED" if not findings else ("ALL_FINDINGS_RESOLVED" if not open_findings else "OPEN_FINDINGS_REMAIN"),
        }


retest_engine = RetestEngine()
