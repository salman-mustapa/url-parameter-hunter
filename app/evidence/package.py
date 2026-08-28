"""Structured Evidence Package Builder & Cryptographic Provenance (V5 §21, §22, §26).
Assembles defensible, reproducible, structured packages per finding:
finding/
├── summary.json
├── timeline.json
├── request-metadata.json
├── response-metadata.json
├── validation.json
├── hashes.json
└── reproduction.md
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.reporting.redaction import RedactionEngine


class EvidencePackageBuilder:
    """Builds and computes cryptographic integrity for V8 Evidence Packages (§28)."""

    COLLECTOR_VERSION = "hunter-v8.0.0"

    @staticmethod
    def hash_content(content: Any) -> str:
        """Compute SHA-256 hash of a string or JSON object."""
        if isinstance(content, (dict, list)):
            raw = json.dumps(content, sort_keys=True, default=str).encode("utf-8")
        elif isinstance(content, str):
            raw = content.encode("utf-8")
        elif isinstance(content, bytes):
            raw = content
        else:
            raw = str(content).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def build_package(
        cls,
        *,
        finding_id: str,
        finding_code: str,
        title: str,
        severity: str,
        confidence: str,
        evidence_level: str,
        target_host: str,
        endpoint_url: str,
        cwe_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        description: Optional[str] = None,
        impact_matrix: Optional[Dict[str, Any]] = None,
        root_cause: Optional[str] = None,
        preconditions: Optional[List[str]] = None,
        reproduction_steps: Optional[List[str]] = None,
        expected_result: Optional[str] = None,
        actual_result: Optional[str] = None,
        remediation: Optional[str] = None,
        request_metadata: Optional[Dict[str, Any]] = None,
        response_metadata: Optional[Dict[str, Any]] = None,
        validation_observations: Optional[List[Dict[str, Any]]] = None,
        observations: Optional[List[Dict[str, Any]]] = None,
        timeline_events: Optional[List[Dict[str, Any]]] = None,
        screenshots: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Assemble complete structured evidence package with per-artifact SHA-256 hashes."""
        now_utc = datetime.now(timezone.utc).isoformat()
        obs_list = validation_observations or observations or []

        # 1. Summary JSON
        summary_data = {
            "finding_id": finding_id,
            "finding_code": finding_code,
            "title": title,
            "severity": severity.upper(),
            "confidence": confidence.upper(),
            "evidence_level": evidence_level.upper(),
            "target_host": target_host,
            "endpoint_url": endpoint_url,
            "cwe_id": cwe_id or "N/A",
            "cve_id": cve_id or "N/A",
            "cvss_score": cvss_score,
            "description": description or "",
            "impact_matrix": impact_matrix or {},
            "root_cause": root_cause or "Not established",
            "collector_version": cls.COLLECTOR_VERSION,
            "generated_at": now_utc,
        }

        # 2. Timeline JSON
        timeline_data = timeline_events or []

        # 3. Request & Response Metadata
        req_meta = request_metadata or {}
        resp_meta = response_metadata or {}

        # 4. Validation JSON
        validation_data = {
            "validation_status": "RECORDED_OBSERVATIONS" if obs_list else "NEEDS_REVIEW",
            "evidence_level": evidence_level,
            "observations": obs_list,
            "preconditions": preconditions or [],
            "expected_result": expected_result or "Not recorded",
            "actual_result": actual_result or "Not recorded",
            "cleanup_status": "NOT_RECORDED",
        }

        # 5. Reproduction Markdown (§24)
        steps_rendered = "\n".join(
            f"{i}. {step}" for i, step in enumerate(reproduction_steps or ["Reproduction steps not recorded; review evidence before testing."], 1)
        )

        reproduction_md = f"""# Reproduction Guide: {finding_code} - {title}

## Overview
- **Target:** `{target_host}`
- **Endpoint:** `{endpoint_url}`
- **Severity:** `{severity.upper()}`
- **Confidence:** `{confidence.upper()}`
- **Evidence Level:** `{evidence_level.upper()}`

## Preconditions
- Confirm the authorized scope before any replay.
- Target availability and required identities must be checked.

## Steps to Reproduce
{steps_rendered}

## Expected Result
{expected_result or "Expected result not recorded."}

## Actual Result
{actual_result or "Actual result not recorded."}

## Replay Template (Not Executed or Validated)
```bash
curl -s -k -X {req_meta.get('method', 'GET')} '{endpoint_url}'
```

## Remediation
{remediation or "Apply robust input validation, parameter binding, and strict output encoding."}
"""

        # 6. Hashes JSON (§22 Evidence Integrity)
        # Hash exactly what will be shared; filtering after hashing breaks integrity checks.
        summary_data = RedactionEngine.redact_dict(summary_data)
        timeline_data = RedactionEngine.redact_dict(timeline_data)
        req_meta = RedactionEngine.redact_dict(req_meta)
        resp_meta = RedactionEngine.redact_dict(resp_meta)
        validation_data = RedactionEngine.redact_dict(validation_data)
        reproduction_md = RedactionEngine.redact_text(reproduction_md)
        hashes_data = {
            "summary_sha256": cls.hash_content(summary_data),
            "timeline_sha256": cls.hash_content(timeline_data),
            "request_metadata_sha256": cls.hash_content(req_meta),
            "response_metadata_sha256": cls.hash_content(resp_meta),
            "validation_sha256": cls.hash_content(validation_data),
            "reproduction_md_sha256": cls.hash_content(reproduction_md),
            "package_seal_sha256": "",
            "sealed_at": now_utc,
            "collector_version": cls.COLLECTOR_VERSION,
        }
        # Seal all hashes
        hashes_data["package_seal_sha256"] = cls.hash_content(hashes_data)

        return {
            "summary": summary_data,
            "summary_data": summary_data,
            "summary.json": summary_data,
            "timeline": timeline_data,
            "timeline_data": timeline_data,
            "timeline.json": timeline_data,
            "request_metadata": req_meta,
            "request-metadata.json": req_meta,
            "response_metadata": resp_meta,
            "response-metadata.json": resp_meta,
            "validation": validation_data,
            "validation_data": validation_data,
            "validation.json": validation_data,
            "reproduction_md": reproduction_md,
            "reproduction.md": reproduction_md,
            "hashes": hashes_data,
            "hashes_data": hashes_data,
            "hashes.json": hashes_data,
        }
