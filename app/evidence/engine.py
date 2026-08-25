"""Evidence Engine (§30).

Evidence wajib memiliki provenance:
source, timestamp, asset, scanner, rule, request_id, response_hash, confidence.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("evidence")


class EvidenceEngine:
    """Structured evidence collection with provenance tracking (§30)."""

    @staticmethod
    def create_evidence(
        *,
        finding_id: str,
        evidence_type: str,  # screenshot, request, response, headers, tls_metadata, etc.
        source: str,         # scanner name / validator name
        asset_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        confidence: str = "OBSERVED",
        content: Optional[str] = None,
        content_hash: Optional[str] = None,
        storage_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """Create a structured evidence record with full provenance."""
        eid = f"evd_{uuid.uuid4().hex[:12]}"

        if content and not content_hash:
            content_hash = hashlib.sha256(content.encode()).hexdigest()

        return {
            "id": eid,
            "finding_id": finding_id,
            "type": evidence_type,
            "source": source,
            "asset_id": asset_id,
            "rule_id": rule_id,
            "confidence": confidence,
            "content": content,
            "content_hash": content_hash,
            "storage_path": storage_path,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def create_request_evidence(
        *,
        finding_id: str,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
        status_code: Optional[int] = None,
        response_headers: Optional[dict] = None,
        response_body_hash: Optional[str] = None,
        timing_ms: Optional[float] = None,
        scanner: str = "unknown",
    ) -> dict:
        """Create evidence from an HTTP request/response pair."""
        from app.reporting.redaction import redact

        # Sanitize sensitive data before storing
        safe_headers = {k: redact(v) for k, v in (headers or {}).items()}
        safe_resp_headers = {k: redact(v) for k, v in (response_headers or {}).items()}
        safe_body = redact(body) if body else None

        return EvidenceEngine.create_evidence(
            finding_id=finding_id,
            evidence_type="request",
            source=scanner,
            confidence="DIRECT_OBSERVATION",
            metadata={
                "method": method,
                "url": url,
                "request_headers": safe_headers,
                "request_body_redacted": safe_body[:500] if safe_body else None,
                "status_code": status_code,
                "response_headers": safe_resp_headers,
                "response_body_hash": response_body_hash,
                "timing_ms": timing_ms,
            },
        )


evidence_engine = EvidenceEngine()
