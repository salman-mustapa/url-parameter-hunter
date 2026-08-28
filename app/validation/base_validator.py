"""V9.1 Base Deep Validator Interface & Pipeline (V9.1 §1, §2, §5, §16).

Implements the mandatory 6-stage V9.1 validation flow:
1. Precondition Check: verifies asset scope, required parameters, and active endpoints.
2. Baseline Capture: records baseline response attributes (status, length, hash, DOM fingerprint).
3. Controlled Test (Mutation): dispatches minimal non-destructive mutation.
4. Behavioral Comparison: performs differential comparison between baseline and mutated responses.
5. Security Behavior Confirmation: verifies boundary violation or security anomaly.
6. Impact Proof & PoC Generation: builds cryptographic, wire-verified PoC via RequestRecorder.
"""

from __future__ import annotations

from app.validation.safety.legacy import ValidationHTTPClient

import abc
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from app.findings.lifecycle import ExploitabilityState, FindingQualityProfile
from app.validation.poc import CanonicalRequest, PoCCompiler, PoCValidator, RequestRecorder

logger = logging.getLogger("validation.base")


@dataclass
class PreconditionResult:
    is_ready: bool
    status: str  # "READY", "NOT_APPLICABLE", "BLOCKED"
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BaselineProfile:
    url: str
    method: str
    status_code: int
    content_length: int
    content_hash: str
    headers: Dict[str, str] = field(default_factory=dict)
    dom_title: Optional[str] = None
    response_time_ms: float = 0.0
    body_sample: str = ""
    is_auth_enforced: bool = False
    is_waf_blocked: bool = False


@dataclass
class DifferentialComparisonResult:
    is_different: bool
    status_code_changed: bool
    length_delta: int
    content_diff_ratio: float
    time_delta_ms: float
    reflected_canary: bool = False
    error_signature_detected: bool = False
    boundary_crossed: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class DeepValidationFinding:
    vulnerability_type: str
    title: str
    target_url: str
    method: str
    parameter: Optional[str]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str  # OBSERVED, SUSPECTED, VALIDATED, CONFIRMED
    evidence_level: str  # E0, E1, E2, E3, E4
    exploitability_state: str
    proof_level: str  # P0, P1, P2, P3, P4
    baseline: BaselineProfile
    comparison: DifferentialComparisonResult
    canonical_request: CanonicalRequest
    poc_curl: str
    poc_valid: bool
    reproduction_steps: List[str]
    evidence_data: Dict[str, Any]
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None


class BaseDeepValidator(abc.ABC):
    """Abstract base class for all V9.1 deep validators."""

    def __init__(self, family_name: str, cwe_id: str = "CWE-200") -> None:
        self.family_name = family_name
        self.cwe_id = cwe_id
        self.recorder = RequestRecorder()

    @abc.abstractmethod
    async def check_preconditions(self, target_url: str, context: Optional[Dict[str, Any]] = None) -> PreconditionResult:
        """Stage 1: Verify prerequisites before sending active payloads."""
        pass

    async def capture_baseline(self, target_url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None) -> Optional[BaselineProfile]:
        """Stage 2: Capture initial un-mutated baseline response state."""
        clean_headers = headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Antigravity-V9/1.0"}
        start_t = datetime.now(timezone.utc)
        try:
            async with ValidationHTTPClient(verify=False, timeout=8.0, follow_redirects=False) as client:
                resp = await client.request(method=method, url=target_url, headers=clean_headers, data=data)
                elapsed_ms = (datetime.now(timezone.utc) - start_t).total_seconds() * 1000.0
                body = resp.text
                c_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
                
                # Check WAF or Auth indicators
                is_waf = any(w in body.lower() for w in ("cloudflare", "attention required", "captcha", "security check"))
                is_auth = resp.status_code in (401, 403) or any(k in body.lower() for k in ("password", "sign in", "login"))

                return BaselineProfile(
                    url=target_url,
                    method=method,
                    status_code=resp.status_code,
                    content_length=len(body),
                    content_hash=c_hash,
                    headers=dict(resp.headers),
                    response_time_ms=elapsed_ms,
                    body_sample=body[:1000],
                    is_auth_enforced=is_auth,
                    is_waf_blocked=is_waf,
                )
        except Exception as exc:
            logger.warning("[%s] Failed to capture baseline for %s: %s", self.family_name, target_url, exc)
            return None

    def compare_responses(
        self,
        baseline: BaselineProfile,
        mutated_status: int,
        mutated_body: str,
        mutated_time_ms: float,
        canary: Optional[str] = None,
        error_regexes: Optional[List[Any]] = None,
    ) -> DifferentialComparisonResult:
        """Stage 4: Perform behavioral comparison between baseline and mutated response."""
        status_changed = baseline.status_code != mutated_status
        length_delta = abs(len(mutated_body) - baseline.content_length)
        time_delta = mutated_time_ms - baseline.response_time_ms
        notes = []

        reflected = False
        if canary and canary in mutated_body:
            reflected = True
            notes.append(f"Canary '{canary}' reflected in response body.")

        has_err = False
        if error_regexes:
            for pattern in error_regexes:
                if pattern.search(mutated_body):
                    has_err = True
                    notes.append("Vulnerability error/stack signature detected.")
                    break

        # Compute content similarity ratio
        mut_hash = hashlib.sha256(mutated_body.encode()).hexdigest()[:16]
        is_diff = (mut_hash != baseline.content_hash) or status_changed

        return DifferentialComparisonResult(
            is_different=is_diff,
            status_code_changed=status_changed,
            length_delta=length_delta,
            content_diff_ratio=1.0 if is_diff else 0.0,
            time_delta_ms=time_delta,
            reflected_canary=reflected,
            error_signature_detected=has_err,
            boundary_crossed=False,
            notes=notes,
        )

    @abc.abstractmethod
    async def execute_validation(
        self,
        target_url: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[DeepValidationFinding]:
        """Stage 3-6: Orchestrate controlled test, comparison, proof, and finding assembly."""
        pass
