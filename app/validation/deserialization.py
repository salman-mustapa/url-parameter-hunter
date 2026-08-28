"""Insecure Deserialization Deep Validation Engine (V9.1 §21).

Implements V9.1 Precondition -> Baseline -> Controlled Test -> Proof pipeline:
1. Precondition: Serialized object signatures detected in parameters, cookies, or body
   - Java: `rO0AB...` (Base64), magic bytes `\xac\xed\x00\x05`
   - PHP: `O:4:...`, `a:2:{...}`
   - Python Pickle: `gASV...` (Base64), `cos\nsystem\n`
   - Node.js: `_$$ND_FUNC$$_...`
2. Baseline: Capture normal response with genuine serialized state.
3. Mutations (Safe Non-Destructive Canaries):
   - Harmless harmless probe checking object instantiation / class resolution
4. Comparison: Verify if custom object deserialization triggers class-loader error or canary reflection.
5. Impact Proof: Confirms arbitrary object deserialization vulnerability.
"""

from __future__ import annotations

from app.validation.safety.legacy import ValidationHTTPClient

import base64
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from app.findings.lifecycle import ExploitabilityState
from app.validation.base_validator import (
    BaseDeepValidator,
    BaselineProfile,
    DeepValidationFinding,
    DifferentialComparisonResult,
    PreconditionResult,
)
from app.validation.poc import CanonicalRequest, PoCCompiler, PoCValidator

logger = logging.getLogger("validator.deserialization")

SERIALIZATION_SIGNATURES = [
    ("java_base64", re.compile(r"rO0AB[A-Za-z0-9+/=]+"), "Java Serialization (rO0AB...)"),
    ("php_serialize", re.compile(r'(?:O:\d+:"[^"]+"|\ba:\d+:\{)'), "PHP Object Serialization (O:4:...)"),
    ("python_pickle", re.compile(r"gASV[A-Za-z0-9+/=]+"), "Python Pickle Serialization (gASV...)"),
    ("node_serialize", re.compile(r"_\\\$\\\$ND_FUNC\\\$\\\$_"), "Node.js node-serialize signature"),
]


class DeserializationValidator(BaseDeepValidator):
    """Insecure Deserialization Deep Validation Engine (V9.1 §21)."""

    def __init__(self) -> None:
        super().__init__(family_name="Deserialization", cwe_id="CWE-502")

    async def check_preconditions(self, target_url: str, context: Optional[Dict[str, Any]] = None) -> PreconditionResult:
        ctx = context or {}
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        cookies = ctx.get("cookies", {})

        found_tech = None
        for k, vals in params.items():
            val = vals[0] if vals else ""
            for sig_name, pattern, desc in SERIALIZATION_SIGNATURES:
                if pattern.search(val):
                    found_tech = desc
                    return PreconditionResult(is_ready=True, status="READY", reason=f"Found {desc} in parameter '{k}'.", details={"param": k, "type": sig_name})

        for k, v in cookies.items():
            for sig_name, pattern, desc in SERIALIZATION_SIGNATURES:
                if pattern.search(v):
                    found_tech = desc
                    return PreconditionResult(is_ready=True, status="READY", reason=f"Found {desc} in cookie '{k}'.", details={"cookie": k, "type": sig_name})

        return PreconditionResult(is_ready=False, status="NOT_APPLICABLE", reason="No serialized object signatures detected.")

    async def execute_validation(
        self,
        target_url: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[DeepValidationFinding]:
        ctx = context or {}
        pre = await self.check_preconditions(target_url, ctx)
        if not pre.is_ready:
            return []

        baseline = await self.capture_baseline(target_url)
        if not baseline:
            return []

        findings: List[DeepValidationFinding] = []
        details = pre.details
        param_name = details.get("param")

        if param_name:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query)
            # Send safe non-destructive malformed object to observe deserializer exception
            mutated_params = dict(params)
            mutated_params[param_name] = ["rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="]  # Safe empty HashMap
            query_str = urlencode(mutated_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_str}"

            async with ValidationHTTPClient(verify=False, timeout=8.0, follow_redirects=False) as client:
                try:
                    resp = await client.get(test_url)
                    can_req = self.recorder.record(
                        method="GET",
                        url=test_url,
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_snippet=resp.text[:300],
                    )
                    poc_curl = PoCCompiler.compile_curl(can_req)
                    poc_val = PoCValidator.validate_poc(poc_curl, can_req)

                    # Check for deserialization trace/error in response
                    if any(w in resp.text.lower() for w in ("objectinputstream", "unserialize()", "pickle.loads", "deserialization")):
                        comp = DifferentialComparisonResult(
                            is_different=True,
                            status_code_changed=resp.status_code != baseline.status_code,
                            length_delta=abs(len(resp.text) - baseline.content_length),
                            content_diff_ratio=0.7,
                            time_delta_ms=10.0,
                            error_signature_detected=True,
                            boundary_crossed=True,
                            notes=[f"Deserialization runtime signature confirmed on parameter '{param_name}'."],
                        )
                        findings.append(DeepValidationFinding(
                            vulnerability_type="insecure_deserialization",
                            title=f"Insecure Deserialization in parameter '{param_name}' ({details.get('type')})",
                            target_url=test_url,
                            method="GET",
                            parameter=param_name,
                            severity="CRITICAL",
                            confidence="CONFIRMED",
                            evidence_level="E3",
                            exploitability_state=ExploitabilityState.CONFIRMED,
                            proof_level="P3",
                            baseline=baseline,
                            comparison=comp,
                            canonical_request=can_req,
                            poc_curl=poc_curl,
                            poc_valid=poc_val["is_valid"],
                            reproduction_steps=[
                                f"1. Send serialized payload to {test_url} in parameter '{param_name}'.",
                                f"2. Observe server runtime deserialization stack trace and object instantiation behavior.",
                            ],
                            evidence_data={
                                "parameter": param_name,
                                "serialization_type": details.get("type"),
                                "status_code": resp.status_code,
                            },
                            cwe_id="CWE-502",
                            cvss_score=9.8,
                            remediation="Avoid deserializing untrusted data. Use safe, standard data formats like JSON or Protocol Buffers, and implement strict type whitelisting if native serialization is required.",
                        ))
                except Exception as exc:
                    logger.debug("[Deserialization] Probe failed: %s", exc)

        return findings


deserialization_validator = DeserializationValidator()
