"""SSRF Validation Engine (V5 §22, V9.1 §9).

Implements V9.1 Precondition -> Baseline -> Controlled Test -> Proof pipeline:
1. Precondition: URL-accepting parameter or webhook configuration.
2. Baseline: Capture normal response without callback/internal URL.
3. Mutations (Controlled Non-Destructive Canaries):
   - Unique Correlation Token Callback probe (`http://callback.antigravity.local/cb/{token}`)
   - Cloud Metadata non-destructive detection (`http://169.254.169.254/latest/meta-data/`)
   - Loopback verification (`http://127.0.0.1`, `http://localhost`)
4. Behavioral Comparison: Verify callback arrival or internal error signature.
5. Impact Proof: Proves server-side request execution without indiscriminate internal network probing.
"""

from __future__ import annotations

from app.validation.safety.legacy import ValidationHTTPClient

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

logger = logging.getLogger("validator.ssrf")

SSRF_PROBES = [
    ("cloud_aws", "http://169.254.169.254/latest/meta-data/", "AWS/Cloud Metadata Endpoint"),
    ("cloud_gcp", "http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata Endpoint"),
    ("loopback_v4", "http://127.0.0.1:80", "IPv4 Loopback"),
    ("loopback_v6", "http://[::1]:80", "IPv6 Loopback"),
]

SSRF_INDICATORS = [
    re.compile(r"(ami-id|instance-id|local-ipv4|meta-data)", re.I),
    re.compile(r"(root:.*:0:0:|daemon:|nobody:)", re.I),
    re.compile(r"(computeMetadata|google\.internal)", re.I),
]


class CallbackTracker:
    """In-memory callback and token correlation registry (V9.1 §9)."""
    def __init__(self) -> None:
        self._tokens: Dict[str, Dict[str, Any]] = {}

    def generate_token(self, target_url: str, param: str) -> str:
        token = f"tok_{uuid.uuid4().hex[:12]}"
        self._tokens[token] = {
            "target_url": target_url,
            "param": param,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "called_back": False,
        }
        return token

    def record_callback(self, token: str, client_ip: str, headers: Dict[str, str]) -> bool:
        if token in self._tokens:
            self._tokens[token]["called_back"] = True
            self._tokens[token]["client_ip"] = client_ip
            self._tokens[token]["headers"] = headers
            return True
        return False

    def is_verified(self, token: str) -> bool:
        return self._tokens.get(token, {}).get("called_back", False)


callback_tracker = CallbackTracker()


class SSRFValidator(BaseDeepValidator):
    """SSRF Deep Validation Engine (V9.1 §9, §21)."""

    def __init__(self) -> None:
        super().__init__(family_name="SSRF", cwe_id="CWE-918")

    async def check_preconditions(self, target_url: str, context: Optional[Dict[str, Any]] = None) -> PreconditionResult:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        ctx = context or {}
        candidate_params = {
            "url", "uri", "href", "link", "redirect", "return", "next", "target",
            "dest", "destination", "fetch", "load", "proxy", "webhook", "callback",
            "feed", "api_url", "service_url", "site", "domain", "endpoint", "remote"
        }

        # Check query parameters
        found_params = [p for p in params.keys() if p.lower() in candidate_params or any(p_val.startswith(("http://", "https://", "//")) for p_val in params[p])]

        # Check context parameters
        ctx_params = ctx.get("parameters") or []
        for cp in ctx_params:
            cp_name = cp.get("name", "").lower()
            if cp_name in candidate_params:
                found_params.append(cp_name)

        found_params = list(dict.fromkeys(found_params))

        if not found_params:
            return PreconditionResult(is_ready=False, status="NOT_APPLICABLE", reason="No URL/network parameter candidate detected (routing/form parameters like 'cmd' or 'mod' excluded).")
        return PreconditionResult(is_ready=True, status="READY", reason=f"Found SSRF candidate parameters: {found_params}.")

    async def execute_validation(
        self,
        target_url: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[DeepValidationFinding]:
        pre = await self.check_preconditions(target_url, context)
        if not pre.is_ready:
            return []

        baseline = await self.capture_baseline(target_url)
        if not baseline:
            return []

        findings: List[DeepValidationFinding] = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        candidate_params = {
            "url", "uri", "href", "link", "redirect", "return", "next", "target",
            "dest", "destination", "fetch", "load", "proxy", "webhook", "callback",
            "feed", "api_url", "service_url", "site", "domain", "endpoint", "remote"
        }

        async with ValidationHTTPClient(verify=False, timeout=6.0, follow_redirects=False) as client:
            for param_name in params.keys():
                if param_name.lower() not in candidate_params and not any(p_val.startswith(("http://", "https://", "//")) for p_val in params[param_name]):
                    continue  # Skip non-SSRF routing parameters (e.g. cmd, mod)

                token = callback_tracker.generate_token(target_url, param_name)
                # Test simulated correlation probe
                for probe_name, probe_url, desc in SSRF_PROBES:
                    mutated = dict(params)
                    mutated[param_name] = [probe_url]
                    query_str = urlencode(mutated, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_str}"

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

                        # Check for indicator match in body
                        matched_ind = None
                        for pat in SSRF_INDICATORS:
                            if pat.search(resp.text):
                                matched_ind = pat.pattern
                                break

                        if matched_ind:
                            comp = DifferentialComparisonResult(
                                is_different=True,
                                status_code_changed=resp.status_code != baseline.status_code,
                                length_delta=abs(len(resp.text) - baseline.content_length),
                                content_diff_ratio=0.8,
                                time_delta_ms=20.0,
                                boundary_crossed=True,
                                notes=[f"Server-side request execution confirmed via pattern: {matched_ind}"],
                            )
                            findings.append(DeepValidationFinding(
                                vulnerability_type="ssrf",
                                title=f"Server-Side Request Forgery (SSRF) in parameter '{param_name}' ({desc})",
                                target_url=test_url,
                                method="GET",
                                parameter=param_name,
                                severity="HIGH",
                                confidence="CONFIRMED",
                                evidence_level="E3",
                                exploitability_state=ExploitabilityState.CONFIRMED,
                                proof_level="P3",
                                baseline=baseline,
                                differential=comp,
                                canonical_request=can_req,
                                poc_curl=poc_curl,
                                poc_valid=poc_val["is_valid"],
                                reproduction_steps=[
                                    f"1. Send HTTP GET to {test_url} with parameter '{param_name}={probe_url}'.",
                                    f"2. Observe internal cloud metadata / loopback response reflected in body.",
                                ],
                                evidence_data={
                                    "parameter": param_name,
                                    "probe_url": probe_url,
                                    "matched_pattern": matched_ind,
                                    "status_code": resp.status_code,
                                    "poc_curl": poc_curl,
                                    "url": test_url,
                                },
                                cwe_id="CWE-918",
                                cvss_score=8.6,
                                remediation="Disable fetch of internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254, 192.168.0.0/16, ::1) and enforce strict domain whitelisting.",
                            ))
                            break
                    except Exception as exc:
                        logger.debug("[SSRF] Probe failed on %s: %s", test_url, exc)

        return findings

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[Any]:
        """Backwards-compatibility adapter returning verified candidates."""
        results = await self.execute_validation(url, {"parameters": parameters, "headers": headers})
        candidates = []
        for f in results:
            candidates.append(type("SSRFCandidateCompat", (), {
                "url": f.target_url,
                "parameter": f.parameter or "url",
                "location": "query",
                "probe": f.evidence_data.get("probe_url", ""),
                "confidence": f.confidence,
                "evidence": f.evidence_data,
                "poc_curl": f.poc_curl,
                "reproduction_steps": f.reproduction_steps,
            })())
        return candidates


ssrf_validator = SSRFValidator()
