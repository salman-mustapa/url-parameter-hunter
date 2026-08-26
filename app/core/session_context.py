"""Stateful HTTP & Session Context Engine (V15 Core).

Provides unified, stateful HTTP execution across the attack lifecycle:
- Multi-identity session management (Identity A, Identity B, Unauthenticated, Admin).
- Automatic cookie jar persistence and CSRF token extraction.
- Response classification (WAF blocks, rate limits, auth barriers, server crashes).
- Multi-identity differential authorization engine for IDOR/BOLA confirmation.
"""

from __future__ import annotations

import asyncio
import difflib
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import httpx
from app.core.config import settings
from app.core.rate_limit import RateLimiter

logger = logging.getLogger("core.session_context")


class NetworkClassification(str, Enum):
    SUCCESS = "SUCCESS"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"
    RATE_LIMIT = "RATE_LIMIT"
    WAF_BLOCK = "WAF_BLOCK"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    SERVER_ERROR = "SERVER_ERROR"


# Common WAF signatures in body or headers
WAF_SIGNATURES = [
    r"cloudflare",
    r"cf-ray",
    r"sucuri",
    r"wordfence",
    r"incapsula",
    r"imperva",
    r"mod_security",
    r"modsecurity",
    r"akamai",
    r"barracuda",
    r"f5 big-ip",
    r"fortiweb",
    r"aws waf",
    r"access denied",
    r"request blocked",
    r"security block",
    r"web application firewall",
]

CSRF_FIELD_PATTERNS = [
    r'<input[^>]+name=["\'](csrf[-_]?token|_token|authenticity_token|__RequestVerificationToken|xsrf[-_]?token)["\'][^>]+value=["\']([^"\']+)["\']',
    r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](csrf[-_]?token|_token|authenticity_token|__RequestVerificationToken|xsrf[-_]?token)["\']',
    r'<meta[^>]+name=["\'](csrf[-_]?token|xsrf[-_]?token)["\'][^>]+content=["\']([^"\']+)["\']',
    r'["\'](csrfToken|csrf_token|_token)["\']\s*:\s*["\']([^"\']+)["\']',
]


@dataclass
class SessionIdentity:
    id: str
    name: str = "Default"
    role: str = "user"  # admin, user_a, user_b, unauthenticated
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    csrf_tokens: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_headers(self) -> Dict[str, str]:
        hdrs = dict(self.headers)
        if self.auth_token:
            if not any(k.lower() == "authorization" for k in hdrs):
                hdrs["Authorization"] = (
                    f"Bearer {self.auth_token}"
                    if not self.auth_token.lower().startswith("bearer ")
                    else self.auth_token
                )
        if self.csrf_tokens:
            primary_token = next(iter(self.csrf_tokens.values()))
            if not any(k.lower() in ("x-csrf-token", "x-xsrf-token") for k in hdrs):
                hdrs["X-CSRF-Token"] = primary_token
        return hdrs


@dataclass
class SessionResponse:
    status_code: int
    headers: Dict[str, str]
    text: str
    content: bytes
    url: str
    elapsed_ms: float
    classification: NetworkClassification
    csrf_tokens: Dict[str, str] = field(default_factory=dict)
    identity_id: str = "default"
    raw_response: Optional[httpx.Response] = None

    @property
    def is_success(self) -> bool:
        return self.classification == NetworkClassification.SUCCESS

    @property
    def is_waf_blocked(self) -> bool:
        return self.classification == NetworkClassification.WAF_BLOCK

    @property
    def content_length(self) -> int:
        return len(self.content)


@dataclass
class MultiIdentityAuthDiff:
    is_idor_confirmed: bool
    is_privilege_escalation: bool
    identity_a_status: int
    identity_b_status: int
    unauth_status: int
    body_similarity_ab: float
    boundary_violated: bool
    explanation: str
    details: Dict[str, Any] = field(default_factory=dict)


class SessionContext:
    """Stateful HTTP Client and Multi-Identity Penetration Testing Session Manager."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 15.0,
        verify_ssl: bool = False,
        default_headers: Optional[Dict[str, str]] = None,
        rate_limiter: Optional[RateLimiter] = None,
        proxies: Optional[List[str]] = None,
    ) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_headers = default_headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        self.rate_limiter = rate_limiter
        self.proxies = proxies or []
        if not self.proxies and settings.proxy_pool:
            self.proxies = [p.strip() for p in settings.proxy_pool.split(",") if p.strip()]
        self._proxy_index = 0
        self.identities: Dict[str, SessionIdentity] = {}
        self.active_identity_id: str = "default"
        self._clients: Dict[Tuple[str, Optional[str]], httpx.AsyncClient] = {}
        self._lock = asyncio.Lock()

        # Initialize default identity
        self.register_identity(SessionIdentity(id="default", name="Default Session", role="user"))

    def register_identity(self, identity: SessionIdentity) -> SessionIdentity:
        """Registers a session identity (e.g. Identity A, Identity B, Admin)."""
        self.identities[identity.id] = identity
        return identity

    def switch_identity(self, identity_id: str) -> bool:
        """Switches the currently active identity."""
        if identity_id in self.identities:
            self.active_identity_id = identity_id
            return True
        return False

    def get_active_identity(self) -> SessionIdentity:
        return self.identities.get(
            self.active_identity_id,
            SessionIdentity(id="default", name="Default Session"),
        )

    def get_identity(self, identity_id: str) -> Optional[SessionIdentity]:
        return self.identities.get(identity_id)

    async def _get_client(self, identity_id: str, proxy: Optional[str] = None) -> httpx.AsyncClient:
        key = (identity_id, proxy)
        if key not in self._clients:
            ident = self.identities.get(identity_id) or SessionIdentity(id=identity_id)
            client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=True,
                cookies=ident.cookies,
                proxy=proxy,
            )
            self._clients[key] = client
        return self._clients[key]

    @staticmethod
    def extract_csrf_tokens(text: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Extracts CSRF tokens from HTML bodies and headers."""
        tokens: Dict[str, str] = {}
        if headers:
            for k, v in headers.items():
                if k.lower() in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
                    tokens[k.lower()] = v

        if not text:
            return tokens

        for pattern in CSRF_FIELD_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                groups = match.groups()
                if len(groups) == 2:
                    if len(groups[0]) > len(groups[1]):
                        # value, name
                        val, name = groups[0], groups[1]
                    else:
                        name, val = groups[0], groups[1]
                    tokens[name] = val

        return tokens

    @staticmethod
    def classify_response(
        status_code: int,
        headers: Dict[str, str],
        body_text: str,
    ) -> NetworkClassification:
        """Classifies response into operational status categories."""
        if status_code in (429, 503) and ("retry-after" in headers or "too many requests" in body_text.lower()):
            return NetworkClassification.RATE_LIMIT

        lower_body = body_text.lower()
        if status_code in (403, 406, 429, 502, 503):
            for sig in WAF_SIGNATURES:
                if re.search(sig, lower_body) or any(re.search(sig, str(v).lower()) for v in headers.values()):
                    return NetworkClassification.WAF_BLOCK

        if status_code in (401, 403) and ("login" in lower_body or "unauthorized" in lower_body or "authentication required" in lower_body):
            return NetworkClassification.AUTH_REQUIRED

        if status_code in (500, 502, 504):
            return NetworkClassification.SERVER_ERROR

        if 200 <= status_code < 400 or status_code in (400, 404, 405, 422):
            return NetworkClassification.SUCCESS

        return NetworkClassification.SUCCESS

    async def request(
        self,
        method: str,
        url: str,
        identity_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> SessionResponse:
        """Dispatches an HTTP request using the specified or active session identity."""
        target_ident_id = identity_id or self.active_identity_id
        identity = self.identities.get(target_ident_id) or SessionIdentity(id=target_ident_id)

        # Merge headers
        req_headers = dict(self.default_headers)
        req_headers.update(identity.get_headers())
        if headers:
            req_headers.update(headers)

        # Inject CSRF token into form data if present and missing
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE") and isinstance(data, dict):
            if identity.csrf_tokens and not any(k.lower() in ("csrf_token", "_token", "authenticity_token") for k in data):
                primary_name, primary_val = next(iter(identity.csrf_tokens.items()))
                data[primary_name] = primary_val

        # Select proxy from pool in round-robin fashion
        proxy = None
        if self.proxies:
            async with self._lock:
                proxy = self.proxies[self._proxy_index % len(self.proxies)]
                self._proxy_index += 1

        # Wait on rate limiter if configured
        if self.rate_limiter:
            await self.rate_limiter.wait()

        client = await self._get_client(target_ident_id, proxy)
        start_t = time.time()

        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=req_headers,
                params=params,
                data=data,
                json=json,
                cookies=cookies,
                timeout=timeout or self.timeout,
                **kwargs,
            )
            elapsed_ms = (time.time() - start_t) * 1000.0
            body_text = resp.text
            resp_headers = dict(resp.headers)

            # Extract CSRF tokens from response
            extracted_csrf = self.extract_csrf_tokens(body_text, resp_headers)
            if extracted_csrf:
                identity.csrf_tokens.update(extracted_csrf)

            # Sync cookies back to identity
            for k, v in resp.cookies.items():
                identity.cookies[k] = v

            classification = self.classify_response(resp.status_code, resp_headers, body_text)

            # Adaptive Rate Limiting: Backoff on blocks, decay on success
            if self.rate_limiter:
                if classification in (NetworkClassification.WAF_BLOCK, NetworkClassification.RATE_LIMIT):
                    self.rate_limiter.backoff()
                    logger.warning("WAF block or Rate Limit detected on %s. Backed off rate limiter: delay = %.2fs", url, self.rate_limiter.delay)
                elif classification == NetworkClassification.SUCCESS:
                    self.rate_limiter.decay()

            return SessionResponse(
                status_code=resp.status_code,
                headers=resp_headers,
                text=body_text,
                content=resp.content,
                url=str(resp.url),
                elapsed_ms=elapsed_ms,
                classification=classification,
                csrf_tokens=extracted_csrf,
                identity_id=target_ident_id,
                raw_response=resp,
            )

        except httpx.TimeoutException:
            return SessionResponse(
                status_code=0,
                headers={},
                text="",
                content=b"",
                url=url,
                elapsed_ms=(time.time() - start_t) * 1000.0,
                classification=NetworkClassification.TIMEOUT,
                identity_id=target_ident_id,
            )
        except Exception as exc:
            logger.warning("Request error on %s: %s", url, exc)
            return SessionResponse(
                status_code=0,
                headers={},
                text=str(exc),
                content=b"",
                url=url,
                elapsed_ms=(time.time() - start_t) * 1000.0,
                classification=NetworkClassification.NETWORK_ERROR,
                identity_id=target_ident_id,
            )

    async def get(self, url: str, **kwargs) -> SessionResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> SessionResponse:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> SessionResponse:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> SessionResponse:
        return await self.request("DELETE", url, **kwargs)

    async def compare_authorization(
        self,
        url: str,
        method: str = "GET",
        identity_a: str = "identity_a",
        identity_b: str = "identity_b",
        unauth_identity: str = "unauthenticated",
        **kwargs,
    ) -> MultiIdentityAuthDiff:
        """Executes multi-identity comparative authorization test for IDOR/BOLA verification."""
        # 1. Dispatch as Identity A (Owner / Authenticated User)
        resp_a = await self.request(method=method, url=url, identity_id=identity_a, **kwargs)

        # 2. Dispatch as Identity B (Attacker / Different Tenant / Different User)
        resp_b = await self.request(method=method, url=url, identity_id=identity_b, **kwargs)

        # 3. Dispatch as Unauthenticated
        # Create unauth identity if missing
        if unauth_identity not in self.identities:
            self.register_identity(SessionIdentity(id=unauth_identity, name="Unauthenticated", role="unauthenticated"))
        resp_unauth = await self.request(method=method, url=url, identity_id=unauth_identity, **kwargs)

        # Calculate similarity between Identity A and Identity B responses
        matcher = difflib.SequenceMatcher(None, resp_a.text, resp_b.text)
        similarity = matcher.ratio() if resp_a.text and resp_b.text else 0.0

        is_idor = False
        is_privesc = False
        boundary_violated = False
        explanation = "Access controls properly enforced."

        # Analysis logic:
        # If Identity A gets 200 (Success) and Identity B also gets 200 with identical or similar sensitive content
        if resp_a.status_code == 200 and resp_b.status_code == 200:
            if similarity > 0.85:
                is_idor = True
                boundary_violated = True
                explanation = (
                    f"CRITICAL: IDOR confirmed on {url}. Identity B (attacker) accessed Identity A's "
                    f"resource with HTTP 200 and {similarity:.1%} body similarity."
                )
            elif resp_b.content_length > 100 and resp_b.status_code != 403:
                is_idor = True
                boundary_violated = True
                explanation = (
                    f"HIGH: IDOR/BOLA suspected on {url}. Identity B returned HTTP 200 with data "
                    f"({resp_b.content_length} bytes)."
                )

        # Check if unauthenticated identity gets 200
        if resp_unauth.status_code == 200 and resp_a.status_code == 200 and resp_unauth.content_length > 100:
            if similarity > 0.75:
                is_idor = True
                boundary_violated = True
                explanation += " Unauthenticated actor also obtained successful HTTP 200 access!"

        # Check privilege escalation (e.g. user performing admin actions)
        role_a = self.identities.get(identity_a, SessionIdentity(id="a")).role
        role_b = self.identities.get(identity_b, SessionIdentity(id="b")).role
        if role_a == "admin" and role_b != "admin" and resp_b.status_code in (200, 201, 204):
            is_privesc = True
            boundary_violated = True
            explanation = f"CRITICAL: Privilege Escalation confirmed. Low-privilege role ({role_b}) successfully executed privileged action ({method} {url})."

        return MultiIdentityAuthDiff(
            is_idor_confirmed=is_idor,
            is_privilege_escalation=is_privesc,
            identity_a_status=resp_a.status_code,
            identity_b_status=resp_b.status_code,
            unauth_status=resp_unauth.status_code,
            body_similarity_ab=similarity,
            boundary_violated=boundary_violated,
            explanation=explanation,
            details={
                "resp_a_length": resp_a.content_length,
                "resp_b_length": resp_b.content_length,
                "unauth_length": resp_unauth.content_length,
            },
        )

    async def close(self) -> None:
        """Closes all underlying HTTP client connections."""
        for client in self._clients.values():
            try:
                await client.aclose()
            except Exception:
                pass
        self._clients.clear()
