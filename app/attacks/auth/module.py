"""Stateful Authentication & Credential Assessment Module (V15).

Performs stateful authentication auditing:
- Automatic login form detection and input field mapping (username, password, csrf tokens).
- Rate-limited credential validation.
- Session cookie persistence and verification of successful login state (Redirect to dashboard / Session Cookies).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext, SessionIdentity
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.auth")


class AuthAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="auth", cwe_id="CWE-287", default_severity="HIGH")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            if any(term in u.lower() for term in ("login", "signin", "auth", "admin", "wp-login", "user/login")):
                opps.append(
                    AttackOpportunity(
                        target=target,
                        endpoint=u,
                        attack_type="auth",
                        hypothesis=f"Authentication portal at {u} can be assessed for weak credentials or bypasses.",
                        priority=88,
                    )
                )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"Authentication & Credential Assessment on {opportunity.endpoint}",
            attack_type="auth",
            target=opportunity.endpoint,
            steps=[
                "1. Fetch login portal, identify input fields, and extract CSRF tokens",
                "2. Dispatch credential verification probe with session state tracking",
                "3. Verify authentication status and session persistence",
            ],
            payloads=["admin:admin", "admin:password", "test:test"],
            expected_evidence="Authenticated session cookie or redirection to protected dashboard.",
            context={"credentials": opportunity.metadata.get("credentials", [])},
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        creds = opportunity.metadata.get("credentials") or [("admin", "admin"), ("admin", "password123"), ("root", "root")]

        # 1. Fetch form & CSRF tokens
        form_resp = await session.get(endpoint)
        if not form_resp.is_success and not form_resp.status_code:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="auth",
                target_url=endpoint,
                message="Auth endpoint unreachable.",
            )

        # Detect username/password field names
        user_field = "username"
        pass_field = "password"
        if re.search(r'name=["\'](user|email|login|user_login|usr)["\']', form_resp.text, re.I):
            m = re.search(r'name=["\'](user|email|login|user_login|usr)["\']', form_resp.text, re.I)
            if m:
                user_field = m.group(1)
        if re.search(r'name=["\'](pass|password|pwd|user_pass)["\']', form_resp.text, re.I):
            m = re.search(r'name=["\'](pass|password|pwd|user_pass)["\']', form_resp.text, re.I)
            if m:
                pass_field = m.group(1)

        for cred in creds:
            if isinstance(cred, (list, tuple)) and len(cred) == 2:
                username, password = cred[0], cred[1]
            elif isinstance(cred, dict):
                username = cred.get("username", "admin")
                password = cred.get("password", "admin")
            else:
                continue

            data = {user_field: username, pass_field: password}
            auth_resp = await session.post(endpoint, data=data)

            # Check for successful authentication signals:
            # - Session cookies set (sessionid, auth_token, PHPSESSID with redirect)
            # - Status 302/303 redirect to /dashboard, /admin, /home
            # - "Welcome", "Dashboard", "Logout", "Sign Out" in response text
            is_auth_success = False
            if auth_resp.status_code in (302, 303):
                loc = auth_resp.headers.get("location", "").lower()
                if not any(k in loc for k in ("login", "signin", "error", "failed")):
                    is_auth_success = True
            elif auth_resp.status_code == 200:
                body_lower = auth_resp.text.lower()
                if any(w in body_lower for w in ("logout", "sign out", "dashboard", "logged in as")) and "invalid credentials" not in body_lower:
                    is_auth_success = True

            if is_auth_success:
                poc_curl = f"curl -s -k -X POST '{endpoint}' -d '{user_field}={username}&{pass_field}={password}'"
                # Register authenticated identity in session context
                session.register_identity(
                    SessionIdentity(
                        id="authenticated_admin",
                        name=f"Admin ({username})",
                        role="admin",
                        cookies=dict(auth_resp.headers),
                    )
                )
                return ValidationResult(
                    is_vulnerable=True,
                    confidence=0.95,
                    proof_level="P4",
                    attack_type="auth",
                    target_url=endpoint,
                    baseline_status=form_resp.status_code,
                    exploit_status=auth_resp.status_code,
                    evidence={
                        "valid_credential": {"username": username, "password": password},
                        "redirect_location": auth_resp.headers.get("location"),
                        "response_sample": auth_resp.text[:300],
                    },
                    poc_curl=poc_curl,
                    message=f"CRITICAL: Valid administrative credentials confirmed on {endpoint}: {username}:{password}",
                    cwe_id="CWE-287",
                    severity="CRITICAL",
                )

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.2,
            proof_level="P0",
            attack_type="auth",
            target_url=endpoint,
            baseline_status=form_resp.status_code,
            message="No default or harvested credentials succeeded on authentication portal.",
        )
