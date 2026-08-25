"""Identity Context Engine & Multi-Role Authorization Matrix (Specialist Agent V2 §11, §12).

Manages structured actors for differential authorization and access control testing:
- Roles: ANONYMOUS, USER_A, USER_B, MODERATOR, ADMIN, SERVICE_ACCOUNT
- Tracks: Session Cookies, Bearer Tokens, Custom Headers, Roles, and Tenant IDs.
- Provides differential matrix evaluation for IDOR, BFLA, and Privilege Escalation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai.identity_context")


class ActorRole(str, Enum):
    ANONYMOUS = "anonymous"
    USER_A = "user_a"          # Primary low-privilege user
    USER_B = "user_b"          # Secondary low-privilege user (for IDOR horizontal tests)
    MODERATOR = "moderator"    # Medium-privilege user
    ADMIN = "admin"            # High-privilege administrator
    SERVICE_ACCOUNT = "service_account"


@dataclass
class IdentityContext:
    role: ActorRole
    username: str = ""
    user_id: str = ""
    auth_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tenant_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_request_headers(self) -> Dict[str, str]:
        """Builds HTTP request headers for this identity."""
        req_headers = dict(self.headers)
        if self.auth_token:
            req_headers["Authorization"] = f"Bearer {self.auth_token}" if not self.auth_token.startswith("Bearer ") else self.auth_token
        if self.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
            req_headers["Cookie"] = cookie_str
        return req_headers

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "username": self.username,
            "user_id": self.user_id,
            "has_token": bool(self.auth_token),
            "cookies_count": len(self.cookies),
            "tenant_id": self.tenant_id,
        }


class IdentityContextManager:
    """Manages identity profiles and differential authorization matrices."""

    def __init__(self) -> None:
        self._identities: Dict[ActorRole, IdentityContext] = {
            ActorRole.ANONYMOUS: IdentityContext(role=ActorRole.ANONYMOUS, username="anonymous"),
            ActorRole.USER_A: IdentityContext(role=ActorRole.USER_A, username="alice_user_a", user_id="1001"),
            ActorRole.USER_B: IdentityContext(role=ActorRole.USER_B, username="bob_user_b", user_id="1002"),
            ActorRole.MODERATOR: IdentityContext(role=ActorRole.MODERATOR, username="mod_carol", user_id="501"),
            ActorRole.ADMIN: IdentityContext(role=ActorRole.ADMIN, username="admin_super", user_id="1"),
            ActorRole.SERVICE_ACCOUNT: IdentityContext(role=ActorRole.SERVICE_ACCOUNT, username="svc_pipeline", user_id="999"),
        }

    def set_identity_credentials(
        self,
        role: ActorRole,
        auth_token: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> IdentityContext:
        """Configures or updates tokens/cookies for a test identity."""
        ctx = self._identities[role]
        if auth_token is not None:
            ctx.auth_token = auth_token
        if cookies is not None:
            ctx.cookies = dict(cookies)
        if headers is not None:
            ctx.headers = dict(headers)
        if user_id is not None:
            ctx.user_id = user_id
        if tenant_id is not None:
            ctx.tenant_id = tenant_id
        return ctx

    def get_identity(self, role: ActorRole) -> IdentityContext:
        return self._identities[role]

    def compare_authorization_access(
        self,
        endpoint_url: str,
        role_a_response: Dict[str, Any],  # {"status_code": 200, "body_len": 1200, "contains_data": True}
        role_b_response: Dict[str, Any],  # {"status_code": 200, "body_len": 1200, "contains_data": True}
    ) -> Dict[str, Any]:
        """Evaluates differential access behavior between two identities (e.g. User A vs User B for IDOR)."""
        status_a = role_a_response.get("status_code", 0)
        status_b = role_b_response.get("status_code", 0)

        # Both returned 200 on another user's private object -> IDOR
        is_idor = (status_a == 200 and status_b == 200 and role_a_response.get("contains_data") and role_b_response.get("contains_data"))
        is_auth_bypass = (status_a == 200 and role_b_response.get("is_anonymous") and status_b == 200)

        return {
            "endpoint": endpoint_url,
            "status_role_a": status_a,
            "status_role_b": status_b,
            "is_idor_detected": is_idor,
            "is_auth_bypass_detected": is_auth_bypass,
            "differential_confidence": 0.95 if (is_idor or is_auth_bypass) else 0.1,
        }

    def reset(self) -> None:
        """Resets all credentials to defaults."""
        self.__init__()


identity_context_manager = IdentityContextManager()
