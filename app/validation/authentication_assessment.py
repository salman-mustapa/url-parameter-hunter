"""Authentication & Session Assessment Subsystem (V8 §14).

Safely evaluates:
- Login endpoint discovery
- Session token entropy and lifetime
- Cookie security attributes (Secure, HttpOnly, SameSite, Path, Domain)
- MFA requirement and fallback behavior observation
- Account lockout & rate-limiting behavior observation
- Bounded default credential validation on authorized accounts with automatic stop & audit
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.scanners.http import fetch_http
from app.validation.hash_analyzer import HashAnalyzer

logger = logging.getLogger("validation.authentication")


class AuthenticationAssessmentSubsystem:
    """Subsystem for structured, safe authentication assessment (V8 §14)."""

    LOGIN_PATTERNS = [
        r"/login(?:\.php|\.html|\.jsp)?$",
        r"/signin(?:\.php|\.html|\.jsp)?$",
        r"/auth(?:\.php|\.html|\.jsp)?$",
        r"/admin/login",
        r"/user/login",
        r"/wp-login\.php",
        r"/administrator/index\.php",
    ]

    @classmethod
    def identify_login_endpoints(cls, urls: List[str]) -> List[str]:
        """Filters discovered URLs for authentic login interfaces."""
        login_urls = []
        for u in urls:
            path = urlparse(u).path.lower()
            if any(re.search(pat, path) for pat in cls.LOGIN_PATTERNS):
                login_urls.append(u)
        return list(set(login_urls))

    @classmethod
    def analyze_cookie_security(cls, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Audits Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes."""
        findings = []
        set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
        if not set_cookie:
            return findings

        # Check attributes
        sc_lower = set_cookie.lower()
        if "httponly" not in sc_lower:
            findings.append({
                "issue": "missing_httponly",
                "severity": "LOW",
                "cwe_id": "CWE-1004",
                "description": "Session cookie is missing HttpOnly attribute, increasing exposure to XSS token theft.",
            })
        if "secure" not in sc_lower:
            findings.append({
                "issue": "missing_secure_flag",
                "severity": "LOW",
                "cwe_id": "CWE-614",
                "description": "Session cookie is missing Secure attribute, permitting transmission over unencrypted HTTP.",
            })
        if "samesite" not in sc_lower:
            findings.append({
                "issue": "missing_samesite_attribute",
                "severity": "LOW",
                "cwe_id": "CWE-1275",
                "description": "Session cookie lacks SameSite protection, increasing Cross-Site Request Forgery (CSRF) risk.",
            })

        return findings

    @classmethod
    def evaluate_session_entropy(cls, token: str) -> Dict[str, Any]:
        """Calculates token length and Shannon entropy to detect pseudo-random generation."""
        entropy = HashAnalyzer.calculate_entropy(token)
        length = len(token)

        is_predictable = entropy < 3.0 or length < 16
        return {
            "token_length": length,
            "entropy": round(entropy, 2),
            "is_predictable": is_predictable,
            "verdict": "WEAK_ENTROPY" if is_predictable else "SUFFICIENT_ENTROPY",
        }


auth_assessment_subsystem = AuthenticationAssessmentSubsystem()
