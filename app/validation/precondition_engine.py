"""Precondition Engine (§25, §75).

Ensures active tests are only executed when strict prerequisite conditions are met:
- Eliminates wasteful requests (Do Not Run Everything §75).
- Ensures high signal-to-noise ratio.
- Evaluates candidate applicability before task dispatch.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("validation.precondition_engine")


class PreconditionStatus(str, Enum):
    SATISFIED = "SATISFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MISSING_PREREQUISITES = "MISSING_PREREQUISITES"


@dataclass
class PreconditionResult:
    status: PreconditionStatus
    vulnerability_class: str
    target_endpoint: str
    satisfied_conditions: List[str] = field(default_factory=list)
    missing_conditions: List[str] = field(default_factory=list)
    reason: str = ""


class PreconditionEngine:
    """Evaluates prerequisites for every vulnerability class before test execution."""

    def __init__(self) -> None:
        self.idor_param_patterns = [
            r"^id$", r".*_id$", r"^user$", r"^account$", r"^uid$", r"^doc$",
            r"^file_id$", r"^order$", r"^invoice$", r"^customer_id$", r"^profile_id$"
        ]
        self.ssrf_param_patterns = [
            r"^url$", r"^target$", r"^dest$", r"^destination$", r"^redirect$",
            r"^next$", r"^feed$", r"^webhook$", r"^uri$", r"^callback$", r"^fetch$", r"^proxy$"
        ]
        self.rce_param_patterns = [
            r"^cmd$", r"^exec$", r"^command$", r"^ping$", r"^host$", r"^ip$",
            r"^run$", r"^script$", r"^cli$", r"^eval$", r"^system$"
        ]

    def evaluate(self, vuln_class: str, target_context: Dict[str, Any]) -> PreconditionResult:
        """Evaluate if target_context satisfies preconditions for vuln_class."""
        vuln_norm = vuln_class.upper().strip()
        endpoint = target_context.get("url") or target_context.get("path") or target_context.get("endpoint") or ""
        params = target_context.get("parameters") or []
        method = (target_context.get("method") or "GET").upper()
        headers = target_context.get("headers") or {}
        technologies = target_context.get("technologies") or []

        if vuln_norm in ("SQLI", "SQL_INJECTION"):
            return self._check_sqli(endpoint, params, method, technologies)
        elif vuln_norm in ("IDOR", "BOLA"):
            return self._check_idor(endpoint, params, target_context)
        elif vuln_norm in ("XSS", "CROSS_SITE_SCRIPTING"):
            return self._check_xss(endpoint, params, target_context)
        elif vuln_norm in ("SSRF", "SERVER_SIDE_REQUEST_FORGERY"):
            return self._check_ssrf(endpoint, params, target_context)
        elif vuln_norm in ("AUTH_BYPASS", "AUTHENTICATION_BYPASS"):
            return self._check_auth_bypass(endpoint, target_context)
        elif vuln_norm in ("PATH_TRAVERSAL", "LFI", "FILE_INCLUSION"):
            return self._check_path_traversal(endpoint, params, target_context)
        elif vuln_norm in ("COMMAND_INJECTION", "RCE"):
            return self._check_rce(endpoint, params, target_context)
        elif vuln_norm in ("FILE_UPLOAD",):
            return self._check_file_upload(endpoint, method, headers, target_context)
        else:
            # Generic fallback
            if params or endpoint:
                return PreconditionResult(
                    status=PreconditionStatus.SATISFIED,
                    vulnerability_class=vuln_norm,
                    target_endpoint=endpoint,
                    satisfied_conditions=["Generic parameter/endpoint context available"],
                    reason="Standard test preconditions met."
                )
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class=vuln_norm,
                target_endpoint=endpoint,
                missing_conditions=["Target endpoint or parameters required"],
                reason="No endpoint or parameter provided for test."
            )

    # -------------------------------------------------------------------------
    # Specific Precondition Checkers
    # -------------------------------------------------------------------------

    def _check_sqli(self, endpoint: str, params: List[Dict[str, Any]], method: str, technologies: List[str]) -> PreconditionResult:
        if not params and "?" not in endpoint and method == "GET":
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="SQLI",
                target_endpoint=endpoint,
                missing_conditions=["Controllable input parameter (query, body, or path)"],
                reason="SQLi testing skipped: static or parameterless endpoint."
            )
        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="SQLI",
            target_endpoint=endpoint,
            satisfied_conditions=["Controllable input parameter present", "Server-side dynamic context expected"],
            reason="Preconditions satisfied for controlled SQLi validation."
        )

    def _check_idor(self, endpoint: str, params: List[Dict[str, Any]], context: Dict[str, Any]) -> PreconditionResult:
        has_id_param = False
        param_names = [p.get("name", "") if isinstance(p, dict) else str(p) for p in params]
        
        # Check in URL path (e.g. /api/users/123 or /orders/UUID)
        path_has_id = bool(re.search(r"/(?:users|accounts|orders|invoices|docs|files|items|profile|v\d+)/[a-zA-Z0-9_-]+", endpoint))
        
        for name in param_names:
            name_lower = name.lower()
            if any(re.match(pat, name_lower) for pat in self.idor_param_patterns):
                has_id_param = True
                break

        if not has_id_param and not path_has_id:
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="IDOR",
                target_endpoint=endpoint,
                missing_conditions=["Controllable object identifier parameter or restful entity path"],
                reason="IDOR testing skipped: No object identifier found."
            )

        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="IDOR",
            target_endpoint=endpoint,
            satisfied_conditions=["Controllable object identifier identified", "Identity boundary applicable"],
            reason="Preconditions satisfied for cross-identity IDOR authorization validation."
        )

    def _check_xss(self, endpoint: str, params: List[Dict[str, Any]], context: Dict[str, Any]) -> PreconditionResult:
        if not params and "?" not in endpoint:
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="XSS",
                target_endpoint=endpoint,
                missing_conditions=["Controllable input parameter for reflection or DOM injection"],
                reason="XSS testing skipped: No controllable input."
            )
        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="XSS",
            target_endpoint=endpoint,
            satisfied_conditions=["Controllable input present", "Reflective/DOM surface testable"],
            reason="Preconditions satisfied for XSS validation."
        )

    def _check_ssrf(self, endpoint: str, params: List[Dict[str, Any]], context: Dict[str, Any]) -> PreconditionResult:
        has_ssrf_param = False
        param_names = [p.get("name", "") if isinstance(p, dict) else str(p) for p in params]
        
        for name in param_names:
            name_lower = name.lower()
            if any(re.match(pat, name_lower) for pat in self.ssrf_param_patterns):
                has_ssrf_param = True
                break

        if not has_ssrf_param:
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="SSRF",
                target_endpoint=endpoint,
                missing_conditions=["URL/URI or destination parameter capable of triggering outbound request"],
                reason="SSRF testing skipped: No URL/destination parameter."
            )

        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="SSRF",
            target_endpoint=endpoint,
            satisfied_conditions=["Outbound URL parameter present", "Callback validation capable"],
            reason="Preconditions satisfied for controlled SSRF validation."
        )

    def _check_auth_bypass(self, endpoint: str, context: Dict[str, Any]) -> PreconditionResult:
        is_auth_endpoint = bool(re.search(r"/(?:login|auth|signin|admin|dashboard|portal|api/v\d+/user)", endpoint, re.IGNORECASE))
        if not is_auth_endpoint and not context.get("requires_auth"):
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="AUTH_BYPASS",
                target_endpoint=endpoint,
                missing_conditions=["Authentication workflow or protected resource boundary"],
                reason="Auth bypass testing skipped: Endpoint is not an authentication endpoint or protected resource."
            )
        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="AUTH_BYPASS",
            target_endpoint=endpoint,
            satisfied_conditions=["Authentication workflow or protected resource verified"],
            reason="Preconditions satisfied for authentication bypass validation."
        )

    def _check_path_traversal(self, endpoint: str, params: List[Dict[str, Any]], context: Dict[str, Any]) -> PreconditionResult:
        param_names = [p.get("name", "").lower() if isinstance(p, dict) else str(p).lower() for p in params]
        has_file_param = any(p in ("file", "path", "page", "include", "doc", "template", "view", "download", "load") for p in param_names)
        
        if not has_file_param:
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="PATH_TRAVERSAL",
                target_endpoint=endpoint,
                missing_conditions=["File or path parameter capable of file retrieval"],
                reason="Path traversal skipped: No file/path parameter."
            )
        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="PATH_TRAVERSAL",
            target_endpoint=endpoint,
            satisfied_conditions=["File/path parameter identified"],
            reason="Preconditions satisfied for path traversal validation."
        )

    def _check_rce(self, endpoint: str, params: List[Dict[str, Any]], context: Dict[str, Any]) -> PreconditionResult:
        param_names = [p.get("name", "").lower() if isinstance(p, dict) else str(p).lower() for p in params]
        has_rce_param = any(any(re.match(pat, p) for pat in self.rce_param_patterns) for p in param_names)
        
        if not has_rce_param:
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="RCE",
                target_endpoint=endpoint,
                missing_conditions=["Execution-capable parameter or system sink"],
                reason="RCE testing skipped: No command/execution sink parameter."
            )
        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="RCE",
            target_endpoint=endpoint,
            satisfied_conditions=["Execution sink parameter identified", "Harmless canary proof enabled"],
            reason="Preconditions satisfied for controlled RCE validation."
        )

    def _check_file_upload(self, endpoint: str, method: str, headers: Dict[str, Any], context: Dict[str, Any]) -> PreconditionResult:
        content_type = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
        is_upload = "multipart/form-data" in content_type or bool(re.search(r"/(?:upload|attach|import|avatar|file)", endpoint, re.IGNORECASE))
        
        if not is_upload and method != "POST":
            return PreconditionResult(
                status=PreconditionStatus.NOT_APPLICABLE,
                vulnerability_class="FILE_UPLOAD",
                target_endpoint=endpoint,
                missing_conditions=["Multipart form upload capability or upload endpoint"],
                reason="File upload testing skipped: No upload capability."
            )
        return PreconditionResult(
            status=PreconditionStatus.SATISFIED,
            vulnerability_class="FILE_UPLOAD",
            target_endpoint=endpoint,
            satisfied_conditions=["Upload sink verified"],
            reason="Preconditions satisfied for file upload validation."
        )


# Global Singleton Instance
precondition_engine = PreconditionEngine()
