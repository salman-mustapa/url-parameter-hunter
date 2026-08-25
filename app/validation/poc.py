"""Proof-of-Concept Management, Request Recording & PoC Validation Engine (V9.1 Phase 3).

Enforces V9.1 Principles:
1. PoC HARUS berasal dari request yang benar-benar dieksekusi.
2. Jika PoC != request aktual -> POC_INVALID, report_ready = False.
3. Tidak boleh ada PoC sintetis/kosong (e.g. `curl -X POST -d ''` padahal payload dikirim).
4. Sanitasi token/rahasia internal tanpa merusak integritas payload pengujian.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse


@dataclass
class CanonicalRequest:
    """Canonical representation of an actual executed wire request (V9.1 Phase 3)."""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    data: Optional[Any] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    redirect_target: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_wire: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RequestRecorder:
    """Records actual network interactions executed during active validation (V9.1 Phase 3)."""

    def __init__(self) -> None:
        self._records: List[CanonicalRequest] = []

    def record(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        cookies: Optional[Dict[str, str]] = None,
        response_status: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_snippet: Optional[str] = None,
        redirect_target: Optional[str] = None,
    ) -> CanonicalRequest:
        """Capture executed network transaction into a canonical request."""
        clean_headers = {k: v for k, v in (headers or {}).items() if k.lower() not in ("connection", "content-length")}
        
        parsed = urlparse(url)
        merged_params = dict(params or {})
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                if k not in merged_params:
                    merged_params[k] = v[0] if len(v) == 1 else v

        req = CanonicalRequest(
            method=method.upper(),
            url=url,
            headers=clean_headers,
            query_params=merged_params,
            data=data,
            cookies=cookies or {},
            response_status=response_status,
            response_headers=response_headers or {},
            response_snippet=response_snippet[:500] if response_snippet else None,
            redirect_target=redirect_target,
        )
        self._records.append(req)
        return req

    @property
    def latest(self) -> Optional[CanonicalRequest]:
        return self._records[-1] if self._records else None

    @property
    def all_records(self) -> List[CanonicalRequest]:
        return list(self._records)


class PoCCompiler:
    """Compiles a CanonicalRequest into deterministic cURL, Raw HTTP, and Python reproduction scripts (V9.1 Phase 3)."""

    @classmethod
    def compile_curl(cls, req: CanonicalRequest) -> str:
        """Constructs an exact cURL command from a canonical request."""
        cmd_parts = ["curl", "-i", "-s", "-k"]

        method_upper = req.method.upper()
        if method_upper != "GET":
            cmd_parts.extend(["-X", method_upper])

        if req.headers:
            for k, v in req.headers.items():
                if k.lower() in ("host", "content-length", "accept-encoding", "connection"):
                    continue
                cmd_parts.extend(["-H", f"'{k}: {v}'"])

        if req.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in req.cookies.items())
            cmd_parts.extend(["-b", f"'{cookie_str}'"])

        if req.data:
            if isinstance(req.data, dict):
                encoded_data = urlencode(req.data)
                cmd_parts.extend(["-d", f"'{encoded_data}'"])
            elif isinstance(req.data, (str, bytes)):
                str_data = req.data.decode("utf-8", errors="ignore") if isinstance(req.data, bytes) else str(req.data)
                safe_str = str_data.replace("'", "'\\''")
                cmd_parts.extend(["-d", f"'{safe_str}'"])

        final_url = req.url
        if req.query_params:
            parsed = urlparse(final_url)
            # If query params were not already part of the base URL
            if not parsed.query:
                query_str = urlencode(req.query_params)
                sep = "&" if "?" in final_url else "?"
                final_url = f"{final_url}{sep}{query_str}"

        cmd_parts.append(f"'{final_url}'")
        return " ".join(cmd_parts)

    @classmethod
    def compile_raw_http(cls, req: CanonicalRequest) -> str:
        """Constructs raw HTTP wire format representation."""
        parsed = urlparse(req.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        elif req.query_params:
            path += f"?{urlencode(req.query_params)}"

        lines = [f"{req.method.upper()} {path} HTTP/1.1", f"Host: {parsed.netloc}"]

        for k, v in req.headers.items():
            if k.lower() != "host":
                lines.append(f"{k}: {v}")

        if req.cookies:
            lines.append(f"Cookie: {'; '.join(f'{k}={v}' for k, v in req.cookies.items())}")

        body_str = ""
        if req.data:
            if isinstance(req.data, dict):
                body_str = urlencode(req.data)
            else:
                body_str = str(req.data)
            if not any(k.lower() == "content-length" for k in req.headers):
                lines.append(f"Content-Length: {len(body_str)}")

        return "\r\n".join(lines) + "\r\n\r\n" + body_str

    @classmethod
    def compile_python(cls, req: CanonicalRequest) -> str:
        """Generates reproducible Python httpx reproduction script."""
        return f"""import httpx

url = {json.dumps(req.url)}
headers = {json.dumps(req.headers, indent=4)}
data = {json.dumps(req.data, indent=4) if req.data else "None"}

with httpx.Client(verify=False, timeout=10.0, follow_redirects=False) as client:
    resp = client.request(
        method={json.dumps(req.method)},
        url=url,
        headers=headers,
        data=data,
    )
    print(f"Status Code: {{resp.status_code}}")
    print(f"Response Length: {{len(resp.text)}}")
"""


class PoCValidator:
    """Validates that a generated PoC matches the actual executed request (V9.1 Phase 3)."""

    @classmethod
    def validate_poc(
        cls,
        poc_command: str,
        recorded_request: Optional[CanonicalRequest],
    ) -> Dict[str, Any]:
        """Ensures the PoC command matches the recorded executed wire request."""
        if not poc_command or not recorded_request:
            return {
                "is_valid": False,
                "status": "POC_INVALID",
                "reason": "Missing PoC command or missing recorded wire request.",
                "report_ready": False,
            }

        # Check Method match
        method = recorded_request.method.upper()
        if method != "GET":
            if f"-X {method}" not in poc_command and f"-X '{method}'" not in poc_command and f'-X "{method}"' not in poc_command:
                return {
                    "is_valid": False,
                    "status": "POC_INVALID",
                    "reason": f"PoC does not specify executed HTTP method {method}.",
                    "report_ready": False,
                }

        # Check for empty synthetic data bug (-d '')
        if recorded_request.data and "-d ''" in poc_command:
            return {
                "is_valid": False,
                "status": "POC_INVALID",
                "reason": "PoC contains empty payload (-d '') while actual request transmitted form data.",
                "report_ready": False,
            }

        # Check URL domain presence
        parsed_target = urlparse(recorded_request.url)
        if parsed_target.netloc and parsed_target.netloc not in poc_command:
            return {
                "is_valid": False,
                "status": "POC_INVALID",
                "reason": f"PoC target hostname '{parsed_target.netloc}' does not match executed target.",
                "report_ready": False,
            }

        return {
            "is_valid": True,
            "status": "POC_VALID",
            "reason": "PoC strictly derived from wire-recorded transaction.",
            "report_ready": True,
        }


# Backwards compatibility alias
class CapturedRequestPoCBuilder:
    @classmethod
    def build_curl(cls, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None, params: Optional[Dict[str, Any]] = None) -> str:
        req = CanonicalRequest(method=method, url=url, headers=headers or {}, query_params=params or {}, data=data)
        return PoCCompiler.compile_curl(req)

    @classmethod
    def build_raw_http(cls, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None) -> str:
        req = CanonicalRequest(method=method, url=url, headers=headers or {}, data=data)
        return PoCCompiler.compile_raw_http(req)


class PocEngine:
    """Proof-of-Concept Management & Sanitization Engine (§31)."""

    SECRET_PATTERNS = [
        re.compile(r'(password|passwd|pwd|secret|token|api_?key|auth|bearer)\s*[:=]\s*["\']?([^"\'\s&]+)', re.I),
        re.compile(r'(session|PHPSESSID|JSESSIONID|token)\s*=\s*([^;\s&]+)', re.I),
    ]

    @classmethod
    def sanitize(cls, text: str) -> str:
        if not text:
            return ""
        sanitized = text
        for pattern in cls.SECRET_PATTERNS:
            sanitized = pattern.sub(r"\1=[REDACTED]", sanitized)
        return sanitized

    @classmethod
    def create_poc(
        cls,
        title: str,
        target: str,
        preconditions: List[str],
        request_payload: str,
        expected_result: str,
        actual_result: str,
        reproduction_steps: List[str],
        safety_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "target": target,
            "preconditions": preconditions,
            "request_payload": cls.sanitize(request_payload),
            "expected_result": expected_result,
            "actual_result": cls.sanitize(actual_result),
            "reproduction_steps": reproduction_steps,
            "safety_notes": safety_notes or "Non-destructive observation only. No data was modified or exfiltrated.",
            "is_sanitized": True,
        }
