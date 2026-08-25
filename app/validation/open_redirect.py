"""Open Redirect Validation Engine (§22).

Detects unvalidated redirects. Non-destructive.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.open_redirect")

# Controlled redirect targets (safe, external domains)
REDIRECT_PROBES = [
    "https://evil.example.com",
    "//evil.example.com",
    "https://evil.example.com/%2f..",
    "/\\evil.example.com",
    "////evil.example.com",
    "https://evil.example.com@legitimate.com",
]


@dataclass
class OpenRedirectCandidate:
    url: str
    parameter: str
    location: str
    probe: str
    redirect_target: str
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)
    poc_curl: str = ""


class OpenRedirectValidator:
    """Controlled Open Redirect validator (§22)."""

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[OpenRedirectCandidate]:
        candidates: List[OpenRedirectCandidate] = []

        redirect_param_names = {"redirect", "url", "next", "return", "returnurl",
                                "redirect_uri", "redirect_url", "return_to", "rurl",
                                "dest", "destination", "continue", "goto", "target",
                                "callback", "forward", "ref", "redir"}

        for param in parameters:
            name = param.get("name", "").lower()
            location = param.get("location", "query")
            if name not in redirect_param_names:
                continue

            for probe in REDIRECT_PROBES:
                candidate = await self._test_redirect(url, param["name"], location, probe, headers)
                if candidate:
                    candidates.append(candidate)
                    break

        logger.info("Open Redirect validation: %d candidates on %s", len(candidates), url)
        return candidates

    async def _test_redirect(
        self,
        url: str,
        param_name: str,
        location: str,
        probe: str,
        headers: Optional[dict] = None,
    ) -> Optional[OpenRedirectCandidate]:
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False,
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

                # Check for redirect to external domain
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("location", "")
                    parsed_loc = urlparse(loc)
                    if parsed_loc.netloc and "evil.example.com" in parsed_loc.netloc:
                        return OpenRedirectCandidate(
                            url=final_url,
                            parameter=param_name,
                            location=location,
                            probe=probe,
                            redirect_target=loc[:200],
                            confidence="VALIDATED",
                            poc_curl=poc_curl,
                            evidence={
                                "status_code": resp.status_code,
                                "location_header": loc[:200],
                                "redirect_to_external": True,
                                "poc_curl": poc_curl,
                                "url": final_url,
                                "probe": probe,
                            },
                        )

                # Check for meta refresh or JS redirect in body
                if resp.status_code == 200:
                    body = resp.text[:5000]
                    meta_refresh = re.search(
                        r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>\s]+)',
                        body, re.I
                    )
                    if meta_refresh and "evil.example.com" in meta_refresh.group(1):
                        return OpenRedirectCandidate(
                            url=final_url,
                            parameter=param_name,
                            location=location,
                            probe=probe,
                            redirect_target=meta_refresh.group(1)[:200],
                            confidence="SUSPECTED",
                            poc_curl=poc_curl,
                            evidence={
                                "status_code": resp.status_code,
                                "meta_refresh": meta_refresh.group(0)[:200],
                                "poc_curl": poc_curl,
                                "url": final_url,
                                "probe": probe,
                            },
                        )

        except Exception as exc:
            logger.debug("Open redirect test failed for %s: %s", url, exc)

        return None


open_redirect_validator = OpenRedirectValidator()
