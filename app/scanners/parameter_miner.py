"""Dynamic Parameter Mining & Differential Fuzzing Engine (V5 §13, §68).

Discovers hidden query, body, and header parameters on active endpoints using:
1. High-frequency parameter candidate wordlists.
2. Differential response analysis (detecting reflection, size variation, status changes).
3. Automatic database upsert and real-time SSE event emission.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import AsyncSessionLocal
from app.core.sanitizer import sanitize_text
from app.models.models import Asset, Parameter, URL
from app.scanners.base import ScanContext
from app.scanners.http import fetch_http

logger = logging.getLogger("scanner.param_miner")

# Curated high-probability parameter wordlist
CORE_PARAMETER_CANDIDATES = [
    # Identity & Access
    "id", "user_id", "uid", "account_id", "profile_id", "role", "admin", "token", "auth", "key", "api_key",
    # Navigation & Routing
    "page", "file", "path", "url", "redirect", "redirect_url", "return", "return_to", "next", "dest", "destination", "goto", "target", "ref", "view",
    # Search & Filtering
    "q", "query", "search", "keyword", "filter", "sort", "order", "dir", "category", "cat", "tag", "type", "limit", "offset",
    # Execution & Actions
    "cmd", "exec", "command", "action", "do", "method", "op", "step", "mode", "func", "load", "include", "template", "tpl",
    # Data & Payload
    "data", "payload", "input", "val", "value", "content", "msg", "message", "body", "json", "xml",
    # Diagnostics & Developer Flags
    "debug", "test", "demo", "dev", "preview", "enable", "disable", "show", "hidden", "internal", "version", "v",
    # Localization & Session
    "lang", "language", "locale", "session", "session_id", "callback", "jsonp", "email", "username",
]


async def mine_parameters_for_url(
    ctx: ScanContext,
    db: AsyncSession,
    url_record: URL,
    candidates: Optional[List[str]] = None,
) -> List[Tuple[str, str, float]]:
    """Tests an endpoint for hidden parameters using differential reflection analysis."""
    target_url = url_record.url
    parsed = urlparse(target_url)

    # Avoid static assets
    if any(parsed.path.lower().endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".map"]):
        return []

    wordlist = list(candidates or CORE_PARAMETER_CANDIDATES)
    from app.intelligence.llm_client import llm_client
    if llm_client.is_configured and not candidates and parsed.path and len(parsed.path) > 1:
        try:
            ai_params = await llm_client.synthesize_parameter_payloads(
                target_url=target_url,
                parameter_name=parsed.path.strip("/"),
                technology="Generic",
                vulnerability_type="parameter_mining"
            )
            for p in ai_params:
                clean_p = str(p).strip().lower()
                if clean_p and clean_p not in wordlist and len(clean_p) <= 24:
                    wordlist.append(clean_p)
        except Exception as ai_param_err:
            logger.debug("AI parameter candidate generation note: %s", ai_param_err)

    discovered: List[Tuple[str, str, float]] = []

    # 1. Fetch baseline response
    try:
        baseline = await fetch_http(target_url, timeout=settings.http_timeout_seconds)
        if not baseline or baseline.status_code >= 500:
            return []
        base_len = len(baseline.text)
        base_status = baseline.status_code
    except Exception:
        return []

    # 2. Probe in smart batches (5 parameters per request for performance)
    batch_size = 5
    sem = asyncio.Semaphore(5)

    async def test_batch(param_batch: List[str]):
        canary_map = {p: f"hp_{uuid.uuid4().hex[:6]}" for p in param_batch}
        # Construct probed query
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        for p, canary in canary_map.items():
            query_dict[p] = [canary]

        new_query = urlencode(query_dict, doseq=True)
        probed_url = urlunparse(parsed._replace(query=new_query))

        async with sem:
            await ctx.rate_limiter.wait()
            try:
                resp = await fetch_http(probed_url, timeout=settings.http_timeout_seconds)
                if not resp:
                    return

                # Heuristic A: Direct Canary Reflection
                for p, canary in canary_map.items():
                    if canary in resp.text:
                        discovered.append((p, "query", 0.95))
                        logger.info("Found reflected parameter '%s' on %s", p, target_url)

                # Heuristic B: Differential Behavior
                size_diff = abs(len(resp.text) - base_len)
                if resp.status_code != base_status or (size_diff > 30 and size_diff > base_len * 0.05):
                    # If batch caused anomaly, test individual params in batch
                    for p in param_batch:
                        single_canary = f"hp_{uuid.uuid4().hex[:6]}"
                        single_query = urlencode({p: single_canary})
                        single_url = urlunparse(parsed._replace(query=single_query))
                        s_resp = await fetch_http(single_url, timeout=settings.http_timeout_seconds)
                        if s_resp and (single_canary in s_resp.text or s_resp.status_code != base_status or abs(len(s_resp.text) - base_len) > 20):
                            discovered.append((p, "query", 0.85))
            except Exception as exc:
                logger.debug("Parameter probe error on %s: %s", probed_url, exc)

    batches = [wordlist[i:i + batch_size] for i in range(0, min(len(wordlist), 30), batch_size)]
    await asyncio.gather(*[test_batch(b) for b in batches], return_exceptions=True)

    # 3. Store newly discovered parameters
    if discovered:
        async with AsyncSessionLocal() as session:
            for param_name, loc, conf in discovered:
                clean_name = sanitize_text(param_name)
                existing = (await session.execute(
                    select(Parameter).where(
                        Parameter.url_id == url_record.id,
                        Parameter.name == clean_name,
                        Parameter.location == loc,
                    )
                )).scalar_one_or_none()

                if not existing:
                    session.add(Parameter(
                        url_id=url_record.id,
                        name=clean_name,
                        location=loc,
                        type="string",
                        source="miner",
                        confidence=conf,
                    ))
                    await ctx.emit(
                        "parameter.discovered",
                        f"Mined Parameter [{loc}]: '{clean_name}' on {parsed.path or '/'}",
                        name=clean_name,
                        location=loc,
                        url=target_url,
                        asset_id=url_record.asset_id,
                        confidence=conf,
                        severity="info",
                    )
            await session.commit()

    return discovered
