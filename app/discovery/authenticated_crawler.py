"""Authenticated Crawler & Surface Differencing Engine (V15 Autonomous Architecture).

Spiders web applications using an acquired authenticated session context (cookies/tokens),
maps the differential attack surface (Delta Surface = Authenticated - Unauthenticated),
and automatically identifies second-stage attack vectors (file upload portals, IDOR candidates,
administrative functionality, and sensitive authenticated endpoints).
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from app.core.session_context import SessionContext, SessionIdentity, SessionResponse
from app.orchestration.attack_opportunity import AttackOpportunity, OpportunityState

logger = logging.getLogger("discovery.authenticated_crawler")

COMMON_AUTH_SEED_PATHS = [
    "/",
    "/home",
    "/dashboard",
    "/admin",
    "/profile",
    "/account",
    "/kuesioner",
    "/upload",
    "/uploads",
    "/files",
    "/settings",
    "/users",
    "/reports",
    "/surveys",
    "/panel",
    "/portal",
    "/mahasiswa",
    "/alumni",
    "/tracer",
]


@dataclass
class AuthenticatedSurfaceEndpoint:
    url: str
    method: str = "GET"
    is_authenticated_only: bool = True
    status_code: int = 200
    has_form: bool = False
    has_file_upload: bool = False
    has_parameters: bool = False
    tags: List[str] = field(default_factory=list)  # authenticated_only, file_upload, idor_candidate, admin_functionality
    form_details: List[Dict[str, Any]] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)


class AuthenticatedCrawlerEngine:
    """Stateful Crawler for differential attack surface discovery and second-stage escalation."""

    def __init__(self) -> None:
        self.unauthenticated_surface: Set[str] = set()
        self.authenticated_surface: Set[str] = set()
        self.discovered_endpoints: Dict[str, AuthenticatedSurfaceEndpoint] = {}

    def register_unauthenticated_url(self, url: str) -> None:
        """Registers a URL known to be accessible without authentication."""
        clean_url = self._clean_url(url)
        self.unauthenticated_surface.add(clean_url)

    @staticmethod
    def _clean_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    @staticmethod
    def extract_links(html_text: str, base_url: str) -> Set[str]:
        """Extracts absolute HTTP/HTTPS links from anchor tags, scripts, and forms."""
        links: Set[str] = set()
        if not html_text:
            return links

        base_parsed = urlparse(base_url)
        base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        # 1. <a href="...">
        for m in re.finditer(r'<a\b[^>]*\bhref=["\']([^"\'#]+)["\']', html_text, re.I):
            href = m.group(1).strip()
            if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("tel:"):
                continue
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == base_parsed.netloc:
                links.add(full_url)

        # 2. <form action="...">
        for m in re.finditer(r'<form\b[^>]*\baction=["\']([^"\'#]*)["\']', html_text, re.I):
            action = m.group(1).strip()
            full_url = urljoin(base_url, action) if action else base_url
            if urlparse(full_url).netloc == base_parsed.netloc:
                links.add(full_url)

        # 3. Scripts / API fetch / AJAX endpoints
        for m in re.finditer(r'["\'](/api/[a-zA-Z0-9_\-/\.]+|(?:/admin|/kuesioner|/upload|/user|/dashboard)/[a-zA-Z0-9_\-/\.]+)["\']', html_text, re.I):
            path = m.group(1).strip()
            full_url = urljoin(base_origin, path)
            links.add(full_url)

        return links

    @staticmethod
    def extract_upload_forms(html_text: str, base_url: str) -> List[Dict[str, Any]]:
        """Identifies file upload forms and file input fields."""
        upload_forms: List[Dict[str, Any]] = []
        if not html_text:
            return upload_forms

        form_regex = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.DOTALL)
        input_regex = re.compile(r"<input\b([^>]*)>", re.I)
        attr_regex = re.compile(r'([a-zA-Z0-9_\-]+)=(?:["\']([^"\']*)["\']|([^\s>]+))')

        for f_match in form_regex.finditer(html_text):
            f_attrs_raw = f_match.group(1)
            f_body = f_match.group(2)

            f_attrs = {}
            for m in attr_regex.finditer(f_attrs_raw):
                k = m.group(1).lower()
                v = m.group(2) if m.group(2) is not None else m.group(3)
                f_attrs[k] = v or ""

            action = f_attrs.get("action", "")
            action_url = urljoin(base_url, action) if action else base_url
            method = f_attrs.get("method", "POST").upper()
            is_multipart = "multipart/form-data" in f_attrs.get("enctype", "").lower()

            file_inputs = []
            other_inputs = []

            for inp_match in input_regex.finditer(f_body):
                i_raw = inp_match.group(1)
                i_attrs = {}
                for m in attr_regex.finditer(i_raw):
                    k = m.group(1).lower()
                    v = m.group(2) if m.group(2) is not None else m.group(3)
                    i_attrs[k] = v or ""

                f_type = i_attrs.get("type", "text").lower()
                f_name = i_attrs.get("name")
                if not f_name:
                    continue

                if f_type == "file":
                    file_inputs.append({
                        "name": f_name,
                        "accept": i_attrs.get("accept", ""),
                    })
                else:
                    other_inputs.append({
                        "name": f_name,
                        "type": f_type,
                        "value": i_attrs.get("value", ""),
                    })

            if file_inputs or is_multipart:
                upload_forms.append({
                    "action": action_url,
                    "method": method,
                    "is_multipart": is_multipart,
                    "file_inputs": file_inputs or [{"name": "file", "accept": ""}],
                    "other_inputs": other_inputs,
                })

        return upload_forms

    async def crawl_authenticated_surface(
        self,
        session: SessionContext,
        base_url: str,
        start_urls: Optional[List[str]] = None,
        identity_id: Optional[str] = None,
        max_depth: int = 2,
        max_pages: int = 30,
    ) -> List[AuthenticatedSurfaceEndpoint]:
        """Performs stateful spidering across protected routes with the authenticated session."""
        target_ident = identity_id or session.active_identity_id
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        # Initialize seeds
        seeds = list(start_urls or [])
        for p in COMMON_AUTH_SEED_PATHS:
            full_seed = urljoin(origin, p)
            if full_seed not in seeds:
                seeds.append(full_seed)

        queue: List[Tuple[str, int]] = [(u, 0) for u in seeds]
        visited: Set[str] = set()
        discovered: List[AuthenticatedSurfaceEndpoint] = []

        while queue and len(visited) < max_pages:
            current_url, depth = queue.pop(0)
            clean_cur = self._clean_url(current_url)

            if clean_cur in visited:
                continue
            visited.add(clean_cur)

            try:
                resp = await session.get(current_url, identity_id=target_ident)
                if not resp.status_code or resp.status_code in (404, 500, 502, 503):
                    continue

                body_text = resp.text
                tags: List[str] = []

                is_auth_only = clean_cur not in self.unauthenticated_surface
                if is_auth_only:
                    tags.append("authenticated_only")
                    self.authenticated_surface.add(clean_cur)

                # Check for upload forms
                upload_forms = self.extract_upload_forms(body_text, current_url)
                has_upload = len(upload_forms) > 0 or any(k in current_url.lower() for k in ("upload", "kuesioner", "dokumen", "lampiran", "attachment"))
                if has_upload:
                    tags.append("file_upload")

                # Check for IDOR candidate parameters
                parsed = urlparse(current_url)
                params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
                has_params = len(params) > 0
                if any(p in ("id", "user_id", "nim", "nip", "doc_id", "file_id", "account", "no") for p in params):
                    tags.append("idor_candidate")

                # Check for administrative functionality
                if any(adm in current_url.lower() for adm in ("admin", "manage", "setting", "config", "control", "root")):
                    tags.append("admin_functionality")

                endpoint_obj = AuthenticatedSurfaceEndpoint(
                    url=current_url,
                    method="GET",
                    is_authenticated_only=is_auth_only,
                    status_code=resp.status_code,
                    has_form=len(upload_forms) > 0 or "<form" in body_text.lower(),
                    has_file_upload=has_upload,
                    has_parameters=has_params,
                    tags=tags,
                    form_details=upload_forms,
                    parameters=params,
                )
                self.discovered_endpoints[clean_cur] = endpoint_obj
                discovered.append(endpoint_obj)

                # Follow links if depth permits
                if depth < max_depth:
                    links = self.extract_links(body_text, current_url)
                    for link in links:
                        clean_lnk = self._clean_url(link)
                        if clean_lnk not in visited and urlparse(link).netloc == parsed_base.netloc:
                            queue.append((link, depth + 1))

            except Exception as crawl_err:
                logger.debug("Crawl error on %s: %s", current_url, crawl_err)

        return discovered

    def generate_second_stage_opportunities(
        self,
        endpoints: List[AuthenticatedSurfaceEndpoint],
    ) -> List[AttackOpportunity]:
        """Generates prioritized second-stage attack opportunities (Upload, IDOR, Admin bypass)."""
        opportunities: List[AttackOpportunity] = []

        for ep in endpoints:
            # 1. File Upload Opportunity (Top Priority)
            if ep.has_file_upload or "file_upload" in ep.tags:
                upload_action = ep.url
                form_meta = {}
                if ep.form_details:
                    upload_action = ep.form_details[0].get("action") or ep.url
                    form_meta = ep.form_details[0]

                opp = AttackOpportunity(
                    target=upload_action,
                    endpoint=upload_action,
                    attack_type="upload",
                    hypothesis=f"Authenticated file upload functionality discovered on {upload_action} can be assessed with safe non-destructive canaries.",
                    priority=96,
                    state=OpportunityState.DISCOVERED,
                    prerequisites=["Authenticated session context", "File upload endpoint accessible"],
                    metadata={
                        "form_details": form_meta,
                        "source_url": ep.url,
                        "chained_from": "authenticated_crawler",
                        "tags": ep.tags,
                    },
                )
                opportunities.append(opp)

            # 2. IDOR / Authorization Opportunity
            if "idor_candidate" in ep.tags:
                opp = AttackOpportunity(
                    target=ep.url,
                    endpoint=ep.url,
                    attack_type="idor",
                    hypothesis=f"Authenticated endpoint {ep.url} exposes object identifiers ({ep.parameters}) for multi-identity authorization validation.",
                    priority=85,
                    state=OpportunityState.DISCOVERED,
                    prerequisites=["Multi-identity session contexts"],
                    metadata={
                        "parameters": ep.parameters,
                        "chained_from": "authenticated_crawler",
                        "tags": ep.tags,
                    },
                )
                opportunities.append(opp)

        return opportunities

    def get_delta_surface(self) -> List[str]:
        """Returns the Delta Surface: routes accessible authenticated only."""
        return list(self.authenticated_surface - self.unauthenticated_surface)


authenticated_crawler = AuthenticatedCrawlerEngine()
