"""
app/reporting/openapi_generator.py
Automated OpenAPI 3.0.3 Specification Generator
Converts Katana crawl endpoints, mined parameters, and API routes into valid OpenAPI 3.0.3 specs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import Asset, Parameter, Port, Scan, URL


class OpenApiGenerator:
    @staticmethod
    async def generate_spec(scan_id: str, db: AsyncSession) -> Dict[str, Any]:
        """Generate OpenAPI 3.0.3 JSON schema from scan's discovered attack surface."""
        scan = await db.get(Scan, scan_id)
        target_name = scan.root_domain if scan else "target.local"

        # Fetch assets, urls, and parameters
        assets = (await db.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()
        asset_ids = [a.id for a in assets]

        urls: List[URL] = []
        if asset_ids:
            urls = (await db.execute(select(URL).where(URL.asset_id.in_(asset_ids)))).scalars().all()

        url_ids = [u.id for u in urls]
        params: List[Parameter] = []
        if url_ids:
            params = (await db.execute(select(Parameter).where(Parameter.url_id.in_(url_ids)))).scalars().all()

        # Group parameters by URL id
        params_by_url: Dict[str, List[Parameter]] = {}
        for p in params:
            params_by_url.setdefault(p.url_id, []).append(p)

        # Build server list
        servers = []
        seen_origins = set()
        for a in assets:
            host = a.hostname or a.ip
            if host and host not in seen_origins:
                seen_origins.add(host)
                servers.append({"url": f"https://{host}", "description": f"Target Host: {host}"})
        if not servers:
            servers.append({"url": f"https://{target_name}", "description": "Primary Target Server"})

        # Build paths
        paths: Dict[str, Any] = {}

        for u in urls:
            raw_url = u.url or "/"
            parsed = urlparse(raw_url)
            path = parsed.path or "/"
            query_str = parsed.query

            # Normalize path for OpenAPI (e.g. replace /user/123 with /user/{id} if numeric)
            path_clean = re.sub(r"/(\d+)(?=/|$)", r"/{id}", path)
            if not path_clean.startswith("/"):
                path_clean = "/" + path_clean

            method = "get"
            title = u.title or f"Endpoint {path_clean}"

            if path_clean not in paths:
                paths[path_clean] = {}

            # Build parameter definitions
            openapi_parameters = []
            seen_param_names = set()

            # 1. From database parameters table
            url_params = params_by_url.get(u.id, [])
            for p in url_params:
                p_name = p.name
                if not p_name or p_name in seen_param_names:
                    continue
                seen_param_names.add(p_name)
                param_loc = (p.location or "query").lower()
                if param_loc not in ("query", "header", "path", "cookie"):
                    param_loc = "query"

                openapi_parameters.append({
                    "name": p_name,
                    "in": param_loc,
                    "required": param_loc == "path",
                    "description": f"Discovered parameter [{p.type or 'string'}]",
                    "schema": {"type": "string", "example": "test_payload"},
                })

            # 2. From URL query string if not yet tracked
            if query_str:
                for qk in parse_qs(query_str):
                    if qk not in seen_param_names:
                        seen_param_names.add(qk)
                        openapi_parameters.append({
                            "name": qk,
                            "in": "query",
                            "required": False,
                            "description": "Auto-extracted query parameter",
                            "schema": {"type": "string"},
                        })

            status_str = str(u.status_code) if u.status_code else "200"
            content_type = u.content_type or "application/json"

            operation_id = re.sub(r"[^a-zA-Z0-9_]", "_", f"{method}_{path_clean.strip('/')}") or "getRoot"

            paths[path_clean][method] = {
                "summary": f"{method.upper()} {path_clean}",
                "description": f"Discovered endpoint via Hunter Aja autonomous crawler. Title: {title}",
                "operationId": operation_id,
                "tags": [path_clean.split("/")[1] if len(path_clean.split("/")) > 1 and path_clean.split("/")[1] else "General"],
                "parameters": openapi_parameters,
                "responses": {
                    status_str: {
                        "description": f"Server response ({status_str})",
                        "content": {
                            content_type.split(";")[0]: {
                                "schema": {"type": "object"}
                            }
                        }
                    }
                }
            }

        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": f"Hunter Aja Attack Surface API Spec — {target_name}",
                "version": "1.0.0",
                "description": f"Auto-generated OpenAPI 3.0.3 specification produced from Level L4 autonomous crawling and parameter intelligence on target {target_name}.",
                "contact": {
                    "name": "Hunter Aja Security Intelligence Platform",
                }
            },
            "servers": servers[:10],
            "paths": paths,
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "apiKeyHeader": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key"
                    }
                }
            }
        }
        return spec
