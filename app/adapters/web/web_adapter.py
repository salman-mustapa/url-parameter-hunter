"""Web Assessment Adapter (HTTP, Parameter Mining, Technology Fingerprinting, Screenshots) (V8 §8)."""

from __future__ import annotations

import logging
from typing import Any, Dict, Set

from app.adapters.base.base_adapter import BaseAdapter
from app.scanners.http import fetch_http

logger = logging.getLogger("adapters.web")


class WebAdapter(BaseAdapter):
    name: str = "web_adapter"
    version: str = "8.0.0"
    capabilities: Set[str] = {"web", "browser"}

    async def healthcheck(self) -> bool:
        return True

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        url = task.get("url", "")
        method = task.get("method", "GET")
        headers = task.get("headers")

        raw_result: Dict[str, Any] = {
            "url": url,
            "method": method,
            "response": None,
        }

        try:
            resp = await fetch_http(url, method=method, headers=headers)
            if resp:
                raw_result["response"] = {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "text_sample": resp.text[:2000] if resp.text else "",
                    "url": str(resp.url),
                }
        except Exception as exc:
            logger.warning("Web adapter request error for %s: %s", url, exc)
            raw_result["error"] = str(exc)

        return raw_result

    async def normalize(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        resp = raw_result.get("response") or {}
        return {
            "adapter": self.name,
            "url": raw_result.get("url"),
            "status_code": resp.get("status_code"),
            "headers": resp.get("headers", {}),
            "body_preview": resp.get("text_sample", ""),
            "has_error": "error" in raw_result,
        }
