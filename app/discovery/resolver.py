from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

import tldextract


class AssetResolver:
    """Asset canonicalization, fingerprinting, and deduplication resolver (§6, §198)."""

    @staticmethod
    def canonicalize_hostname(hostname: str) -> str:
        return hostname.strip().lower().rstrip(".")

    @staticmethod
    def generate_fingerprint(asset_type: str, identifier: str) -> str:
        raw = f"{asset_type.lower().strip()}:{identifier.lower().strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def is_subdomain(hostname: str, root_domain: str) -> bool:
        h = AssetResolver.canonicalize_hostname(hostname)
        r = AssetResolver.canonicalize_hostname(root_domain)
        return h == r or h.endswith(f".{r}")

    @staticmethod
    def calculate_depth(hostname: str, root_domain: str) -> int:
        h = AssetResolver.canonicalize_hostname(hostname)
        r = AssetResolver.canonicalize_hostname(root_domain)
        if h == r:
            return 0
        if not h.endswith(f".{r}"):
            return 0
        sub_part = h[: -(len(r) + 1)]
        return len(sub_part.split("."))
