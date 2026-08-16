from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import tldextract


def normalize_target(raw: str) -> tuple[str, str]:
    value = raw.strip().lower()
    if not value:
        raise ValueError("Target kosong")
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or value.split("/")[0]).strip(".")
    if not is_valid_hostname(host):
        raise ValueError("Domain tidak valid")
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        raise ValueError("Root domain tidak valid")
    return host, f"{ext.domain}.{ext.suffix}"


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    return all(0 < len(x) <= 63 and re.match(r"^[a-z0-9-]+$", x) and not x.startswith("-") and not x.endswith("-") for x in labels)


class Scope:
    def __init__(self, root_domain: str, allowed_hosts: list[str] | None = None, allowed_cidrs: list[str] | None = None):
        self.root_domain = root_domain.lower().strip(".")
        self.allowed_hosts = {self.root_domain, *(h.lower().strip(".") for h in (allowed_hosts or []))}
        self.allowed_cidrs = [ipaddress.ip_network(c, strict=False) for c in (allowed_cidrs or [])]

    def host_allowed(self, host: str | None) -> bool:
        if not host:
            return False
        h = host.lower().strip(".")
        return any(h == d or h.endswith(f".{d}") for d in self.allowed_hosts)

    def ip_allowed(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return bool(self.allowed_cidrs and any(obj in net for net in self.allowed_cidrs))

    def url_allowed(self, url: str) -> bool:
        return self.host_allowed(urlparse(url).hostname)

    def assert_host(self, host: str) -> None:
        if not self.host_allowed(host):
            raise ValueError(f"Out of scope: {host}")
