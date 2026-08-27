from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import tldextract


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    return all(0 < len(x) <= 63 and re.match(r"^[a-z0-9-]+$", x) and not x.startswith("-") and not x.endswith("-") for x in labels)


def normalize_target(raw: str) -> tuple[str, str]:
    value = raw.strip().lower()
    if not value:
        raise ValueError("Target tidak boleh kosong.")
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = (parsed.hostname or value.split("/")[0]).strip(".")
    if not is_valid_hostname(host):
        raise ValueError(f"Format domain/host '{host}' tidak valid.")
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        labels = host.split(".")
        if len(labels) >= 2:
            return host, f"{labels[-2]}.{labels[-1]}"
        raise ValueError(f"Root domain untuk '{host}' tidak valid.")
    return host, f"{ext.domain}.{ext.suffix}"



class ScopeEngine:
    """Security Assessment Scope Engine (§2, §102).
    Enforces include/exclude rules, allowed ports/protocols, test levels, and authorization checks.
    Every worker MUST pass through this check before making outbound requests.
    """

    def __init__(
        self,
        root_domain: str,
        allowed_hosts: Optional[List[str]] = None,
        excluded_hosts: Optional[List[str]] = None,
        allowed_cidrs: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        allowed_protocols: Optional[List[str]] = None,
        allowed_modules: Optional[List[str]] = None,
        recursive: bool = True,
        authorization_id: Optional[str] = None,
        allow_private_networks: bool = False,
    ):
        self.root_domain = root_domain.lower().strip(".")
        self.recursive = recursive
        self.authorization_id = authorization_id
        self.allow_private_networks = bool(allow_private_networks)

        if not self.recursive and allowed_hosts:
            self.allowed_hosts: Set[str] = {h.lower().strip(".") for h in allowed_hosts}
        else:
            self.allowed_hosts: Set[str] = {self.root_domain, *(h.lower().strip(".") for h in (allowed_hosts or []))}
        self.excluded_hosts: Set[str] = {h.lower().strip(".") for h in (excluded_hosts or [])}

        self.allowed_cidrs = [ipaddress.ip_network(c, strict=False) for c in (allowed_cidrs or [])]
        self.allowed_ports: Set[int] = set(allowed_ports) if allowed_ports else set()
        self.allowed_protocols: Set[str] = {p.lower() for p in (allowed_protocols or ["http", "https", "tcp", "udp", "dns"])}
        self.allowed_modules: Set[str] = {m.lower() for m in (allowed_modules or [])} if allowed_modules else set()

    def host_allowed(self, host: Optional[str]) -> bool:
        if not host:
            return False
        h = host.lower().strip(".")

        # Check explicit exclusions first
        if any(h == ex or h.endswith(f".{ex}") for ex in self.excluded_hosts):
            return False

        if not self.recursive:
            return h in self.allowed_hosts

        return any(h == d or h.endswith(f".{d}") for d in self.allowed_hosts)

    def ip_allowed(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        # Explicit CIDRs are the only implicit authorization for non-public ranges.
        if self.allowed_cidrs:
            return any(obj in net for net in self.allowed_cidrs)
        if self.allow_private_networks:
            return True
        return bool(obj.is_global)

    def port_allowed(self, port: int) -> bool:
        if not self.allowed_ports:
            return True
        return port in self.allowed_ports

    def protocol_allowed(self, proto: str) -> bool:
        if not self.allowed_protocols:
            return True
        return proto.lower() in self.allowed_protocols

    def module_allowed(self, module_name: str) -> bool:
        if not self.allowed_modules:
            return True
        return module_name.lower() in self.allowed_modules

    def url_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme and not self.protocol_allowed(parsed.scheme):
            return False
        if parsed.port and not self.port_allowed(parsed.port):
            return False
        host = parsed.hostname
        if not self.host_allowed(host):
            return False
        try:
            ipaddress.ip_address(host or "")
        except ValueError:
            return True
        return self.ip_allowed(host)

    def assert_host(self, host: str) -> None:
        if not self.host_allowed(host):
            raise PermissionError(f"[Scope Engine Violation] Host '{host}' is outside authorized scope.")

    def assert_url(self, url: str) -> None:
        if not self.url_allowed(url):
            raise PermissionError(f"[Scope Engine Violation] URL '{url}' is outside authorized scope.")
