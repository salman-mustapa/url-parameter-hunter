"""Deterministic Correlation Engine (Specialist Agent V2 §6, §37, §39).

Performs lightning-fast, deterministic relational joins without AI overhead:
- Correlates: Asset -> Domain -> IP -> Port -> Service -> Technology -> Endpoint -> Parameter -> Identity -> Credential -> Artifact -> Finding -> CVE -> Evidence.
- Provides immediate contextual lookups for specialist agents.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("orchestration.correlation_engine")


@dataclass
class CorrelatedEntityContext:
    target: str
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    cves: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "domains": list(self.domains),
            "ips": list(self.ips),
            "ports": self.ports,
            "services": self.services,
            "technologies": self.technologies,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "credentials": self.credentials,
            "artifacts": self.artifacts,
            "findings": self.findings,
            "cves": self.cves,
        }


class CorrelationEngine:
    """Deterministic indexing and cross-entity correlation hub."""

    def __init__(self) -> None:
        # target_host -> CorrelatedEntityContext
        self._target_index: Dict[str, CorrelatedEntityContext] = {}
        # tech_name -> list of associated targets
        self._tech_to_targets: Dict[str, Set[str]] = defaultdict(set)
        # cve_id -> list of affected technologies
        self._cve_index: Dict[str, Dict[str, Any]] = {}
        # username/email -> list of observed targets
        self._identity_index: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def _get_or_create_context(self, target: str) -> CorrelatedEntityContext:
        clean = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
        if clean not in self._target_index:
            ctx = CorrelatedEntityContext(target=clean)
            ctx.domains.add(clean)
            self._target_index[clean] = ctx
        return self._target_index[clean]

    def register_ip(self, domain: str, ip: str) -> None:
        ctx = self._get_or_create_context(domain)
        ctx.ips.add(ip)

    def register_port_service(
        self,
        target: str,
        port: int,
        protocol: str = "tcp",
        service_name: Optional[str] = None,
        banner: Optional[str] = None,
    ) -> None:
        ctx = self._get_or_create_context(target)
        port_entry = {"port": port, "protocol": protocol, "service": service_name, "banner": banner}
        if not any(p["port"] == port and p["protocol"] == protocol for p in ctx.ports):
            ctx.ports.append(port_entry)
        if service_name:
            ctx.services.append(port_entry)

    def register_technology(
        self,
        target: str,
        tech_name: str,
        version: Optional[str] = None,
        confidence: float = 1.0,
    ) -> None:
        ctx = self._get_or_create_context(target)
        entry = {"name": tech_name, "version": version, "confidence": confidence}
        if not any(t["name"].lower() == tech_name.lower() for t in ctx.technologies):
            ctx.technologies.append(entry)
        self._tech_to_targets[tech_name.lower()].add(ctx.target)

    def register_endpoint(self, target: str, url: str, params: Optional[List[str]] = None) -> None:
        ctx = self._get_or_create_context(target)
        if url not in ctx.endpoints:
            ctx.endpoints.append(url)
        if params:
            for p in params:
                if p not in ctx.parameters:
                    ctx.parameters.append(p)

    def register_credential(self, target: str, username: str, password_hash_or_type: str) -> None:
        ctx = self._get_or_create_context(target)
        cred = {"username": username, "credential": password_hash_or_type, "target": ctx.target}
        ctx.credentials.append(cred)
        self._identity_index[username.lower()].append(cred)

    def register_finding(self, target: str, finding_id: str, title: str, severity: str, cve_id: Optional[str] = None) -> None:
        ctx = self._get_or_create_context(target)
        f_entry = {"id": finding_id, "title": title, "severity": severity, "cve_id": cve_id}
        ctx.findings.append(f_entry)
        if cve_id:
            ctx.cves.append({"cve_id": cve_id, "finding_id": finding_id})

    def correlate_target(self, target: str) -> Optional[Dict[str, Any]]:
        """Returns the fully aggregated 360-degree attack surface context for a target."""
        clean = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
        ctx = self._target_index.get(clean)
        return ctx.to_dict() if ctx else None

    def find_targets_by_technology(self, tech_name: str) -> List[str]:
        """Finds all targets running a specific framework or technology."""
        return list(self._tech_to_targets.get(tech_name.lower(), set()))

    def correlate_credentials_to_services(self, target: str) -> List[Dict[str, Any]]:
        """Finds potential credential reuse vectors across services on the target."""
        ctx = self._get_or_create_context(target)
        return ctx.credentials

    def reset(self) -> None:
        """Resets the in-memory index."""
        self._target_index.clear()
        self._tech_to_targets.clear()
        self._cve_index.clear()
        self._identity_index.clear()


correlation_engine = CorrelationEngine()
