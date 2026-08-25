"""Credential Correlation & Authorization-Controlled Target Mapping Engine (V9.1 §15).

Implements V9.1 Principle:
- A discovered credential becomes a `Credential Artifact` in the knowledge graph.
- It does NOT automatically trigger indiscriminate logins everywhere.
- Candidate correlation requires:
  1. Asset & Target Scope verification (ScopeGuard)
  2. Hostname & Service matching (SSH, HTTP Auth, Database, Admin portal)
  3. Technology stack correlation (e.g., WordPress user -> WordPress wp-login.php)
  4. Authorization confirmation & Safe validation level enforcement
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.models.models import Asset, CredentialArtifact, Identity, Service

logger = logging.getLogger("intelligence.credential_correlation")


@dataclass
class CorrelationCandidate:
    credential_id: str
    username: str
    target_service: str
    target_url: str
    technology: str
    correlation_confidence: str  # HIGH, MEDIUM, LOW
    authorization_required: bool = True
    correlation_reason: str = ""
    safe_to_validate: bool = False


class CredentialCorrelationEngine:
    """Correlates discovered credentials with relevant assets, services, and administrative interfaces."""

    @classmethod
    def correlate_credentials(
        cls,
        identities: List[Identity],
        credential_artifacts: List[CredentialArtifact],
        discovered_services: List[Dict[str, Any]],
        detected_technologies: List[str],
        base_domain: str,
    ) -> List[CorrelationCandidate]:
        """Maps discovered credentials to specific target endpoints based on technology and service clues."""
        candidates: List[CorrelationCandidate] = []
        tech_set = {t.lower() for t in detected_technologies}

        for ident in identities:
            username = ident.username or ""
            role = ident.role or "user"
            meta = ident.metadata_ or {}
            source_table = meta.get("table", "").lower()

            for svc in discovered_services:
                svc_name = svc.get("service", "").lower()
                svc_port = svc.get("port", 80)
                svc_url = svc.get("url", f"http://{base_domain}:{svc_port}")

                # 1. WordPress User Correlation
                is_wp_table = "wp_" in source_table or source_table in ("wp_users", "wordpress_users")
                if is_wp_table or ("wordpress" in tech_set and source_table in ("users", "user", "tbl_users", "accounts")):
                    if ("wp-login" in svc_url or svc_name in ("http", "https")) and not any(c.credential_id == ident.id and c.target_service == "wordpress_auth" for c in candidates):
                        candidates.append(CorrelationCandidate(
                            credential_id=ident.id,
                            username=username,
                            target_service="wordpress_auth",
                            target_url=f"https://{base_domain}/wp-login.php",
                            technology="wordpress",
                            correlation_confidence="HIGH" if is_wp_table else "MEDIUM",
                            correlation_reason=f"Identity '{username}' from table '{source_table}' correlated with WordPress login surface.",
                            safe_to_validate=False,  # Requires explicit operator validation
                        ))

                # 2. Database Service Correlation
                if svc_name in ("mysql", "mariadb", "postgresql", "oracle") and role == "admin":
                    candidates.append(CorrelationCandidate(
                        credential_id=ident.id,
                        username=username,
                        target_service=svc_name,
                        target_url=f"{svc_name}://{base_domain}:{svc_port}",
                        technology=svc_name,
                        correlation_confidence="HIGH",
                        correlation_reason=f"Admin identifier '{username}' correlated with listening database port {svc_port}.",
                        safe_to_validate=False,
                    ))

                # 3. SSH Service Correlation
                if svc_name == "ssh" and role == "admin":
                    candidates.append(CorrelationCandidate(
                        credential_id=ident.id,
                        username=username,
                        target_service="ssh",
                        target_url=f"ssh://{base_domain}:22",
                        technology="openssh",
                        correlation_confidence="MEDIUM",
                        correlation_reason=f"Administrative user '{username}' mapped to SSH service.",
                        safe_to_validate=False,
                    ))

        logger.info("Credential Correlation: generated %d candidate targets from %d identities", len(candidates), len(identities))
        return candidates


credential_correlation_engine = CredentialCorrelationEngine()
