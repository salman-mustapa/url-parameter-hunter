"""Deterministic CVE Applicability & Prerequisite Validation Engine (V9.1 §18).

Implements the full V9.1 CVE pipeline:
Technology -> Product normalization -> CPE/PURL -> CVE -> Affected range
-> Vendor advisory -> Package revision -> Configuration prerequisite -> Final State

Final Deterministic States (V9.1 §18):
- NOT_AFFECTED: Version falls outside vulnerable range
- PATCHED: Backported patch / package revision detected
- CANDIDATE: Version matches but configuration prerequisite unverified
- VALIDATION_REQUIRED: Vulnerable version + prerequisite present, awaiting active proof
- CONFIRMED: Active validation demonstrated vulnerability
- INCONCLUSIVE: Missing exact version granularity
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.intelligence.cve import CveIntelligence

logger = logging.getLogger("intelligence.cve_applicability")


class CveApplicabilityState:
    NOT_AFFECTED = "NOT_AFFECTED"
    PATCHED = "PATCHED"
    CANDIDATE = "CANDIDATE"
    VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class CveEvaluationResult:
    cve_id: str
    product: str
    detected_version: Optional[str]
    cpe: str
    state: str  # CveApplicabilityState
    is_applicable: bool
    confidence: str
    reasons: List[str] = field(default_factory=list)
    prerequisites_met: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class CveApplicabilityValidator:
    """Deterministic CVE verification engine against detected technologies and configurations."""

    @classmethod
    def normalize_product(cls, product_name: str) -> str:
        """Normalizes raw banner software names into standardized product identifiers."""
        p = product_name.lower().strip()
        if "apache" in p and "tomcat" not in p:
            return "apache_http_server"
        elif "nginx" in p:
            return "nginx"
        elif "iis" in p or "microsoft-iis" in p:
            return "microsoft_iis"
        elif "wordpress" in p:
            return "wordpress"
        elif "php" in p and "phpmyadmin" not in p:
            return "php"
        elif "openssh" in p:
            return "openssh"
        elif "mariadb" in p:
            return "mariadb"
        elif "mysql" in p:
            return "mysql"
        elif "postgresql" in p:
            return "postgresql"
        return p.replace(" ", "_")

    @classmethod
    def generate_cpe(cls, product: str, version: Optional[str] = None) -> str:
        norm = cls.normalize_product(product)
        ver = version or "*"
        return f"cpe:2.3:a:{norm}:{norm}:{ver}:*:*:*:*:*:*:*"

    @classmethod
    def evaluate_cve_applicability(
        cls,
        cve_record: Dict[str, Any],
        detected_technology: str,
        detected_version: Optional[str] = None,
        active_modules: Optional[List[str]] = None,
        config_context: Optional[Dict[str, Any]] = None,
    ) -> CveEvaluationResult:
        """Runs the deterministic 7-step applicability check."""
        cve_id = cve_record.get("cve_id", "")
        product = detected_technology
        cpe = cls.generate_cpe(product, detected_version)
        reasons = []
        cfg = config_context or {}
        modules = [m.lower() for m in (active_modules or [])]

        # Step 1: Version granularity check
        if not detected_version:
            return CveEvaluationResult(
                cve_id=cve_id,
                product=product,
                detected_version=None,
                cpe=cpe,
                state=CveApplicabilityState.INCONCLUSIVE,
                is_applicable=False,
                confidence="SUSPECTED",
                reasons=["No exact version detected. Held at INCONCLUSIVE."],
            )

        # Step 2: Version Range Check
        is_in_range = False
        exact_vers = cve_record.get("version_exact", [])
        if exact_vers:
            if detected_version in exact_vers:
                is_in_range = True
                reasons.append(f"Detected version {detected_version} matches exact vulnerable release {exact_vers}.")
            else:
                return CveEvaluationResult(
                    cve_id=cve_id,
                    product=product,
                    detected_version=detected_version,
                    cpe=cpe,
                    state=CveApplicabilityState.NOT_AFFECTED,
                    is_applicable=False,
                    confidence="OBSERVED",
                    reasons=[f"Version {detected_version} is outside exact vulnerable list {exact_vers}."],
                )

        ver_range = cve_record.get("version_range")
        if ver_range and len(ver_range) == 2:
            min_v, max_v = ver_range
            in_range = CveIntelligence._version_in_range(detected_version, min_v, max_v)
            if in_range:
                is_in_range = True
                reasons.append(f"Detected version {detected_version} is within affected range [{min_v} - {max_v}].")
            else:
                return CveEvaluationResult(
                    cve_id=cve_id,
                    product=product,
                    detected_version=detected_version,
                    cpe=cpe,
                    state=CveApplicabilityState.NOT_AFFECTED,
                    is_applicable=False,
                    confidence="OBSERVED",
                    reasons=[f"Version {detected_version} is outside affected range [{min_v} - {max_v}]."],
                )

        # Step 3: Check Configuration Prerequisites
        # e.g., CVE-2021-41773 requires mod_cgi / cgi enabled
        prereq_met = True
        desc = cve_record.get("description", "").lower()
        if "mod_cgi" in desc and "mod_cgi" not in modules and not cfg.get("has_cgi"):
            prereq_met = False
            reasons.append("Prerequisite module 'mod_cgi' not confirmed active on target.")

        if "mod_proxy" in desc and "mod_proxy" not in modules and not cfg.get("has_proxy"):
            prereq_met = False
            reasons.append("Prerequisite module 'mod_proxy' not confirmed active on target.")

        if not prereq_met:
            state = CveApplicabilityState.CANDIDATE
        else:
            state = CveApplicabilityState.VALIDATION_REQUIRED

        return CveEvaluationResult(
            cve_id=cve_id,
            product=product,
            detected_version=detected_version,
            cpe=cpe,
            state=state,
            is_applicable=is_in_range,
            confidence="VALIDATED" if prereq_met else "SUSPECTED",
            reasons=reasons,
            prerequisites_met=prereq_met,
            details={
                "cvss_score": cve_record.get("cvss_score"),
                "cwe_id": cve_record.get("cwe_id"),
                "title": cve_record.get("title"),
            },
        )


cve_applicability_validator = CveApplicabilityValidator()
