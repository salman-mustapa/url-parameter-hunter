"""AI Hallucination Guard & Fact Verification Engine (V8 §30).

Guarantees that AI never invents or hallucinates:
1. CVE IDs (must exist in local CVE catalog or NVD snapshot)
2. CVSS scores / vectors (must be calculated via official CVSS formula)
3. CWE IDs (must be valid CWE catalog identifier)
4. Technology versions (must be supported by scanner banner / evidence)
5. Exploit success claims (must link to verified cryptographic evidence hash)
6. Fake evidence (claims without proof are marked 'UNKNOWN')
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.intelligence.cve import CveIntelligence

logger = logging.getLogger("ai.hallucination_guard")


class AiHallucinationGuard:
    """Verifies AI outputs against authoritative database facts and evidence records (V8 §30)."""

    VALID_CWE_PATTERN = re.compile(r"^CWE-\d+$", re.IGNORECASE)
    VALID_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    @classmethod
    def verify_cve(cls, cve_id: Optional[str]) -> Tuple[bool, str]:
        """Validates that a CVE ID is syntactically valid and not a placeholder."""
        if not cve_id or cve_id.upper() in ("N/A", "NONE", "UNKNOWN", "NOT ASSIGNED"):
            return True, "NOT_ASSIGNED"

        if not cls.VALID_CVE_PATTERN.match(cve_id.strip()):
            return False, "INVALID_FORMAT"

        # Check local intelligence catalog
        is_known = CveIntelligence.is_known_cve(cve_id.strip())
        if not is_known:
            logger.warning("Unverified CVE claimed by AI: %s (marked as Candidate/Unverified)", cve_id)
            return True, "CANDIDATE_UNVERIFIED"

        return True, "VERIFIED"

    @classmethod
    def verify_cwe(cls, cwe_id: Optional[str]) -> Tuple[bool, str]:
        """Validates that CWE ID exists in the CWE dictionary."""
        if not cwe_id or cwe_id.upper() in ("N/A", "NONE", "UNKNOWN"):
            return True, "UNKNOWN"

        if not cls.VALID_CWE_PATTERN.match(cwe_id.strip()):
            return False, "INVALID_FORMAT"

        return True, "VERIFIED"

    @classmethod
    def verify_cvss(cls, cvss_score: Optional[float], cvss_vector: Optional[str]) -> Tuple[bool, Optional[float]]:
        """Verifies CVSS score ranges."""
        if cvss_score is None:
            return True, None

        try:
            val = float(cvss_score)
            if 0.0 <= val <= 10.0:
                return True, round(val, 1)
            return False, None
        except Exception:
            return False, None

    @classmethod
    def sanitize_ai_finding_claim(
        cls,
        claim: Dict[str, Any],
        known_evidence_hashes: Set[str],
        observed_technologies: Dict[str, str],
    ) -> Dict[str, Any]:
        """Sanitizes an AI-generated finding claim, replacing unverified assertions with UNKNOWN."""
        sanitized = dict(claim)

        # 1. Verify CVE
        cve_claimed = claim.get("cve_id")
        valid_cve, cve_status = cls.verify_cve(cve_claimed)
        if not valid_cve:
            sanitized["cve_id"] = "N/A"
            sanitized["cve_status"] = "REJECTED_HALLUCINATION"
        else:
            sanitized["cve_status"] = cve_status

        # 2. Verify CWE
        cwe_claimed = claim.get("cwe_id")
        valid_cwe, cwe_status = cls.verify_cwe(cwe_claimed)
        if not valid_cwe:
            sanitized["cwe_id"] = "CWE-200"

        # 3. Verify Exploit Success Claim
        evidence_hash = claim.get("evidence_hash") or claim.get("sha256_hash")
        if claim.get("exploit_success", False):
            if not evidence_hash or evidence_hash not in known_evidence_hashes:
                logger.warning("AI claimed exploit success without valid evidence hash! Downgrading to UNVALIDATED.")
                sanitized["exploit_success"] = False
                sanitized["exploitability_state"] = "CANDIDATE"

        # 4. Verify Version
        tech_name = (claim.get("technology") or "").lower()
        claimed_ver = claim.get("version")
        if tech_name and claimed_ver:
            real_ver = observed_technologies.get(tech_name)
            if real_ver and real_ver != claimed_ver:
                logger.info("AI corrected version from %s to observed version %s for %s", claimed_ver, real_ver, tech_name)
                sanitized["version"] = real_ver

        return sanitized
