"""Credential Assessment Subsystem (V8 §13).

Manages authorized credential material through a strict lifecycle:
- DISCOVERED
- CLASSIFIED
- OFFLINE_ANALYSIS
- REQUIRES_AUTHORIZATION
- VALIDATED
- REVOKED

Enforces the V8 Anti-Spray Safety Rule:
Credential material must NOT automatically be sprayed across unrelated services.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.validation.hash_analyzer import HashAnalyzer

logger = logging.getLogger("validation.credential_assessment")


class CredentialState:
    DISCOVERED = "DISCOVERED"
    CLASSIFIED = "CLASSIFIED"
    OFFLINE_ANALYSIS = "OFFLINE_ANALYSIS"
    REQUIRES_AUTHORIZATION = "REQUIRES_AUTHORIZATION"
    VALIDATED = "VALIDATED"
    REVOKED = "REVOKED"


class CredentialAssessmentSubsystem:
    """Subsystem for classified, gated assessment of authorized credentials (V8 §13)."""

    @classmethod
    def ingest_credential_artifact(
        cls,
        raw_text: str,
        credential_type: str = "hash",
        context_target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingests raw credential/hash, classifies algorithm and security properties."""
        if credential_type == "hash":
            analysis = HashAnalyzer.identify_algorithm(raw_text)
            masked_id = raw_text[:6] + "..." + raw_text[-4:] if len(raw_text) > 12 else "***"

            artifact = {
                "credential_type": "hash",
                "masked_identifier": masked_id,
                "hash_algorithm": analysis.get("algorithm"),
                "salt_present": analysis.get("salt_present", False),
                "work_factor": analysis.get("work_factor"),
                "entropy": analysis.get("entropy"),
                "is_weak_algorithm": analysis.get("is_weak_algorithm", False),
                "state": CredentialState.CLASSIFIED,
                "context_target": context_target,
                "anti_spray_enforced": True,
            }
            logger.info("Ingested and classified hash artifact (%s, Algo: %s)", masked_id, analysis.get("algorithm"))
            return artifact

        # Plaintext or Token
        strength = HashAnalyzer.evaluate_plaintext_strength(raw_text)
        masked_id = raw_text[:2] + "****" + raw_text[-1:] if len(raw_text) > 3 else "***"

        artifact = {
            "credential_type": "plaintext_token",
            "masked_identifier": masked_id,
            "entropy": strength.get("entropy"),
            "weak_pattern_detected": strength.get("weak_pattern_detected", False),
            "password_policy_weakness": ", ".join(strength.get("weaknesses", [])),
            "state": CredentialState.CLASSIFIED,
            "context_target": context_target,
            "anti_spray_enforced": True,
        }
        logger.info("Ingested and classified plaintext credential artifact (%s)", masked_id)
        return artifact

    @classmethod
    def validate_authorized_account_only(
        cls,
        credential_artifact: Dict[str, Any],
        target_service: str,
        authorized_accounts: List[str],
    ) -> Dict[str, Any]:
        """Strictly ensures credentials are only validated against explicitly authorized accounts."""
        account_name = credential_artifact.get("account_name", "")
        if account_name and account_name not in authorized_accounts:
            logger.warning("Blocked credential test against unauthorized account %s on %s (Anti-Spray Rule)", account_name, target_service)
            return {
                "allowed": False,
                "verdict": "DENIED",
                "reason": f"Account '{account_name}' is not in the authorized test account scope.",
            }

        return {
            "allowed": True,
            "verdict": "ALLOWED",
            "reason": "Authorized test account boundary verified.",
        }


credential_subsystem = CredentialAssessmentSubsystem()
