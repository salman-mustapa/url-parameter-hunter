"""Webshell & Payload Capability Validator (V8 §16).

Represents webshell / arbitrary payload capabilities strictly as:
EXECUTION_CAPABILITY

Features:
- Default Validator: Controlled execution proof via harmless canaries.
- Lab mode: Disposable test fixtures with automated teardown registration.
- Production mode: Zero invasive writes or persistent files.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.validation.execution_validation import controlled_execution_validator

logger = logging.getLogger("validation.payload")


class PayloadCapabilityValidator:
    """Validates payload upload and execution capabilities under safe constraints (V8 §16)."""

    @classmethod
    def create_harmless_test_payload(cls, file_ext: str = "txt") -> Dict[str, Any]:
        """Generates a harmless non-executable or canary test payload."""
        canary = controlled_execution_validator.generate_harmless_canary("payload_test")
        token = canary["canary_token"]

        if file_ext in ("php", "phtml"):
            content = f"<?php echo '{token}'; ?>"
        elif file_ext in ("jsp", "jspx"):
            content = f"<%= \"{token}\" %>"
        elif file_ext in ("asp", "aspx"):
            content = f"<% Response.Write(\"{token}\") %>"
        else:
            content = f"BugHunter Harmless Security Test Canary: {token}"

        return {
            "filename": f"bh_canary_{token[-6:]}.{file_ext}",
            "content": content,
            "canary_data": canary,
            "is_harmless": True,
            "capability_classification": "EXECUTION_CAPABILITY",
        }

    @classmethod
    def evaluate_payload_response(
        cls,
        status_code: int,
        response_body: str,
        canary_data: Dict[str, str],
        endpoint: str,
    ) -> Dict[str, Any]:
        """Evaluates whether the uploaded test artifact is accessible and executable."""
        proof = controlled_execution_validator.verify_canary_reflection(
            response_body=response_body,
            canary_data=canary_data,
            target_url=endpoint,
        )

        return {
            "endpoint": endpoint,
            "status_code": status_code,
            "execution_confirmed": proof.confirmed,
            "finding_type": "EXECUTION_CAPABILITY",
            "proof_details": proof.evidence_data,
            "requires_cleanup": True,
        }


payload_capability_validator = PayloadCapabilityValidator()
