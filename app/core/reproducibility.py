"""Reproducibility & Rule Versioning Engine (V8 §46, §47).

Ensures deterministic reproducibility of security findings by tracking:
- Tool version (e.g. hunter-v8.0.0)
- Adapter version
- Rule version
- DB schema version
- AI model version
- Configuration profile
- Target fingerprint
- Timestamp
- Evidence SHA-256 hash

Enables:
reproduce → compare → audit → retest
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ReproducibilityRecord:
    tool_version: str = "v8.0.0"
    adapter_version: str = "v8.0.0"
    rule_version: str = "v8.0.0"
    db_version: str = "v8.0.0"
    model_version: str = "v8-local-embedded"
    configuration_profile: str = "standard"
    target_fingerprint: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    evidence_hash: Optional[str] = None


class ReproducibilityEngine:
    """Helper for generating and comparing reproducibility metadata (V8 §46)."""

    @classmethod
    def generate_record(
        cls,
        *,
        adapter_version: str = "v8.0.0",
        rule_version: str = "v8.0.0",
        configuration_profile: str = "standard",
        target_fingerprint: str = "",
        evidence_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates a standardized reproducibility metadata dictionary."""
        rec = ReproducibilityRecord(
            adapter_version=adapter_version,
            rule_version=rule_version,
            configuration_profile=configuration_profile,
            target_fingerprint=target_fingerprint,
            evidence_hash=evidence_hash,
        )
        return {
            "tool_version": rec.tool_version,
            "adapter_version": rec.adapter_version,
            "rule_version": rec.rule_version,
            "db_version": rec.db_version,
            "model_version": rec.model_version,
            "configuration_profile": rec.configuration_profile,
            "target_fingerprint": rec.target_fingerprint,
            "timestamp": rec.timestamp,
            "evidence_hash": rec.evidence_hash,
        }


reproducibility_engine = ReproducibilityEngine()
