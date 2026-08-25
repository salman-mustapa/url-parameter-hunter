"""Deep Validation Adapter Contract (V5 §38).
Standardized interface implemented by all specialized vulnerability validation modules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.validation.result import NormalizedValidationResult


class ValidationAdapter(ABC):
    """Abstract Contract for Deep Validation Modules (§38)."""

    name: str = "base_validator"
    vulnerability_type: str = "generic"
    risk_level: str = "SAFE"  # SAFE, CONTROLLED, HIGH_RISK

    @abstractmethod
    async def prerequisites(self, target: str, parameters: Optional[List[Dict[str, Any]]] = None) -> bool:
        """Check if target environment and parameter inputs meet validation prerequisites."""
        pass

    @abstractmethod
    async def safe_validate(
        self,
        url: str,
        parameters: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[NormalizedValidationResult]:
        """Perform passive and safe non-destructive checks (E0/E1)."""
        pass

    @abstractmethod
    async def controlled_validate(
        self,
        url: str,
        parameters: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
        approval_granted: bool = True,
    ) -> List[NormalizedValidationResult]:
        """Perform active controlled validation to prove security impact (E2/E3)."""
        pass

    async def cleanup(self, context: Dict[str, Any]) -> bool:
        """Clean up any temporary test artifacts, sessions, or probe footprints."""
        return True

    def explain(self, result: NormalizedValidationResult) -> Dict[str, str]:
        """Generate dual-view technical and plain-English executive explanations (§30)."""
        return {
            "technical": result.description or "Observed parameter behavior deviates from secure baseline.",
            "business": result.actual_result or "Potential risk of unauthorized data access or boundary deviation.",
            "remediation": result.remediation or "Implement strict parameterization and access controls.",
        }
