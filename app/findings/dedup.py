from __future__ import annotations

import hashlib
from typing import Optional


class FindingDedup:
    """Finding Deduplication Engine (§32).
    Generates unified correlation keys across asset, vulnerability type, location, and parameter.
    """

    @staticmethod
    def generate_dedup_key(
        asset_identifier: str,
        vulnerability_type: str,
        location: Optional[str] = None,
        parameter: Optional[str] = None,
        technology: Optional[str] = None,
    ) -> str:
        parts = [
            asset_identifier.lower().strip(),
            vulnerability_type.lower().strip(),
            (location or "").lower().strip(),
            (parameter or "").lower().strip(),
            (technology or "").lower().strip(),
        ]
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
