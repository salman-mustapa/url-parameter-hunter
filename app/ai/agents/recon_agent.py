"""Reconnaissance AI Agent (V8 §10).

Responsibilities:
- Asset clustering (domain groups, CDN vs origin, internal vs external)
- Discovery correlation (DNS records, reverse lookups, certificate SANs)
- Technology inference from banners and response signatures
- Interesting-asset prioritization (admin panels, staging APIs, auth portals)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.ai.gateway import ai_gateway

logger = logging.getLogger("ai.agents.recon")


class ReconAgent:
    """Specialized AI agent for asset clustering, tech inference, and target prioritization (V8 §10)."""

    @classmethod
    async def analyze_attack_surface(
        cls,
        assets: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]],
        ports: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Triages and prioritizes the attack surface for high-value targets."""
        prioritized_assets: List[Dict[str, Any]] = []

        for asset in assets:
            hostname = asset.get("hostname") or asset.get("fqdn") or asset.get("ip") or ""
            score = 10  # default base score
            reasons = []

            # Heuristic high-value keyword detection
            h_lower = hostname.lower()
            if any(k in h_lower for k in ("admin", "api", "vpn", "portal", "corp", "internal", "auth", "dev", "stage")):
                score += 40
                reasons.append("High-value keyword in hostname")

            if any(k in h_lower for k in ("prod", "app", "login", "sso", "dashboard")):
                score += 30
                reasons.append("Production or authentication service indicator")

            prioritized_assets.append({
                "asset": hostname,
                "priority_score": score,
                "priority_tier": "P0_CRITICAL" if score >= 50 else ("P1_HIGH" if score >= 30 else "P2_STANDARD"),
                "reasons": reasons,
            })

        # Sort descending by priority score
        prioritized_assets.sort(key=lambda x: x["priority_score"], reverse=True)

        return {
            "agent": "recon_agent",
            "total_assets_analyzed": len(assets),
            "prioritized_assets": prioritized_assets,
            "high_value_targets": [a["asset"] for a in prioritized_assets if a["priority_tier"] in ("P0_CRITICAL", "P1_HIGH")],
        }
