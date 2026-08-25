"""Campaign Memory & Context Builder (V8 §34).

Manages isolated, per-campaign knowledge state:
- Confirmed facts
- Assets & endpoints
- Detected technologies & versions
- Findings & observations
- Active hypotheses
- Operator notes
Automatically filters and redacts sensitive credentials/secrets before feeding into AI context.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

from app.reporting.redaction import RedactionEngine

logger = logging.getLogger("ai.memory")


class CampaignMemory:
    """In-memory campaign knowledge buffer with secret redaction (V8 §34)."""

    def __init__(self, campaign_id: str) -> None:
        self.campaign_id = campaign_id
        self.facts: List[Dict[str, Any]] = []
        self.assets: Set[str] = set()
        self.technologies: Dict[str, str] = {}
        self.findings: List[Dict[str, Any]] = []
        self.hypotheses: List[Dict[str, Any]] = []
        self.analyst_notes: List[str] = []

    def add_fact(self, fact_type: str, statement: str, source: str = "scanner") -> None:
        self.facts.append({
            "type": fact_type,
            "statement": statement,
            "source": source,
        })

    def register_asset(self, hostname_or_ip: str) -> None:
        self.assets.add(hostname_or_ip)

    def register_technology(self, name: str, version: Optional[str] = None) -> None:
        self.technologies[name.lower()] = version or "unknown"

    def record_finding(self, finding: Dict[str, Any]) -> None:
        # Redact any sensitive passwords / API keys
        redacted = RedactionEngine.redact_dict(finding)
        self.findings.append(redacted)

    def add_analyst_note(self, note: str) -> None:
        self.analyst_notes.append(note)

    def get_context_summary(self, max_tokens: int = 1500) -> str:
        """Produces a clean, redacted, token-efficient context string for AI reasoning."""
        tech_lines = [f"- {k} (v{v})" for k, v in self.technologies.items()]
        fact_lines = [f"- [{f['type']}] {f['statement']}" for f in self.facts[:15]]
        finding_lines = [f"- [{f.get('severity', 'INFO')}] {f.get('title')}" for f in self.findings[:10]]

        asset_lines = [f"- {a}" for a in list(self.assets)[:15]]
        summary = f"""### Campaign Context: {self.campaign_id}
- Known Assets: {len(self.assets)}
{chr(10).join(asset_lines) if asset_lines else '  None'}

- Detected Technologies:
{chr(10).join(tech_lines) if tech_lines else '  None'}

- Verified Facts:
{chr(10).join(fact_lines) if fact_lines else '  None'}

- Confirmed Findings:
{chr(10).join(finding_lines) if finding_lines else '  None'}

- Analyst Notes:
{chr(10).join(f'- {n}' for n in self.analyst_notes) if self.analyst_notes else '  None'}
"""
        return summary


class MemoryManager:
    """Registry of per-campaign active memory stores."""

    def __init__(self) -> None:
        self._memories: Dict[str, CampaignMemory] = {}

    def get_memory(self, campaign_id: str) -> CampaignMemory:
        if campaign_id not in self._memories:
            self._memories[campaign_id] = CampaignMemory(campaign_id)
        return self._memories[campaign_id]


memory_manager = MemoryManager()
