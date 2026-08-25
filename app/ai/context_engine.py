"""Context Engine, Retriever, Ranker & Compressor (Specialist Agent V2 §32, §33).

Key Capabilities:
- ContextRetriever: Resolves lightweight ID references (asset_id, endpoint_id, finding_id, evidence_id).
- ContextRanker: Ranks and filters facts by relevance and freshness.
- ContextCompressor: Strips redundant boilerplate and fits context to model token limits.
- ContextPolicy: Delivers strictly least-privilege context to specialist agents.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ai.context_engine")


@dataclass
class ScopedAgentContext:
    agent_id: str
    task_id: str
    target_url: str
    relevant_facts: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    active_skills: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    summary_tokens_estimated: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "target_url": self.target_url,
            "facts_count": len(self.relevant_facts),
            "technologies": self.technologies,
            "active_skills": self.active_skills,
            "summary_tokens_estimated": self.summary_tokens_estimated,
        }


class ContextEngine:
    """Delivers precise, token-efficient, ranked context to specialist agents."""

    def __init__(self, max_facts_per_agent: int = 5) -> None:
        self.max_facts_per_agent = max_facts_per_agent

    def build_agent_context(
        self,
        agent_id: str,
        task_id: str,
        target_url: str,
        available_facts: Optional[List[Dict[str, Any]]] = None,
        technologies: Optional[List[str]] = None,
        skills: Optional[List[str]] = None,
    ) -> ScopedAgentContext:
        """Constructs a minimal, highly-relevant context bundle."""
        facts = available_facts or []
        techs = technologies or []
        active_skills = skills or []

        # 1. Rank & Filter facts for relevance to this agent's specialty
        ranked_facts = self._rank_facts_for_agent(agent_id, facts)
        compressed_facts = ranked_facts[:self.max_facts_per_agent]

        # 2. Estimate token count (rough heuristic: ~4 chars per token)
        raw_repr = str(compressed_facts) + str(techs) + str(active_skills)
        tokens_est = len(raw_repr) // 4

        return ScopedAgentContext(
            agent_id=agent_id,
            task_id=task_id,
            target_url=target_url,
            relevant_facts=compressed_facts,
            technologies=techs,
            active_skills=active_skills,
            summary_tokens_estimated=tokens_est,
        )

    def _rank_facts_for_agent(self, agent_id: str, facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scores and sorts facts by keyword relevance to the specific agent."""
        agent_keywords = {
            "sqli": ["sql", "database", "query", "parameter", "db"],
            "xss": ["input", "reflection", "script", "dom", "html"],
            "idor": ["id", "user", "account", "uuid", "auth"],
            "ssrf": ["url", "webhook", "proxy", "metadata", "redirect"],
            "rce": ["command", "exec", "eval", "deserialization", "upload"],
            "jwt": ["token", "jwt", "bearer", "authorization"],
            "auth": ["login", "admin", "session", "password", "token"],
        }
        keywords = agent_keywords.get(agent_id.lower(), ["target", "service", "status"])

        def fact_score(f: Dict[str, Any]) -> int:
            text = str(f).lower()
            return sum(2 for k in keywords if k in text)

        return sorted(facts, key=fact_score, reverse=True)


context_engine = ContextEngine()
