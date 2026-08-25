"""AI Reasoning Layer — Intelligence Above Deterministic Core (V4 Architecture).

Unified AI reasoning coordinator that sits above the deterministic core:
- Observes current application model state
- Identifies gaps in security coverage
- Generates hypotheses for unexplored attack surfaces
- Ranks hypotheses by expected value
- Generates attack plans (sequence of tool invocations)
- Submits plans to deterministic orchestrator for execution

Gracefully degrades: if no AI provider is available, falls back to heuristic rules.

Integrates existing: hypothesis_engine, decision_policy, critic_agent, security_invariants.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from app.ai.hypothesis_engine import HypothesisDecisionEngine, HypothesisRecord, DecisionAction
from app.ai.decision_policy import NextBestActionEngine, CandidateAction, InvestigationActionType
from app.ai.critic_agent import SelfCriticAgent, CriticReviewResult
from app.ai.security_invariants import SecurityInvariantEngine, ExploitationDepthLevel
from app.models.application_model import ApplicationModel, EntityType, AuthType, RelationType
from app.intelligence.knowledge_engine import SecurityKnowledgeEngine
from app.core.tool_registry import ToolRegistry, ToolCategory

logger = logging.getLogger("ai.reasoning_layer")


class CoverageGapType(str, Enum):
    UNTESTED_ASSET = "UNTESTED_ASSET"
    UNTESTED_ENDPOINT = "UNTESTED_ENDPOINT"
    UNTESTED_PARAMETER = "UNTESTED_PARAMETER"
    MISSING_AUTH_TEST = "MISSING_AUTH_TEST"
    MISSING_IDOR_TEST = "MISSING_IDOR_TEST"
    UNTESTED_TECHNOLOGY = "UNTESTED_TECHNOLOGY"
    UNINVESTIGATED_OBSERVATION = "UNINVESTIGATED_OBSERVATION"
    INCOMPLETE_CHAIN = "INCOMPLETE_CHAIN"


@dataclass
class CoverageGap:
    """A gap in security test coverage that should be investigated."""
    gap_id: str
    gap_type: CoverageGapType
    entity_id: str
    entity_label: str
    description: str
    priority: float  # 0.0 - 1.0
    suggested_tools: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "gap_type": self.gap_type.value,
            "entity_id": self.entity_id,
            "entity_label": self.entity_label,
            "description": self.description,
            "priority": self.priority,
            "suggested_tools": self.suggested_tools,
        }


@dataclass
class ReasoningResult:
    """Output of a reasoning cycle."""
    gaps_identified: List[CoverageGap] = field(default_factory=list)
    hypotheses_generated: List[HypothesisRecord] = field(default_factory=list)
    actions_recommended: List[CandidateAction] = field(default_factory=list)
    model_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_gaps": len(self.gaps_identified),
            "total_hypotheses": len(self.hypotheses_generated),
            "total_actions": len(self.actions_recommended),
            "gaps": [g.to_dict() for g in self.gaps_identified],
            "hypotheses": [h.to_dict() for h in self.hypotheses_generated],
            "actions": [a.to_dict() for a in self.actions_recommended],
            "model_summary": self.model_summary,
        }


class AIReasoningLayer:
    """Unified AI reasoning coordinator.

    Sits above the deterministic core and drives intelligent
    security testing decisions. Degrades gracefully to heuristic
    mode when no AI provider is available.
    """

    def __init__(
        self,
        app_model: Optional[ApplicationModel] = None,
        knowledge_engine: Optional[SecurityKnowledgeEngine] = None,
        tool_registry: Optional[ToolRegistry] = None,
    ) -> None:
        self.app_model = app_model
        self.knowledge_engine = knowledge_engine
        self.tool_registry = tool_registry
        self.hypothesis_engine = HypothesisDecisionEngine()
        self.decision_engine = NextBestActionEngine()
        self.critic = SelfCriticAgent()
        self.invariant_engine = SecurityInvariantEngine()
        self._tested_entities: Set[str] = set()

    def set_app_model(self, model: ApplicationModel) -> None:
        self.app_model = model

    def set_knowledge_engine(self, engine: SecurityKnowledgeEngine) -> None:
        self.knowledge_engine = engine

    def set_tool_registry(self, registry: ToolRegistry) -> None:
        self.tool_registry = registry

    # ---- Main Reasoning Cycle ----

    def reason(self) -> ReasoningResult:
        """Execute one reasoning cycle.

        Steps:
        1. Observe current model state
        2. Identify coverage gaps
        3. Generate hypotheses for unexplored attack surfaces
        4. Rank hypotheses by expected value
        5. Generate candidate actions
        6. Return structured reasoning result
        """
        result = ReasoningResult()

        if not self.app_model:
            logger.warning("No application model available for reasoning")
            return result

        result.model_summary = self.app_model.get_attack_surface_summary()

        # Step 1-2: Identify coverage gaps
        result.gaps_identified = self._identify_coverage_gaps()

        # Step 3: Generate hypotheses from gaps
        for gap in result.gaps_identified:
            hyp = self._generate_hypothesis_from_gap(gap)
            if hyp:
                result.hypotheses_generated.append(hyp)

        # Step 4-5: Generate and rank candidate actions
        result.actions_recommended = self._generate_candidate_actions(result.gaps_identified)

        return result

    # ---- Coverage Analysis ----

    def _identify_coverage_gaps(self) -> List[CoverageGap]:
        """Identify gaps in security test coverage using heuristic analysis."""
        gaps: List[CoverageGap] = []
        if not self.app_model:
            return gaps

        # 0. Untested Assets / Subdomains / Exposed Services
        assets = self.app_model.get_entities_by_type(EntityType.ASSET)
        for ast in assets[:30]:
            if ast.id not in self._tested_entities:
                ports_cnt = ast.properties.get("ports_count", 0)
                priority = 0.85 if ports_cnt > 0 else 0.7
                suggested = ["nuclei", "httpx", "dalfox"]
                if ports_cnt > 5:
                    suggested.insert(0, "nmap")
                gaps.append(CoverageGap(
                    gap_id=f"gap_{uuid.uuid4().hex[:8]}",
                    gap_type=CoverageGapType.UNTESTED_ASSET,
                    entity_id=ast.id,
                    entity_label=ast.label,
                    description=f"Asset {ast.label} ({ports_cnt} open ports) attack surface not yet fully verified",
                    priority=priority,
                    suggested_tools=suggested,
                ))

        # 1. Untested endpoints
        endpoints = self.app_model.get_entities_by_type(EntityType.ENDPOINT)
        for ep in endpoints:
            if ep.id not in self._tested_entities:
                priority = 0.7
                suggested = ["info_disclosure_validator"]

                # Higher priority for authenticated endpoints (IDOR potential)
                auth_type = ep.properties.get("auth_type", "none")
                if auth_type != "none":
                    priority = 0.85
                    suggested.extend(["idor_validator", "auth_bypass_validator"])

                # Higher priority for endpoints with parameters
                method = ep.properties.get("method", "GET")
                if method in ("POST", "PUT", "PATCH", "DELETE"):
                    priority = 0.9
                    suggested.extend(["sqli_validator", "xss_validator", "csrf_validator"])

                gaps.append(CoverageGap(
                    gap_id=f"gap_{uuid.uuid4().hex[:8]}",
                    gap_type=CoverageGapType.UNTESTED_ENDPOINT,
                    entity_id=ep.id,
                    entity_label=ep.label,
                    description=f"Endpoint {ep.label} has not been tested ({method}, auth: {auth_type})",
                    priority=priority,
                    suggested_tools=suggested,
                ))

        # 2. Unauthenticated endpoints (potential auth bypass)
        unauth_eps = self.app_model.find_unauthenticated_endpoints()
        for ep in unauth_eps:
            if ep.properties.get("expected_auth", False):
                gaps.append(CoverageGap(
                    gap_id=f"gap_{uuid.uuid4().hex[:8]}",
                    gap_type=CoverageGapType.MISSING_AUTH_TEST,
                    entity_id=ep.id,
                    entity_label=ep.label,
                    description=f"Endpoint {ep.label} is unauthenticated but expected to require auth",
                    priority=0.95,
                    suggested_tools=["auth_bypass_validator", "bypass_403_validator"],
                ))

        # 3. Untested parameters
        params = self.app_model.get_entities_by_type(EntityType.PARAMETER)
        for param in params:
            if param.id not in self._tested_entities:
                location = param.properties.get("location", "query")
                param_type = param.properties.get("type", "string")
                priority = 0.6
                suggested = ["xss_validator"]

                if param_type in ("integer", "id", "number"):
                    priority = 0.8
                    suggested = ["sqli_validator", "idor_validator"]
                elif location == "header":
                    suggested = ["host_header_validator"]
                elif "url" in param.label.lower() or "redirect" in param.label.lower():
                    priority = 0.85
                    suggested = ["ssrf_validator", "open_redirect_validator"]
                elif "file" in param.label.lower() or "path" in param.label.lower():
                    priority = 0.85
                    suggested = ["path_traversal_validator"]

                gaps.append(CoverageGap(
                    gap_id=f"gap_{uuid.uuid4().hex[:8]}",
                    gap_type=CoverageGapType.UNTESTED_PARAMETER,
                    entity_id=param.id,
                    entity_label=param.label,
                    description=f"Parameter '{param.label}' ({location}, {param_type}) not tested",
                    priority=priority,
                    suggested_tools=suggested,
                ))

        # 4. Technology-specific patterns
        if self.knowledge_engine:
            techs = self.app_model.get_entities_by_type(EntityType.TECHNOLOGY)
            for tech in techs:
                if tech.id not in self._tested_entities:
                    patterns = self.knowledge_engine.get_attack_patterns_for_technology(tech.label)
                    if patterns:
                        gaps.append(CoverageGap(
                            gap_id=f"gap_{uuid.uuid4().hex[:8]}",
                            gap_type=CoverageGapType.UNTESTED_TECHNOLOGY,
                            entity_id=tech.id,
                            entity_label=tech.label,
                            description=f"Technology '{tech.label}' has {len(patterns)} known attack patterns",
                            priority=0.75,
                            suggested_tools=[p.attack_vector for p in patterns[:3]],
                            context={"pattern_count": len(patterns)},
                        ))

        # Sort by priority descending
        gaps.sort(key=lambda g: g.priority, reverse=True)
        return gaps

    # ---- Hypothesis Generation ----

    def _generate_hypothesis_from_gap(self, gap: CoverageGap) -> Optional[HypothesisRecord]:
        """Generate a security hypothesis from a coverage gap."""
        hypothesis_map = {
            CoverageGapType.UNTESTED_ASSET: "Asset attack surface may expose unauthenticated administrative services or sensitive configuration",
            CoverageGapType.UNTESTED_ENDPOINT: "Endpoint may contain injection vulnerabilities or access control flaws",
            CoverageGapType.UNTESTED_PARAMETER: "Parameter may be vulnerable to injection or manipulation",
            CoverageGapType.MISSING_AUTH_TEST: "Authentication may be bypassable on this endpoint",
            CoverageGapType.MISSING_IDOR_TEST: "Objects may be accessible without proper authorization",
            CoverageGapType.UNTESTED_TECHNOLOGY: "Technology may have known vulnerabilities or misconfigurations",
            CoverageGapType.UNINVESTIGATED_OBSERVATION: "Observation may indicate a security weakness",
            CoverageGapType.INCOMPLETE_CHAIN: "Attack chain may have additional exploitable steps",
        }

        statement = hypothesis_map.get(gap.gap_type, "Security weakness may exist")

        return self.hypothesis_engine.create_hypothesis(
            statement=f"{statement}: {gap.entity_label}",
            target_endpoint=gap.entity_label,
            initial_confidence=gap.priority * 0.5,  # Convert priority to initial confidence
            exploitability=gap.priority * 0.8,
            impact=gap.priority * 0.7,
            chain_potential=0.5,
            business_criticality=0.5,
            next_test=gap.suggested_tools[0] if gap.suggested_tools else "manual_review",
            expected_result="Vulnerability confirmed or rejected with evidence",
        )

    # ---- Action Generation ----

    def _generate_candidate_actions(self, gaps: List[CoverageGap]) -> List[CandidateAction]:
        """Generate and rank candidate investigation actions from coverage gaps."""
        actions: List[CandidateAction] = []

        for gap in gaps[:20]:  # Limit to top 20 gaps
            action_type = self._map_gap_to_action_type(gap)
            tool_cost = self._estimate_tool_cost(gap.suggested_tools)
            risk = self._estimate_risk(gap)

            action = CandidateAction(
                action_type=action_type,
                target_endpoint=gap.entity_label,
                parameter=gap.context.get("parameter"),
                expected_info_gain=gap.priority * 0.8,
                expected_security_impact=gap.priority * 0.9,
                chain_potential=0.5,
                confidence_gain=gap.priority * 0.6,
                request_cost=tool_cost,
                target_risk=risk,
            )
            actions.append(action)

        return NextBestActionEngine.rank_candidate_actions(actions)

    def _map_gap_to_action_type(self, gap: CoverageGap) -> InvestigationActionType:
        mapping = {
            CoverageGapType.UNTESTED_ENDPOINT: InvestigationActionType.PROBE,
            CoverageGapType.UNTESTED_PARAMETER: InvestigationActionType.VALIDATE,
            CoverageGapType.MISSING_AUTH_TEST: InvestigationActionType.VALIDATE,
            CoverageGapType.MISSING_IDOR_TEST: InvestigationActionType.VALIDATE,
            CoverageGapType.UNTESTED_TECHNOLOGY: InvestigationActionType.RECON,
            CoverageGapType.UNINVESTIGATED_OBSERVATION: InvestigationActionType.PROBE,
            CoverageGapType.INCOMPLETE_CHAIN: InvestigationActionType.CHAIN,
        }
        return mapping.get(gap.gap_type, InvestigationActionType.PROBE)

    def _estimate_tool_cost(self, tools: List[str]) -> float:
        if not self.tool_registry or not tools:
            return 2.0
        total = 0.0
        for tool_name in tools:
            tool = self.tool_registry.get(tool_name)
            if tool:
                total += tool.cost
        return max(1.0, total / len(tools)) if tools else 2.0

    def _estimate_risk(self, gap: CoverageGap) -> float:
        risk_map = {
            CoverageGapType.UNTESTED_ENDPOINT: 1.0,
            CoverageGapType.UNTESTED_PARAMETER: 1.5,
            CoverageGapType.MISSING_AUTH_TEST: 2.0,
            CoverageGapType.MISSING_IDOR_TEST: 2.0,
            CoverageGapType.UNTESTED_TECHNOLOGY: 1.0,
            CoverageGapType.UNINVESTIGATED_OBSERVATION: 1.0,
            CoverageGapType.INCOMPLETE_CHAIN: 2.5,
        }
        return risk_map.get(gap.gap_type, 1.5)

    # ---- Entity State Tracking ----

    def mark_tested(self, entity_id: str) -> None:
        """Mark an entity as having been tested."""
        self._tested_entities.add(entity_id)

    def mark_tested_bulk(self, entity_ids: List[str]) -> None:
        self._tested_entities.update(entity_ids)

    # ---- Critic Integration ----

    def review_finding(self, finding: Dict[str, Any]) -> CriticReviewResult:
        """Submit a finding for adversarial review."""
        return self.critic.review_finding(
            vulnerability_type=finding.get("vulnerability_type", ""),
            target_endpoint=finding.get("target", ""),
            baseline_state=finding.get("baseline", {}),
            observed_test_result=finding.get("observed", {}),
            claimed_severity=finding.get("severity", "MEDIUM"),
            reproduction_verified=finding.get("reproduced", False),
        )

    # ---- Reset ----

    def reset(self) -> None:
        self.hypothesis_engine.reset()
        self._tested_entities.clear()
