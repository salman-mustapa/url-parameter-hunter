"""Master Orchestrator & Native Multi-Agent Brain (V12 §4, §5, §13, §14, §15, §40, §62).

Coordinates the entire multi-agent cybersecurity research ecosystem:
- IntentGate (Sanitizes & Classifies user intents and scope)
- AdaptiveOrchestrator (Manages Task DAG, Priority Queue, and Worker Execution)
- ResearchOpportunityEngine (Converts live discoveries into prioritized test candidates)
- TeamManager (Directs specialist agent teams in parallel)
- SkillRegistry & SkillRetriever (Selects approved cybersecurity methodologies)
- InvestigationMemory (Maintains shared facts, decisions, and behavioral models)
- AIProviderRouter (Routes reasoning tasks to model categories)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

from app.ai.context_engine import context_engine
from app.ai.intent_gate import IntentClassification, IntentType, intent_gate
from app.ai.investigation_memory import FactPrecedence, investigation_memory_manager
from app.ai.provider_router import ModelCategory, ai_provider_router
from app.core.events import event_bus
from app.core.scope import Scope
from app.orchestration.adaptive_orchestrator import (
    OrchestratorTask,
    TaskState,
    adaptive_orchestrator,
)
from app.orchestration.attack_opportunity import AttackOpportunity, opportunity_bus
from app.orchestration.attack_path_engine import attack_path_engine
from app.orchestration.correlation_engine import correlation_engine
from app.orchestration.opportunity_engine import Opportunity, opportunity_engine
from app.orchestration.risk_scoring import risk_scoring_engine
from app.orchestration.team_manager import TeamName, team_manager
from app.skills.skill_registry import skill_retriever

logger = logging.getLogger("orchestration.master")


class MasterOrchestrator:
    """Master Multi-Agent Orchestrator directing specialist teams and dynamic escalation."""

    def __init__(self, scan_id: str = "global_campaign") -> None:
        self.scan_id = scan_id
        self.is_active = True

    async def handle_event(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        scope: Optional[Scope] = None,
    ) -> List[OrchestratorTask]:
        """Core event-driven loop: Ingests event -> Intent Gate -> Opportunity -> Skill -> Specialist Task."""
        if not self.is_active:
            return []

        target = event_data.get("url") or event_data.get("target") or event_data.get("host") or ""
        
        # 1. Intent Gate Evaluation
        intent_cls = intent_gate.classify_intent(
            command_or_event=event_type,
            target=target,
            scope=scope,
            context=event_data,
        )

        if not intent_cls.is_allowed:
            logger.warning("MasterOrchestrator: Event %s blocked by IntentGate (%s)", event_type, intent_cls.reason)
            return []

        # 2. Deterministic Entity Correlation
        if target:
            if "ip" in event_data:
                correlation_engine.register_ip(target, event_data["ip"])
            if "port" in event_data:
                correlation_engine.register_port_service(
                    target=target,
                    port=int(event_data["port"]),
                    protocol=event_data.get("protocol", "tcp"),
                    service_name=event_data.get("service"),
                )
            if "technology" in event_data or "tech" in event_data:
                tech = event_data.get("technology") or event_data.get("tech")
                correlation_engine.register_technology(target, str(tech))
            if "url" in event_data:
                correlation_engine.register_endpoint(target, event_data["url"], event_data.get("parameters"))

        # 3. Update Shared Investigation Memory
        memory = investigation_memory_manager.get_memory(self.scan_id)
        if target:
            memory.record_fact(
                key=f"target_active_{target}",
                value=event_data,
                precedence=FactPrecedence.VALIDATED_OBSERVATION,
                source=event_type,
            )

        # 4. Opportunity Detection & Attack Path Analysis
        opportunities = opportunity_engine.evaluate_event(event_type, event_data)
        created_tasks: List[OrchestratorTask] = []

        # Convert and publish to OpportunityBus for specialist attack execution
        for opp in opportunities:
            opp_attack_type = opp.opportunity_type.value.replace("_candidate", "")
            if opp_attack_type in ("auth_bypass", "default_credentials"):
                opp_attack_type = "auth"
            elif opp_attack_type in ("access_control_403",):
                opp_attack_type = "idor"
            elif opp_attack_type in ("sensitive_file_exposure", "directory_listing"):
                opp_attack_type = "artifact"

            bus_opp = AttackOpportunity(
                target=opp.target_url,
                endpoint=opp.target_url,
                attack_type=opp_attack_type,
                hypothesis=f"Opportunity from {event_type} on {opp.target_url}",
                priority=opp.priority,
                prerequisites=opp.preconditions,
                context=opp.context,
            )
            await opportunity_bus.publish(bus_opp)

        # Optional Attack Path Reasoning
        if target and ("auth" in event_type or "sqli" in event_type or "endpoint" in event_type):
            attack_path_engine.analyze_attack_paths(target, [event_data])

        for opp in opportunities:
            # 5. Retrieve Relevant Skills for Progressive Disclosure
            relevant_skills = skill_retriever.retrieve_skills_for_context(
                target_url=opp.target_url,
                event_type=opp.opportunity_type.value,
                limit=2,
            )
            skill_context = [s.get_concise_procedure() for s in relevant_skills]

            # 6. Assign to Specialist Agent via Capability Match
            agent = team_manager.find_agent_for_capability(opp.recommended_worker) or team_manager.find_agent_for_capability("sqli")
            agent_name = agent.name if agent else "ValidationAgent"
            agent_id = agent.id if agent else "validation"

            # 7. Build Scoped Context for Agent
            scoped_ctx = context_engine.build_agent_context(
                agent_id=agent_id,
                task_id=f"task_{int(time.time()*1000)}",
                target_url=opp.target_url,
                available_facts=[event_data],
                skills=skill_context,
            )

            # 8. Record Structured Decision in Memory
            memory.record_decision(
                agent_name=agent_name,
                action=f"Escalate {opp.opportunity_type.value}",
                rationale=f"Opportunity {opp.opportunity_type.value} matched preconditions on {opp.target_url}",
                confidence=opp.priority / 100.0,
            )

            # 9. Submit Task to Adaptive Orchestrator
            task = await adaptive_orchestrator.submit_task(
                task_type=f"validate.{opp.opportunity_type.value}",
                target=opp.target_url,
                priority=opp.priority,
                worker_class=opp.recommended_worker,
                dependencies=[],  # Fast path validation runs immediately
                context={**opp.context, "skills": skill_context, "assigned_agent": agent_name, "scoped_context": scoped_ctx.to_dict()},
                parent_task_id=event_data.get("task_id"),
                lineage_reason=f"Spawned by MasterOrchestrator via {agent_name} from {event_type}",
            )
            if task:
                created_tasks.append(task)
                if agent:
                    team_manager.claim_task(agent.name, task.task_id)

                # Emit real-time telemetry
                await event_bus.publish({
                    "type": "orchestrator.specialist_dispatched",
                    "agent": agent_name,
                    "team": agent.team.value if agent else "Vulnerability Team",
                    "opportunity": opp.to_dict(),
                    "task_id": task.task_id,
                    "priority": opp.priority,
                    "timestamp": time.time(),
                })

        return created_tasks

    def get_live_orchestration_graph(self) -> Dict[str, Any]:
        """Returns live visualization graph of active teams, agents, and task lineage."""
        orch_metrics = adaptive_orchestrator.get_metrics()
        teams_summary = team_manager.get_teams_summary()
        memory = investigation_memory_manager.get_memory(self.scan_id)

        return {
            "orchestrator_status": "ACTIVE" if self.is_active else "IDLE",
            "metrics": orch_metrics,
            "teams": teams_summary["teams"],
            "total_teams": teams_summary["total_teams"],
            "total_specialists": teams_summary["total_specialists"],
            "memory_summary": memory.get_context_summary(max_items=20),
            "timestamp": time.time(),
        }


master_orchestrator = MasterOrchestrator()

