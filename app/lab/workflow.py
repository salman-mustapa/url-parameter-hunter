"""Discover -> reason -> select -> validate -> correlate using synthetic data only."""

from app.ai.evidence_reasoning import EvidenceReasoner, ReasoningInput
from app.discovery.data_discovery import DataDiscovery
from app.intelligence.evidence_graph import EvidenceGraph, ObservationNode
from app.lab.plans import lab_plan
from app.orchestration.next_test import NextBestTestEngine, TestCandidate
from app.validation.context import ValidationContext
from app.validation.engine import EvidenceValidationEngine
from app.validation.safety.executor import AuthorizedExecutor, AuthorizedScope
from app.validation.validators import validator_registry


async def investigate_local_lab(base, state, provider=None, *, persist=None, progress=None):
    scope = AuthorizedScope((base,), "disposable synthetic local lab")
    async with AuthorizedExecutor(scope) as executor:
        discovery = ValidationContext(base + "/data", "data_discovery")
        await executor.request(discovery, "discovery", "GET", discovery.target)
        artifacts = DataDiscovery().discover(discovery)
        if progress:
            await progress("discovery", {"artifacts": len(artifacts), "url": discovery.target})
        reasoning = await EvidenceReasoner().reason(
            ReasoningInput(
                asset={"url": base},
                endpoint={"url": discovery.target},
                evidence=discovery.evidence,
                observations=[a.to_dict() for a in artifacts],
                authentication_context={"kind": "test_user", "synthetic": True},
            ),
            provider,
        )
        plan = lab_plan(state, base, "authorization")
        candidates = [
            TestCandidate(
                "authorization",
                plan.endpoint,
                tuple(reasoning.evidence_ids),
                ("owner identity", "non-owner identity", "control", "repeat"),
                relevance=1,
            )
        ]
        selection = NextBestTestEngine().select(
            candidates, discovery.evidence, [], scope, validator_registry
        )
        if selection is None:
            return {"status": "INCONCLUSIVE", "reasoning": reasoning.model_dump(), "findings": []}
        if progress:
            await progress("validating", {"test": plan.test, "url": plan.endpoint})
        result = await EvidenceValidationEngine().execute(plan, executor)
        finding_id = await persist(result) if persist else None
        if progress:
            await progress("finding", {"status": result.status, "finding_id": finding_id})
        evidence = discovery.evidence + result.evidence
        graph = EvidenceGraph(scope, evidence)
        graph.add_node(
            ObservationNode(
                "data", discovery.target, "Observed synthetic data", tuple(reasoning.evidence_ids)
            )
        )
        graph.add_node(
            ObservationNode(
                "access", result.endpoint_url, "Authorization test", tuple(result.evidence_ids)
            )
        )
        graph.connect(
            "data",
            "access",
            [reasoning.evidence_ids[0], result.evidence_ids[0]],
            "Observed data motivated a synthetic access-policy test",
            result=result if result.validation_proof else None,
        )
        return {
            "status": result.status,
            "scope": {
                "origins": scope.origins,
                "authorization_reference": scope.authorization_reference,
            },
            "data_discovery": [a.to_dict() for a in artifacts],
            "reasoning": reasoning.model_dump(),
            "selection": selection,
            "graph": graph.to_dict(),
            "findings": [result.to_dict()],
            "finding_ids": [finding_id] if finding_id else [],
            "evidence": evidence,
            "request_count": executor.request_count,
        }
