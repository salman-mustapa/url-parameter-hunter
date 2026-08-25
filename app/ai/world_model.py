"""AI World Model & Target Knowledge Graph (Master Prompt v2 §4, §5).

Maintains a persistent, structured, graph-backed world model of the target:
- Assets, Domains, Subdomains, IPs, Ports, Services, Applications, Technologies
- Routes, Endpoints, Parameters, Users, Roles, Sessions, Tokens, Cookies
- Objects, Object IDs, API Schemas, Database Hints, Source Code Locations
- Business Entities, State Transitions, Trust Boundaries, Security Controls
- Observed Behaviors, Known Vulnerabilities, Potential Attack Paths
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("ai.world_model")


@dataclass
class WorldModelNode:
    id: str
    category: str  # Asset, Endpoint, Parameter, Identity, Object, BusinessEntity, Control, Vulnerability
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    state: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=lambda: 0.0)
    last_updated: float = field(default_factory=lambda: 0.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "label": self.label,
            "properties": self.properties,
            "state": self.state,
        }


@dataclass
class WorldModelEdge:
    id: str
    source_id: str
    target_id: str
    relation: str  # CONTAINS, AUTHENTICATES_AS, ACCESSES, MUTATES, TRANSITIONS_TO, VULNERABLE_TO, PROVES
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "confidence": self.confidence,
            "properties": self.properties,
        }


class AIWorldModel:
    """Persistent structured world model tracking target state, entities, and attack graph."""

    def __init__(self, target_root: str = "global") -> None:
        self.target_root = target_root
        self.nodes: Dict[str, WorldModelNode] = {}
        self.edges: Dict[str, WorldModelEdge] = {}
        # Entity Indexes
        self.endpoints_index: Set[str] = set()
        self.parameters_index: Set[str] = set()
        self.users_index: Dict[str, str] = {}  # username -> node_id
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

    def upsert_node(self, node_id: str, category: str, label: str, **properties) -> WorldModelNode:
        """Adds or updates an entity node in the world model."""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.properties.update(properties)
            if "state" in properties:
                node.state.update(properties["state"])
            return node

        node = WorldModelNode(
            id=node_id,
            category=category,
            label=label,
            properties=properties,
            state=properties.get("state", {}),
        )
        self.nodes[node_id] = node

        if category == "Endpoint":
            self.endpoints_index.add(label)
        elif category == "Parameter":
            self.parameters_index.add(label)
        elif category == "Identity":
            self.users_index[label] = node_id

        return node

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        confidence: float = 1.0,
        **properties,
    ) -> WorldModelEdge:
        """Connects two entities with a typed directed edge."""
        edge_id = f"rel_{uuid.uuid4().hex[:8]}"
        edge = WorldModelEdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            confidence=confidence,
            properties=properties,
        )
        self.edges[edge_id] = edge
        return edge

    def record_state_transition(
        self,
        from_entity_id: str,
        to_entity_id: str,
        action: str,
        state_mutation: Dict[str, Any],
    ) -> None:
        """Records a state change (e.g. basket -> checkout -> order with wallet mutation)."""
        self.add_relation(
            source_id=from_entity_id,
            target_id=to_entity_id,
            relation="TRANSITIONS_TO",
            action=action,
            mutation=state_mutation,
        )

    def get_attack_graph_summary(self) -> Dict[str, Any]:
        """Returns the complete structured graph view for AI reasoning and visualization."""
        return {
            "target_root": self.target_root,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "summary": {
                "endpoints_count": len(self.endpoints_index),
                "parameters_count": len(self.parameters_index),
                "users_count": len(self.users_index),
            },
        }

    def reset(self) -> None:
        self.nodes.clear()
        self.edges.clear()
        self.endpoints_index.clear()
        self.parameters_index.clear()
        self.users_index.clear()
        self.active_sessions.clear()


ai_world_model = AIWorldModel()
