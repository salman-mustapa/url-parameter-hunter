"""Attack Path Graph Engine (V8 §19).

Represents security findings, identities, credentials, services, and assets as an interconnected graph:
Nodes:
- Asset (domain, host, ip)
- Identity (user, service account, role)
- Credential (password, hash, api token)
- Service (http, ssh, rdp, database)
- Vulnerability (cve, misconfiguration)
- Finding (validated security finding)

Edges:
- REACHABLE
- AUTHENTICATES
- ACCESSES
- TRUSTS
- DEPENDS_ON
- POTENTIALLY_ESCALATES_TO
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("intelligence.attack_graph")


@dataclass
class GraphNode:
    id: str
    node_type: str  # Asset, Identity, Credential, Service, Vulnerability, Finding
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    source_node_id: str
    target_node_id: str
    edge_type: str  # REACHABLE, AUTHENTICATES, ACCESSES, TRUSTS, DEPENDS_ON, POTENTIALLY_ESCALATES_TO
    confidence: float = 1.0
    evidence_id: Optional[str] = None
    source: str = "DIRECT_OBSERVATION"
    properties: Dict[str, Any] = field(default_factory=dict)


class AttackGraphEngine:
    """In-memory Graph Engine representing complex attack paths (V8 §19)."""

    def __init__(self, graph_id: Optional[str] = None) -> None:
        self.graph_id = graph_id or f"graph_{uuid.uuid4().hex[:8]}"
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

    def add_node(self, node_id: str, node_type: str, label: str, **properties) -> GraphNode:
        node = GraphNode(id=node_id, node_type=node_type, label=label, properties=properties)
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        confidence: float = 1.0,
        evidence_id: Optional[str] = None,
        source: str = "DIRECT_OBSERVATION",
        **properties,
    ) -> GraphEdge:
        edge = GraphEdge(
            id=f"edge_{uuid.uuid4().hex[:8]}",
            source_node_id=source_id,
            target_node_id=target_id,
            edge_type=edge_type,
            confidence=confidence,
            evidence_id=evidence_id,
            source=source,
            properties=properties,
        )
        self.edges.append(edge)
        return edge

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "nodes_count": len(self.nodes),
            "edges_count": len(self.edges),
            "nodes": [
                {"id": n.id, "type": n.node_type, "label": n.label, "properties": n.properties}
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "source": e.source_node_id,
                    "target": e.target_node_id,
                    "type": e.edge_type,
                    "confidence": e.confidence,
                    "evidence_id": e.evidence_id,
                }
                for e in self.edges
            ],
        }

    def find_paths_to_critical_assets(self, target_node_id: str) -> List[List[str]]:
        """Breadth-first search for reachability paths to a specific target."""
        paths: List[List[str]] = []
        queue = [[n_id] for n_id in self.nodes if n_id != target_node_id]

        while queue:
            current_path = queue.pop(0)
            last_node = current_path[-1]

            if last_node == target_node_id:
                paths.append(current_path)
                continue

            if len(current_path) > 6:  # limit search depth
                continue

            for edge in self.edges:
                if edge.source_node_id == last_node and edge.target_node_id not in current_path:
                    queue.append(current_path + [edge.target_node_id])

        return paths
