"""Evidence-linked observation graph. Possible links never authorize execution."""

from dataclasses import asdict, dataclass

from app.validation.context import has_verified_proof
from app.validation.safety.executor import AuthorizedScope


@dataclass(frozen=True)
class ObservationNode:
    id: str
    endpoint: str
    label: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ObservationEdge:
    source: str
    target: str
    evidence_ids: tuple[str, ...]
    status: str
    relationship: str


class EvidenceGraph:
    def __init__(self, scope: AuthorizedScope, evidence: list[dict]):
        self.scope = scope
        self.evidence = {e["id"]: e for e in evidence}
        if len(self.evidence) != len(evidence):
            raise ValueError("Duplicate evidence IDs")
        self.nodes = {}
        self.edges = []

    def _check(self, ids):
        if not ids or not set(ids) <= self.evidence.keys():
            raise ValueError("Every graph transition requires known evidence")

    def add_node(self, node: ObservationNode):
        self.scope.check(node.endpoint)
        self._check(node.evidence_ids)
        if node.id in self.nodes:
            raise ValueError("Duplicate graph node")
        self.nodes[node.id] = node

    def connect(self, source: str, target: str, evidence_ids, relationship: str, result=None):
        if source not in self.nodes or target not in self.nodes or source == target:
            raise ValueError("Two existing distinct observation nodes are required")
        self._check(evidence_ids)
        for node in (self.nodes[source], self.nodes[target]):
            if not set(node.evidence_ids) & set(evidence_ids):
                raise ValueError("Relationship must cite evidence from both nodes")
        status = "HYPOTHESIS"
        if result is not None:
            if not has_verified_proof(result) or result.endpoint_url != self.nodes[target].endpoint:
                raise ValueError("Target validation receipt does not support this transition")
            if not set(result.evidence_ids) & set(evidence_ids):
                raise ValueError("Transition does not cite validation evidence")
            # The target mechanism is verified, not causality of the entire chain.
            status = "TARGET_VALIDATED"
        edge = ObservationEdge(source, target, tuple(evidence_ids), status, relationship)
        self.edges.append(edge)
        return edge

    def to_dict(self):
        return {
            "nodes": [asdict(n) for n in self.nodes.values()],
            "edges": [asdict(e) for e in self.edges],
        }
