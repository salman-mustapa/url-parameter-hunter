"""Run-local wire evidence. Untrusted dictionaries cannot stand in for a collected run."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from uuid import uuid4

import httpx

from app.validation.evidence.typed_evidence import Evidence, EvidenceType


@dataclass(frozen=True)
class Exchange:
    id: str
    phase: str
    method: str
    url: str
    request_body: str
    request_headers: tuple[tuple[str, str], ...]
    status: int
    body: str
    headers: tuple[tuple[str, str], ...]
    actor: str
    elapsed: float

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None

    def header(self, name: str) -> str:
        return dict(self.headers).get(name.lower(), "")

    def sent_header(self, name: str) -> str:
        return dict(self.request_headers).get(name.lower(), "")


@dataclass
class ValidationContext:
    target: str
    vulnerability_type: str
    parameter: str = ""
    metadata: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex)
    _exchanges: dict[str, Exchange] = field(default_factory=dict, init=False, repr=False)
    _evidence: list[Evidence] = field(default_factory=list, init=False, repr=False)
    _authorized: bool = field(default=False, init=False, repr=False)

    def record(
        self,
        phase: str,
        request: httpx.Request,
        response: httpx.Response,
        actor: str,
        elapsed: float,
    ) -> Exchange:
        if phase in self._exchanges:
            raise ValueError(f"Duplicate evidence phase: {phase}")
        item = Evidence(
            EvidenceType.HTTP_RESPONSE,
            f"{phase} HTTP exchange",
            "Captured by bounded executor",
            data={"phase": phase, "actor": actor},
            asset=str(request.url),
            request={
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": request.content.decode(errors="replace"),
            },
            response={
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            },
            confidence=1,
            relevance=1,
            comparison={"elapsed_seconds": elapsed},
        )
        exchange = Exchange(
            item.id,
            phase,
            request.method,
            str(request.url),
            request.content.decode(errors="replace"),
            tuple(request.headers.items()),
            response.status_code,
            response.text,
            tuple(response.headers.items()),
            actor,
            elapsed,
        )
        self._exchanges[phase] = exchange
        self._evidence.append(item)
        return exchange

    def get(self, phase: str) -> Exchange | None:
        return self._exchanges.get(phase)

    def require(self, *phases: str) -> list[Exchange]:
        if any(p not in self._exchanges for p in phases):
            raise ValueError(
                "Missing captured phases: "
                + ", ".join(p for p in phases if p not in self._exchanges)
            )
        return [self._exchanges[p] for p in phases]

    @property
    def evidence(self) -> list[dict]:
        return [e.to_dict() for e in self._evidence]

    def add_observation(self, item: Evidence) -> None:
        if any(e.id == item.id for e in self._evidence):
            raise ValueError("Duplicate evidence ID")
        self._evidence.append(deepcopy(item))


def evidence_digest(evidence: list[dict]) -> str:
    return hashlib.sha256(
        json.dumps(evidence, sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()


@dataclass(frozen=True)
class ValidationProof:
    """In-process receipt; external JSON and AI responses cannot supply this object."""

    vulnerability_type: str
    target: str
    status: str
    evidence_ids: tuple[str, ...]
    digest: str
    mechanism: str
    reproducible: bool

    def matches(self, result) -> bool:
        return (
            self.vulnerability_type == result.vulnerability_type
            and self.target == result.endpoint_url
            and self.status == result.status
            and self.status in {"VALIDATED", "CONFIRMED"}
            and bool(self.mechanism)
            and self.reproducible
            and self.evidence_ids == tuple(result.evidence_ids)
            and bool(self.evidence_ids)
            and len(set(self.evidence_ids)) == len(self.evidence_ids)
            and set(self.evidence_ids) <= {e["id"] for e in result.evidence}
            and self.digest == evidence_digest(result.evidence)
        )


def has_verified_proof(result) -> bool:
    proof = getattr(result, "validation_proof", None)
    return isinstance(proof, ValidationProof) and proof.matches(result)
