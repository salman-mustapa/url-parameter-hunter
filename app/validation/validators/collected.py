"""Shared evidence transport contract; mechanisms remain in individual validators."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from app.validation.context import ValidationContext, ValidationProof, evidence_digest
from app.validation.result import NormalizedValidationResult
from app.validation.validators.base import BaseVulnerabilityValidator


@dataclass(frozen=True)
class Decision:
    status: str
    reason: str
    checks: tuple[str, ...]


class EvidenceValidator(BaseVulnerabilityValidator):
    """Only a collected, authorized run can produce a validation receipt."""

    severity = "HIGH"

    def assess(self, context: ValidationContext) -> Decision:
        raise NotImplementedError

    async def validate(self, target_url, finding_context, session_context=None):
        run = (
            finding_context
            if isinstance(finding_context, ValidationContext)
            else finding_context.get("run")
        )
        if not isinstance(run, ValidationContext) or not run._authorized:
            return self.create_empty_result(
                target_url,
                {},
                reason="No authorized collected evidence; caller flags and HTTP status are observations only",
            )
        if run.target != target_url or run.vulnerability_type != self.vulnerability_type:
            return self.create_empty_result(
                target_url, {}, reason="Evidence target or vulnerability type mismatch"
            )
        try:
            decision = self.assess(run)
        except (ValueError, KeyError, TypeError, AttributeError):
            decision = Decision(
                "INCONCLUSIVE", "Required mechanism evidence is missing or malformed", ()
            )
        evidence = run.evidence
        ids = [e["id"] for e in evidence]
        proven = decision.status in {"VALIDATED", "CONFIRMED"}
        result = NormalizedValidationResult(
            status=decision.status,
            confidence=decision.status if proven else "OBSERVED",
            evidence_level="E3" if decision.status == "CONFIRMED" else "E2" if proven else "E0",
            evidence_score=95 if decision.status == "CONFIRMED" else 80 if proven else 10,
            vulnerability_type=self.vulnerability_type,
            adapter_name=type(self).__name__,
            title=f"{self.contract.name}: {decision.status}",
            severity=self.severity if proven else "INFO",
            target_host=urlsplit(target_url).hostname or "",
            endpoint_url=target_url,
            parameter=run.parameter,
            cwe_id=self.contract.cwe_id,
            actual_result=decision.reason,
            expected_result=self.contract.validation_strategy,
            evidence=evidence,
            evidence_ids=ids,
            false_positive_checks=list(decision.checks),
            request_metadata=evidence[0]["request"] if evidence else {},
            response_metadata=evidence[-1]["response"] if evidence else {},
            reproduction_steps=[
                f"Replay captured {e['data'].get('phase', 'observation')} exchange [{e['id']}] using a fresh synthetic session"
                for e in evidence
            ],
            remediation="Enforce the boundary described by the vulnerability contract and repeat the control/probe comparison.",
        )
        if proven:
            result.validation_proof = ValidationProof(
                self.vulnerability_type,
                target_url,
                decision.status,
                tuple(ids),
                evidence_digest(evidence),
                decision.reason,
                True,
            )
        return result

    def evaluate_evidence(self, evidence_pkg):
        # Historical packages lack wire provenance; never trust behavioral_anomaly_confirmed.
        return False, "INCONCLUSIVE", 10


def repeated(context: ValidationContext):
    baseline, control, test, repeat = context.require("baseline", "control", "test", "repeat")
    if any(e.status == 0 or e.status >= 500 for e in (baseline, control, test, repeat)):
        raise ValueError("Transport/server error is not mechanism evidence")
    return baseline, control, test, repeat


def private_content(exchange, resource: dict) -> bool:
    body = exchange.json()
    return bool(
        isinstance(body, dict)
        and resource.get("private_marker")
        and body.get("id") == resource.get("id")
        and body.get("owner") == resource.get("owner")
        and body.get("private_marker") == resource["private_marker"]
    )
