"""Incremental evidence pipeline using existing validators, findings and database tables."""

import asyncio
from dataclasses import dataclass, field
from http.cookies import SimpleCookie

import httpx

from app.validation.context import ValidationContext, evidence_digest
from app.validation.quality_gate import ProofQualityGate
from app.validation.result import NormalizedValidationResult
from app.validation.safety.executor import AuthorizedExecutor, SafetyViolation, origin
from app.validation.state_machine import Finding, FindingLifecycleState
from app.validation.validators import get_validator


@dataclass(frozen=True)
class Probe:
    phase: str
    url: str
    method: str = "GET"
    actor: str = "anonymous"
    kwargs: dict = field(default_factory=dict)
    url_from: tuple[str, str] | None = None
    cookie_from: str | None = None


@dataclass(frozen=True)
class ValidationPlan:
    test: str
    endpoint: str
    probes: tuple[Probe, ...]
    parameter: str = ""
    metadata: dict = field(default_factory=dict)


class EvidenceValidationEngine:
    async def execute(self, plan: ValidationPlan, executor: AuthorizedExecutor):
        validator = get_validator(plan.test)
        if validator is None:
            return NormalizedValidationResult(
                status="INCONCLUSIVE",
                vulnerability_type=plan.test,
                endpoint_url=plan.endpoint,
                actual_result="No vulnerability-specific validator registered",
            )
        executor.scope.check(plan.endpoint)
        run = ValidationContext(
            plan.endpoint, validator.vulnerability_type, plan.parameter, dict(plan.metadata)
        )
        finding = Finding(
            run.id, vulnerability_type=validator.vulnerability_type, asset=plan.endpoint
        )
        finding.transition_to(FindingLifecycleState.CANDIDATE, "Explicit test plan")
        finding.transition_to(FindingLifecycleState.VALIDATING, "Collecting bounded probe evidence")
        try:
            for probe in plan.probes:
                url = probe.url
                kwargs = dict(probe.kwargs)
                if probe.url_from:
                    source, key = probe.url_from
                    (captured,) = run.require(source)
                    url = captured.json()[key]
                    executor.scope.check(url)
                if probe.cookie_from:
                    (captured,) = run.require(probe.cookie_from)
                    if origin(captured.url) != origin(url):
                        raise SafetyViolation("Session cookie cannot cross origins")
                    cookie = SimpleCookie()
                    cookie.load(captured.header("set-cookie"))
                    kwargs["cookies"] = {name: value.value for name, value in cookie.items()}
                await executor.request(
                    run, probe.phase, probe.method, url, actor=probe.actor, **kwargs
                )
            result = await validator.validate(plan.endpoint, run)
        except (
            SafetyViolation,
            httpx.HTTPError,
            TimeoutError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
        ) as error:
            result = NormalizedValidationResult(
                status="INCONCLUSIVE",
                vulnerability_type=validator.vulnerability_type,
                endpoint_url=plan.endpoint,
                actual_result=f"Validation stopped: {type(error).__name__}",
                evidence=run.evidence,
                evidence_ids=[e["id"] for e in run.evidence],
            )
        except asyncio.CancelledError:
            executor.abort()
            raise
        gate = ProofQualityGate.evaluate(result, scope_decision="ALLOWED")
        if gate.passed:
            finding.transition_to(
                FindingLifecycleState.VALIDATED,
                result.actual_result,
                evidence_ids=result.evidence_ids,
            )
            if result.status == "CONFIRMED":
                finding.transition_to(
                    FindingLifecycleState.CONFIRMED, "Repeated mechanism proof", confidence_score=95
                )
        else:
            state = "REJECTED" if result.status == "NOT_VULNERABLE" else "INCONCLUSIVE"
            finding.transition_to(FindingLifecycleState(state), result.actual_result)
        result.observations.append({"finding_lifecycle": finding.to_dict()})
        return result

    async def persist(self, db, scan_id: str, result, asset_id=None):
        """Store redacted evidence and validation in the application's existing tables."""
        from app.models.models import Evidence, EvidencePackage, Validation
        from app.services.results import result_service

        gate = ProofQualityGate.evaluate(result)
        serialized = result.to_dict()
        validation = Validation(
            scan_id=scan_id,
            asset_id=asset_id,
            status=result.status,
            confidence=result.confidence,
            input_data={"endpoint": serialized["endpoint_url"]},
            result_data=serialized,
        )
        db.add(validation)
        await db.flush()
        finding = await result_service.upsert_finding(
            db,
            scan_id=scan_id,
            asset_id=asset_id,
            finding_type=result.vulnerability_type,
            title=f"{result.vulnerability_type}: {result.endpoint_url}",
            severity=result.severity,
            confidence=result.confidence,
            cwe_id=result.cwe_id,
            evidence_level=result.evidence_level,
            evidence_score=result.evidence_score,
            validation_status=gate.final_status,
            exploitability_state=gate.exploitability_state,
            actual_result=result.actual_result,
            expected_result=result.expected_result,
            remediation=result.remediation,
            evidence={"structured_validation": serialized},
            validated_result=result,
        )
        await db.flush()  # Materialize the finding ID before inserting its evidence package.
        for item in result.evidence:
            db.add(
                Evidence(
                    id=item["id"],
                    scan_id=scan_id,
                    asset_id=asset_id,
                    validation_id=validation.id,
                    evidence_type=item["type"],
                    data=item,
                    sha256_hash=evidence_digest([item]),
                    provenance={"collector": "authorized_executor", "asset": item["asset"]},
                )
            )
        if finding:
            db.add(
                EvidencePackage(
                    finding_id=finding.id,
                    summary_data=serialized,
                    request_metadata=result.request_metadata,
                    response_metadata=result.response_metadata,
                    validation_data={
                        "status": gate.final_status,
                        "evidence_ids": result.evidence_ids,
                    },
                    hashes_data={"sha256": evidence_digest(result.evidence)},
                    reproduction_md="\n".join(result.reproduction_steps),
                )
            )
        await db.flush()
        return finding
