"""Proof gate: status labels and HTTP success cannot replace a mechanism receipt."""

from app.findings.lifecycle import ExploitabilityState, FindingQualityProfile
from app.validation.context import has_verified_proof


class ProofQualityGateResult(tuple):
    def __new__(cls, passed, final_status, exploitability_state, checklist_logs, profile=None):
        return super().__new__(cls, (passed, final_status, exploitability_state, checklist_logs))

    def __init__(self, passed, final_status, exploitability_state, checklist_logs, profile=None):
        self.passed = passed
        self.final_status = final_status
        self.exploitability_state = exploitability_state
        self.checklist = checklist_logs
        self.profile = profile


class ProofQualityGate:
    @classmethod
    def evaluate(cls, result, scope_decision="ALLOWED", poc_valid=True):
        checks = []
        verified = has_verified_proof(result)
        checks.append(
            "Collected evidence receipt matches"
            if verified
            else "Missing/mismatched mechanism proof"
        )
        checks.append(
            "Authorized scope supplied" if scope_decision == "ALLOWED" else "Scope blocked"
        )
        passed = verified and scope_decision == "ALLOWED" and poc_valid
        status = (
            result.status
            if passed
            else (
                result.status
                if result.status in {"NOT_VULNERABLE", "REJECTED", "FALSE_POSITIVE", "INCONCLUSIVE"}
                else "INCONCLUSIVE"
            )
        )
        if status == "CONFIRMED":
            state, confidence = ExploitabilityState.CONFIRMED, "CONFIRMED"
        elif status == "VALIDATED":
            state, confidence = ExploitabilityState.VALIDATED, "VALIDATED"
        elif status in {"NOT_VULNERABLE", "REJECTED", "FALSE_POSITIVE"}:
            state, confidence = ExploitabilityState.NOT_EXPLOITABLE, "OBSERVED"
        else:
            state, confidence = ExploitabilityState.INCONCLUSIVE, "SUSPECTED"
        profile = FindingQualityProfile(
            severity=result.severity,
            confidence=confidence,
            evidence_level=result.evidence_level,
            exploitability=state,
            poc_valid=passed,
            report_ready=status == "CONFIRMED",
            details={"checks": checks, "false_positive_checks": result.false_positive_checks},
        )
        return ProofQualityGateResult(passed, status, state, checks, profile)
