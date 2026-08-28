"""Real loopback HTTP integration tests; no mocked success flags or public targets."""

import pytest

from app.lab.plans import lab_plan
from app.lab.runtime import local_lab
from app.validation.engine import EvidenceValidationEngine
from app.validation.quality_gate import ProofQualityGate
from app.validation.safety.executor import AuthorizedExecutor, AuthorizedScope


@pytest.fixture
async def lab():
    async with local_lab() as fixture:
        yield fixture


@pytest.mark.anyio
@pytest.mark.parametrize(
    "family",
    [
        "sqli",
        "xss",
        "idor",
        "authorization",
        "auth_bypass",
        "ssrf",
        "path_traversal",
        "file_upload",
        "rce",
        "csrf",
        "jwt",
    ],
)
@pytest.mark.parametrize("variant", ["vuln", "safe"])
async def test_real_vulnerable_and_secure_endpoints(lab, family, variant):
    base, state = lab
    async with AuthorizedExecutor(
        AuthorizedScope((base,), "synthetic integration test")
    ) as executor:
        result = await EvidenceValidationEngine().execute(
            lab_plan(state, base, family, variant), executor
        )
    expected = (
        "NOT_VULNERABLE" if variant == "safe" else "VALIDATED" if family == "xss" else "CONFIRMED"
    )
    assert result.status == expected, result.to_dict()
    assert len(result.evidence) >= 4
    assert all(e["id"] and e["timestamp"] for e in result.evidence)
    assert ProofQualityGate.evaluate(result).passed == (variant == "vuln")


@pytest.mark.anyio
@pytest.mark.parametrize("scenario", ["horizontal", "vertical", "bola", "bfla", "tenant"])
async def test_authorization_matrix_boundaries(lab, scenario):
    base, state = lab
    for variant in ("vuln", "safe"):
        async with AuthorizedExecutor(
            AuthorizedScope((base,), "synthetic authorization")
        ) as executor:
            plan = lab_plan(state, base, "authorization", variant, scenario)
            result = await EvidenceValidationEngine().execute(plan, executor)
        assert result.status == ("CONFIRMED" if variant == "vuln" else "NOT_VULNERABLE"), (
            result.actual_result
        )
        matrix = [e for e in result.evidence if e["type"] == "AUTHORIZATION_CONTEXT"]
        assert matrix[0]["data"]["expected_result"] == "DENY"
