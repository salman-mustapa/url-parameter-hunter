"""Evidence-Driven Autonomous Pentest Validation Engine Test Suite (V10 Architecture).

Strictly tests:
1. HTTP 200 / 500 / timeouts / latency are NOT vulnerabilities.
2. Escaped reflections are NOT XSS.
3. Upload forms without execution are NOT RCE.
4. Relative redirects are NOT Open Redirect.
5. Single-user access is NOT IDOR.
6. Public login 200 OK is NOT Auth Bypass.
7. Slowloris without connection exhaustion is INCONCLUSIVE.
8. Differential semantic confirmation across 10+ vulnerability classes.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.validation.contracts.model import SafeValidationLevel, VulnerabilityContract
from app.validation.contracts.registry import contract_registry
from app.validation.evidence.typed_evidence import (
    DifferentialObservation,
    EvidenceType,
    TypedEvidenceItem,
    TypedEvidencePackage,
)
from app.validation.quality_gate import ProofQualityGate
from app.validation.result import NormalizedValidationResult
from app.validation.safety.engine import SafetyEngine, safety_engine
from app.validation.safety.policy import SafetyPolicy
from app.validation.state_machine import (
    ConfidenceRating,
    FindingLifecycleRecord,
    FindingLifecycleState,
)
from app.validation.validators import (
    auth_bypass_validator,
    cors_validator,
    file_upload_validator,
    idor_validator,
    open_redirect_validator,
    path_traversal_validator,
    rce_validator,
    slowloris_validator,
    sqli_validator,
    ssrf_validator,
    xss_validator,
)


class TestNegativeAntiFalsePositiveRules:
    """Ensures generic HTTP responses are strictly rejected as proofs of vulnerability."""

    @pytest.mark.anyio
    async def test_200_is_not_vulnerability(self):
        """HTTP 200 on an un-mutated parameter or generic page MUST NOT confirm vulnerability."""
        session = AsyncMock()
        context = {
            "parameter": "page",
            "raw_evidence": {"status_code": 200, "response_body": "<html><body>Welcome to our website</body></html>"},
        }
        res = await sqli_validator.validate("https://example.com/item", context, session)
        assert res.status != "CONFIRMED"
        assert res.status in ("INCONCLUSIVE", "REJECTED", "FALSE_POSITIVE")

    @pytest.mark.anyio
    async def test_500_is_not_vulnerability(self):
        """Generic HTTP 500 server error without database or execution evidence MUST NOT confirm SQLi or RCE."""
        session = AsyncMock()
        context = {
            "parameter": "id",
            "raw_evidence": {
                "status_code": 500,
                "response_body": "<html><body>Internal Server Error: Something went wrong</body></html>",
                "syntax_error_body": "Internal Server Error",
            },
        }
        res = await sqli_validator.validate("https://example.com/api/item", context, session)
        assert res.status != "CONFIRMED"
        assert "Internal Server Error" not in res.actual_result or "generic" in res.actual_result.lower()

    @pytest.mark.anyio
    async def test_reflection_is_not_xss(self):
        """HTML-entity encoded reflection or application/json reflection MUST NOT confirm XSS."""
        session = AsyncMock()
        context = {
            "parameter": "search",
            "raw_evidence": {
                "payload": "<script>alert(1)</script>",
                "response_body": "<html><body>Search results for &lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
                "content_type": "text/html",
            },
        }
        res = await xss_validator.validate("https://example.com/search", context, session)
        assert res.status != "CONFIRMED"
        assert res.status == "REJECTED"
        assert "encoded" in res.actual_result.lower()

    @pytest.mark.anyio
    async def test_upload_success_is_not_rce(self):
        """File upload form returning HTTP 200 / accepted without server-side execution MUST NOT confirm RCE."""
        session = AsyncMock()
        context = {
            "raw_evidence": {
                "upload_accepted": True,
                "file_stored_url": "https://example.com/uploads/canary.phtml",
                "canary_script_executed": False,  # Not executed!
                "canary_output": "",
            }
        }
        res = await file_upload_validator.validate("https://example.com/upload", context, session)
        assert res.status != "CONFIRMED"
        assert res.status == "INCONCLUSIVE"
        assert res.severity != "CRITICAL"

    @pytest.mark.anyio
    async def test_redirect_is_not_open_redirect(self):
        """Internal / same-origin redirect (e.g. /dashboard) MUST NOT confirm Open Redirect."""
        session = AsyncMock()
        context = {
            "parameter": "next",
            "raw_evidence": {
                "location_header": "/dashboard",
                "injected_domain": "https://attacker.example.com",
            },
        }
        res = await open_redirect_validator.validate("https://example.com/login", context, session)
        assert res.status != "CONFIRMED"
        assert res.status == "REJECTED"

    @pytest.mark.anyio
    async def test_url_parameter_is_not_ssrf(self):
        """URL parameter accepted with HTTP 200 without internal network interaction MUST NOT confirm SSRF."""
        session = AsyncMock()
        context = {
            "parameter": "callback_url",
            "raw_evidence": {
                "status_code": 200,
                "response_body": "{\"status\":\"ok\",\"url\":\"http://127.0.0.1/\"}",
                "internal_resource_fetched": False,
            },
        }
        res = await ssrf_validator.validate("https://example.com/webhook", context, session)
        assert res.status != "CONFIRMED"
        assert res.status == "REJECTED"

    @pytest.mark.anyio
    async def test_object_access_is_not_idor(self):
        """Single-user resource access or public endpoint access MUST NOT confirm IDOR."""
        session = AsyncMock()
        context = {
            "parameter": "id",
            "raw_evidence": {
                "actor_a": "alice",
                "actor_b": "alice",  # Same actor accessing own resource
                "resource_b_id": "1001",
                "actor_a_accessed_resource_b": True,
                "resource_contains_private_data": False,
            },
        }
        res = await idor_validator.validate("https://example.com/api/user/1001", context, session)
        assert res.status != "CONFIRMED"
        assert res.status == "REJECTED"

    @pytest.mark.anyio
    async def test_login_200_is_not_auth_bypass(self):
        """Public login page legitimately returning HTTP 200 MUST NOT confirm Auth Bypass."""
        session = AsyncMock()
        context = {
            "raw_evidence": {
                "is_login_or_public_page": True,
                "protected_admin_data_accessed": False,
                "baseline_unauthorized_status": 200,
            }
        }
        res = await auth_bypass_validator.validate("https://example.com/login", context, session)
        assert res.status != "CONFIRMED"
        assert res.status == "REJECTED"

    @pytest.mark.anyio
    async def test_latency_is_not_slowloris(self):
        """Slow response time or HTTP 200 on incomplete connection MUST be classified as INCONCLUSIVE / NOT CONFIRMED."""
        session = AsyncMock()
        session.get = AsyncMock(return_value=MagicMock(status_code=200))
        context = {
            "raw_evidence": {
                "connection_held_seconds": 3.5,  # Short hold time
                "concurrent_pool_starvation_observed": False,  # No starvation!
                "server_enforced_socket_timeout": True,
            }
        }
        res = await slowloris_validator.validate("https://example.com/", context, session)
        assert res.status != "CONFIRMED"
        assert res.status in ("INCONCLUSIVE", "NOT_VULNERABLE", "REJECTED")

        # Now evaluate through ProofQualityGate
        gate_res = ProofQualityGate.evaluate(res)
        assert gate_res.final_status != "CONFIRMED"
        assert gate_res.final_status in ("INCONCLUSIVE", "FALSE_POSITIVE")


class TestPositiveVulnerabilityConfirmations:
    """Ensures that true semantic evidence correctly confirms findings across vulnerability classes."""

    @pytest.mark.anyio
    async def test_sqli_differential_confirmation(self):
        """True boolean differential & syntax error confirms SQLi."""
        session = AsyncMock()
        context = {
            "parameter": "id",
            "raw_evidence": {
                "baseline_body": "User details for ID 100",
                "true_condition_body": "User details for ID 100",
                "false_condition_body": "No records found matching criteria",
                "syntax_error_body": "Warning: mysqli_fetch_array() error: You have an error in your SQL syntax near '' at line 1",
            },
        }
        res = await sqli_validator.validate("https://example.com/profile", context, session)
        assert res.status == "CONFIRMED"
        assert res.severity == "HIGH"
        assert res.cwe_id == "CWE-89"

        # Check ProofQualityGate
        gate_res = ProofQualityGate.evaluate(res)
        assert gate_res.passed is True
        assert gate_res.final_status == "CONFIRMED"

    @pytest.mark.anyio
    async def test_xss_executable_reflection_confirmation(self):
        """Unencoded script tag reflected in HTML text/html context confirms XSS."""
        session = AsyncMock()
        context = {
            "parameter": "query",
            "raw_evidence": {
                "payload": "<script>alert(1)</script>",
                "response_body": "<div>Results for: <script>alert(1)</script></div>",
                "content_type": "text/html",
            },
        }
        res = await xss_validator.validate("https://example.com/search", context, session)
        assert res.status == "CONFIRMED"
        assert res.cwe_id == "CWE-79"

    @pytest.mark.anyio
    async def test_rce_canary_execution_confirmation(self):
        """Server calculating and returning benign canary token confirms RCE."""
        session = AsyncMock()
        canary = "BH_CANARY_TEST_MD5"
        expected = "8973b4007bb0b213b2c953509de3801f"
        context = {
            "parameter": "host",
            "raw_evidence": {
                "canary_token": canary,
                "expected_output": expected,
                "response_body": f"PING localhost ... output: {expected}\npacket loss 0%",
                "status_code": 200,
            },
        }
        res = await rce_validator.validate("https://example.com/tools/ping", context, session)
        assert res.status == "CONFIRMED"
        assert res.severity == "CRITICAL"
        assert res.cwe_id == "CWE-94"

    @pytest.mark.anyio
    async def test_idor_cross_tenant_confirmation(self):
        """Actor A accessing private data of Actor B confirms IDOR."""
        session = AsyncMock()
        context = {
            "parameter": "account_id",
            "raw_evidence": {
                "actor_a": "attacker_user",
                "actor_b": "victim_executive",
                "resource_b_id": "acc_7788",
                "actor_a_accessed_resource_b": True,
                "resource_contains_private_data": True,
            },
        }
        res = await idor_validator.validate("https://example.com/api/billing/acc_7788", context, session)
        assert res.status == "CONFIRMED"
        assert res.cwe_id == "CWE-639"

    @pytest.mark.anyio
    async def test_auth_bypass_protected_route_confirmation(self):
        """Protected admin route accessed without authentication confirms Auth Bypass."""
        session = AsyncMock()
        context = {
            "raw_evidence": {
                "is_login_or_public_page": False,
                "protected_admin_data_accessed": True,
                "bypass_header": "X-Custom-Auth: bypass",
                "baseline_unauthorized_status": 401,
            }
        }
        res = await auth_bypass_validator.validate("https://example.com/admin/settings", context, session)
        assert res.status == "CONFIRMED"
        assert res.severity == "CRITICAL"
        assert res.cwe_id == "CWE-287"

    @pytest.mark.anyio
    async def test_file_upload_multi_stage_execution_confirmation(self):
        """Multi-stage upload + storage + execution output confirms File Upload RCE."""
        session = AsyncMock()
        context = {
            "raw_evidence": {
                "upload_accepted": True,
                "file_stored_url": "https://example.com/uploads/canary_exec.phtml",
                "canary_script_executed": True,
                "canary_output": "BH_CANARY_ECHO_TOKEN_9988",
            }
        }
        res = await file_upload_validator.validate("https://example.com/avatar/upload", context, session)
        assert res.status == "CONFIRMED"
        assert res.severity == "CRITICAL"
        assert res.cwe_id == "CWE-434"

    @pytest.mark.anyio
    async def test_cors_credentials_and_origin_reflection_confirmation(self):
        """Arbitrary origin reflection with Allow-Credentials: true on private API confirms CORS."""
        session = AsyncMock()
        context = {
            "raw_evidence": {
                "injected_origin": "https://evil-attacker.com",
                "allow_origin_header": "https://evil-attacker.com",
                "allow_credentials_header": True,
                "endpoint_is_authenticated_sensitive": True,
            }
        }
        res = await cors_validator.validate("https://example.com/api/user/private", context, session)
        assert res.status == "CONFIRMED"
        assert res.cwe_id == "CWE-942"

    @pytest.mark.anyio
    async def test_slowloris_genuine_starvation_is_confirmed(self):
        """Slowloris holding sockets > 45s causing demonstrated pool starvation confirms vulnerability."""
        session = AsyncMock()
        session.get = AsyncMock(return_value=MagicMock(status_code=200))
        context = {
            "raw_evidence": {
                "connection_held_seconds": 65.0,  # > 45s
                "concurrent_pool_starvation_observed": True,  # Genuine starvation
                "server_enforced_socket_timeout": False,
            }
        }
        res = await slowloris_validator.validate("https://example.com/", context, session)
        assert res.status == "CONFIRMED"
        assert res.cwe_id == "CWE-400"


class TestArchitectureContractsAndSchemas:
    """Verifies contracts, typed evidence, safety engine, and finding state machine."""

    def test_contract_registry_contains_all_core_vulnerabilities(self):
        """Verifies contract registry has contracts for all required vulnerability families."""
        expected_contracts = [
            "sqli", "xss", "rce", "ssrf", "path_traversal", "idor",
            "auth_bypass", "file_upload", "open_redirect", "cors",
            "csrf", "jwt", "slowloris"
        ]
        for cid in expected_contracts:
            contract = contract_registry.get(cid)
            assert contract is not None, f"Contract {cid} missing from registry"
            assert contract.allows_status_code_only_confirmation is False
            assert len(contract.required_evidence) > 0

    def test_typed_evidence_package_and_sha256_fingerprint(self):
        """Verifies TypedEvidencePackage deterministically computes SHA-256 fingerprint."""
        pkg = TypedEvidencePackage(
            finding_id="finding_123",
            vulnerability_type="sqli",
            target_url="https://example.com/api",
            contract_id="sqli",
            items=[
                TypedEvidenceItem(
                    evidence_type=EvidenceType.DATABASE_ERROR,
                    title="MySQL Syntax Error",
                    description="Exposed SQL error trace",
                    data={"error": "syntax error near quote"},
                )
            ],
            differential=DifferentialObservation(
                baseline_request={"url": "https://example.com/api"},
                baseline_response={"status": 200},
            ),
        )
        fp = pkg.compute_fingerprint()
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex length
        assert pkg.to_dict()["sha256_fingerprint"] == fp

    def test_safety_policy_enforcement(self):
        """Verifies SafetyPolicy detects and blocks dangerous commands."""
        policy = SafetyPolicy()
        assert policy.is_safe_command("cat /tmp/test.txt") is True
        assert policy.is_safe_command("echo 12345") is True
        assert policy.is_safe_command("rm -rf /var/www") is False
        assert policy.is_safe_command("DROP TABLE users;") is False

    def test_finding_lifecycle_state_machine(self):
        """Verifies 11-state finding lifecycle transitions and confidence ratings."""
        record = FindingLifecycleRecord(finding_id="f_001")
        assert record.current_state == FindingLifecycleState.DISCOVERED
        assert record.confidence_rating == ConfidenceRating.INFORMATIONAL

        # Transition to VALIDATING
        record.transition_to(FindingLifecycleState.VALIDATING, "Dispatching differential validator")
        assert record.current_state == FindingLifecycleState.VALIDATING

        # Transition to CONFIRMED with high confidence score
        record.transition_to(FindingLifecycleState.CONFIRMED, "All proof quality gate checks passed", confidence_score=95)
        assert record.current_state == FindingLifecycleState.CONFIRMED
        assert record.confidence_rating == ConfidenceRating.CONFIRMED
        assert record.confidence_score == 95
        assert len(record.history) == 2
