import pytest

from app.core.engagement import EngagementRules
from app.reporting.engine import ReportEngine
from app.reporting.redaction import RedactionEngine
from app.services.scan_manager import ScanManager


def finding_fixture(platform="Private"):
    return {
        "id": "fixture-1", "title": "Synthetic object access boundary", "severity": "HIGH",
        "confidence": "CONFIRMED", "status": "CONFIRMED", "evidence_level": "E3",
        "location": "https://app.example.invalid/test", "description": "Synthetic local test only.",
        "impact": "Test identity accessed another synthetic record.", "remediation": "Enforce object ownership.",
        "evidence": {
            "actual_result": "Record returned to test identity B.", "expected_result": "Access denied.",
            "preconditions": ["Two approved test identities and synthetic records."],
            "reproduction_steps": ["Sign in as approved test identity B.", "Replay the recorded request."],
            "structured_validation": {
                "evidence_ids": ["captured-1"],
                "evidence": [{"id": "captured-1", "request": {"method": "GET", "url": "https://app.example.invalid/test",
                    "headers": {"Authorization": "Bearer synthetic-secret"}},
                    "response": {"status_code": 200, "body": "synthetic-record-body", "headers": {"Set-Cookie": "private=synthetic-cookie"}}}],
            },
        },
        "report_context": {
            "authorization_reference": "OWNER-APPROVAL-TEST", "report": {"program": "Private fixture"},
            "rules": {"platform": platform, "authorization_acknowledged": True,
                      "scope_hosts": ["app.example.invalid"], "excluded_hosts": ["excluded.example.invalid"]},
            "scan_status": "degraded", "coverage_complete": False,
            "coverage_failures": [{"phase": "fixture-tool", "error": "Tool not installed"}],
        },
    }


@pytest.mark.parametrize("platform", ["HackerOne", "Bugcrowd", "Intigriti", "Private", "Other"])
def test_disclosure_report_preserves_proof_context_and_missing_coverage(platform):
    report = ReportEngine.generate_bug_bounty_markdown(finding_fixture(platform), "app.example.invalid")
    for value in [platform, "OWNER-APPROVAL-TEST", "captured-1", "synthetic-record-body", "Access denied.",
                  "Record returned", "Tool not installed", "degraded", "False", "Preconditions", "Expected vs Actual"]:
        assert value in report
    assert "synthetic-secret" not in report
    assert "synthetic-cookie" not in report
    assert "[REDACTED]" in report
    assert "READY_FOR_HUMAN_REVIEW" in report
    assert "No automatic submission" in report


def test_report_never_promotes_generated_checklist_to_recorded_reproduction():
    report = ReportEngine.generate_bug_bounty_markdown({"title": "Unverified fixture"}, "example.invalid")
    assert "NEEDS_REVIEW" in report
    assert "Reproduction steps were not captured" in report
    assert "authorization_and_scope" in report
    assert "Response not captured" in report
    assert "HTTP/1.1 200" not in report


def test_non_http_observation_does_not_hide_a_captured_http_exchange():
    finding = finding_fixture()
    structured = finding["evidence"]["structured_validation"]
    structured["evidence_ids"].append("observation")
    structured["evidence"].append({"id": "observation", "type": "AUTHORIZATION_CONTEXT", "request": {}, "response": {}})
    report = ReportEngine.generate_bug_bounty_markdown(finding, "app.example.invalid")
    assert "Recorded request fields" in report
    assert "Recorded response fields" in report
    assert "Response not captured" not in report
    assert "synthetic-cookie" not in report


def test_redacted_heading_gets_a_neutral_classification_without_restoring_secret():
    finding = finding_fixture()
    finding["finding_type"] = "authorization"
    finding["title"] = "authorization: Bearer synthetic-title-secret"
    report = ReportEngine.generate_bug_bounty_markdown(finding, "app.example.invalid")
    assert report.startswith("# Authorization finding on app.example.invalid")
    assert "synthetic-title-secret" not in report


def test_header_redaction_preserves_the_rest_of_a_replay_command():
    command = "curl --header 'Authorization: Bearer synthetic-secret' --url https://example.invalid/test"
    redacted = RedactionEngine.redact_text(command)
    assert "synthetic-secret" not in redacted
    assert "[REDACTED]" in redacted
    assert "' --url https://example.invalid/test" in redacted


def test_private_mode_does_not_remove_authorization_requirement():
    with pytest.raises(ValueError, match="authorized"):
        EngagementRules(platform="Private", authorization_reference="private-test", scope_hosts=["example.invalid"])


@pytest.mark.asyncio
async def test_empty_private_scope_is_rejected_before_scan_starts():
    rules = EngagementRules(platform="Private", authorization_reference="private-test", authorization_acknowledged=True)
    with pytest.raises(ValueError, match="in-scope"):
        await ScanManager().create_scan("example.invalid", engagement=rules.model_dump(mode="json"))
