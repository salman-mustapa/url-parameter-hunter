"""One finding contract for the workspace, dossiers and exported reports."""
from urllib.parse import urlsplit


def finding_location(finding, host: str) -> str:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    for value in (evidence.get("url"), evidence.get("endpoint_url"), evidence.get("location"),
                  evidence.get("endpoint"), getattr(finding, "technical_details", None)):
        if not isinstance(value, str) or any(c in value for c in "\r\n "):
            continue
        if value.startswith("/") and not value.startswith("//"):
            return f"https://{host}{value}"
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            return value
    return ""  # A prose description is not an endpoint URL.


def finding_quality(finding: dict) -> dict:
    evidence = finding.get("evidence") or {}
    evidence = evidence if isinstance(evidence, dict) else {}
    observed = any(evidence.get(key) for key in (
        "raw_http_response", "response_body", "body_sample", "response", "response_headers",
        "command_output", "observations", "execution_proof", "screenshot_id",
    ))
    steps = finding.get("reproduction_steps") or evidence.get("reproduction_steps")
    command = finding.get("poc") or any(evidence.get(k) for k in ("curl", "poc_curl", "curl_command", "poc"))
    checks = {
        "endpoint": bool(finding.get("location") or finding.get("endpoint_url")),
        "observed_evidence": bool(observed),
        "reproduction": bool(steps or command),
        "actual_result": bool(finding.get("actual_result") or evidence.get("actual_result")),
        "impact": bool(finding.get("impact") or finding.get("business_impact")),
        "remediation": bool(finding.get("remediation")),
    }
    missing = [name for name, present in checks.items() if not present]
    verified = (str(finding.get("evidence_level", "E0")) in {"E3", "E4"}
                and str(finding.get("confidence", "")).upper() == "CONFIRMED"
                and str(finding.get("status", "")).upper() not in {"FALSE_POSITIVE", "INCONCLUSIVE"}
                and bool(observed))
    return {"status": "READY_FOR_REVIEW" if not missing and verified else "NEEDS_REVIEW",
            "confirmed_with_evidence": verified, "missing": missing,
            "note": "Completeness check only; human validation and scope review are required."}


def serialize_finding(finding, root_domain: str, asset_map: dict | None = None) -> dict:
    host = (asset_map or {}).get(finding.asset_id) or root_domain
    evidence = dict(finding.evidence) if isinstance(finding.evidence, dict) else {}
    for key in ("actual_result", "expected_result", "preconditions"):
        if getattr(finding, key, None):
            evidence.setdefault(key, getattr(finding, key))
    result = {key: getattr(finding, key, None) for key in (
        "id", "scan_id", "finding_type", "title", "severity", "confidence", "status",
        "evidence_level", "evidence_score", "validation_status", "cwe_id", "cve_id",
        "cvss_score", "description", "impact", "business_impact", "technical_details",
        "remediation", "root_cause", "expected_result", "actual_result", "preconditions",
        "impact_matrix", "reproducibility_meta",
    )}
    result.update({"finding_code": finding.finding_code or f"INV-F-{finding.id[:12]}",
                   "asset_hostname": host, "location": finding_location(finding, host),
                   "evidence": evidence, "exploitation_data": evidence.get("exploitation_data", {}),
                   "reproduction_steps": evidence.get("reproduction_steps") or [],
                   "poc": next((evidence[k] for k in ("curl", "poc_curl", "curl_command", "poc")
                                if isinstance(evidence.get(k), str) and evidence[k]), ""),
                   "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
                   "last_seen": finding.last_seen.isoformat() if finding.last_seen else None})
    result["report_quality"] = finding_quality(result)
    result["cvss_version"] = evidence.get("cvss_version")
    result["cvss_vector"] = evidence.get("cvss_vector")
    result["cve_match_status"] = evidence.get("cve_match_status") or ("CANDIDATE_REQUIRES_APPLICABILITY_REVIEW" if result.get("cve_id") else "NOT_MAPPED")
    result["references"] = evidence.get("references") or []
    return result
