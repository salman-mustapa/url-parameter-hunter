"""Evidence-backed dossiers. Generated replay examples are never validation results."""
from __future__ import annotations

import json
import shlex
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


class PocBuilder:
    @classmethod
    def generate_dossier(cls, *, title: str, finding_type: str, severity: str,
                         target_url: str, target_host: str, parameter=None, method="GET",
                         headers=None, payload=None, cwe_id=None, cve_id=None, cvss_score=None,
                         description=None, technical_details=None, evidence=None,
                         screenshot_id=None, screenshot_url=None, has_real_screenshot=False) -> dict:
        evidence = dict(evidence) if isinstance(evidence, dict) else {}
        structured = evidence.get("structured_validation")
        if isinstance(structured, dict):
            for key in ("actual_result", "expected_result", "preconditions", "reproduction_steps"):
                if structured.get(key):
                    evidence.setdefault(key, structured[key])
            references = structured.get("evidence_ids") or []
            captures = [item for item in structured.get("evidence", [])
                        if isinstance(item, dict) and item.get("id") in references
                        and isinstance(item.get("request"), dict) and item["request"].get("url")
                        and (not target_url or item["request"]["url"] == target_url)
                        and isinstance(item.get("response"), dict) and item["response"].get("status_code")]
            if captures:
                capture = captures[-1]
                request = capture.get("request") or {}
                response = capture.get("response") or {}
                if isinstance(request, dict) and isinstance(response, dict):
                    for key, value in {"method": request.get("method"), "request_headers": request.get("headers"),
                                       "request_body": request.get("body"), "response_status": response.get("status_code"),
                                       "response_headers": response.get("headers"), "response_body": response.get("body")}.items():
                        if value is not None:
                            evidence.setdefault(key, value)
                    evidence.setdefault("selected_capture_id", capture.get("id"))
        headers = headers or evidence.get("request_headers") or evidence.get("headers") or {}
        headers = headers if isinstance(headers, dict) else {}
        headers = {str(k): str(v) for k, v in headers.items()
                   if str(k).lower() not in {"host", "content-length"}}
        method = str(evidence.get("method") or method or "GET").upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            method = "GET"
        url = target_url or ""
        try:
            parsed = urlsplit(url)
            valid_url = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
        except ValueError:
            valid_url = False
        body = evidence.get("request_body")
        if body is not None and not isinstance(body, str):
            body = json.dumps(body, ensure_ascii=False)
        recorded_curl = next((evidence[k] for k in ("curl", "poc_curl", "curl_command", "poc")
                              if isinstance(evidence.get(k), str) and evidence[k]), None)
        generated = ["curl", "--include", "--max-time", "15", "--request", method]
        for key, value in headers.items():
            generated.extend(["--header", f"{key}: {value}"])
        if body is not None:
            generated.extend(["--data-raw", body])
        generated.extend(["--url", url])
        curl = recorded_curl or ("# Replay template; not executed or validated. Review authorization and redacted values.\n"
                                 + shlex.join(generated) if valid_url else "# No endpoint/request recorded.")
        python = ("#!/usr/bin/env python3\n"
                  "# Replay template only. Review authorized scope, method, body and credentials before use.\n"
                  "# A successful HTTP response does not prove a vulnerability.\n"
                  "import requests\n\n"
                  f"URL = {url!r}\nMETHOD = {method!r}\nHEADERS = {headers!r}\nBODY = {body!r}\n\n"
                  "if __name__ == '__main__':\n"
                  "    if not URL.startswith(('https://', 'http://')):\n"
                  "        raise SystemExit('No recorded endpoint; review finding evidence first.')\n"
                  "    response = requests.request(METHOD, URL, headers=HEADERS, data=BODY,\n"
                  "                                timeout=15, allow_redirects=False)\n"
                  "    print('HTTP status:', response.status_code)\n"
                  "    print(response.text[:2000])\n"
                  "    print('Compare with the recorded baseline; validation is not automatic.')\n")
        raw_request = evidence.get("raw_http_request") or evidence.get("request_dump")
        if not raw_request and evidence.get("selected_capture_id"):
            raw_request = "Recorded request fields (not a complete raw HTTP capture):\n" + json.dumps(
                {"capture_id": evidence["selected_capture_id"], "method": method,
                 "url": url, "headers": headers, "body": body}, ensure_ascii=False)
        if not raw_request:
            raw_request = "Request not captured. See the explicitly labelled replay template."
        raw_response = evidence.get("raw_http_response") or evidence.get("response_dump")
        response_body = next((evidence[k] for k in ("response_body", "body_sample", "response")
                              if evidence.get(k) is not None), None)
        response_headers = evidence.get("response_headers")
        status = evidence.get("response_status", evidence.get("status_code"))
        if not raw_response:
            parts = ["Recorded response fields (not a complete raw HTTP capture):"]
            if status is not None:
                parts.append(f"Status: {status}")
            if response_headers:
                parts.append(json.dumps(response_headers, ensure_ascii=False) if isinstance(response_headers, dict) else str(response_headers))
            if response_body is not None:
                parts.append(str(response_body))
            raw_response = "\n".join(parts) if len(parts) > 1 else "Response not captured; vulnerability is not demonstrated by this dossier."
        steps = evidence.get("reproduction_steps")
        recorded_steps = isinstance(steps, list) and bool(steps)
        if not recorded_steps:
            steps = ["Confirm the authorized scope and required test identities.",
                     "Review the recorded request, method, body and any redacted credentials.",
                     "Capture a baseline and replay only the recorded test under approved limits.",
                     "Compare the observed security boundary and retain request/response evidence; HTTP status alone is insufficient."]
        actual = evidence.get("actual_result") or "Actual behavior has not been recorded."
        expected = evidence.get("expected_result") or "Expected security behavior has not been documented; review the applicable access and input rules."
        return {"title": title, "severity": (severity or "INFO").upper(), "target_url": url,
                "target_host": target_host, "method": method,
                "parameter": parameter or evidence.get("parameter") or "Not recorded",
                "payload": payload or evidence.get("payload") or "Not recorded",
                "cwe_id": cwe_id, "cve_id": cve_id, "cvss_score": cvss_score,
                "reproduction_steps": [str(s) for s in steps], "python_poc": python,
                "curl_command": curl, "raw_http_request": str(raw_request),
                "raw_http_response": str(raw_response), "expected_behavior": str(expected),
                "actual_behavior": str(actual), "evidence": evidence,
                "provenance": {"python_poc": "generated_replay_template",
                               "curl_command": "recorded" if recorded_curl else "generated_replay_template",
                               "reproduction_steps": "recorded" if recorded_steps else "review_checklist",
                               "raw_http_request": "recorded" if evidence.get("raw_http_request") or evidence.get("request_dump") else "recorded_fields" if evidence.get("selected_capture_id") else "missing",
                               "raw_http_response": "recorded_fields" if status is not None or response_headers or response_body is not None or evidence.get("raw_http_response") or evidence.get("response_dump") else "missing"},
                "screenshot": {"has_screenshot": bool(has_real_screenshot and (screenshot_url or screenshot_id)),
                               "image_url": screenshot_url or (f"/api/screenshots/{screenshot_id}/image" if screenshot_id else None),
                               "thumb_url": f"/api/screenshots/{screenshot_id}/thumbnail" if screenshot_id else None,
                               "caption": f"Stored screenshot associated with {target_host}; context must be reviewed.",
                               "explanation_if_none": "No screenshot is attached. This does not establish whether visual validation is applicable."},
                "remediation_playbook": cls._build_remediation_playbook(vuln_type=(finding_type or title or "").lower(), cwe_id=cwe_id)}

    @classmethod
    def _build_remediation_playbook(cls, *, vuln_type: str, cwe_id: Optional[str]) -> List[str]:
        """Actionable developer fix steps."""
        if "sql" in vuln_type:
            return [
                "Migrate all raw SQL concatenations to Parameterized Queries / Prepared Statements.",
                "Use modern ORM frameworks with strict typed parameter bindings.",
                "Apply principle of least privilege to database user accounts.",
            ]
        elif "xss" in vuln_type:
            return [
                "Implement context-aware HTML / JavaScript output encoding (e.g. DOMPurify, OWASP Java Encoder).",
                "Enforce a strict Content Security Policy (CSP) with `script-src 'self'` and nonce protection.",
                "Set `HttpOnly` and `SameSite=Strict` flags on all authentication cookies.",
            ]
        elif "ssrf" in vuln_type:
            return [
                "Implement a strict DNS and IP whitelist for outbound request handlers.",
                "Block RFC 1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local (169.254.169.254).",
                "Disable unused URL schemes (e.g. `gopher://`, `dict://`, `file://`).",
            ]
        elif "auth" in vuln_type or "idor" in vuln_type:
            return [
                "Implement server-side authorization checks on every state-changing and data-retrieval route.",
                "Validate that the authenticated session owner matches the requested object identifier.",
                "Adopt centralized middleware for RBAC / ABAC policy enforcement.",
            ]
        else:
            return [
                "Implement strict input validation and type checking on all request parameters.",
                "Remove sensitive artifacts, backups, and debug configurations from web-accessible directories.",
                "Follow OWASP Top 10 and secure development lifecycle (SDLC) best practices.",
            ]
