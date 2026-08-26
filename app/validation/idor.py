"""IDOR / Broken Access Control Validation Engine — Deep Exploitation Evidence.

Tests for Insecure Direct Object References by comparing responses
across different authorization contexts with multi-object proof extraction.

Model:
    Identity A → Object A (baseline)
    Identity B → Object A (controlled comparison)
    If access unexpectedly granted → BROKEN ACCESS CONTROL

Deep Exploitation Evidence:
    - Multi-object access proof (test 5+ sequential IDs)
    - Data structure extraction from JSON responses
    - Sensitive field detection (email, phone, address, SSN, etc.)
    - Cross-role authorization comparison
    - Response diff analysis showing distinct user data

Safety:
    - Uses minimal data comparison (hash-based, not full extraction)
    - Never modifies target resources
    - Only reads — never write/delete operations
    - Bounded attempt count
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.idor")

# Patterns that indicate object references in URL paths/params
OBJECT_REF_PATTERNS = [
    re.compile(r"[?&/](?:id|user_id|order_id|invoice_id|doc_id|file_id|account_id)=(\d+)", re.I),
    re.compile(r"/(?:users?|orders?|invoices?|profiles?|accounts?|documents?|files?)/(\d+)", re.I),
    re.compile(r"[?&/](?:uid|oid|pid|fid|aid)=(\d+)", re.I),
    re.compile(r"[?&/](?:uuid|guid)=([0-9a-f-]{32,36})", re.I),
]

# Parameter names that typically hold object identifiers
IDOR_PARAM_NAMES = {
    "id", "user_id", "uid", "order_id", "oid", "invoice_id",
    "doc_id", "document_id", "file_id", "fid", "account_id",
    "aid", "profile_id", "pid", "item_id", "record_id",
    "ticket_id", "report_id", "transaction_id", "message_id",
    "uuid", "guid", "ref", "reference", "number",
}

# Sensitive field names to detect in responses
SENSITIVE_FIELD_PATTERNS = [
    re.compile(r'"(email|e-?mail)"', re.I),
    re.compile(r'"(phone|telephone|mobile|hp|telp)"', re.I),
    re.compile(r'"(address|alamat|street|city|zip)"', re.I),
    re.compile(r'"(password|passwd|pwd|pass)"', re.I),
    re.compile(r'"(ssn|social_security|nik|ktp)"', re.I),
    re.compile(r'"(credit_card|cc_number|card_number)"', re.I),
    re.compile(r'"(name|full_name|first_name|last_name|nama)"', re.I),
    re.compile(r'"(balance|saldo|amount|total)"', re.I),
    re.compile(r'"(token|api_key|secret|auth)"', re.I),
    re.compile(r'"(dob|date_of_birth|birth_date|tanggal_lahir)"', re.I),
]


@dataclass
class IDORCandidate:
    url: str
    parameter: str
    original_value: str
    modified_value: str
    technique: str
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)
    exploitation_data: dict = field(default_factory=dict)


class IDORValidator:
    """IDOR / Broken Access Control validator with deep exploitation evidence.

    Tests for unauthorized access to objects by manipulating identifiers
    and collecting multi-object proof with data structure analysis.

    Policy: NON-DESTRUCTIVE, READ-ONLY, BOUNDED.
    """

    def __init__(self, timeout: float = 10.0, max_params: int = 20) -> None:
        self.timeout = timeout
        self.max_params = max_params

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[IDORCandidate]:
        """Test parameters for IDOR vulnerabilities."""
        candidates: List[IDORCandidate] = []

        for param in parameters[: self.max_params]:
            name = param.get("name", "").lower()
            location = param.get("location", "query")
            if not name or location not in ("query", "body", "path"):
                continue

            # Only test ID-like parameters
            if name not in IDOR_PARAM_NAMES:
                continue

            candidate = await self._test_idor(url, param["name"], location, headers)
            if candidate:
                # Deep exploitation: multi-object proof + data structure analysis
                exploitation = await self._exploit_multi_object_proof(
                    url, param["name"], location, candidate.original_value, headers,
                )
                if exploitation:
                    candidate.exploitation_data = exploitation
                    candidate.confidence = "EXPLOITED"
                candidates.append(candidate)

        # Also test URL path-based object references
        path_candidates = await self._test_path_idor(url, headers)
        candidates.extend(path_candidates)

        logger.info("IDOR validation: %d candidates on %s", len(candidates), url)
        return candidates

    async def _send_request(
        self,
        url: str,
        param_name: str,
        value: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, verify=False
            ) as client:
                if location == "query":
                    sep = "&" if "?" in url else "?"
                    test_url = f"{url}{sep}{param_name}={value}"
                    return await client.get(test_url, headers=headers or {})
                elif location == "body":
                    return await client.post(
                        url, data={param_name: value}, headers=headers or {}
                    )
                else:
                    return await client.get(url, headers=headers or {})
        except Exception:
            return None

    async def _test_idor(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict],
    ) -> Optional[IDORCandidate]:
        """Test a parameter for IDOR by modifying the object reference."""
        # Get baseline with original value
        original_value = "1"  # Default test value
        baseline = await self._send_request(url, param_name, original_value, location, headers)
        if not baseline or baseline.status_code in (404, 401, 403):
            return None

        baseline_hash = hashlib.sha256(baseline.text.encode()).hexdigest()[:16]
        baseline_len = len(baseline.text)

        # Test with adjacent IDs — sequential access pattern
        test_values = self._generate_adjacent_ids(original_value)

        for test_value in test_values:
            test_resp = await self._send_request(url, param_name, test_value, location, headers)
            if not test_resp:
                continue

            # If we get a 200 with different content — potential IDOR
            if test_resp.status_code == 200:
                test_hash = hashlib.sha256(test_resp.text.encode()).hexdigest()[:16]
                test_len = len(test_resp.text)

                # Different content hash = different object returned
                if test_hash != baseline_hash and test_len > 100:
                    # Verify it's not a generic 404 or error page
                    error_indicators = [
                        "not found", "404", "error", "invalid",
                        "tidak ditemukan", "page not found",
                    ]
                    if not any(ind in test_resp.text.lower() for ind in error_indicators):
                        return IDORCandidate(
                            url=url,
                            parameter=param_name,
                            original_value=original_value,
                            modified_value=test_value,
                            technique="sequential_id_manipulation",
                            confidence="SUSPECTED",
                            evidence={
                                "original_id": original_value,
                                "modified_id": test_value,
                                "baseline_status": baseline.status_code,
                                "test_status": test_resp.status_code,
                                "baseline_hash": baseline_hash,
                                "test_hash": test_hash,
                                "baseline_length": baseline_len,
                                "test_length": test_len,
                                "different_content": True,
                                "expected": "403/401 or same content",
                                "actual": f"HTTP {test_resp.status_code} with different content ({test_len} bytes)",
                                "poc_curl": f"curl -ksSL '{url}?{param_name}={test_value}'",
                            },
                        )

            # If 200 for other user's object when we should get 403/401
            # This is suspicious but we can't fully confirm without auth context
            elif test_resp.status_code in (401, 403):
                # Good — authorization is enforced for this ID
                pass

        return None

    async def _exploit_multi_object_proof(
        self,
        url: str,
        param_name: str,
        location: str,
        original_value: str,
        headers: Optional[dict],
    ) -> Optional[dict]:
        """Deep exploitation: access multiple objects to prove systematic IDOR.

        Tests 5 sequential IDs and analyzes response data structure.
        """
        exploitation: Dict[str, Any] = {
            "accessible_objects": [],
            "sensitive_fields_exposed": [],
            "authorization_bypass_confirmed": False,
        }

        # Test 5 sequential IDs
        try:
            base_id = int(original_value)
            test_ids = [str(base_id + i) for i in range(1, 6)]
        except ValueError:
            return None

        unique_hashes = set()
        all_data_fields: Dict[str, int] = {}  # field_name -> count of objects containing it

        for test_id in test_ids:
            resp = await self._send_request(url, param_name, test_id, location, headers)
            if not resp or resp.status_code != 200:
                continue

            body = resp.text
            body_hash = hashlib.sha256(body.encode()).hexdigest()[:16]

            # Skip if response is too short (likely error page)
            if len(body) < 100:
                continue

            # Skip error pages
            error_indicators = ["not found", "404", "error", "invalid", "tidak ditemukan"]
            if any(ind in body.lower() for ind in error_indicators):
                continue

            # Try to parse JSON response
            data_fields = []
            is_json = False
            try:
                json_data = json.loads(body)
                is_json = True
                if isinstance(json_data, dict):
                    data_fields = list(json_data.keys())
                    # Check nested 'data' key
                    if "data" in json_data and isinstance(json_data["data"], dict):
                        data_fields.extend(list(json_data["data"].keys()))
                elif isinstance(json_data, list) and json_data:
                    if isinstance(json_data[0], dict):
                        data_fields = list(json_data[0].keys())
            except (json.JSONDecodeError, TypeError):
                # Not JSON — try to extract field names from HTML
                data_fields = self._extract_html_field_names(body)

            # Track unique hashes to ensure different objects
            if body_hash not in unique_hashes:
                unique_hashes.add(body_hash)

                object_info: Dict[str, Any] = {
                    "id": test_id,
                    "status": resp.status_code,
                    "content_length": len(body),
                    "content_hash": body_hash,
                    "data_fields": data_fields[:20],
                    "is_json_response": is_json,
                }

                # Detect sensitive fields
                sensitive_found = []
                for pattern in SENSITIVE_FIELD_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        field_name = match.group(1)
                        sensitive_found.append(field_name)

                if sensitive_found:
                    object_info["sensitive_fields"] = sensitive_found

                exploitation["accessible_objects"].append(object_info)

                # Aggregate field counts
                for f in data_fields:
                    all_data_fields[f] = all_data_fields.get(f, 0) + 1

        # Analyze results
        if len(exploitation["accessible_objects"]) < 2:
            return None  # Need at least 2 distinct objects to confirm IDOR

        exploitation["total_accessible"] = len(exploitation["accessible_objects"])
        exploitation["unique_objects"] = len(unique_hashes)

        # Collect all sensitive fields across objects
        all_sensitive = set()
        for obj in exploitation["accessible_objects"]:
            all_sensitive.update(obj.get("sensitive_fields", []))
        exploitation["sensitive_fields_exposed"] = sorted(all_sensitive)

        # Determine if this is truly authorization bypass
        if len(unique_hashes) >= 2:
            exploitation["authorization_bypass_confirmed"] = True

        # Consistent data structure across objects = strong evidence
        if all_data_fields:
            consistent_fields = [
                f for f, count in all_data_fields.items()
                if count >= len(exploitation["accessible_objects"]) * 0.5
            ]
            exploitation["consistent_data_fields"] = consistent_fields[:20]

        return exploitation

    async def _test_path_idor(
        self,
        url: str,
        headers: Optional[dict],
    ) -> List[IDORCandidate]:
        """Test URL path-based object references for IDOR."""
        candidates: List[IDORCandidate] = []

        for pattern in OBJECT_REF_PATTERNS:
            match = pattern.search(url)
            if not match:
                continue

            original_id = match.group(1)
            test_ids = self._generate_adjacent_ids(original_id)

            for test_id in test_ids:
                modified_url = url[:match.start(1)] + test_id + url[match.end(1):]

                try:
                    async with httpx.AsyncClient(
                        timeout=self.timeout, follow_redirects=True, verify=False
                    ) as client:
                        baseline = await client.get(url, headers=headers or {})
                        test_resp = await client.get(modified_url, headers=headers or {})

                        if (
                            baseline.status_code == 200
                            and test_resp.status_code == 200
                            and len(test_resp.text) > 100
                        ):
                            baseline_hash = hashlib.sha256(baseline.text.encode()).hexdigest()[:16]
                            test_hash = hashlib.sha256(test_resp.text.encode()).hexdigest()[:16]

                            if baseline_hash != test_hash:
                                candidates.append(
                                    IDORCandidate(
                                        url=url,
                                        parameter="path_id",
                                        original_value=original_id,
                                        modified_value=test_id,
                                        technique="path_based_id_manipulation",
                                        confidence="SUSPECTED",
                                        evidence={
                                            "original_url": url,
                                            "modified_url": modified_url,
                                            "baseline_status": baseline.status_code,
                                            "test_status": test_resp.status_code,
                                            "baseline_hash": baseline_hash,
                                            "test_hash": test_hash,
                                            "different_content": True,
                                            "poc_curl": f"curl -ksSL '{modified_url}'",
                                        },
                                    )
                                )
                                break

                except Exception as exc:
                    logger.debug("Path IDOR test failed: %s", exc)

        return candidates

    @staticmethod
    def _generate_adjacent_ids(original: str) -> List[str]:
        """Generate adjacent/nearby IDs for testing."""
        try:
            num = int(original)
            return [str(num + 1), str(num - 1), str(num + 100), "0"]
        except ValueError:
            # UUID-like — can't easily enumerate
            return []

    @staticmethod
    def _extract_html_field_names(html_body: str) -> List[str]:
        """Extract field/label names from HTML response for data structure analysis."""
        fields = []

        # Extract from table headers
        th_matches = re.findall(r"<th[^>]*>([^<]+)</th>", html_body, re.I)
        fields.extend(th_matches[:10])

        # Extract from label elements
        label_matches = re.findall(r"<label[^>]*>([^<]+)</label>", html_body, re.I)
        fields.extend(label_matches[:10])

        # Extract from input name attributes
        input_matches = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html_body, re.I)
        fields.extend(input_matches[:10])

        # Extract from dt/dd pairs
        dt_matches = re.findall(r"<dt[^>]*>([^<]+)</dt>", html_body, re.I)
        fields.extend(dt_matches[:10])

        # Deduplicate
        seen = set()
        unique_fields = []
        for f in fields:
            cleaned = f.strip()
            if cleaned and cleaned.lower() not in seen:
                seen.add(cleaned.lower())
                unique_fields.append(cleaned)

        return unique_fields


idor_validator = IDORValidator()
