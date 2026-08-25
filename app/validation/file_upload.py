"""File Upload Validation Engine (V5 §16, V4 §84).

Tests file upload security via non-malicious controlled test files.
Pipeline:
    Upload endpoint → file type validation → storage behavior
    → execution behavior → access control → controlled canary

Safety:
    - Uses only non-malicious marker files (.txt, .html with canary)
    - Never uploads actual malware, shells, or backdoors
    - Checks for dangerous acceptance rather than exploiting it
"""

import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("validator.file_upload")


def _make_canary() -> str:
    return f"BH-UPLOAD-{secrets.token_hex(4).upper()}"


# Test file definitions — all benign content
UPLOAD_TEST_FILES = [
    {
        "name": "test_image.php",
        "content": b"<?php echo 'BH_CANARY'; ?>",
        "content_type": "image/jpeg",
        "technique": "extension_bypass_php",
        "description": "PHP file disguised as JPEG (Content-Type mismatch)",
        "risk": "HIGH",
    },
    {
        "name": "test.php.jpg",
        "content": b"<?php echo 'BH_CANARY'; ?>",
        "content_type": "image/jpeg",
        "technique": "double_extension",
        "description": "Double extension bypass (file.php.jpg)",
        "risk": "HIGH",
    },
    {
        "name": "test.svg",
        "content": b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("BH_XSS_CANARY")</script></svg>',
        "content_type": "image/svg+xml",
        "technique": "svg_xss",
        "description": "SVG with embedded JavaScript",
        "risk": "MEDIUM",
    },
    {
        "name": "test.html",
        "content": b"<html><body><script>document.write('BH_CANARY')</script></body></html>",
        "content_type": "text/html",
        "technique": "html_upload",
        "description": "HTML file with JavaScript (stored XSS vector)",
        "risk": "MEDIUM",
    },
    {
        "name": "..%2F..%2Ftest.txt",
        "content": b"BH_PATH_TRAVERSAL_CANARY",
        "content_type": "text/plain",
        "technique": "path_traversal_filename",
        "description": "Path traversal in filename",
        "risk": "HIGH",
    },
    {
        "name": "test.txt",
        "content": b"BH_SAFE_UPLOAD_TEST",
        "content_type": "application/x-php",
        "technique": "content_type_confusion",
        "description": "Text file with PHP content-type (Content-Type confusion)",
        "risk": "MEDIUM",
    },
    {
        "name": "test.phtml",
        "content": b"<?php echo 'BH_CANARY'; ?>",
        "content_type": "application/octet-stream",
        "technique": "alternative_php_ext",
        "description": "Alternative PHP extension (.phtml)",
        "risk": "HIGH",
    },
    {
        "name": "test.jsp",
        "content": b'<%= "BH_CANARY" %>',
        "content_type": "application/octet-stream",
        "technique": "jsp_upload",
        "description": "JSP file upload test",
        "risk": "HIGH",
    },
    {
        "name": "test.aspx",
        "content": b'<%@ Page Language="C#" %><%= "BH_CANARY" %>',
        "content_type": "application/octet-stream",
        "technique": "aspx_upload",
        "description": "ASPX file upload test",
        "risk": "HIGH",
    },
]

# Common upload form field names
UPLOAD_FIELD_NAMES = [
    "file", "upload", "attachment", "document", "image",
    "photo", "avatar", "picture", "media", "data",
]


@dataclass
class FileUploadCandidate:
    url: str
    technique: str
    filename: str
    confidence: str = "OBSERVED"
    evidence: dict = field(default_factory=dict)


class FileUploadValidator:
    """Controlled File Upload security validator (V5 §16, V4 §84).

    Policy: SAFE, CONTROLLED, NON-DESTRUCTIVE.
    Uses harmless marker files — never actual exploitation payloads.
    """

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    async def validate_url(
        self,
        url: str,
        *,
        headers: Optional[dict] = None,
        field_name: Optional[str] = None,
    ) -> List[FileUploadCandidate]:
        """Test upload endpoint for dangerous file acceptance."""
        candidates: List[FileUploadCandidate] = []
        canary = _make_canary()

        # Determine upload field name
        field_names = [field_name] if field_name else UPLOAD_FIELD_NAMES

        for test_file in UPLOAD_TEST_FILES:
            content = test_file["content"].replace(b"BH_CANARY", canary.encode())

            for fname in field_names:
                candidate = await self._test_upload(
                    url, fname, test_file["name"], content,
                    test_file["content_type"], test_file["technique"],
                    test_file["description"], test_file["risk"],
                    canary, headers,
                )
                if candidate:
                    candidates.append(candidate)
                    break  # One confirmed per technique is enough

        logger.info("File upload validation: %d candidates on %s", len(candidates), url)
        return candidates

    async def _test_upload(
        self,
        url: str,
        field_name: str,
        filename: str,
        content: bytes,
        content_type: str,
        technique: str,
        description: str,
        risk: str,
        canary: str,
        headers: Optional[dict],
    ) -> Optional[FileUploadCandidate]:
        """Attempt to upload a controlled test file and analyze the response."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True, verify=False
            ) as client:
                files = {field_name: (filename, content, content_type)}
                resp = await client.post(url, files=files, headers=headers or {})

                body = resp.text.lower()

                # Successful upload indicators
                accepted = False
                upload_indicators = [
                    "uploaded", "success", "file saved", "upload complete",
                    "stored", "accepted", "berhasil", "tersimpan",
                ]
                rejection_indicators = [
                    "not allowed", "invalid", "rejected", "forbidden",
                    "unsupported", "blocked", "ditolak", "tidak diizinkan",
                    "file type", "extension",
                ]

                if resp.status_code in (200, 201, 204):
                    if any(ind in body for ind in upload_indicators):
                        accepted = True
                    elif not any(ind in body for ind in rejection_indicators):
                        # 200 without explicit rejection could mean accepted
                        accepted = True

                if accepted:
                    # Check if response contains a URL to the uploaded file
                    upload_url = self._extract_upload_url(resp.text, url)

                    # If we can find the uploaded file, check if it's executable
                    executable = False
                    if upload_url:
                        executable = await self._check_execution(client, upload_url, canary)

                    confidence = "CONFIRMED" if executable else "VALIDATED"
                    response_hash = hashlib.sha256(resp.text.encode()).hexdigest()[:16]

                    return FileUploadCandidate(
                        url=url,
                        technique=technique,
                        filename=filename,
                        confidence=confidence,
                        evidence={
                            "description": description,
                            "risk_level": risk,
                            "field_name": field_name,
                            "filename_sent": filename,
                            "content_type_sent": content_type,
                            "status_code": resp.status_code,
                            "response_hash": response_hash,
                            "file_accepted": True,
                            "file_executable": executable,
                            "upload_url": upload_url or "not_found",
                            "canary_token": canary,
                        },
                    )

        except Exception as exc:
            logger.debug("File upload test failed for %s: %s", url, exc)

        return None

    async def _check_execution(
        self,
        client: httpx.AsyncClient,
        upload_url: str,
        canary: str,
    ) -> bool:
        """Check if uploaded file is served back and/or executed."""
        try:
            resp = await client.get(upload_url)
            if canary in resp.text:
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _extract_upload_url(response_text: str, base_url: str) -> Optional[str]:
        """Try to extract the URL where the uploaded file is stored."""
        import re
        # Common patterns for upload responses
        patterns = [
            r'"(?:url|path|file_url|location|src)"\s*:\s*"([^"]+)"',
            r'(?:href|src)=["\']([^"\']*(?:upload|file|media|storage)[^"\']*)',
        ]
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                found_url = match.group(1)
                if found_url.startswith("http"):
                    return found_url
                elif found_url.startswith("/"):
                    from urllib.parse import urlparse
                    parsed = urlparse(base_url)
                    return f"{parsed.scheme}://{parsed.netloc}{found_url}"
        return None


file_upload_validator = FileUploadValidator()
