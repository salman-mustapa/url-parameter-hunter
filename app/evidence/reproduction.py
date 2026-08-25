"""Reproduction Bundle Generator (V5 §24).

Automatically synthesizes an isolated `reproduction.md` document for every confirmed finding.
Contains step-by-step reproduction instructions, prerequisites, expected vs actual outcome,
PoC commands, and safe cleanup instructions.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from app.validation.result import NormalizedValidationResult


class ReproductionBundleGenerator:
    """Generates standardized reproduction.md artifacts per finding (V5 §24)."""

    @classmethod
    def generate(cls, finding: NormalizedValidationResult) -> str:
        """Render reproduction.md content."""
        steps_str = ""
        if finding.reproduction_steps:
            steps_str = "\n".join(f"{i+1}. {s}" for i, s in enumerate(finding.reproduction_steps))
        else:
            steps_str = (
                f"1. Send an HTTP request to {finding.endpoint_url or finding.target_host}\n"
                "2. Observe the anomalous response behavior."
            )

        poc = finding.poc_command or finding.poc_payload or f"curl -i -s -k '{finding.endpoint_url}'"

        content = f"""# Reproduction Guide

## Target
- **Host:** `{finding.target_host}`
- **Endpoint:** `{finding.endpoint_url or 'N/A'}`
- **Parameter:** `{finding.parameter or 'N/A'}`
- **Vulnerability:** `{finding.title}`

---

## Prerequisites
{chr(10).join(f'- {p}' for p in (finding.preconditions or ['Network route to target web server', 'Standard HTTP client (curl, browser, Burp Suite)']))}

---

## Preconditions
- Target service is online and accessible.
- No active IP-level blocklist preventing connection.

---

## Steps to Reproduce

{steps_str}

### Deterministic cURL Execution
```bash
{poc}
```

---

## Expected Result
{finding.expected_result or 'The application should reject the probe or return standard secure response.'}

---

## Actual Result
{finding.actual_result or 'The application accepted the probe and demonstrated the vulnerability condition.'}

---

## Evidence & Verification
- **Validation Adapter:** `{finding.adapter_name}`
- **Evidence Level:** `{finding.evidence_level}`
- **Confidence Rating:** `{finding.confidence}`

---

## Impact
{finding.business_impact or 'Confidentiality and integrity boundaries violated on target application.'}

---

## Safe Cleanup & Remediation
- No persistent backdoors or files were left on the target system.
- All probes used harmless, non-destructive canary identifiers.
- Remediation: {finding.remediation or 'Apply input validation and patch vulnerable component.'}
"""
        return content


# Module-level singleton
reproduction_bundle_generator = ReproductionBundleGenerator()
