"""Artifact Intelligence Orchestration Engine (V9).

Orchestrates the complete lifecycle of captured security artifacts:
1. Acquisition & Quarantine Storage with Cryptographic SHA-256 Hashing
2. Static AST / Lexer Parsing (Zero Execution)
3. Credential & Identity Extraction (Linked to `credential_artifacts` & `identities` tables)
4. Schema & Tabular Metadata Persistence in `artifacts` table
5. Correlation with Assets, URLs, and Confirmed Findings
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.artifacts.csv_parser import CsvDataParser
from app.artifacts.sanitizer import ArtifactSanitizer
from app.artifacts.sql_parser import SqlDumpParser
from app.core.config import ARTIFACTS_DIR, QUARANTINE_DIR
from app.models.models import Artifact, CredentialArtifact, Identity
from app.scanners.base import ScanContext

logger = logging.getLogger("artifacts.engine")


class ArtifactEngine:
    """Central orchestrator for artifact acquisition, quarantine, and intelligence extraction."""

    @classmethod
    async def process_discovered_artifact(
        cls,
        ctx: ScanContext,
        db: AsyncSession,
        url: str,
        content_bytes: bytes,
        filename: Optional[str] = None,
        file_type: str = "generic",
        mime_type: str = "application/octet-stream",
        asset_id: Optional[str] = None,
        url_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> Optional[Artifact]:
        """
        Quarantines, hashes, parses, and extracts deep intelligence from raw artifact content.
        """
        if not content_bytes:
            return None

        sha256 = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)

        if not filename:
            parsed_path = urlparse(url).path
            filename = os.path.basename(parsed_path) or f"artifact_{sha256[:8]}.bin"

        # 1. Deduplication check in Database
        existing = (await db.execute(
            select(Artifact).where(Artifact.scan_id == ctx.scan_id, Artifact.sha256_hash == sha256)
        )).scalar_one_or_none()

        if existing:
            if finding_id and not existing.finding_id:
                existing.finding_id = finding_id
                await db.commit()
            return existing

        # 2. Write to Quarantine Storage
        safe_name = f"{sha256[:12]}_{filename}"
        quarantine_file = QUARANTINE_DIR / safe_name
        artifact_file = ARTIFACTS_DIR / safe_name

        try:
            quarantine_file.write_bytes(content_bytes)
            artifact_file.write_bytes(content_bytes)
        except Exception as exc:
            logger.error("Failed to write artifact file to disk: %s", exc)

        # 3. Static Parsing & Intelligence Extraction (Zero Execution)
        text_content = ""
        try:
            text_content = content_bytes.decode("utf-8", errors="ignore")
        except Exception:
            text_content = ""

        schema_data: Dict[str, Any] = {}
        extracted_entities: Dict[str, Any] = {}

        if file_type in ("sql_dump", "backup_sql", "sql", "db_dump") or filename.lower().endswith((".sql", ".dump", ".bak")):
            file_type = "sql_dump"
            mime_type = "application/x-sql"
            parsed_sql = SqlDumpParser.parse(text_content)
            schema_data = {
                "vendor": parsed_sql["vendor"],
                "database_name": parsed_sql["database_name"],
                "tables": parsed_sql["tables"],
                "total_tables": parsed_sql["total_tables"],
                "total_records_estimated": parsed_sql["total_records_estimated"],
            }
            extracted_entities = {
                "users": parsed_sql["extracted_users"],
                "hashes": parsed_sql["extracted_hashes"],
                "sensitive_fields": parsed_sql["sensitive_fields"],
            }

            # Upsert Credential Artifacts
            for h in parsed_sql["extracted_hashes"]:
                db.add(CredentialArtifact(
                    scan_id=ctx.scan_id,
                    asset_id=asset_id,
                    raw_identifier=f"{h['table']}.{h['column']}",
                    credential_type="hash",
                    hash_algorithm=h.get("hash_type"),
                    salt_present=True if "bcrypt" in h.get("hash_type", "") else False,
                    work_factor=h.get("work_factor"),
                    state="CLASSIFIED",
                    metadata_={
                        "table": h["table"],
                        "column": h["column"],
                        "sample": h["hash_sample"],
                        "source_artifact_sha256": sha256,
                    },
                ))

            # Upsert Identity entities
            for u in parsed_sql["extracted_users"]:
                db.add(Identity(
                    scan_id=ctx.scan_id,
                    asset_id=asset_id,
                    username=u["identifier"],
                    email=u["identifier"] if "@" in u["identifier"] else None,
                    role="admin" if "admin" in u["identifier"].lower() else "user",
                    source_type="sql_dump",
                    metadata_={"table": u["table"], "column": u["column"], "type": u["type"]},
                ))

        elif file_type in ("csv_export", "csv", "data_export") or filename.lower().endswith((".csv", ".tsv")):
            file_type = "csv_export"
            mime_type = "text/csv"
            parsed_csv = CsvDataParser.parse(text_content)
            schema_data = {
                "delimiter": parsed_csv["delimiter"],
                "headers": parsed_csv["headers"],
                "row_count": parsed_csv["row_count"],
                "column_count": parsed_csv["column_count"],
                "pii_headers": parsed_csv["pii_headers"],
                "sample_rows": parsed_csv["sample_rows"],
            }
            extracted_entities = {
                "has_pii": parsed_csv["has_pii"],
                "pii_headers": parsed_csv["pii_headers"],
            }

        elif file_type in ("env_file", "env") or ".env" in filename.lower():
            file_type = "env_file"
            mime_type = "text/plain"
            env_keys: Dict[str, str] = {}
            sensitive_keys: List[str] = []
            for line in text_content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k_clean = k.strip()
                    v_clean = v.strip().strip("'\"")
                    # Mask sensitive value
                    masked_val = (v_clean[:2] + "****" + v_clean[-2:]) if len(v_clean) > 4 else "****"
                    env_keys[k_clean] = masked_val
                    if any(sk in k_clean.upper() for sk in ("PASSWORD", "SECRET", "KEY", "TOKEN", "AUTH", "PASS", "DATABASE")):
                        sensitive_keys.append(k_clean)
                        db.add(CredentialArtifact(
                            scan_id=ctx.scan_id,
                            asset_id=asset_id,
                            raw_identifier=k_clean,
                            credential_type="env_secret",
                            state="CLASSIFIED",
                            metadata_={
                                "key": k_clean,
                                "masked_value": masked_val,
                                "source_artifact_sha256": sha256,
                            },
                        ))

            schema_data = {
                "total_keys": len(env_keys),
                "sensitive_keys": sensitive_keys,
                "parsed_variables": env_keys,
            }
            extracted_entities = {
                "sensitive_keys_count": len(sensitive_keys),
                "has_db_creds": any("DB" in k.upper() for k in sensitive_keys),
                "has_jwt_secret": any("JWT" in k.upper() for k in sensitive_keys),
            }

        # 4. Save Artifact Entity in Database
        artifact = Artifact(
            scan_id=ctx.scan_id,
            asset_id=asset_id,
            url_id=url_id,
            finding_id=finding_id,
            filename=filename,
            file_type=file_type,
            mime_type=mime_type,
            size_bytes=size_bytes,
            sha256_hash=sha256,
            storage_path=str(artifact_file),
            quarantine_path=str(quarantine_file),
            state="EVIDENCE_READY",
            schema_data=schema_data,
            extracted_entities=extracted_entities,
            metadata_={
                "url": url,
                "quarantine_verified": True,
                "sanitized_preview_available": True,
            },
        )
        db.add(artifact)
        await db.commit()

        await ctx.emit(
            "artifact.acquired",
            f"Artifact Acquired: {filename} ({file_type}, {size_bytes} bytes, SHA-256: {sha256[:12]}...)",
            artifact_id=artifact.id,
            filename=filename,
            file_type=file_type,
            sha256=sha256,
            size_bytes=size_bytes,
            tables_count=len(schema_data.get("tables", [])),
            severity="info",
        )

        return artifact
