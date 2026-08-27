from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.artifacts.csv_parser import CsvDataParser
from app.artifacts.sanitizer import ArtifactSanitizer
from app.artifacts.sql_parser import SqlDumpParser
from app.core.config import ARTIFACTS_DIR, QUARANTINE_DIR, STORAGE_DIR
from app.models.models import Artifact, CredentialArtifact, Identity
from app.scanners.base import ScanContext

logger = logging.getLogger("artifacts.engine")


def get_investigation_dirs(scan_id: str) -> Dict[str, Path]:
    """Generates and ensures the full standardized directory structure for an investigation."""
    base = STORAGE_DIR / "investigations" / scan_id
    dirs = {
        "root": base,
        "evidence": base / "evidence",
        "files": base / "files",
        "extracted": base / "extracted",
        "requests": base / "requests",
        "responses": base / "responses",
        "screenshots": base / "screenshots",
        "exports": base / "exports",
        "report": base / "report",
    }
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)
    return dirs


class DocumentClassifier:
    """Classifies discovered artifacts into security classifications and categories (Requirement §20)."""

    NIK_PATTERN = re.compile(r"\b[1-9]\d{15}\b")  # Indonesian NIK 16 digits
    PASSPORT_PATTERN = re.compile(r"\b[A-Z][0-9]{7,8}\b")
    PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
    CREDIT_CARD_PATTERN = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")
    NPWP_PATTERN = re.compile(r"\b\d{2}\.\d{3}\.\d{3}\.\d{1}-\d{3}\.\d{3}\b")

    @classmethod
    def classify(cls, filename: str, content_text: str = "", file_type: str = "") -> Tuple[str, str, List[str]]:
        """
        Returns (classification, category, detected_tags)
        Classifications: PUBLIC, INTERNAL, CONFIDENTIAL, SENSITIVE, HIGHLY_SENSITIVE
        """
        fn_lower = filename.lower()
        tags = []

        # Unix passwd/shadow files -> HIGHLY_SENSITIVE
        if "passwd" in fn_lower or "shadow" in fn_lower:
            tags.append("os_security_file")
            return "HIGHLY_SENSITIVE", "credentials", tags

        # 1. Private keys & secrets -> HIGHLY_SENSITIVE
        if cls.PRIVATE_KEY_PATTERN.search(content_text) or any(k in fn_lower for k in ("id_rsa", ".pem", ".key", "private_key")):
            tags.append("private_key")
            return "HIGHLY_SENSITIVE", "private_keys", tags

        # 2. Environment / Token / API credentials -> HIGHLY_SENSITIVE
        if ".env" in fn_lower or any(sk in content_text.upper() for sk in ("AWS_SECRET", "JWT_SECRET", "DB_PASSWORD", "PRIVATE_KEY")):
            tags.append("configuration_secret")
            if "jwt" in content_text.lower():
                tags.append("jwt_secret")
            if "aws" in content_text.lower():
                tags.append("cloud_credential")
            return "HIGHLY_SENSITIVE", "credentials", tags

        # 3. Identity Documents (KTP, KK, Passport, Biodata) -> HIGHLY_SENSITIVE
        if any(id_kw in fn_lower for id_kw in ("ktp", "kartu_keluarga", "kk", "passport", "paspor", "biodata", "sim", "ijazah")):
            tags.append("identity_document")
            if "ktp" in fn_lower or cls.NIK_PATTERN.search(content_text):
                tags.append("ktp_nik")
            if "kk" in fn_lower:
                tags.append("kartu_keluarga")
            return "HIGHLY_SENSITIVE", "identity_documents", tags

        if cls.NIK_PATTERN.search(content_text):
            tags.append("nik_pattern_matched")
            return "HIGHLY_SENSITIVE", "identity_documents", tags

        # 4. Financial Records (Credit Card, Bank Statements, Invoices, NPWP) -> SENSITIVE / CONFIDENTIAL
        if cls.CREDIT_CARD_PATTERN.search(content_text) or any(fk in fn_lower for fk in ("gaji", "salary", "rekening", "bank", "credit_card", "financial", "ledger")):
            tags.append("financial_record")
            if cls.CREDIT_CARD_PATTERN.search(content_text):
                tags.append("pci_cardholder_data")
            return "HIGHLY_SENSITIVE", "financial_records", tags

        if cls.NPWP_PATTERN.search(content_text) or "npwp" in fn_lower:
            tags.append("tax_identification")
            return "CONFIDENTIAL", "financial_records", tags

        # 5. Database Dumps -> SENSITIVE
        if file_type in ("sql_dump", "backup_sql", "sql", "db_dump") or fn_lower.endswith((".sql", ".dump", ".bak", ".sqlite")):
            tags.append("database_dump")
            if any(pw in content_text.lower() for pw in ("password", "passwd", "user_pass", "$2y$", "$argon2")):
                tags.append("password_hashes")
                return "HIGHLY_SENSITIVE", "database", tags
            return "SENSITIVE", "database", tags

        # 6. Personal Documents / Employee Records / Customer PII -> CONFIDENTIAL
        if any(pk in fn_lower for pk in ("employee", "karyawan", "customer", "pelanggan", "user_list", "kontak")):
            tags.append("personal_documents")
            return "CONFIDENTIAL", "personal_documents", tags

        # 7. Server / Git Configs -> INTERNAL
        if any(ck in fn_lower for ck in (".git", "web.config", "server.xml", "nginx.conf", "httpd.conf", "config.php")):
            tags.append("server_configuration")
            return "INTERNAL", "configuration_secrets", tags

        # 8. Public Files
        if any(pub in fn_lower for pub in ("robots.txt", "sitemap.xml", "security.txt", ".css", ".js", "favicon", ".html", "index.html", ".svg", ".png", ".jpg")):
            tags.append("public_asset")
            return "PUBLIC", "generic", tags


        return "INTERNAL", "generic", tags


class ArtifactEngine:
    """Central orchestrator for artifact acquisition, quarantine, classification, and intelligence extraction."""

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
        Quarantines, hashes, classifies, parses, and extracts structured intelligence from raw artifact content.
        """
        if not content_bytes:
            return None

        # Hard cap raw storage to 5MB per artifact for memory and disk safety
        max_bytes = 5 * 1024 * 1024
        if len(content_bytes) > max_bytes:
            content_bytes = content_bytes[:max_bytes]

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

        # 2. Write to Standardized Investigation Directory & Quarantine Storage
        inv_dirs = get_investigation_dirs(ctx.scan_id)
        safe_name = f"{sha256[:12]}_{filename}"
        quarantine_file = QUARANTINE_DIR / safe_name
        artifact_file = inv_dirs["files"] / safe_name

        try:
            quarantine_file.write_bytes(content_bytes)
            artifact_file.write_bytes(content_bytes)
        except Exception as exc:
            logger.error("Failed to write artifact file to disk: %s", exc)

        # 3. Static Parsing, Decoding & Document Classification
        text_content = ""
        try:
            text_content = content_bytes.decode("utf-8", errors="ignore")
        except Exception:
            text_content = ""

        # Run Document Classification
        classification, category, detected_tags = DocumentClassifier.classify(
            filename=filename,
            content_text=text_content,
            file_type=file_type,
        )

        schema_data: Dict[str, Any] = {}
        extracted_entities: Dict[str, Any] = {"detected_tags": detected_tags}
        preview_data: Dict[str, Any] = {}
        record_count = 0

        # Specialized Parsers based on file type
        if file_type in ("sql_dump", "backup_sql", "sql", "db_dump") or filename.lower().endswith((".sql", ".dump", ".bak")):
            file_type = "sql_dump"
            mime_type = "application/x-sql"
            category = "database"
            parsed_sql = SqlDumpParser.parse(text_content)
            record_count = parsed_sql.get("total_records_estimated", 0)
            schema_data = {
                "vendor": parsed_sql["vendor"],
                "database_name": parsed_sql["database_name"],
                "tables": parsed_sql["tables"],
                "total_tables": parsed_sql["total_tables"],
                "total_records_estimated": record_count,
            }
            extracted_entities.update({
                "users": parsed_sql["extracted_users"],
                "hashes": parsed_sql["extracted_hashes"],
                "sensitive_fields": parsed_sql["sensitive_fields"],
            })

            # Build structured sanitized preview (Requirement §19)
            preview_tables = []
            for tbl_info in parsed_sql["tables"][:5]:
                tname = tbl_info.get("name", "table")
                cols = tbl_info.get("columns", [])
                sample_rows = [ArtifactSanitizer.sanitize_record(r) for r in tbl_info.get("sample_records", [])[:15]]
                preview_tables.append({
                    "name": tname,
                    "columns": cols,
                    "row_count": tbl_info.get("row_count", len(sample_rows)),
                    "sample_records": sample_rows,
                })
            preview_data = {
                "format": "database_tables",
                "database_name": parsed_sql.get("database_name") or "main_db",
                "tables": preview_tables,
            }

            # Upsert Credential Artifacts
            for h in parsed_sql["extracted_hashes"][:50]:
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
            for u in parsed_sql["extracted_users"][:50]:
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
            record_count = parsed_csv.get("row_count", 0)
            schema_data = {
                "delimiter": parsed_csv["delimiter"],
                "headers": parsed_csv["headers"],
                "row_count": record_count,
                "column_count": parsed_csv["column_count"],
                "pii_headers": parsed_csv["pii_headers"],
            }
            extracted_entities.update({
                "has_pii": parsed_csv["has_pii"],
                "pii_headers": parsed_csv["pii_headers"],
            })
            # Build sanitized CSV sample rows
            sanitized_rows = [ArtifactSanitizer.sanitize_record(r) for r in parsed_csv.get("sample_rows", [])[:25]]
            preview_data = {
                "format": "csv_table",
                "headers": parsed_csv.get("headers", []),
                "rows": sanitized_rows,
                "total_rows": record_count,
            }

        elif file_type in ("json", "json_export") or filename.lower().endswith(".json"):
            file_type = "json"
            mime_type = "application/json"
            try:
                parsed_json = json.loads(text_content)
                if isinstance(parsed_json, list):
                    record_count = len(parsed_json)
                    sample = [ArtifactSanitizer.sanitize_record(r) if isinstance(r, dict) else r for r in parsed_json[:20]]
                    preview_data = {"format": "json_array", "total_records": record_count, "sample": sample}
                elif isinstance(parsed_json, dict):
                    record_count = len(parsed_json.keys())
                    preview_data = {"format": "json_object", "total_keys": record_count, "keys": list(parsed_json.keys())[:30]}
                schema_data = {"type": type(parsed_json).__name__, "record_count": record_count}
            except Exception:
                pass

        elif file_type in ("env_file", "env") or ".env" in filename.lower():
            file_type = "env_file"
            mime_type = "text/plain"
            category = "credentials"
            env_keys: Dict[str, str] = {}
            sensitive_keys: List[str] = []
            for line in text_content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k_clean = k.strip()
                    v_clean = v.strip().strip("'\"")
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

            record_count = len(env_keys)
            schema_data = {
                "total_keys": record_count,
                "sensitive_keys": sensitive_keys,
                "parsed_variables": env_keys,
            }
            extracted_entities.update({
                "sensitive_keys_count": len(sensitive_keys),
                "has_db_creds": any("DB" in k.upper() for k in sensitive_keys),
                "has_jwt_secret": any("JWT" in k.upper() for k in sensitive_keys),
            })
            preview_data = {
                "format": "key_value",
                "variables": env_keys,
            }

        elif file_type in ("passwd_file", "passwd") or "passwd" in filename.lower():
            file_type = "passwd_file"
            mime_type = "text/plain"
            category = "credentials"
            real_users = []
            passwd_lines = [l for l in text_content.strip().splitlines() if ":" in l and not l.startswith("#")]
            for line in passwd_lines:
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        uid = int(parts[2])
                        real_users.append({
                            "username": parts[0],
                            "uid": uid,
                            "gid": int(parts[3]),
                            "home": parts[5],
                            "shell": parts[6],
                        })
                    except (ValueError, IndexError):
                        pass

            record_count = len(passwd_lines)
            schema_data = {
                "total_entries": record_count,
                "real_users": real_users,
            }
            extracted_entities.update({
                "users": [{"identifier": u["username"], "table": "passwd", "column": "username"} for u in real_users],
                "hashes": [],
            })
            preview_data = {
                "format": "passwd_users",
                "real_users": real_users,
            }

            # Upsert Identity entities for users with uid >= 1000 or root
            for u in real_users:
                if u["uid"] >= 1000 or u["username"] == "root":
                    db.add(Identity(
                        scan_id=ctx.scan_id,
                        asset_id=asset_id,
                        username=u["username"],
                        email=None,
                        role="admin" if u["username"] == "root" or "admin" in u["username"].lower() else "user",
                        source_type="passwd_file",
                        metadata_={"uid": u["uid"], "gid": u["gid"], "home": u["home"], "shell": u["shell"]},
                    ))

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
            classification=classification,
            category=category,
            record_count=record_count,
            source=url,
            is_redacted=True,
            preview_data=preview_data,
            schema_data=schema_data,
            extracted_entities=extracted_entities,
            metadata_={
                "url": url,
                "quarantine_verified": True,
                "sanitized_preview_available": bool(preview_data),
                "detected_tags": detected_tags,
            },
        )
        db.add(artifact)
        await db.commit()

        # Emit structured telemetry event
        await ctx.emit(
            "artifact.discovered",
            f"Artifact Discovered [{classification}]: {filename} ({category}, {size_bytes} bytes, SHA-256: {sha256[:12]}...)",
            artifact_id=artifact.id,
            filename=filename,
            file_type=file_type,
            classification=classification,
            category=category,
            record_count=record_count,
            sha256=sha256,
            size_bytes=size_bytes,
            severity="error" if classification in ("HIGHLY_SENSITIVE", "SENSITIVE") else "info",
        )

        return artifact

    @classmethod
    async def reprocess_and_sync_scan_artifacts(
        cls,
        db: AsyncSession,
        scan_id: str,
    ) -> list[Artifact]:
        """
        Auto-heal, synchronize, and retroactively reprocess artifacts for a scan (§27).
        Ensures existing historical artifacts with 0 bytes or unparsed schemas/counts
        are parsed, classified, and populated with previews, size, and records.
        Also inspects findings for any leaked files or schemas not yet registered as artifacts.
        """
        from app.models.models import Finding
        dirs = get_investigation_dirs(scan_id)
        classifier = DocumentClassifier()

        # 1. Fetch all artifacts for this scan
        stmt = select(Artifact).where(Artifact.scan_id == scan_id)
        artifacts = list((await db.execute(stmt)).scalars().all())

        # 2. Fetch all findings for this scan
        findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
        findings = list((await db.execute(findings_stmt)).scalars().all())

        modified = False

        # 3. Check existing artifacts for missing sizes or empty previews
        for art in artifacts:
            content_bytes = None
            # Check storage path
            if art.storage_path and os.path.isfile(art.storage_path):
                try:
                    with open(art.storage_path, "rb") as f:
                        content_bytes = f.read()
                except Exception:
                    content_bytes = None
            # Check quarantine path
            if not content_bytes and art.quarantine_path and os.path.isfile(art.quarantine_path):
                try:
                    with open(art.quarantine_path, "rb") as f:
                        content_bytes = f.read()
                except Exception:
                    content_bytes = None

            # Check if linked finding or matching finding has evidence content
            if not content_bytes:
                for f in findings:
                    fn_low = (art.filename or "").lower()
                    ft_low = (art.file_type or "").lower()
                    f_title = (f.title or "").lower()
                    f_url = (getattr(f, "endpoint_url", None) or (f.evidence.get("url") if isinstance(f.evidence, dict) else "") or "").lower()
                    f_type = (f.finding_type or "").lower()

                    matches_finding = (
                        f.id == art.finding_id
                        or (fn_low and fn_low in f_title)
                        or (fn_low and fn_low in f_url)
                        or ("sql" in ft_low and ("sql" in f_type or "sql" in f_title))
                        or ("csv" in ft_low and ("csv" in f_type or "csv" in f_title))
                        or ("passwd" in ft_low and ("passwd" in f_title or "lfi" in f_type or "passwd" in str(f.evidence).lower()))
                        or (f.evidence and (
                            (art.filename and art.filename in str(f.evidence))
                            or (art.sha256_hash and art.sha256_hash in str(f.evidence))
                        ))
                    )
                    if matches_finding:
                        ev = f.evidence if isinstance(f.evidence, dict) else {}
                        cand = ev.get("body_sample") or ev.get("response_body") or ev.get("passwd_content")
                        if not cand and "files_read" in ev and isinstance(ev["files_read"], dict):
                            for fk, fi in ev["files_read"].items():
                                if isinstance(fi, dict) and fi.get("content"):
                                    if art.filename in fi.get("file", "") or fk in art.filename:
                                        cand = fi.get("content")
                                        break
                        if cand:
                            content_bytes = cand.encode("utf-8", errors="ignore") if isinstance(cand, str) else cand
                            break

            # If we obtained content_bytes, update the artifact
            if content_bytes and (art.size_bytes == 0 or not art.preview_data or art.category in ("generic", "", None)):
                art.size_bytes = len(content_bytes)
                content_text = content_bytes.decode("utf-8", errors="ignore")
                classification, category, tags = classifier.classify(art.filename, content_text, art.file_type)
                art.classification = classification
                art.category = category

                # Ensure saved to storage if missing
                if not art.storage_path or not os.path.isfile(art.storage_path):
                    safe_fn = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", art.filename)
                    out_path = dirs["files"] / safe_fn
                    try:
                        with open(out_path, "wb") as f_out:
                            f_out.write(content_bytes)
                        art.storage_path = str(out_path)
                    except Exception:
                        pass

                # Parse depending on type
                fn_lower = art.filename.lower()
                if "passwd" in fn_lower or art.file_type == "passwd_file":
                    passwd_lines = [l for l in content_text.strip().splitlines() if ":" in l and not l.startswith("#")]
                    real_users = []
                    for line in passwd_lines:
                        parts = line.split(":")
                        if len(parts) >= 7:
                            try:
                                uid = int(parts[2])
                                real_users.append({
                                    "username": parts[0],
                                    "uid": uid,
                                    "gid": int(parts[3]),
                                    "home": parts[5],
                                    "shell": parts[6],
                                })
                            except (ValueError, IndexError):
                                pass
                    art.schema_data = {"type": "unix_passwd", "total_entries": len(passwd_lines), "real_users": real_users}
                    art.preview_data = {
                        "columns": ["Username", "UID", "GID", "Home Directory", "Shell"],
                        "rows": [
                            {"Username": u["username"], "UID": str(u["uid"]), "GID": str(u["gid"]), "Home Directory": u["home"], "Shell": u["shell"]}
                            for u in real_users[:50]
                        ]
                    }
                    art.record_count = len(real_users)
                elif fn_lower.endswith(".csv") or "csv" in art.file_type:
                    rows = []
                    lines = content_text.splitlines()[:50]
                    for l in lines:
                        if "," in l or ";" in l:
                            sep = ";" if ";" in l else ","
                            rows.append([cell.strip() for cell in l.split(sep)])
                    if rows:
                        cols = rows[0]
                        data_rows = [dict(zip(cols, r)) for r in rows[1:30]]
                        art.preview_data = {"columns": cols, "rows": data_rows}
                        art.record_count = len(content_text.splitlines()) - 1
                elif fn_lower.endswith(".sql") or "sql" in art.file_type:
                    parsed_sql = SqlDumpParser.parse(content_text, max_sample_rows=50)
                    art.schema_data = parsed_sql
                    art.extracted_entities = {
                        "users": parsed_sql.get("extracted_users", []),
                        "hashes": parsed_sql.get("extracted_hashes", []),
                        "sensitive_fields": parsed_sql.get("sensitive_fields", []),
                    }
                    preview_tables = []
                    for t in parsed_sql.get("tables", [])[:20]:
                        preview_tables.append({
                            "name": t.get("name"),
                            "columns": [c.get("name") if isinstance(c, dict) else str(c) for c in t.get("columns", [])],
                            "sample_rows": t.get("sample_rows", [])[:20],
                            "primary_key": t.get("primary_key"),
                        })
                    art.preview_data = {
                        "format": "database_tables",
                        "vendor": parsed_sql.get("vendor") or "MySQL / MariaDB",
                        "database_name": parsed_sql.get("database_name") or "main_db",
                        "tables": preview_tables,
                        "columns": preview_tables[0]["columns"] if preview_tables else ["Table", "Columns"],
                        "rows": preview_tables[0]["sample_rows"] if preview_tables else [],
                        "extracted_users": parsed_sql.get("extracted_users", [])[:50],
                        "extracted_hashes": parsed_sql.get("extracted_hashes", [])[:50],
                        "sensitive_fields": parsed_sql.get("sensitive_fields", [])[:50],
                        "raw_sample": "\n".join(content_text.splitlines()[:50]),
                    }
                    art.record_count = parsed_sql.get("total_records_estimated") or len(parsed_sql.get("tables", [])) or len(content_text.splitlines())
                elif fn_lower.endswith(".env") or "env" in art.file_type:
                    env_pairs = []
                    for l in content_text.splitlines():
                        if "=" in l and not l.strip().startswith("#"):
                            k, _, v = l.partition("=")
                            env_pairs.append({"Variable": k.strip(), "Value": v.strip()[:3] + "********" if len(v.strip()) > 3 else "********"})
                    art.preview_data = {"columns": ["Variable", "Value"], "rows": env_pairs[:40]}
                    art.record_count = len(env_pairs)
                else:
                    lines = [l for l in content_text.splitlines() if l.strip()]
                    art.preview_data = {
                        "columns": ["Line", "Content"],
                        "rows": [{"Line": idx + 1, "Content": l[:140]} for idx, l in enumerate(lines[:30])]
                    }
                    art.record_count = len(lines)

                art.state = "EVIDENCE_READY"
                modified = True

        # 4. Check findings for unmaterialized files/data
        existing_filenames = {a.filename.lower() for a in artifacts}
        for f in findings:
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            if "files_read" in ev and isinstance(ev["files_read"], dict):
                for fk, fi in ev["files_read"].items():
                    if isinstance(fi, dict) and fi.get("content"):
                        fn = fi.get("file", "").split("/")[-1] or f"lfi_{fk}.txt"
                        if fn.lower() not in existing_filenames:
                            content = fi["content"]
                            c_bytes = content.encode("utf-8", errors="ignore")
                            c_sha = hashlib.sha256(c_bytes).hexdigest()
                            c_tier, c_cat, c_tags = classifier.classify(fn, content, "passwd_file" if "passwd" in fn.lower() else "generic")
                            safe_fn = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", fn)
                            f_path = dirs["files"] / safe_fn
                            try:
                                with open(f_path, "wb") as out_f:
                                    out_f.write(c_bytes)
                            except Exception:
                                f_path = None
                            new_art = Artifact(
                                scan_id=scan_id,
                                asset_id=f.asset_id,
                                finding_id=f.id,
                                filename=fn,
                                file_type="passwd_file" if "passwd" in fn.lower() else "text_file",
                                mime_type="text/plain",
                                size_bytes=len(c_bytes),
                                sha256_hash=c_sha,
                                storage_path=str(f_path) if f_path else None,
                                quarantine_path=str(f_path) if f_path else None,
                                state="EVIDENCE_READY",
                                classification=c_tier,
                                category=c_cat,
                                record_count=len(content.splitlines()),
                                source=fi.get("url") or getattr(f, "endpoint_url", None) or (f.evidence.get("url") if isinstance(f.evidence, dict) else None),
                                is_redacted=True,
                                preview_data={
                                    "columns": ["Line", "Content"],
                                    "rows": [{"Line": idx + 1, "Content": l[:140]} for idx, l in enumerate(content.splitlines()[:30])]
                                },
                                schema_data={},
                                extracted_entities={},
                                metadata_={"detected_tags": c_tags, "auto_healed": True},
                            )
                            db.add(new_art)
                            artifacts.append(new_art)
                            existing_filenames.add(fn.lower())
                            modified = True

        if modified:
            try:
                await db.commit()
            except Exception as commit_err:
                logger.debug("Reprocess commit notice: %s", commit_err)

        return artifacts

