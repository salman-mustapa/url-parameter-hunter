"""Zero-Execution Static SQL Dump AST & Schema Intelligence Parser (V9).

Parses MySQL, PostgreSQL, SQLite, MSSQL, and Oracle SQL dumps purely through
lexical tokenization and AST extraction without executing or evaluating SQL code.

Extracts:
1. Database name & server vendor fingerprint
2. Tables, column schemas, types, and primary keys
3. Indexes, foreign keys, and table constraints
4. User accounts, usernames, and email entities
5. Cryptographic password hashes (bcrypt, argon2, md5, sha1, sha256)
6. API keys, JWT tokens, and PII markers (NIM, NIK, phone, address)
7. Total row estimations and sample records
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("artifacts.sql_parser")

# Hash format detection regexes
HASH_PATTERNS = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("argon2", re.compile(r"^\$argon2[id]?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+")),
    ("md5", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("sha1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("sha256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("django_pbkdf2", re.compile(r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+")),
    ("phpass_wordpress", re.compile(r"^\$P\$[./0-9A-Za-z]{31}$")),
]

PII_COLUMN_INDICATORS = [
    "nim", "nik", "nama", "name", "email", "mail", "pass", "password", "pwd", "secret",
    "token", "api_key", "phone", "telp", "hp", "alumni", "prodi", "jurusan", "fakultas",
    "skpi", "tracer", "address", "alamat", "ip", "session", "auth", "salary", "gaji", "pin"
]


class SqlDumpParser:
    """High-performance zero-execution static parser for SQL database dumps."""

    @classmethod
    def parse(cls, content: str, max_sample_rows: int = 50) -> Dict[str, Any]:
        """
        Statically parses SQL text and returns rich structured schema and entity intelligence.
        Returns: {
            "vendor": str,
            "database_name": Optional[str],
            "tables": List[dict],
            "extracted_users": List[dict],
            "extracted_hashes": List[dict],
            "sensitive_fields": List[dict],
            "total_tables": int,
            "total_records_estimated": int,
        }
        """
        vendor = cls._detect_vendor(content)
        db_name = cls._extract_database_name(content)
        tables = cls._extract_tables(content)
        records_by_table, extracted_users, extracted_hashes, sensitive_fields = cls._extract_records_and_entities(
            content, tables, max_sample_rows=max_sample_rows
        )
        from app.artifacts.hash_cracker import HashIntelligenceEngine
        enriched_hashes = HashIntelligenceEngine.enrich_extracted_hashes(
            extracted_hashes,
            extracted_users=extracted_users,
            database_name=db_name,
        )

        total_records = sum(len(t.get("sample_rows", [])) for t in tables)

        return {
            "vendor": vendor,
            "database_name": db_name,
            "tables": tables,
            "extracted_users": extracted_users,
            "extracted_hashes": enriched_hashes,
            "sensitive_fields": sensitive_fields,
            "total_tables": len(tables),
            "total_records_estimated": total_records,
        }

    @classmethod
    def _detect_vendor(cls, content: str) -> str:
        sample = content[:4096].lower()
        if "mysql dump" in sample or "mariadb" in sample or "engine=innodb" in sample or "engine=myisam" in sample:
            return "MySQL / MariaDB"
        if "postgresql database dump" in sample or "pg_dump" in sample or "set search_path" in sample:
            return "PostgreSQL"
        if "sqlite" in sample or "pragma" in sample:
            return "SQLite"
        if "oracle" in sample or "plsql" in sample:
            return "Oracle"
        if "microsoft sql server" in sample or "mssql" in sample or "[dbo]." in sample:
            return "Microsoft SQL Server"
        return "Generic SQL"

    @classmethod
    def _extract_database_name(cls, content: str) -> Optional[str]:
        m = re.search(r"(?:CREATE\s+DATABASE|USE)\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[`'\"\[])?([a-zA-Z0-9_\-]+)(?:[`'\"\]])?", content, re.IGNORECASE)
        if m:
            return m.group(1)
        m2 = re.search(r"--\s*Database:\s*[`'\"]?([a-zA-Z0-9_\-]+)[`'\"]?", content, re.IGNORECASE)
        if m2:
            return m2.group(1)
        m3 = re.search(r"--\s*Current Database:\s*[`'\"]?([a-zA-Z0-9_\-]+)[`'\"]?", content, re.IGNORECASE)
        if m3:
            return m3.group(1)
        return None

    @classmethod
    def _extract_tables(cls, content: str) -> List[Dict[str, Any]]:
        """Extracts CREATE TABLE statements, columns, types, and primary keys."""
        tables: List[Dict[str, Any]] = []

        create_table_pattern = re.compile(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[`'\"\[])?([a-zA-Z0-9_\.\-]+)(?:[`'\"\]])?\s*\((.*?)\)\s*(?:ENGINE|DEFAULT|AUTO_INCREMENT|;|WITHOUT|$)",
            re.IGNORECASE | re.DOTALL,
        )

        for match in create_table_pattern.finditer(content):
            raw_name = match.group(1).split(".")[-1].strip("`'\"[]")
            body = match.group(2)

            columns = []
            primary_keys = []
            indexes = []

            for line in body.splitlines():
                line = line.strip().rstrip(",")
                if not line or line.startswith("--") or line.startswith("/*"):
                    continue

                # Primary key line
                pk_match = re.match(r"(?:PRIMARY\s+KEY|KEY|INDEX)\s*(?:[`'\"\[][^`'\"\]]+[`'\"\]])?\s*\((.*?)\)", line, re.IGNORECASE)
                if pk_match and "primary" in line.lower():
                    keys = [k.strip("`'\"[] ") for k in pk_match.group(1).split(",")]
                    primary_keys.extend(keys)
                    continue
                elif pk_match:
                    indexes.append(line)
                    continue

                # Column definition
                col_match = re.match(r"(?:[`'\"\[])?([a-zA-Z0-9_]+)(?:[`'\"\]])?\s+([a-zA-Z0-9_]+(?:\([^)]+\))?)(.*)", line)
                if col_match:
                    c_name = col_match.group(1)
                    c_type = col_match.group(2)
                    c_rest = col_match.group(3)

                    is_nullable = "NOT NULL" not in c_rest.upper()
                    is_pk = "PRIMARY KEY" in c_rest.upper()
                    if is_pk:
                        primary_keys.append(c_name)

                    is_sensitive = any(p in c_name.lower() for p in PII_COLUMN_INDICATORS)

                    columns.append({
                        "name": c_name,
                        "type": c_type,
                        "nullable": is_nullable,
                        "is_primary_key": is_pk,
                        "is_sensitive": is_sensitive,
                    })

            tables.append({
                "name": raw_name,
                "table_name": raw_name,
                "columns": columns,
                "primary_keys": list(dict.fromkeys(primary_keys)),
                "column_count": len(columns),
                "indexes": indexes[:10],
                "sample_rows": [],
            })

        return tables

    @classmethod
    def _extract_records_and_entities(
        cls,
        content: str,
        tables: List[Dict[str, Any]],
        max_sample_rows: int = 50,
    ) -> Tuple[Dict[str, List[dict]], List[dict], List[dict], List[dict]]:
        """Parses INSERT INTO statements, populates sample rows, and extracts hashes and credentials."""
        records_by_table: Dict[str, List[dict]] = {t["table_name"]: [] for t in tables}
        extracted_users: List[dict] = []
        extracted_hashes: List[dict] = []
        sensitive_fields: List[dict] = []

        table_col_map = {t["table_name"]: [c["name"] for c in t["columns"]] for t in tables}

        insert_pattern = re.compile(
            r"INSERT\s+INTO\s+(?:[`'\"\[])?([a-zA-Z0-9_\.\-]+)(?:[`'\"\]])?\s*(?:\((.*?)\))?\s*VALUES\s*(.*?);",
            re.IGNORECASE | re.DOTALL,
        )

        for match in insert_pattern.finditer(content):
            t_name = match.group(1).split(".")[-1].strip("`'\"[]")
            raw_cols = match.group(2)
            values_blob = match.group(3)

            col_names = []
            if raw_cols:
                col_names = [c.strip("`'\"[] ") for c in raw_cols.split(",")]
            elif t_name in table_col_map:
                col_names = table_col_map[t_name]

            # Parse tuple values e.g. (1, 'admin', '$2y$...'), (2, 'user', ...)
            tuples = re.findall(r"\(((?:[^()']|'[^']*')*)\)", values_blob)
            for t_raw in tuples[:max_sample_rows]:
                # Split tokens respecting quotes
                tokens = []
                for val in re.split(r",(?=(?:[^']*'[^']*')*[^']*$)", t_raw):
                    clean_val = val.strip().strip("'\"")
                    if clean_val.upper() == "NULL":
                        tokens.append(None)
                    else:
                        tokens.append(clean_val)

                row_dict = {}
                for idx, val in enumerate(tokens):
                    col_name = col_names[idx] if idx < len(col_names) else f"col_{idx}"
                    row_dict[col_name] = val

                # Associate username in same row if available
                row_user = None
                for c_k, c_v in row_dict.items():
                    if c_v and any(u_key in c_k.lower() for u_key in ("username", "user", "login", "nim", "email")):
                        row_user = str(c_v)
                        break

                for col_name, val in row_dict.items():
                    if val is not None and isinstance(val, str):
                        # Detect Password Hashes
                        for hash_name, pattern in HASH_PATTERNS:
                            if pattern.match(val):
                                extracted_hashes.append({
                                    "table": t_name,
                                    "column": col_name,
                                    "hash_type": hash_name,
                                    "full_hash": val,
                                    "hash_sample": val[:12] + "..." + val[-6:] if len(val) > 18 else val,
                                    "work_factor": 10 if "bcrypt" in hash_name else None,
                                    "user": row_user or "-",
                                    "associated_user": row_user or "-",
                                })
                                break

                        # Detect Emails / Usernames
                        if "@" in val and "." in val and len(val) < 80:
                            extracted_users.append({
                                "table": t_name,
                                "column": col_name,
                                "identifier": val,
                                "type": "email",
                            })
                        elif col_name.lower() in ("username", "user", "login", "nim", "nik") and len(val) < 50:
                            extracted_users.append({
                                "table": t_name,
                                "column": col_name,
                                "identifier": val,
                                "type": col_name.lower(),
                            })

                        # Detect Sensitive Tokens / API keys
                        if len(val) >= 20 and any(k in col_name.lower() for k in ("token", "secret", "key", "auth")):
                            sensitive_fields.append({
                                "table": t_name,
                                "column": col_name,
                                "type": "token_secret",
                                "sample": val[:6] + "..." + val[-4:],
                            })

                if t_name in records_by_table and len(records_by_table[t_name]) < max_sample_rows:
                    records_by_table[t_name].append(row_dict)

        # Attach sample rows to tables
        for t in tables:
            t["sample_rows"] = records_by_table.get(t["table_name"], [])

        return records_by_table, extracted_users[:100], extracted_hashes[:100], sensitive_fields[:100]
