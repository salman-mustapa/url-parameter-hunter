"""Tabular CSV / TSV & Data Export Parser (V9).

Statically inspects CSV, TSV, and delimited text exports without execution:
1. Detects delimiter (comma, semicolon, tab, pipe)
2. Parses column headers and types
3. Identifies PII columns (NIM, NIK, Nama, Email, Password, Phone, Address, Faculty, Program of Study)
4. Generates structured sample rows and statistics
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("artifacts.csv_parser")

PII_HEADER_KEYWORDS = [
    "id", "user", "username", "name", "nama", "nim", "nik", "email", "mail", "pass", "password",
    "phone", "telp", "hp", "alumni", "prodi", "jurusan", "fakultas", "skpi", "tracer",
    "tahun", "status", "date", "created_at", "role", "address", "alamat", "ip", "salary", "gaji", "ipk"
]


class CsvDataParser:
    """Zero-execution static parser for tabular CSV/TSV data exports."""

    @classmethod
    def parse(cls, content: str, max_sample_rows: int = 50) -> Dict[str, Any]:
        """
        Parses CSV/TSV content and returns structural metadata and PII findings.
        """
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
        if not lines:
            return {
                "delimiter": ",",
                "headers": [],
                "row_count": 0,
                "column_count": 0,
                "pii_headers": [],
                "has_pii": False,
                "sample_rows": [],
            }

        first_line = lines[0]
        delimiter = cls._detect_delimiter(first_line)

        try:
            reader = csv.reader(io.StringIO(content), delimiter=delimiter)
            all_rows = list(reader)
        except Exception:
            all_rows = [[c.strip() for c in l.split(delimiter)] for l in lines]

        if not all_rows:
            return {
                "delimiter": delimiter,
                "headers": [],
                "row_count": 0,
                "column_count": 0,
                "pii_headers": [],
                "has_pii": False,
                "sample_rows": [],
            }

        headers = [h.strip() for h in all_rows[0]]
        pii_headers = [h for h in headers if any(k in h.lower() for k in PII_HEADER_KEYWORDS)]

        sample_rows = []
        for r in all_rows[1:max_sample_rows + 1]:
            row_dict = {}
            for idx, col in enumerate(headers):
                val = r[idx] if idx < len(r) else ""
                row_dict[col] = val
            sample_rows.append(row_dict)

        return {
            "delimiter": delimiter,
            "headers": headers,
            "row_count": max(0, len(all_rows) - 1),
            "column_count": len(headers),
            "pii_headers": pii_headers,
            "has_pii": len(pii_headers) > 0,
            "sample_rows": sample_rows,
        }

    @classmethod
    def _detect_delimiter(cls, header_line: str) -> str:
        candidates = [",", ";", "\t", "|"]
        counts = {c: header_line.count(c) for c in candidates}
        best = max(counts, key=counts.get)
        return best if counts[best] > 0 else ","
