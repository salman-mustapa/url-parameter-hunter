"""Data-to-Input Action Correlation Engine (V15 Autonomous Architecture).

Correlates discovered structured artifact intelligence (database tables, columns, rows,
cracked password hashes, tokens, PII) with discovered web attack surface (login forms,
input fields, URL parameters, authentication endpoints).

Features:
- Semantic synonym matching for identity and secret fields (including Indonesian academic/civil fields).
- Automated format permutations for dates, PINs, and passwords (YYYY-MM-DD, DD-MM-YYYY, DDMMYYYY, etc.).
- Automated hypothesis generation and conversion into prioritized AttackOpportunity instances.
"""

from __future__ import annotations

import itertools
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from app.orchestration.attack_opportunity import AttackOpportunity, OpportunityState

logger = logging.getLogger("orchestration.data_action_correlator")

# Semantic synonym dictionary for user identifiers
IDENTITY_FIELD_SYNONYMS: Set[str] = {
    "username",
    "user",
    "login",
    "email",
    "mail",
    "usr",
    "user_login",
    "user_email",
    "nim",
    "nip",
    "nik",
    "id_user",
    "user_id",
    "no_induk",
    "identity",
    "account",
    "student_id",
    "npm",
    "nrp",
    "nisn",
    "member_id",
    "client_id",
    "username_or_email",
}

# Semantic synonym dictionary for credentials / secrets / auth challenges
SECRET_FIELD_SYNONYMS: Set[str] = {
    "password",
    "pass",
    "pwd",
    "user_pass",
    "user_password",
    "tanggal_lahir",
    "tgl_lahir",
    "tgl_hr",
    "birth_date",
    "birthdate",
    "dob",
    "date_of_birth",
    "pin",
    "secret",
    "token",
    "auth_key",
    "access_code",
    "otp",
    "security_code",
    "kode_akses",
}


@dataclass
class AuthCandidate:
    """A concrete credential set matched for a form."""
    field_values: Dict[str, str]
    source_table: Optional[str] = None
    source_artifact: Optional[str] = None
    confidence: float = 0.85
    rationale: str = ""


@dataclass
class AuthenticationHypothesis:
    """Hypothesis that discovered data can authenticate to a target endpoint."""
    endpoint: str
    matched_form_action: str
    field_mapping: Dict[str, str]  # form_input_name -> entity_column_name
    candidates: List[AuthCandidate] = field(default_factory=list)
    confidence: float = 0.85
    hypothesis_text: str = ""

    def to_attack_opportunity(self, priority: int = 95) -> AttackOpportunity:
        """Converts hypothesis into an actionable AttackOpportunity for AuthAttackModule."""
        # Flatten candidate credentials into tuple/dict structures
        creds_list: List[Dict[str, str]] = []
        for c in self.candidates:
            creds_list.append(c.field_values)

        return AttackOpportunity(
            target=self.endpoint,
            endpoint=self.endpoint,
            attack_type="auth",
            hypothesis=self.hypothesis_text or f"Discovered artifact records correlate to login inputs at {self.endpoint}",
            priority=priority,
            confidence=self.confidence,
            prerequisites=["Network connectivity to login endpoint", "Extracted artifact records"],
            metadata={
                "credentials": creds_list,
                "field_mapping": self.field_mapping,
                "matched_form_action": self.matched_form_action,
                "chained_from": "data_action_correlator",
                "candidate_count": len(self.candidates),
            },
        )


class DataToInputActionCorrelator:
    """Correlates extracted artifact data with target input surfaces and forms."""

    @staticmethod
    def normalize_field_name(name: str) -> str:
        """Normalizes input/column name (lowercased, stripped, underscores)."""
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", (name or "").lower().strip()).strip("_")
        return clean

    @classmethod
    def is_identity_field(cls, name: str) -> bool:
        norm = cls.normalize_field_name(name)
        return norm in IDENTITY_FIELD_SYNONYMS or any(
            syn in norm for syn in ("user", "login", "nim", "nip", "nik", "email")
        )

    @classmethod
    def is_secret_field(cls, name: str) -> bool:
        norm = cls.normalize_field_name(name)
        return norm in SECRET_FIELD_SYNONYMS or any(
            syn in norm for syn in ("pass", "pwd", "lahir", "birth", "dob", "pin", "secret")
        )

    @classmethod
    def generate_date_permutations(cls, raw_date_str: str) -> List[str]:
        """Generates common date permutations (YYYY-MM-DD, DD-MM-YYYY, DDMMYYYY, YYYYMMDD, etc.)."""
        if not raw_date_str:
            return []

        clean_str = str(raw_date_str).strip()
        permutations: List[str] = [clean_str]

        # Parse standard date formats
        dt = None
        date_formats = [
            "%Y-%m-%d",
            "%d-%m-%Y",
            "%Y/%m/%d",
            "%d/%m/%Y",
            "%Y%m%d",
            "%d%m%Y",
            "%Y.%m.%d",
            "%d.%m.%Y",
        ]
        for fmt in date_formats:
            try:
                dt = datetime.strptime(clean_str, fmt)
                break
            except (ValueError, TypeError):
                continue

        if dt:
            # Generate common input permutations
            perm_formats = [
                "%Y-%m-%d",
                "%d-%m-%Y",
                "%d/%m/%Y",
                "%Y/%m/%d",
                "%d%m%Y",
                "%Y%m%d",
                "%d-%b-%Y",
                "%d%m%y",
                "%y%m%d",
            ]
            for p_fmt in perm_formats:
                formatted = dt.strftime(p_fmt)
                if formatted not in permutations:
                    permutations.append(formatted)

        return list(dict.fromkeys(permutations))

    @classmethod
    def extract_form_inputs_from_html(cls, html_text: str, base_url: str = "") -> List[Dict[str, Any]]:
        """Extracts HTML forms, actions, methods, and input fields."""
        forms: List[Dict[str, Any]] = []
        if not html_text:
            return forms

        form_regex = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
        input_regex = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
        attr_regex = re.compile(r'([a-zA-Z0-9_\-]+)=(?:["\']([^"\']*)["\']|([^\s>]+))')

        for f_match in form_regex.finditer(html_text):
            f_attrs_raw = f_match.group(1)
            f_body = f_match.group(2)

            f_attrs = {}
            for m in attr_regex.finditer(f_attrs_raw):
                key = m.group(1).lower()
                val = m.group(2) if m.group(2) is not None else m.group(3)
                f_attrs[key] = val or ""

            action = f_attrs.get("action", "")
            action_url = urljoin(base_url, action) if base_url else action
            method = f_attrs.get("method", "POST").upper()
            is_multipart = "multipart/form-data" in f_attrs.get("enctype", "").lower()

            fields: List[Dict[str, Any]] = []
            for inp_match in input_regex.finditer(f_body):
                i_raw = inp_match.group(1)
                i_attrs = {}
                for m in attr_regex.finditer(i_raw):
                    k = m.group(1).lower()
                    v = m.group(2) if m.group(2) is not None else m.group(3)
                    i_attrs[k] = v or ""

                f_name = i_attrs.get("name")
                if not f_name:
                    continue

                f_type = i_attrs.get("type", "text").lower()
                fields.append({
                    "name": f_name,
                    "type": f_type,
                    "value": i_attrs.get("value", ""),
                    "placeholder": i_attrs.get("placeholder", ""),
                })

            forms.append({
                "action": action_url or base_url,
                "method": method,
                "is_multipart": is_multipart,
                "fields": fields,
            })

        return forms

    @classmethod
    def correlate_artifact_data_to_forms(
        cls,
        forms: List[Dict[str, Any]],
        tables: List[Dict[str, Any]],
        extracted_users: Optional[List[Dict[str, Any]]] = None,
        extracted_hashes: Optional[List[Dict[str, Any]]] = None,
        target_url: str = "",
        max_candidates_per_form: int = 20,
    ) -> List[AuthenticationHypothesis]:
        """Cross-references database tables/rows against discovered login forms."""
        hypotheses: List[AuthenticationHypothesis] = []

        for form in forms:
            form_fields = [f["name"] for f in form.get("fields", []) if f.get("type") not in ("hidden", "submit", "button")]
            if not form_fields:
                form_fields = [f["name"] for f in form.get("fields", [])]

            if not form_fields:
                continue

            # Identify form input roles
            form_id_field = None
            form_secret_field = None

            for f_name in form_fields:
                if cls.is_identity_field(f_name) and not form_id_field:
                    form_id_field = f_name
                elif cls.is_secret_field(f_name) and not form_secret_field:
                    form_secret_field = f_name

            # Fallback: if 2 fields, first is id, second is secret
            if not form_id_field and len(form_fields) >= 1:
                form_id_field = form_fields[0]
            if not form_secret_field and len(form_fields) >= 2:
                form_secret_field = form_fields[1]

            if not form_id_field:
                continue

            endpoint = form.get("action") or target_url

            # Search in tables for matching column pairs
            for tbl in tables:
                tbl_name = tbl.get("name") or tbl.get("table_name", "")
                columns = [c["name"] if isinstance(c, dict) else str(c) for c in tbl.get("columns", [])]
                samples = tbl.get("sample_records") or tbl.get("sample_rows") or []

                if not columns or not samples:
                    continue

                col_id_match = None
                col_secret_match = None

                # Find identity column in table
                for col in columns:
                    norm_col = cls.normalize_field_name(col)
                    norm_form_id = cls.normalize_field_name(form_id_field)
                    if norm_col == norm_form_id or (cls.is_identity_field(norm_col) and not col_id_match):
                        col_id_match = col

                # Find secret / password / dob column in table
                for col in columns:
                    if col == col_id_match:
                        continue
                    norm_col = cls.normalize_field_name(col)
                    norm_form_sec = cls.normalize_field_name(form_secret_field) if form_secret_field else ""
                    if norm_form_sec and (norm_col == norm_form_sec):
                        col_secret_match = col
                        break
                    elif cls.is_secret_field(norm_col) and not col_secret_match:
                        col_secret_match = col

                if not col_id_match:
                    continue

                # Build candidate pairs from sample records
                candidates: List[AuthCandidate] = []
                for row in samples:
                    if not isinstance(row, dict):
                        continue

                    id_val = row.get(col_id_match)
                    if id_val is None or str(id_val).strip() == "":
                        continue

                    id_str = str(id_val).strip()

                    # Secret values & permutations
                    sec_val = row.get(col_secret_match) if col_secret_match else None
                    candidate_secrets = []
                    if sec_val is not None:
                        sec_str = str(sec_val).strip()
                        # If date field, generate permutations
                        if any(k in (col_secret_match or "").lower() for k in ("lahir", "dob", "birth", "date")):
                            candidate_secrets = cls.generate_date_permutations(sec_str)
                        else:
                            candidate_secrets = [sec_str]
                    else:
                        # Fallback common credentials
                        candidate_secrets = [id_str, "password", "123456", "admin"]

                    for secret in candidate_secrets:
                        field_dict = {form_id_field: id_str}
                        if form_secret_field:
                            field_dict[form_secret_field] = secret

                        candidates.append(
                            AuthCandidate(
                                field_values=field_dict,
                                source_table=tbl_name,
                                confidence=0.90 if col_secret_match else 0.70,
                                rationale=f"Matched table '{tbl_name}' cols ({col_id_match}, {col_secret_match or 'N/A'}) to form ({form_id_field}, {form_secret_field or 'N/A'})",
                            )
                        )

                    if len(candidates) >= max_candidates_per_form:
                        break

                if candidates:
                    field_mapping = {form_id_field: col_id_match}
                    if form_secret_field and col_secret_match:
                        field_mapping[form_secret_field] = col_secret_match

                    hypo = AuthenticationHypothesis(
                        endpoint=endpoint,
                        matched_form_action=form.get("action", endpoint),
                        field_mapping=field_mapping,
                        candidates=candidates,
                        confidence=0.92 if col_secret_match else 0.75,
                        hypothesis_text=f"Authentication Hypothesis: Extracted records from table '{tbl_name}' match login portal at {endpoint} using {list(field_mapping.keys())}",
                    )
                    hypotheses.append(hypo)

        return hypotheses


data_action_correlator = DataToInputActionCorrelator()
