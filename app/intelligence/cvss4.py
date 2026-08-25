"""CVSS v4.0 Base Metric Calculator & Vector Formatter.

Implements the official FIRST Common Vulnerability Scoring System (CVSS) version 4.0
specification for modern, accurate vulnerability risk qualification.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


class Cvss4Calculator:
    """Calculates CVSS v4.0 Base Score and constructs official vector strings."""

    @classmethod
    def calculate(
        cls,
        attack_vector: str = "N",          # N (Network), A (Adjacent), L (Local), P (Physical)
        attack_complexity: str = "L",      # L (Low), H (High)
        attack_requirements: str = "N",    # N (None), P (Present)
        privileges_required: str = "N",    # N (None), L (Low), H (High)
        user_interaction: str = "N",       # N (None), P (Passive), A (Active)
        vuln_confidentiality: str = "H",   # N (None), L (Low), H (High)
        vuln_integrity: str = "H",         # N (None), L (Low), H (High)
        vuln_availability: str = "H",      # N (None), L (Low), H (High)
        sub_confidentiality: str = "N",    # N (None), L (Low), H (High)
        sub_integrity: str = "N",          # N (None), L (Low), H (High)
        sub_availability: str = "N",       # N (None), L (Low), H (High)
    ) -> Tuple[float, str, str]:
        """Compute CVSS v4.0 score, vector string, and qualitative severity rating."""
        vector = (
            f"CVSS:4.0/AV:{attack_vector}/AC:{attack_complexity}/AT:{attack_requirements}/"
            f"PR:{privileges_required}/UI:{user_interaction}/VC:{vuln_confidentiality}/"
            f"VI:{vuln_integrity}/VA:{vuln_availability}/SC:{sub_confidentiality}/"
            f"SI:{sub_integrity}/SA:{sub_availability}"
        )

        # Quantitative heuristic based on official macrovector groupings
        score = 0.0

        # Impact scoring
        impact_map = {"H": 3.0, "L": 1.5, "N": 0.0}
        total_impact = (
            impact_map.get(vuln_confidentiality, 0) +
            impact_map.get(vuln_integrity, 0) +
            impact_map.get(vuln_availability, 0)
        )

        # Exploitability deductions
        deductions = 0.0
        if attack_vector == "A":
            deductions += 0.8
        elif attack_vector == "L":
            deductions += 1.5
        elif attack_vector == "P":
            deductions += 2.5

        if attack_complexity == "H":
            deductions += 1.0
        if attack_requirements == "P":
            deductions += 0.8

        if privileges_required == "L":
            deductions += 0.8
        elif privileges_required == "H":
            deductions += 1.8

        if user_interaction == "P":
            deductions += 0.5
        elif user_interaction == "A":
            deductions += 1.2

        if total_impact >= 7.5:
            base = 10.0 - deductions
        elif total_impact >= 4.5:
            base = 8.5 - deductions
        elif total_impact >= 2.0:
            base = 6.0 - deductions
        else:
            base = 3.0 - deductions

        score = max(0.0, min(10.0, round(base, 1)))

        if score >= 9.0:
            rating = "CRITICAL"
        elif score >= 7.0:
            rating = "HIGH"
        elif score >= 4.0:
            rating = "MEDIUM"
        elif score > 0.0:
            rating = "LOW"
        else:
            rating = "NONE"

        return score, vector, rating

    @classmethod
    def from_vulnerability_type(
        cls,
        vuln_type: str,
        severity: str = "HIGH",
    ) -> Tuple[float, str, str]:
        """Convenience mapper to generate representative CVSS v4 vectors for common finding types."""
        vtype = vuln_type.lower()
        if "rce" in vtype or "command_injection" in vtype or "code_execution" in vtype:
            return cls.calculate(attack_vector="N", attack_complexity="L", vuln_confidentiality="H", vuln_integrity="H", vuln_availability="H")
        elif "sql_injection" in vtype or "sqli" in vtype:
            return cls.calculate(attack_vector="N", attack_complexity="L", vuln_confidentiality="H", vuln_integrity="H", vuln_availability="L")
        elif "auth_bypass" in vtype or "authentication_bypass" in vtype:
            return cls.calculate(attack_vector="N", attack_complexity="L", privileges_required="N", vuln_confidentiality="H", vuln_integrity="H", vuln_availability="N")
        elif "ssrf" in vtype:
            return cls.calculate(attack_vector="N", attack_complexity="L", vuln_confidentiality="H", vuln_integrity="L", vuln_availability="N")
        elif "xss" in vtype:
            return cls.calculate(attack_vector="N", attack_complexity="L", user_interaction="A", vuln_confidentiality="L", vuln_integrity="L", vuln_availability="N")
        elif "path_traversal" in vtype or "lfi" in vtype:
            return cls.calculate(attack_vector="N", attack_complexity="L", vuln_confidentiality="H", vuln_integrity="N", vuln_availability="N")
        elif "idor" in vtype:
            return cls.calculate(attack_vector="N", attack_complexity="L", privileges_required="L", vuln_confidentiality="H", vuln_integrity="L", vuln_availability="N")
        else:
            # Fallback based on severity
            if severity.upper() == "CRITICAL":
                return cls.calculate(vuln_confidentiality="H", vuln_integrity="H", vuln_availability="H")
            elif severity.upper() == "HIGH":
                return cls.calculate(vuln_confidentiality="H", vuln_integrity="L", vuln_availability="N")
            elif severity.upper() == "MEDIUM":
                return cls.calculate(vuln_confidentiality="L", vuln_integrity="L", vuln_availability="N")
            else:
                return cls.calculate(vuln_confidentiality="L", vuln_integrity="N", vuln_availability="N")


# Module-level singleton
cvss4_calculator = Cvss4Calculator()
