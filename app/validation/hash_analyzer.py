"""Cryptographic Hash Analyzer Subsystem (V8 §13).

100% Offline mathematical analysis of credential and hash material:
- Hash algorithm identification (MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, argon2, PBKDF2, WordPress phpass, Cisco, etc.)
- Salt detection and separation
- Work factor / iteration measurement
- Shannon entropy calculation
- Weak / default dictionary pattern detection
- Password policy weakness evaluation
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional


class HashAnalyzer:
    """Offline cryptographic analyzer for hash artifacts (V8 §13)."""

    HASH_PATTERNS = [
        ("bcrypt", r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
        ("argon2", r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"),
        ("pbkdf2_sha256", r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$"),
        ("wordpress_phpass", r"^\$P\$[./0-9A-Za-z]{31}$"),
        ("drupal7", r"^\$S\$[./0-9A-Za-z]{52}$"),
        ("md5_crypt", r"^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$"),
        ("sha512_crypt", r"^\$6\$(rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$"),
        ("sha256_crypt", r"^\$5\$(rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$"),
        ("ntlm", r"^[0-9a-fA-F]{32}$"),
        ("md5_raw", r"^[0-9a-fA-F]{32}$"),
        ("sha1_raw", r"^[0-9a-fA-F]{40}$"),
        ("sha256_raw", r"^[0-9a-fA-F]{64}$"),
        ("sha512_raw", r"^[0-9a-fA-F]{128}$"),
    ]

    COMMON_WEAK_PATTERNS = [
        r"^(password|admin|123456|root|guest|letmein|welcome|qwerty)",
        r"^([a-zA-Z]+)\1+$",  # repeated patterns
        r"^\d{1,8}$",  # numeric only under 8 chars
    ]

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Calculates Shannon entropy in bits per character."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    @classmethod
    def identify_algorithm(cls, hash_str: str) -> Dict[str, Any]:
        """Identifies candidate hash algorithm, work factor, and salt presence."""
        h = hash_str.strip()
        matched_algo = "unknown"
        salt_present = False
        work_factor = None

        for algo_name, pattern in cls.HASH_PATTERNS:
            if re.match(pattern, h):
                matched_algo = algo_name
                break

        # Check work factor and salt
        if matched_algo == "bcrypt":
            salt_present = True
            parts = h.split("$")
            if len(parts) >= 3 and parts[2].isdigit():
                work_factor = int(parts[2])
        elif matched_algo == "argon2":
            salt_present = True
            m_match = re.search(r"t=(\d+)", h)
            if m_match:
                work_factor = int(m_match.group(1))
        elif "crypt" in matched_algo or "pbkdf2" in matched_algo:
            salt_present = True
            rounds_match = re.search(r"rounds=(\d+)", h)
            if rounds_match:
                work_factor = int(rounds_match.group(1))
        elif matched_algo in ("md5_raw", "sha1_raw", "ntlm"):
            salt_present = False

        entropy = cls.calculate_entropy(h)

        return {
            "algorithm": matched_algo,
            "salt_present": salt_present,
            "work_factor": work_factor,
            "entropy": round(entropy, 2),
            "length": len(h),
            "is_weak_algorithm": matched_algo in ("md5_raw", "sha1_raw", "ntlm", "md5_crypt"),
        }

    @classmethod
    def evaluate_plaintext_strength(cls, plaintext: str) -> Dict[str, Any]:
        """Evaluates password policy weakness and complexity."""
        length = len(plaintext)
        entropy = cls.calculate_entropy(plaintext)

        weak_pattern = any(bool(re.search(pat, plaintext, re.IGNORECASE)) for pat in cls.COMMON_WEAK_PATTERNS)
        has_upper = bool(re.search(r"[A-Z]", plaintext))
        has_lower = bool(re.search(r"[a-z]", plaintext))
        has_digit = bool(re.search(r"\d", plaintext))
        has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", plaintext))

        weaknesses = []
        if length < 8:
            weaknesses.append("Length less than 8 characters")
        if not (has_upper and has_lower):
            weaknesses.append("Missing mixed-case characters")
        if not has_digit:
            weaknesses.append("Missing numeric digits")
        if not has_special:
            weaknesses.append("Missing special symbols")
        if weak_pattern:
            weaknesses.append("Matches known weak/default pattern")

        return {
            "length": length,
            "entropy": round(entropy, 2),
            "weak_pattern_detected": weak_pattern,
            "weaknesses": weaknesses,
            "is_weak": bool(weaknesses),
            "strength_tier": "STRONG" if len(weaknesses) == 0 and length >= 12 else ("MODERATE" if len(weaknesses) <= 1 else "WEAK"),
        }
