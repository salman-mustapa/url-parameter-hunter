"""High-Performance Zero-Overhead Hash Intelligence & Cracking Engine.

Automated password hash identification and rainbow dictionary cracking for
security audits and penetration testing reports.
Supports: MD5, SHA1, SHA256, NTLM, and target-specific heuristic mutation cracking.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

# Pre-compiled hash format patterns
HASH_TYPE_PATTERNS = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("argon2", re.compile(r"^\$argon2[id]?\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+")),
    ("phpass_wordpress", re.compile(r"^\$P\$[./0-9A-Za-z]{31}$")),
    ("django_pbkdf2", re.compile(r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+")),
    ("sha256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("sha1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("md5", re.compile(r"^[a-fA-F0-9]{32}$")),
]

# High-frequency dictionary passwords including academic, Indonesian, and administrative defaults
COMMON_PASSWORDS: List[str] = [
    "admin", "password", "123456", "12345678", "123456789", "12345", "1234",
    "root", "toor", "user", "guest", "operator", "staff", "demo", "test",
    "admin123", "admin#123", "admin1234", "password123", "pass123", "secret",
    "rahasia", "rahasia123", "bismillah", "merdeka", "indonesia", "indonesia123",
    "kampus", "universitas", "akademik", "mahasiswa", "dosen", "alumni",
    "tracer", "tracerstudy", "skpi", "simak", "siakad", "portal", "puskom",
    "faperta", "kedokteran", "teknik", "fateka", "feb", "hukum", "pasca",
    "ung", "ung123", "gorontalo", "gorontalo123", "bonebolango",
    "111111", "000000", "654321", "qwerty", "welcome", "login", "master"
]


class HashIntelligenceEngine:
    """Detects hash algorithms, correlates identities, and performs dictionary attacks."""

    _md5_cache: Dict[str, str] = {}
    _sha1_cache: Dict[str, str] = {}
    _sha256_cache: Dict[str, str] = {}

    @classmethod
    def _init_caches(cls) -> None:
        if cls._md5_cache:
            return
        for pwd in COMMON_PASSWORDS:
            b = pwd.encode("utf-8")
            cls._md5_cache[hashlib.md5(b).hexdigest().lower()] = pwd
            cls._sha1_cache[hashlib.sha1(b).hexdigest().lower()] = pwd
            cls._sha256_cache[hashlib.sha256(b).hexdigest().lower()] = pwd

    @classmethod
    def identify_algorithm(cls, hash_val: str) -> str:
        """Identifies cryptographic hash algorithm from format and length."""
        h = hash_val.strip()
        for algo, pat in HASH_TYPE_PATTERNS:
            if pat.match(h):
                return algo
        return "unknown_hash"

    @classmethod
    def attempt_crack(
        cls,
        hash_val: str,
        associated_username: Optional[str] = None,
        extra_hints: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[str], str]:
        """
        Attempts to crack a hash using pre-computed dictionary and dynamic target mutations.
        Returns: (is_cracked, plaintext_password, algorithm)
        """
        cls._init_caches()
        h_clean = hash_val.strip().lower()
        algo = cls.identify_algorithm(h_clean)

        # 1. Check pre-computed cache
        if algo == "md5":
            if h_clean in cls._md5_cache:
                return True, cls._md5_cache[h_clean], algo
        elif algo == "sha1":
            if h_clean in cls._sha1_cache:
                return True, cls._sha1_cache[h_clean], algo
        elif algo == "sha256":
            if h_clean in cls._sha256_cache:
                return True, cls._sha256_cache[h_clean], algo

        # 2. Dynamic target-specific permutations (e.g. username as password)
        candidates = []
        if associated_username:
            u = associated_username.strip().lower()
            candidates.extend([
                u,
                f"{u}123",
                f"{u}2020",
                f"{u}2021",
                f"{u}2022",
                f"{u}2023",
                f"{u}2024",
                f"{u}2025",
                f"{u}2026",
                f"{u}!",
                f"{u}#",
                f"{u}1234",
                f"admin_{u}",
                f"{u}_admin",
            ])

        if extra_hints:
            for hint in extra_hints:
                if hint and isinstance(hint, str):
                    h_lower = hint.strip().lower()
                    candidates.extend([h_lower, f"{h_lower}123", f"{h_lower}2020"])

        for cand in candidates:
            b = cand.encode("utf-8")
            if algo == "md5" and hashlib.md5(b).hexdigest().lower() == h_clean:
                cls._md5_cache[h_clean] = cand
                return True, cand, algo
            elif algo == "sha1" and hashlib.sha1(b).hexdigest().lower() == h_clean:
                cls._sha1_cache[h_clean] = cand
                return True, cand, algo
            elif algo == "sha256" and hashlib.sha256(b).hexdigest().lower() == h_clean:
                cls._sha256_cache[h_clean] = cand
                return True, cand, algo

        return False, None, algo

    @classmethod
    def enrich_extracted_hashes(
        cls,
        extracted_hashes: List[Dict[str, Any]],
        extracted_users: Optional[List[Dict[str, Any]]] = None,
        database_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Enriches hash records with plaintext values, cracking status, and security analysis."""
        cls._init_caches()

        user_by_table: Dict[str, List[str]] = {}
        if extracted_users:
            for u in extracted_users:
                t = u.get("table") or "default"
                ident = u.get("identifier") or u.get("username")
                if ident:
                    user_by_table.setdefault(t, []).append(str(ident))

        hints = [database_name] if database_name else []

        enriched = []
        for h in extracted_hashes:
            full_val = h.get("full_hash") or h.get("hash_sample") or h.get("sample") or ""
            target_hash = full_val if "..." not in full_val else (h.get("full_hash") or full_val)

            tbl = h.get("table") or ""
            candidates_users = user_by_table.get(tbl, [])
            assoc_user = h.get("user") or h.get("associated_user") or (candidates_users[0] if candidates_users else None)

            is_cracked, plaintext, algo = cls.attempt_crack(
                target_hash,
                associated_username=assoc_user,
                extra_hints=hints + candidates_users,
            )

            item = dict(h)
            item["hash_type"] = algo.upper() if algo != "unknown_hash" else (h.get("hash_type") or "MD5").upper()
            item["is_cracked"] = is_cracked
            item["plaintext"] = plaintext
            item["associated_user"] = assoc_user or "-"
            item["cracked_status"] = f"CRACKED: {plaintext}" if is_cracked else "UNCRACKED"
            item["security_level"] = "CRITICAL" if is_cracked else ("MEDIUM" if algo in ("bcrypt", "argon2") else "HIGH")
            enriched.append(item)

        return enriched
