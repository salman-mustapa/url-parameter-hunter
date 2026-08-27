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

# ─── Comprehensive Pentest Password Dictionary ─────────────────────────────
# Sources: RockyYou top-500, SecLists common-credentials, Indonesian defaults,
# academic/university defaults, data-leak common patterns, and mutation rules.
# Pre-computed at startup for O(1) rainbow-table lookup.
# ────────────────────────────────────────────────────────────────────────────

# RockyYou / SecLists Top Passwords (most commonly leaked)
ROCKYOU_TOP: List[str] = [
    "123456", "12345", "123456789", "password", "iloveyou", "princess", "1234567",
    "rockyou", "12345678", "abc123", "nicole", "daniel", "babygirl", "monkey",
    "lovely", "jessica", "654321", "michael", "ashley", "qwerty", "111111",
    "iloveu", "000000", "michelle", "tigger", "sunshine", "chocolate", "password1",
    "soccer", "anthony", "friends", "butterfly", "purple", "angel", "jordan",
    "liverpool", "justin", "loveme", "fuckyou", "123123", "football", "secret",
    "andrea", "carlos", "jennifer", "joshua", "bubbles", "1234567890", "superman",
    "hannah", "amanda", "loveyou", "pretty", "basketball", "andrew", "angels",
    "tweety", "flower", "playboy", "hello", "elizabeth", "hottie", "tinkerbell",
    "charlie", "samantha", "barbie", "chelsea", "lovers", "teamo", "jasmine",
    "brandon", "666666", "shadow", "melissa", "eminem", "matthew", "robert",
    "danielle", "forever", "family", "jonathan", "987654321", "computer", "whatever",
    "dragon", "vanessa", "cookie", "naruto", "summer", "sweety", "spongebob",
    "joseph", "junior", "softball", "taylor", "yellow", "daniela", "pokemon",
    "connie", "callme", "sophia", "letmein", "access", "master", "trustno1",
    "696969", "abc", "batman", "baseball", "passw0rd", "pass123", "welcome",
    "welcome1", "p@ssw0rd", "admin123", "root", "toor", "guest", "operator",
    "changeme", "1q2w3e4r", "q1w2e3r4", "qwerty123", "1qaz2wsx", "zaq1xsw2",
    "login", "starwars", "121212", "flower", "mustang", "1234", "131313",
    "test", "test123", "testing", "demo", "admin1", "admin1234", "administrator",
    "staff", "manager", "user", "user123", "user1234", "default", "temp",
    "123qwe", "qwe123", "asdfgh", "zxcvbn", "asdf1234", "1234abcd", "abcd1234",
    "password123", "password!", "pass1234", "pa55word", "passpass", "p@ss1234",
]

# Indonesian & Academic Domain Passwords
INDONESIAN_ACADEMIC: List[str] = [
    "rahasia", "rahasia123", "bismillah", "merdeka", "indonesia", "indonesia123",
    "pancasila", "garuda", "nkri", "merahputih", "jakarta", "bandung", "surabaya",
    "kampus", "universitas", "akademik", "mahasiswa", "dosen", "alumni", "rektor",
    "dekan", "prodi", "fakultas", "sarjana", "diploma", "magister", "doktor",
    "tracer", "tracerstudy", "skpi", "simak", "siakad", "portal", "puskom",
    "elearning", "lms", "siak", "sia", "simpeg", "sipeg", "siman", "simaba",
    "faperta", "kedokteran", "teknik", "fateka", "feb", "hukum", "pasca",
    "pertanian", "peternakan", "perikanan", "kehutanan", "kesehatan",
    "ung", "ung123", "gorontalo", "gorontalo123", "bonebolango", "limboto",
    "unhas", "ugm", "itb", "ui", "ipb", "undip", "unpad", "unair", "unand",
    "unsri", "unimal", "unmul", "untan", "unsrat", "unesa", "uny", "unnes",
    "admin", "admin123", "admin#123", "admin1234", "admin!", "superadmin",
    "operator", "operator123", "petugas", "petugas123", "kaprodi", "labkom",
]

# Common service/app default passwords
SERVICE_DEFAULTS: List[str] = [
    "mysql", "mysql123", "postgres", "postgres123", "oracle", "oracle123",
    "apache", "nginx", "tomcat", "tomcat123", "jboss", "weblogic", "redis",
    "ftp", "ftp123", "ssh", "ssh123", "root123", "root1234", "r00t",
    "xampp", "wamp", "lampp", "mamp", "phpmyadmin", "cpanel", "plesk",
    "wordpress", "wp-admin", "drupal", "joomla", "magento", "prestashop",
    "db_password", "database", "backup", "server", "system", "sys",
]

# Merge all into single list (deduplicated)
COMMON_PASSWORDS: List[str] = list(dict.fromkeys(
    ROCKYOU_TOP + INDONESIAN_ACADEMIC + SERVICE_DEFAULTS
))


class HashIntelligenceEngine:
    """Detects hash algorithms, correlates identities, and performs dictionary attacks."""

    _md5_cache: Dict[str, str] = {}
    _sha1_cache: Dict[str, str] = {}
    _sha256_cache: Dict[str, str] = {}
    _initialized: bool = False

    @classmethod
    def _init_caches(cls) -> None:
        if cls._initialized:
            return
        cls._initialized = True
        
        # Build rainbow tables from base dictionary
        all_candidates = set(COMMON_PASSWORDS)
        
        # Generate common mutations: append digits, years, symbols
        mutations = []
        for pwd in COMMON_PASSWORDS:
            mutations.extend([
                f"{pwd}1", f"{pwd}12", f"{pwd}123", f"{pwd}1234",
                f"{pwd}!", f"{pwd}@", f"{pwd}#",
                f"{pwd}2020", f"{pwd}2021", f"{pwd}2022", f"{pwd}2023", f"{pwd}2024", f"{pwd}2025", f"{pwd}2026",
                pwd.capitalize(), pwd.upper(),
            ])
        all_candidates.update(mutations)
        
        # Pre-compute hashes for all candidates
        for pwd in all_candidates:
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
