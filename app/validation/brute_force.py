"""Controlled Authentication & Credential Policy Validator (V5 §13).

Features:
1. Safe, Bounded Credential Verification: Tests only top-tier standard default credentials (max 10-15 attempts).
2. Strict Rate Limiting: Max 2-3 requests/second with automatic jitter to prevent server disruption.
3. Lockout & Defense Evasion Detection: Automatically stops if rate limiting (429), CAPTCHA, or account lockout triggers.
4. Policy Evaluation: Identifies lack of brute-force protection, missing lockout policies, or valid default credentials.
5. Zero Sensitive Data Exposure: Hashes or masks attempted credentials in persisted telemetry.
"""

from __future__ import annotations

from app.validation.safety.legacy import ValidationHTTPClient

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("validation.brute_force")

_TIMEOUT = httpx.Timeout(10.0, connect=6.0)
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


@dataclass
class BruteForceCandidate:
    url: str
    username_tested: str
    technique: str
    confidence: str  # CONFIRMED / VALIDATED
    evidence_level: str
    finding_type: str  # default_credentials / missing_rate_limiting / lockout_disabled
    title: str
    severity: str
    reproduction_steps: List[str] = field(default_factory=list)
    poc_curl: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    impact_matrix: Dict[str, str] = field(default_factory=dict)
    remediation: str = ""


class ControlledBruteForceValidator:
    """Controlled, bounded authentication testing engine with dynamic credential injection."""

    # Expanded default test credentials (safe, standard test pairs)
    TEST_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("admin", "Admin123"),
        ("admin", "admin@123"),
        ("admin", "P@ssw0rd"),
        ("admin", "1234"),
        ("admin", "12345678"),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("test", "test"),
        ("test", "test123"),
        ("user", "user"),
        ("user", "password"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("operator", "operator"),
        ("manager", "manager"),
        ("support", "support"),
        ("info", "info"),
        ("default", "default"),
    ]

    # Common password patterns to try with discovered usernames
    PASSWORD_PATTERNS = [
        "{username}",           # username = password
        "{username}123",       # username + 123
        "{username}!",         # username + !
        "{username}@123",      # username + @123
        "password",
        "123456",
        "P@ssw0rd",
        "admin123",
        "Welcome1",
        "letmein",
    ]

    # Stop signals indicating defensive lockout or WAF intervention
    LOCKOUT_SIGNATURES = [
        r"account\s+(?:has\s+been\s+)?locked",
        r"too\s+many\s+(?:failed\s+)?attempts",
        r"ip\s+(?:has\s+been\s+)?blocked",
        r"rate\s+limit\s+exceeded",
        r"try\s+again\s+in\s+\d+\s+minutes",
        r"recaptcha|hcaptcha|turnstile|cf-chl-bypass",
        r"security\s+checkpoint",
    ]

    # Success indicators for authentication
    LOGIN_SUCCESS_SIGNATURES = [
        r"dashboard|logout|signout|my\s+account|welcome,\s+[a-zA-Z]|logged\s+in\s+as",
        r"session_token|auth_token|jwt|bearer",
        r"window\.location\s*=\s*['\"]/(?:admin|dashboard|home|user)",
    ]

    # Failure indicators
    LOGIN_FAILURE_SIGNATURES = [
        r"invalid\s+(?:username|password|credentials)",
        r"incorrect\s+(?:username|password)",
        r"authentication\s+failed",
        r"user\s+not\s+found",
        r"wrong\s+password",
        r"login\s+failed",
    ]

    @staticmethod
    def _origin_port(parsed) -> int:
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    @classmethod
    def _same_origin(cls, left: str, right: str) -> bool:
        left_parsed = urlparse(left)
        right_parsed = urlparse(right)
        return (
            left_parsed.scheme == right_parsed.scheme
            and (left_parsed.hostname or "").lower() == (right_parsed.hostname or "").lower()
            and cls._origin_port(left_parsed) == cls._origin_port(right_parsed)
        )

    @staticmethod
    def _redacted_password(password: str) -> str:
        return "[empty]" if password == "" else "[REDACTED]"

    @staticmethod
    def _password_hash(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()[:16] + "..."

    @staticmethod
    def _looks_like_auth_path(value: str) -> bool:
        lowered = value.lower()
        return any(part in lowered for part in ("login", "signin", "auth", "session"))

    async def _detect_form_fields(self, client: httpx.AsyncClient, url: str) -> Optional[Tuple[str, str, str, Dict[str, str], str, int]]:
        """Detect login form action URL, username field, password field, hidden tokens, final page URL, and GET length."""
        try:
            resp = await client.get(url, headers=_HEADERS)
            if resp.status_code != 200:
                return None

            html = resp.text
            final_url = str(resp.url)
            get_len = len(html)

            # Look for password field (must be genuine password input)
            pass_match = re.search(r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if not pass_match:
                pass_match = re.search(r'<input[^>]+name=["\']([^"\']*(?:password|passwd|pwd)[^"\']*)["\'][^>]*type=["\']password["\']', html, re.IGNORECASE)
            if not pass_match:
                return None
            password_field = pass_match.group(1)

            # Look for username / email field (must be text or email input)
            user_match = re.search(r'<input[^>]+type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']*(?:user|login|email|account|name|nim|nik|identity)[^"\']*)["\']', html, re.IGNORECASE)
            if not user_match:
                user_match = re.search(r'<input[^>]+name=["\']([^"\']*(?:user|login|email|account|nim|nik)[^"\']*)["\']', html, re.IGNORECASE)
            if not user_match:
                return None
            username_field = user_match.group(1)

            # Look for form action
            action_match = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.IGNORECASE)
            action = action_match.group(1) if action_match else final_url
            action_url = urljoin(final_url, action)
            if not self._same_origin(final_url, action_url):
                logger.debug("Skipping cross-origin login action on %s -> %s", final_url, action_url)
                return None

            # Extract CSRF or hidden fields
            hidden_fields: Dict[str, str] = {}
            for hidden in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', html, re.IGNORECASE):
                hidden_fields[hidden.group(1)] = hidden.group(2)

            return action_url, username_field, password_field, hidden_fields, final_url, get_len
        except Exception as exc:
            logger.debug("Failed to detect form fields on %s: %s", url, exc)
            return None

    async def validate_login_portal(
        self,
        url: str,
        discovered_credentials: Optional[List[Tuple[str, str]]] = None,
        discovered_usernames: Optional[List[str]] = None,
        *,
        credential_candidates: Optional[List[Tuple[str, str]]] = None,
        max_attempts: int = 15,
        delay_seconds: float = 0.5,
    ) -> List[BruteForceCandidate]:
        """Perform controlled, rate-limited credential audit and brute-force protection analysis.

        Args:
            url: Login portal URL
            discovered_credentials: Credential pairs from SQL dumps, .env files, etc.
            discovered_usernames: Usernames from CSV exports for password spraying
        """
        candidates: List[BruteForceCandidate] = []

        async with ValidationHTTPClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            form_info = await self._detect_form_fields(client, url)
            if not form_info:
                return candidates

            action_url, user_field, pass_field, hidden_fields, final_url, get_len = form_info
            logger.info("Controlled auth test on %s (Action: %s, User: %s, Pass: %s)", final_url, action_url, user_field, pass_field)

            # Establish baseline with intentionally invalid credentials
            baseline_token = "bh_nonexistent_user_xyz999"
            baseline_payload = {**hidden_fields, user_field: baseline_token, pass_field: "InvalidPassword!987"}
            try:
                baseline_resp = await client.post(action_url, data=baseline_payload, headers=_HEADERS)
            except Exception as exc:
                logger.debug("Baseline post error on %s: %s", action_url, exc)
                return candidates

            # If baseline POST fails with 404/405/500/redirect loop, do NOT test further
            if baseline_resp.status_code not in (200, 301, 302, 303, 307, 308, 401, 403):
                logger.debug("Action URL %s returned status %d on POST (not active login handler)", action_url, baseline_resp.status_code)
                return candidates

            # Anti-False-Positive Check:
            # If the POST response length is identical to GET and contains NO authentication error messages,
            # the endpoint is merely serving the static homepage without processing authentication.
            baseline_text = baseline_resp.text
            has_login_failure_feedback = any(re.search(pat, baseline_text, re.IGNORECASE) for pat in self.LOGIN_FAILURE_SIGNATURES)
            is_identical_to_get = (
                baseline_resp.status_code == 200
                and abs(len(baseline_text) - get_len) < 30
                and not has_login_failure_feedback
            )

            if is_identical_to_get:
                logger.debug("Action URL %s returned unmodified static view on POST; not an active login handler", action_url)
                return candidates

            if not has_login_failure_feedback and baseline_resp.status_code == 200:
                logger.debug("Action URL %s did not provide authentic login failure feedback; skipping rate-limit flagging", action_url)
                return candidates

            attempts_made = 0
            lockout_encountered = False
            valid_credential_found: Optional[Tuple[str, str]] = None
            successful_failure_responses = 0

            # Build credential list: defaults + discovered + username spray
            all_credentials = list(credential_candidates or self.TEST_CREDENTIALS)

            # Add discovered credentials from artifacts (SQL dumps, .env files)
            if discovered_credentials:
                for cred_pair in discovered_credentials[:30]:
                    if cred_pair not in all_credentials:
                        all_credentials.append(cred_pair)
                logger.info("Added %d discovered credentials for testing on %s", len(discovered_credentials), final_url)

            # Generate password spray from discovered usernames
            if discovered_usernames:
                for uname in discovered_usernames[:15]:
                    for pattern in self.PASSWORD_PATTERNS[:5]:
                        pwd = pattern.replace("{username}", uname)
                        pair = (uname, pwd)
                        if pair not in all_credentials:
                            all_credentials.append(pair)
                logger.info("Added %d username-spray pairs for testing on %s", len(discovered_usernames) * 5, final_url)

            max_attempts = min(len(all_credentials), max(1, min(int(max_attempts or 1), 15)))
            safe_delay = max(0.5, min(float(delay_seconds or 0.5), 5.0))
            for username, password in all_credentials[:max_attempts]:
                attempts_made += 1
                await asyncio.sleep(safe_delay)

                post_data = {**hidden_fields, user_field: username, pass_field: password}
                try:
                    resp = await client.post(action_url, data=post_data, headers=_HEADERS)
                except Exception as exc:
                    logger.debug("Auth test request failed on %s: %s", action_url, exc)
                    break

                body_text = resp.text

                # 1. Check for Defensive Lockout / Rate Limit intervention
                if resp.status_code == 429 or any(re.search(pat, body_text, re.IGNORECASE) for pat in self.LOCKOUT_SIGNATURES):
                    logger.info("Defense verified: Account/IP lockout triggered after %d attempts on %s", attempts_made, final_url)
                    lockout_encountered = True
                    break

                # 2. Check for Successful Authentication
                is_success = False
                if resp.status_code in (200, 301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    redirect_url = urljoin(action_url, location) if location else ""
                    redirected_to_app = (
                        bool(redirect_url)
                        and self._same_origin(final_url, redirect_url)
                        and not self._looks_like_auth_path(redirect_url)
                    )
                    if redirected_to_app:
                        is_success = True
                    elif any(re.search(pat, body_text, re.IGNORECASE) for pat in self.LOGIN_SUCCESS_SIGNATURES):
                        if not any(re.search(fail, body_text, re.IGNORECASE) for fail in self.LOGIN_FAILURE_SIGNATURES):
                            is_success = True

                if is_success:
                    valid_credential_found = (username, password)
                    logger.warning("CONFIRMED: Default credential '%s:***' accepted on %s", username, final_url)
                    break
                elif resp.status_code == 200:
                    successful_failure_responses += 1

            # Synthesize Findings based on empirical evidence

            # Finding A: Default Credentials Accepted (CRITICAL)
            if valid_credential_found:
                u, p = valid_credential_found
                curl_cmd = f"curl -sk -X POST '{action_url}' -d '{user_field}={u}&{pass_field}=[REDACTED]'"
                candidates.append(BruteForceCandidate(
                    url=final_url,
                    username_tested=u,
                    technique="default_credential_acceptance",
                    confidence="CONFIRMED",
                    evidence_level="E3",
                    finding_type="default_credentials",
                    title=f"Default Credentials Discovered on Login Portal ({u})",
                    severity="CRITICAL",
                    reproduction_steps=[
                        f"Navigate to login portal: {final_url}",
                        f"Submit the internally verified credential for username '{u}' (password redacted; hash prefix recorded in evidence).",
                        "Observe successful authentication and redirection to authorized interface.",
                    ],
                    poc_curl=curl_cmd,
                    evidence={
                        "action_url": action_url,
                        "login_url": final_url,
                        "username": u,
                        "password_sha256": self._password_hash(p),
                        "password_value": self._redacted_password(p),
                        "attempts_count": attempts_made,
                    },
                    impact_matrix={
                        "confidentiality": "CRITICAL",
                        "integrity": "CRITICAL",
                        "availability": "HIGH",
                        "auth_bypass": "CONFIRMED",
                        "data_exposure": "CRITICAL",
                    },
                    remediation="Immediately revoke and change default administrator passwords. Implement multi-factor authentication (MFA).",
                ))

            # Finding B: Missing Lockout & Rate-Limiting Policy (MEDIUM) - ONLY if authentic login processing was verified!
            elif (
                not lockout_encountered
                and attempts_made >= min(5, max_attempts)
                and successful_failure_responses >= min(5, attempts_made)
            ):
                curl_cmd = f"curl -sk -X POST '{action_url}' -d '{user_field}=admin&{pass_field}=test'"
                candidates.append(BruteForceCandidate(
                    url=final_url,
                    username_tested="admin",
                    technique="unbounded_authentication_attempts",
                    confidence="VALIDATED",
                    evidence_level="E2",
                    finding_type="missing_rate_limiting",
                    title="Missing Rate Limiting & Account Lockout Protection on Login Portal",
                    severity="MEDIUM",
                    reproduction_steps=[
                        f"Send {attempts_made} sequential invalid login attempts to {action_url}",
                        "Observe HTTP 200 responses without 429 Too Many Requests, CAPTCHA, or progressive delay.",
                        "System fails to enforce lockout policy, enabling automated password spraying.",
                    ],
                    poc_curl=curl_cmd,
                    evidence={
                        "action_url": action_url,
                        "login_url": final_url,
                        "attempts_executed": attempts_made,
                        "lockout_observed": False,
                    },
                    impact_matrix={
                        "confidentiality": "MEDIUM",
                        "integrity": "LOW",
                        "availability": "NONE",
                        "auth_bypass": "POSSIBLE",
                    },
                    remediation="Implement progressive rate limiting (e.g. 5 failed attempts per 15 minutes), CAPTCHA challenges, and IP throttling.",
                ))

        return candidates

    async def validate_phpmyadmin(
        self,
        url: str,
        *,
        max_attempts: int = 5,
        delay_seconds: float = 0.5,
    ) -> List[BruteForceCandidate]:
        """Specific default credentials audit for phpMyAdmin portals."""
        candidates: List[BruteForceCandidate] = []

        creds = [
            ("root", ""),
            ("root", "root"),
            ("root", "mysql"),
            ("admin", "admin"),
            ("root", "password"),
        ]

        async with ValidationHTTPClient(timeout=_TIMEOUT, verify=False, follow_redirects=False) as client:
            try:
                resp = await client.get(url, headers=_HEADERS)
                if resp.status_code != 200:
                    return candidates

                body = resp.text
                final_url = str(resp.url)

                if not any(k in body.lower() for k in ["pma_username", "pma_password", "welcome to phpmyadmin", "phpmyadmin"]):
                    return candidates

                token_match = re.search(r'name=["\']token["\']\s+value=["\']([^"\']+)["\']', body, re.IGNORECASE)
                token = token_match.group(1) if token_match else ""

                hidden_fields = {}
                if token:
                    hidden_fields["token"] = token

                action_match = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', body, re.IGNORECASE)
                action = action_match.group(1) if action_match else "index.php"
                action_url = urljoin(final_url, action)

                allowed_attempts = min(len(creds), max(1, min(int(max_attempts or 1), 5)))
                safe_delay = max(0.5, min(float(delay_seconds or 0.5), 5.0))
                for username, password in creds[:allowed_attempts]:
                    await asyncio.sleep(safe_delay)
                    post_data = {
                        **hidden_fields,
                        "pma_username": username,
                        "pma_password": password,
                        "server": "1",
                    }

                    try:
                        post_resp = await client.post(action_url, data=post_data, headers=_HEADERS)
                        post_body = post_resp.text

                        is_success = False
                        if post_resp.status_code in (200, 302):
                            if "logout" in post_body.lower() or "server_sql.php" in post_body.lower() or "db_structure.php" in post_body.lower():
                                is_success = True
                            location = post_resp.headers.get("location", "")
                            redirect_url = urljoin(action_url, location) if location else ""
                            if (
                                redirect_url
                                and self._same_origin(final_url, redirect_url)
                                and ("index.php" in redirect_url or "server" in redirect_url or "token" in redirect_url)
                            ):
                                is_success = True

                        if is_success:
                            curl_cmd = f"curl -sk -X POST '{action_url}' -d 'pma_username={username}&pma_password=[REDACTED]&server=1'"
                            candidates.append(BruteForceCandidate(
                                url=final_url,
                                username_tested=username,
                                technique="phpmyadmin_default_credentials",
                                confidence="CONFIRMED",
                                evidence_level="E3",
                                finding_type="default_credentials",
                                title=f"phpMyAdmin Default Credentials Discovered ({username})",
                                severity="CRITICAL",
                                reproduction_steps=[
                                    f"1. Navigate to phpMyAdmin login portal: {final_url}",
                                    f"2. Submit the internally verified credential for username {username}; password is redacted in reports.",
                                    f"3. Verify successful authentication redirects to phpMyAdmin dashboard.",
                                    f"4. PoC Command:\n```bash\n{curl_cmd}\n```"
                                ],
                                poc_curl=curl_cmd,
                                evidence={
                                    "username": username,
                                    "password_sha256": self._password_hash(password),
                                    "password_value": self._redacted_password(password),
                                    "port_tech": "phpMyAdmin",
                                    "endpoint": final_url,
                                    "technique": "phpmyadmin_default_credentials",
                                    "status_code": post_resp.status_code,
                                    "indicator": "Redirected to dashboard or logout option rendered"
                                },
                                impact_matrix={"confidentiality": "CRITICAL", "integrity": "CRITICAL", "availability": "HIGH"},
                                remediation="Change default MySQL/phpMyAdmin passwords immediately. Restrict phpMyAdmin access to authorized network segments."
                            ))
                            break
                    except Exception as post_err:
                        logger.debug("phpMyAdmin post error on %s: %s", action_url, post_err)

            except Exception as get_err:
                logger.debug("phpMyAdmin get error on %s: %s", url, get_err)

        return candidates

    async def validate_generic_http_login(
        self,
        url: str,
        discovered_credentials: Optional[List[Tuple[str, str]]] = None,
        discovered_usernames: Optional[List[str]] = None,
        *,
        max_attempts: int = 15,
        delay_seconds: float = 0.5,
    ) -> List[BruteForceCandidate]:
        """Alias wrapper to validate general HTTP form logins using ControlledBruteForceValidator."""
        return await self.validate_login_portal(
            url,
            discovered_credentials,
            discovered_usernames,
            max_attempts=max_attempts,
            delay_seconds=delay_seconds,
        )


# Module-level singleton
controlled_brute_force_validator = ControlledBruteForceValidator()
