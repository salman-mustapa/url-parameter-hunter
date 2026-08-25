"""MITRE ATT&CK Enterprise Matrix & Threat Behavioral Modeling Engine (V4 & V5 §26).

Maps reconnaissance observations, technical indicators, and validated findings
to official MITRE ATT&CK Enterprise v14/v15 across all 14 Tactics.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class TtpEngine:
    """MITRE ATT&CK Behavioral and TTP Context Engine."""

    TACTICS_ORDER = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    TTP_REGISTRY = [
        # --- 1. Reconnaissance (TA0043) ---
        {
            "technique_id": "T1595",
            "name": "Active Scanning",
            "tactic": "Reconnaissance",
            "triggers": ["port_scan", "web_probe", "parameter_discovery", "crawler"],
            "mitre_url": "https://attack.mitre.org/techniques/T1595/",
            "description": "Active network and web probing against public attack surfaces.",
        },
        {
            "technique_id": "T1595.002",
            "name": "Active Scanning: Vulnerability Scanning",
            "tactic": "Reconnaissance",
            "triggers": ["vuln_scan", "sqli_probe", "xss_probe", "security_checks"],
            "mitre_url": "https://attack.mitre.org/techniques/T1595/002/",
            "description": "Targeted active testing against specific web application interfaces.",
        },
        {
            "technique_id": "T1596",
            "name": "Search Open Technical Databases",
            "tactic": "Reconnaissance",
            "triggers": ["ct_logs", "passive_dns", "whois", "shodan", "otx"],
            "mitre_url": "https://attack.mitre.org/techniques/T1596/",
            "description": "Gathering historical domain and endpoint metadata from public databases.",
        },
        {
            "technique_id": "T1596.005",
            "name": "Search Open Technical Databases: Code Repositories",
            "tactic": "Reconnaissance",
            "triggers": ["git", "git_head", "git_config", "github", "gitlab"],
            "mitre_url": "https://attack.mitre.org/techniques/T1596/005/",
            "description": "Harvesting exposed code repositories and revision control metadata.",
        },
        {
            "technique_id": "T1592",
            "name": "Gather Victim Host Information",
            "tactic": "Reconnaissance",
            "triggers": ["tls_cert", "banner_grab", "phpinfo", "actuator", "tech_stack"],
            "mitre_url": "https://attack.mitre.org/techniques/T1592/",
            "description": "Extracting server software architectures, diagnostic endpoints, and configurations.",
        },
        {
            "technique_id": "T1590",
            "name": "Gather Victim Network Information",
            "tactic": "Reconnaissance",
            "triggers": ["dns_zone", "dns_record", "asn", "cidr"],
            "mitre_url": "https://attack.mitre.org/techniques/T1590/",
            "description": "Enumerating DNS relationships, IP ranges, and network topologies.",
        },

        # --- 2. Resource Development (TA0042) ---
        {
            "technique_id": "T1588.005",
            "name": "Obtain Capabilities: Exploits",
            "tactic": "Resource Development",
            "triggers": ["cve_exploit", "cve_match", "poc_harness"],
            "mitre_url": "https://attack.mitre.org/techniques/T1588/005/",
            "description": "Acquiring public or customized proof-of-concept exploits matching software vulnerabilities.",
        },
        {
            "technique_id": "T1587.001",
            "name": "Develop Capabilities: Malware / Payloads",
            "tactic": "Resource Development",
            "triggers": ["payload_synthesis", "custom_payload", "canary_token"],
            "mitre_url": "https://attack.mitre.org/techniques/T1587/001/",
            "description": "Constructing specialized verification probes and non-destructive canaries.",
        },

        # --- 3. Initial Access (TA0001) ---
        {
            "technique_id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "triggers": ["cve", "sqli", "rce", "xss", "upload", "ssrf", "traversal", "auth_bypass"],
            "mitre_url": "https://attack.mitre.org/techniques/T1190/",
            "description": "Exploiting software flaws in Internet-accessible applications to execute logic or bypass controls.",
        },
        {
            "technique_id": "T1078",
            "name": "Valid Accounts: Default Credentials",
            "tactic": "Initial Access",
            "triggers": ["default_creds", "admin_admin", "weak_auth", "hardcoded_key"],
            "mitre_url": "https://attack.mitre.org/techniques/T1078/",
            "description": "Obtaining and abusing default or unauthenticated administrative credentials.",
        },
        {
            "technique_id": "T1189",
            "name": "Drive-by Compromise",
            "tactic": "Initial Access",
            "triggers": ["xss", "xss_reflection", "stored_xss", "dom_xss"],
            "mitre_url": "https://attack.mitre.org/techniques/T1189/",
            "description": "Triggering client-side script execution when victim users navigate to vulnerable endpoints.",
        },

        # --- 4. Execution (TA0002) ---
        {
            "technique_id": "T1059.007",
            "name": "Command and Scripting Interpreter: JavaScript",
            "tactic": "Execution",
            "triggers": ["xss", "javascript", "dom_injection", "eval_js"],
            "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
            "description": "Executing untrusted JavaScript in the context of the user's active browser session.",
        },
        {
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter: Command Injection",
            "tactic": "Execution",
            "triggers": ["rce", "command_injection", "shell_exec", "os_exec"],
            "mitre_url": "https://attack.mitre.org/techniques/T1059/",
            "description": "Executing arbitrary operating system commands via shell or scripting interpreters.",
        },

        # --- 5. Persistence (TA0003) ---
        {
            "technique_id": "T1505.003",
            "name": "Server Software Component: Web Shell",
            "tactic": "Persistence",
            "triggers": ["file_upload", "upload_vuln", "webshell", "unrestricted_upload"],
            "mitre_url": "https://attack.mitre.org/techniques/T1505/003/",
            "description": "Uploading executable script files (PHP, JSP, ASPX) to persistent web directories.",
        },
        {
            "technique_id": "T1136",
            "name": "Create Account: Unauthorized Registration",
            "tactic": "Persistence",
            "triggers": ["registration_bypass", "user_creation", "account_takeover"],
            "mitre_url": "https://attack.mitre.org/techniques/T1136/",
            "description": "Creating unauthorized user or admin accounts via vulnerable registration endpoints.",
        },

        # --- 6. Privilege Escalation (TA0004) ---
        {
            "technique_id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "triggers": ["privilege_escalation", "idor_admin", "role_bypass"],
            "mitre_url": "https://attack.mitre.org/techniques/T1068/",
            "description": "Leveraging software weaknesses to gain elevated administrator privileges.",
        },

        # --- 7. Defense Evasion (TA0005) ---
        {
            "technique_id": "T1027",
            "name": "Obfuscated/Encoded Files or Information",
            "tactic": "Defense Evasion",
            "triggers": ["waf_bypass", "encoding_bypass", "unicode_wrap", "url_encode"],
            "mitre_url": "https://attack.mitre.org/techniques/T1027/",
            "description": "Employing encoding, chunking, or obfuscation to evade inspection by WAF rules.",
        },
        {
            "technique_id": "T1562.001",
            "name": "Impair Defenses: Disable or Evade Security Controls",
            "tactic": "Defense Evasion",
            "triggers": ["waf_evasion", "rate_limit_bypass", "ip_spoofing"],
            "mitre_url": "https://attack.mitre.org/techniques/T1562/001/",
            "description": "Bypassing WAF inspection or client IP rate limits via header spoofing.",
        },

        # --- 8. Credential Access (TA0006) ---
        {
            "technique_id": "T1552",
            "name": "Unsecured Credentials",
            "tactic": "Credential Access",
            "triggers": ["db_exposure", "sql_dump", "backup_sql", "credential_leak", "password_hash", "env_file", "secret_exposure"],
            "mitre_url": "https://attack.mitre.org/techniques/T1552/",
            "description": "Searching local or public file structures for unsecured, hardcoded, or exposed database credentials.",
        },
        {
            "technique_id": "T1552.001",
            "name": "Unsecured Credentials: Credentials In Files",
            "tactic": "Credential Access",
            "triggers": ["env", "env_exposure", "backup_sql", "secret_exposure", "git_exposure", "jwt_secret", "env_file"],
            "mitre_url": "https://attack.mitre.org/techniques/T1552/001/",
            "description": "Extracting API keys, database connection strings, and plaintext credentials from exposed files.",
        },
        {
            "technique_id": "T1110",
            "name": "Brute Force: Credential Stuffing / Password Guessing",
            "tactic": "Credential Access",
            "triggers": ["brute_force", "weak_password", "credential_stuffing"],
            "mitre_url": "https://attack.mitre.org/techniques/T1110/",
            "description": "Iterating authentication credentials against unprotected login forms.",
        },

        # --- 9. Discovery (TA0007) ---
        {
            "technique_id": "T1046",
            "name": "Network Service Discovery",
            "tactic": "Discovery",
            "triggers": ["ssrf", "port_scan", "service_probe"],
            "mitre_url": "https://attack.mitre.org/techniques/T1046/",
            "description": "Iterating ports and internal services to map listening application components.",
        },
        {
            "technique_id": "T1083",
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "triggers": ["traversal", "path_traversal", "directory_listing", "lfi", "sensitive_files"],
            "mitre_url": "https://attack.mitre.org/techniques/T1083/",
            "description": "Enumerating files and directories on local and remote filesystem hierarchies.",
        },
        {
            "technique_id": "T1082",
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "triggers": ["log_file", "log_exposure", "actuator", "phpinfo", "system_info", "info_exposure"],
            "mitre_url": "https://attack.mitre.org/techniques/T1082/",
            "description": "Harvesting detailed operating system, framework, and software revision telemetry.",
        },

        # --- 10. Lateral Movement (TA0008) ---
        {
            "technique_id": "T1021.001",
            "name": "Remote Services: Remote Desktop Protocol",
            "tactic": "Lateral Movement",
            "triggers": ["rdp", "rdp_exposed", "port_3389"],
            "mitre_url": "https://attack.mitre.org/techniques/T1021/001/",
            "description": "Interacting with exposed RDP management interfaces across network segments.",
        },
        {
            "technique_id": "T1021.004",
            "name": "Remote Services: SSH",
            "tactic": "Lateral Movement",
            "triggers": ["ssh", "ssh_exposed", "port_22"],
            "mitre_url": "https://attack.mitre.org/techniques/T1021/004/",
            "description": "Connecting to remote interactive shell listeners via SSH protocols.",
        },

        # --- 11. Collection (TA0009) ---
        {
            "technique_id": "T1005",
            "name": "Data from Local System",
            "tactic": "Collection",
            "triggers": ["data_exposure", "csv", "csv_export", "data_leak", "pii_exposure", "db_exposure", "sql_dump"],
            "mitre_url": "https://attack.mitre.org/techniques/T1005/",
            "description": "Harvesting sensitive PII records, student rosters, or database tables stored on application endpoints.",
        },
        {
            "technique_id": "T1530",
            "name": "Data from Cloud Storage Object",
            "tactic": "Collection",
            "triggers": ["s3_bucket", "cloud_storage", "azure_blob", "bucket_leak", "archive_exposure", "backup_archive"],
            "mitre_url": "https://attack.mitre.org/techniques/T1530/",
            "description": "Accessing and retrieving data from misconfigured or unauthenticated cloud storage buckets.",
        },
        {
            "technique_id": "T1213",
            "name": "Data from Information Repositories",
            "tactic": "Collection",
            "triggers": ["sqli_data", "dump_data", "unauthorized_export", "db_exposure"],
            "mitre_url": "https://attack.mitre.org/techniques/T1213/",
            "description": "Extracting structured proprietary data from application databases and repositories.",
        },

        # --- 12. Command and Control (TA0011) ---
        {
            "technique_id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "triggers": ["c2_beacon", "http_tunnel", "ssrf_callback"],
            "mitre_url": "https://attack.mitre.org/techniques/T1071/001/",
            "description": "Establishing bi-directional outbound HTTP/HTTPS communication channels.",
        },

        # --- 13. Exfiltration (TA0010) ---
        {
            "technique_id": "T1567",
            "name": "Exfiltration Over Web Service",
            "tactic": "Exfiltration",
            "triggers": ["oob_dns", "oob_http", "data_exfil", "ssrf_exfil"],
            "mitre_url": "https://attack.mitre.org/techniques/T1567/",
            "description": "Transferring extracted application data or tokens out-of-band via web services.",
        },

        # --- 14. Impact (TA0040) ---
        {
            "technique_id": "T1499",
            "name": "Endpoint Denial of Service",
            "tactic": "Impact",
            "triggers": ["rapid_reset", "dos_flaw", "resource_exhaustion"],
            "mitre_url": "https://attack.mitre.org/techniques/T1499/",
            "description": "Exploiting concurrency or stream flaws to cause service degradation.",
        },
        {
            "technique_id": "T1491.001",
            "name": "Defacement: Internal Defacement",
            "tactic": "Impact",
            "triggers": ["defacement", "html_injection", "content_spoofing"],
            "mitre_url": "https://attack.mitre.org/techniques/T1491/001/",
            "description": "Modifying web application content or appearance visible to authorized users.",
        },
    ]

    @classmethod
    def correlate(cls, trigger: str) -> List[Dict[str, Any]]:
        """Correlates a given trigger or keyword with registered MITRE ATT&CK techniques."""
        matched = []
        t_clean = trigger.lower().strip()
        seen_ids = set()

        for item in cls.TTP_REGISTRY:
            if item["technique_id"] in seen_ids:
                continue
            if any(t_clean in trig or trig in t_clean for trig in item["triggers"]):
                seen_ids.add(item["technique_id"])
                matched.append({
                    "technique_id": item["technique_id"],
                    "technique_name": item["name"],
                    "tactic": item["tactic"],
                    "mitre_url": item["mitre_url"],
                    "description": item.get("description", ""),
                    "confidence": "OBSERVED",
                })

        return matched
