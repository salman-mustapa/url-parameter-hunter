"""Deep Service Profiles (V8 §22).

Contains authoritative profiles for 18 core network services:
1. FTP
2. SSH
3. Telnet
4. HTTP/HTTPS
5. SMTP
6. DNS
7. SMB
8. LDAP
9. RDP
10. MSSQL
11. Oracle
12. MySQL / MariaDB
13. PostgreSQL
14. Redis
15. MongoDB
16. Elasticsearch
17. Docker API
18. Kubernetes API

Each profile defines:
- Fingerprint indicators
- Safe non-destructive checks
- Configuration audit checks
- CVE correlation rules
- Validation rules
- Evidence requirements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ServiceProfile:
    name: str
    default_ports: List[int]
    banner_patterns: List[str]
    safe_checks: List[str]
    configuration_checks: List[str]
    cve_correlation_tags: List[str]
    validation_rules: List[str]
    evidence_requirements: List[str]


SERVICE_PROFILES: Dict[str, ServiceProfile] = {
    "ftp": ServiceProfile(
        name="FTP",
        default_ports=[21],
        banner_patterns=[r"^220.*FTP", r"vsftpd", r"Pure-FTPd", r"ProFTPD"],
        safe_checks=["anonymous_login_check", "banner_version_grab", "tls_support_probe"],
        configuration_checks=["cleartext_auth_allowed", "unrestricted_write_permission"],
        cve_correlation_tags=["vsftpd", "proftpd", "pure-ftpd", "filezilla_server"],
        validation_rules=["ftp_anonymous_auth_rule"],
        evidence_requirements=["ftp_banner_text", "server_response_code"],
    ),
    "ssh": ServiceProfile(
        name="SSH",
        default_ports=[22],
        banner_patterns=[r"^SSH-2\.0-OpenSSH", r"^SSH-2\.0-libssh", r"^SSH-2\.0-Dropbear"],
        safe_checks=["kex_algorithm_probe", "host_key_fingerprint", "version_audit"],
        configuration_checks=["deprecated_ciphers", "cbc_mode_enabled", "weak_mac_algorithms"],
        cve_correlation_tags=["openssh", "libssh", "dropbear"],
        validation_rules=["ssh_weak_kex_rule", "ssh_terrapin_cve_2023_48795"],
        evidence_requirements=["kex_algorithms_list", "host_key_sha256", "banner_string"],
    ),
    "telnet": ServiceProfile(
        name="Telnet",
        default_ports=[23],
        banner_patterns=[r"telnetd", r"login:"],
        safe_checks=["banner_grab", "auth_prompt_detection"],
        configuration_checks=["cleartext_protocol_exposed"],
        cve_correlation_tags=["telnetd"],
        validation_rules=["telnet_cleartext_risk_rule"],
        evidence_requirements=["telnet_banner", "connection_transcript"],
    ),
    "http": ServiceProfile(
        name="HTTP/HTTPS",
        default_ports=[80, 443, 8080, 8443],
        banner_patterns=[r"Apache", r"nginx", r"Microsoft-IIS", r"LiteSpeed", r"Cloudflare"],
        safe_checks=["methods_probe", "tls_handshake", "security_headers_audit", "hsts_check"],
        configuration_checks=["debug_endpoints_exposed", "directory_indexing", "weak_tls_ciphers"],
        cve_correlation_tags=["apache_http_server", "nginx", "iis", "tomcat"],
        validation_rules=["http_options_trace_rule", "missing_hsts_rule"],
        evidence_requirements=["response_headers", "status_code", "tls_certificate_sha256"],
    ),
    "smtp": ServiceProfile(
        name="SMTP",
        default_ports=[25, 465, 587],
        banner_patterns=[r"^220.*ESMTP", r"Postfix", r"Exim", r"Sendmail"],
        safe_checks=["ehlo_probe", "starttls_check", "open_relay_check"],
        configuration_checks=["open_relay_misconfiguration", "vrfy_user_enumeration"],
        cve_correlation_tags=["postfix", "exim", "sendmail"],
        validation_rules=["smtp_open_relay_validation_rule"],
        evidence_requirements=["ehlo_response_capabilities", "starttls_cipher"],
    ),
    "dns": ServiceProfile(
        name="DNS",
        default_ports=[53],
        banner_patterns=[r"BIND", r"dnsmasq", r"PowerDNS"],
        safe_checks=["version_bind_query", "recursion_check", "axfr_zone_transfer_probe"],
        configuration_checks=["open_dns_resolver", "zone_transfer_enabled"],
        cve_correlation_tags=["bind", "dnsmasq", "powerdns"],
        validation_rules=["dns_zone_transfer_axfr_rule"],
        evidence_requirements=["axfr_records_sample", "version_bind_txt"],
    ),
    "smb": ServiceProfile(
        name="SMB",
        default_ports=[445, 139],
        banner_patterns=[r"SMB", r"Samba", r"Windows Server"],
        safe_checks=["smb_dialect_negotiation", "null_session_probe", "signing_check"],
        configuration_checks=["smb_v1_enabled", "smb_signing_disabled", "anonymous_shares"],
        cve_correlation_tags=["samba", "ms17_010", "cve_2020_0796"],
        validation_rules=["smb_null_session_rule", "smb_signing_disabled_rule"],
        evidence_requirements=["dialect_version", "signing_status", "share_listing"],
    ),
    "ldap": ServiceProfile(
        name="LDAP",
        default_ports=[389, 636],
        banner_patterns=[r"OpenLDAP", r"Active Directory"],
        safe_checks=["root_dse_search", "anonymous_bind_check", "starttls_probe"],
        configuration_checks=["anonymous_ldap_query_allowed", "cleartext_ldap_enabled"],
        cve_correlation_tags=["openldap", "active_directory"],
        validation_rules=["ldap_anonymous_bind_rule"],
        evidence_requirements=["root_dse_attributes", "naming_contexts"],
    ),
    "rdp": ServiceProfile(
        name="RDP",
        default_ports=[3389],
        banner_patterns=[r"Remote Desktop", r"mstsc", r"xrdp"],
        safe_checks=["nla_negotiation_check", "tls_certificate_audit", "cookie_routing_probe"],
        configuration_checks=["nla_disabled", "weak_encryption_level", "bluekeep_cve_2019_0708"],
        cve_correlation_tags=["remote_desktop_services", "xrdp", "cve_2019_0708"],
        validation_rules=["rdp_nla_disabled_rule", "rdp_weak_encryption_rule"],
        evidence_requirements=["rdp_security_layer", "nla_enforced_flag", "tls_fingerprint"],
    ),
    "mssql": ServiceProfile(
        name="MSSQL",
        default_ports=[1433],
        banner_patterns=[r"Microsoft SQL Server"],
        safe_checks=["tds_prelogin_handshake", "tls_encryption_check", "instance_discovery"],
        configuration_checks=["force_encryption_disabled", "default_sa_account"],
        cve_correlation_tags=["mssql_server"],
        validation_rules=["mssql_unencrypted_tds_rule"],
        evidence_requirements=["tds_version", "encryption_flags"],
    ),
    "oracle": ServiceProfile(
        name="Oracle DB",
        default_ports=[1521],
        banner_patterns=[r"TNSLSNR", r"Oracle Database"],
        safe_checks=["tns_ping", "version_banner_grab", "sid_enumeration"],
        configuration_checks=["tns_listener_unprotected"],
        cve_correlation_tags=["oracle_database"],
        validation_rules=["oracle_tns_listener_info_rule"],
        evidence_requirements=["tns_version_banner", "status_response"],
    ),
    "mysql": ServiceProfile(
        name="MySQL / MariaDB",
        default_ports=[3306],
        banner_patterns=[r"mysql_native_password", r"MariaDB", r"MySQL"],
        safe_checks=["server_greeting_packet", "auth_plugin_check", "tls_support_check"],
        configuration_checks=["unencrypted_auth_allowed", "unauthenticated_exposure"],
        cve_correlation_tags=["mysql", "mariadb"],
        validation_rules=["mysql_unprotected_exposure_rule"],
        evidence_requirements=["mysql_protocol_version", "server_version_string"],
    ),
    "postgresql": ServiceProfile(
        name="PostgreSQL",
        default_ports=[5432],
        banner_patterns=[r"PostgreSQL"],
        safe_checks=["startup_message_probe", "ssl_negotiation_check"],
        configuration_checks=["unencrypted_ssl_disabled", "public_postgres_exposure"],
        cve_correlation_tags=["postgresql"],
        validation_rules=["postgres_cleartext_auth_rule"],
        evidence_requirements=["ssl_support_code", "error_response_payload"],
    ),
    "redis": ServiceProfile(
        name="Redis",
        default_ports=[6379],
        banner_patterns=[r"^REDIS", r"-ERR unknown command", r"-NOAUTH"],
        safe_checks=["info_command_probe", "ping_command_probe"],
        configuration_checks=["unauthenticated_redis_access", "protected_mode_disabled"],
        cve_correlation_tags=["redis"],
        validation_rules=["redis_unauthenticated_access_rule"],
        evidence_requirements=["redis_version_string", "unauth_command_output"],
    ),
    "mongodb": ServiceProfile(
        name="MongoDB",
        default_ports=[27017],
        banner_patterns=[r"isMaster", r"buildInfo"],
        safe_checks=["isMaster_command_probe", "buildInfo_probe"],
        configuration_checks=["unauthenticated_mongodb_access", "exposed_databases_list"],
        cve_correlation_tags=["mongodb"],
        validation_rules=["mongodb_unauthenticated_access_rule"],
        evidence_requirements=["mongodb_build_info", "databases_list_sample"],
    ),
    "elasticsearch": ServiceProfile(
        name="Elasticsearch",
        default_ports=[9200],
        banner_patterns=[r"tagline.*You Know, for Search", r"cluster_name"],
        safe_checks=["cluster_health_probe", "nodes_info_probe"],
        configuration_checks=["unauthenticated_elasticsearch_access", "indices_exposed"],
        cve_correlation_tags=["elasticsearch"],
        validation_rules=["elasticsearch_unauthenticated_access_rule"],
        evidence_requirements=["cluster_name", "indices_metadata_sample"],
    ),
    "docker": ServiceProfile(
        name="Docker API",
        default_ports=[2375, 2376],
        banner_patterns=[r"Docker", r"/version", r"/info"],
        safe_checks=["docker_version_probe", "docker_ping_probe"],
        configuration_checks=["unauthenticated_docker_daemon_api"],
        cve_correlation_tags=["docker"],
        validation_rules=["docker_unauthenticated_api_rule"],
        evidence_requirements=["docker_api_version", "engine_metadata"],
    ),
    "kubernetes": ServiceProfile(
        name="Kubernetes API",
        default_ports=[6443, 8443, 10250],
        banner_patterns=[r"k8s", r"kubernetes", r"/api/v1"],
        safe_checks=["unauthenticated_version_probe", "anonymous_auth_check"],
        configuration_checks=["anonymous_kubelet_api", "apiserver_public_read"],
        cve_correlation_tags=["kubernetes"],
        validation_rules=["k8s_anonymous_apiserver_rule"],
        evidence_requirements=["k8s_git_version", "api_resources_sample"],
    ),
}


class ServiceProfileRegistry:
    """Registry providing fast lookup for the 18 deep service profiles."""

    @classmethod
    def get_profile(cls, name: str) -> Optional[ServiceProfile]:
        return SERVICE_PROFILES.get(name.lower().strip())

    @classmethod
    def find_profile_for_port(cls, port: int) -> Optional[ServiceProfile]:
        for prof in SERVICE_PROFILES.values():
            if port in prof.default_ports:
                return prof
        return None

    @classmethod
    def list_profiles(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": p.name,
                "default_ports": p.default_ports,
                "safe_checks": p.safe_checks,
                "cve_tags": p.cve_correlation_tags,
            }
            for p in SERVICE_PROFILES.values()
        ]
