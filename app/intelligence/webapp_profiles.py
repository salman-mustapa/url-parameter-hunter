"""Deep Web & Application Stack Profiles (V8 §23).

Contains authoritative profiles for 15 core web technologies & frameworks:
1. WordPress
2. Drupal
3. Joomla
4. Laravel
5. Django
6. Spring
7. Node.js
8. PHP
9. Apache
10. Nginx
11. IIS
12. Tomcat
13. REST API
14. GraphQL
15. WebSocket

Each profile determines specific test plans, fingerprint signatures, safe checks,
and validation rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class WebAppProfile:
    name: str
    category: str
    signature_patterns: List[str]
    safe_checks: List[str]
    config_audit_checks: List[str]
    cve_tags: List[str]
    validation_modules: List[str]
    evidence_requirements: List[str]


WEBAPP_PROFILES: Dict[str, WebAppProfile] = {
    "wordpress": WebAppProfile(
        name="WordPress",
        category="CMS",
        signature_patterns=[r"wp-content", r"wp-includes", r"wp-json", r"meta name=\"generator\" content=\"WordPress"],
        safe_checks=["wp_version_probe", "plugin_enumeration", "theme_detection", "user_enum_rest_api"],
        config_audit_checks=["debug_log_exposed", "xmlrpc_enabled", "wp_config_backup_probe"],
        cve_tags=["wordpress", "wp_plugin", "wp_theme"],
        validation_modules=["cms.wordpress", "file.sensitive"],
        evidence_requirements=["wp_version_string", "active_plugins_list", "xmlrpc_response"],
    ),
    "drupal": WebAppProfile(
        name="Drupal",
        category="CMS",
        signature_patterns=[r"Drupal", r"sites/default", r"misc/drupal\.js"],
        safe_checks=["drupal_version_probe", "changelog_txt_probe"],
        config_audit_checks=["drupalgeddon_cve_check", "exposed_install_php"],
        cve_tags=["drupal", "drupalgeddon"],
        validation_modules=["cms.drupal", "injection.sqli"],
        evidence_requirements=["drupal_version", "changelog_headers"],
    ),
    "joomla": WebAppProfile(
        name="Joomla",
        category="CMS",
        signature_patterns=[r"Joomla!", r"/administrator/help/", r"meta name=\"generator\" content=\"Joomla!"],
        safe_checks=["joomla_manifest_probe", "version_xml_check"],
        config_audit_checks=["configuration_php_bak_probe", "debug_system_plugin"],
        cve_tags=["joomla"],
        validation_modules=["cms.joomla"],
        evidence_requirements=["joomla_version", "manifest_xml_snippet"],
    ),
    "laravel": WebAppProfile(
        name="Laravel",
        category="Framework",
        signature_patterns=[r"laravel_session", r"XSRF-TOKEN", r"Whoops! There was an error"],
        safe_checks=["laravel_debug_mode_check", "telescope_exposure_check", "horizon_dashboard_check"],
        config_audit_checks=["ignition_rce_cve_2021_3129", "env_file_exposed"],
        cve_tags=["laravel", "ignition"],
        validation_modules=["injection.rce", "file.sensitive"],
        evidence_requirements=["debug_page_trace", "env_variables_sample"],
    ),
    "django": WebAppProfile(
        name="Django",
        category="Framework",
        signature_patterns=[r"csrftoken", r"django-debug-toolbar", r"DisallowedHost at /"],
        safe_checks=["django_admin_discovery", "debug_traceback_check", "static_media_leak"],
        config_audit_checks=["debug_true_exposure", "secret_key_leak"],
        cve_tags=["django"],
        validation_modules=["auth.login", "injection.sqli"],
        evidence_requirements=["django_debug_page", "admin_redirect_url"],
    ),
    "spring": WebAppProfile(
        name="Spring Framework / Boot",
        category="Framework",
        signature_patterns=[r"Whitelabel Error Page", r"X-Application-Context", r"/actuator/"],
        safe_checks=["actuator_endpoints_probe", "heapdump_exposure_check", "env_actuator_check"],
        config_audit_checks=["spring4shell_cve_2022_22965", "spel_injection_check"],
        cve_tags=["spring_boot", "spring_framework", "spring4shell"],
        validation_modules=["injection.rce", "file.sensitive"],
        evidence_requirements=["actuator_endpoints_json", "whitelabel_header"],
    ),
    "nodejs": WebAppProfile(
        name="Node.js / Express",
        category="Runtime",
        signature_patterns=[r"X-Powered-By: Express", r"connect\.sid", r"node_modules"],
        safe_checks=["express_error_disclosure", "source_map_exposure", "prototype_pollution_probe"],
        config_audit_checks=["package_json_exposed", "debug_npm_logs"],
        cve_tags=["express", "nodejs"],
        validation_modules=["injection.ssrf", "injection.rce"],
        evidence_requirements=["express_error_snippet", "source_map_url"],
    ),
    "php": WebAppProfile(
        name="PHP",
        category="Language Runtime",
        signature_patterns=[r"PHPSESSID", r"X-Powered-By: PHP", r"\.php(?:\?|$)"],
        safe_checks=["phpinfo_probe", "cgi_argument_injection_cve_2024_4577", "expose_php_header"],
        config_audit_checks=["php_errors_displayed", "phpmyadmin_exposed"],
        cve_tags=["php", "cve_2024_4577"],
        validation_modules=["injection.rce", "file.sensitive"],
        evidence_requirements=["phpinfo_headers", "php_version_string"],
    ),
    "apache": WebAppProfile(
        name="Apache HTTP Server",
        category="Web Server",
        signature_patterns=[r"Server: Apache", r"Apache/2\."],
        safe_checks=["apache_server_status_probe", "server_info_probe", "mod_status_check"],
        config_audit_checks=["cve_2021_41773_path_traversal", "cve_2021_42013_rce", "htaccess_exposed"],
        cve_tags=["apache_http_server", "cve_2021_41773"],
        validation_modules=["file.traversal", "injection.rce"],
        evidence_requirements=["apache_server_banner", "traversal_response_evidence"],
    ),
    "nginx": WebAppProfile(
        name="Nginx",
        category="Web Server",
        signature_patterns=[r"Server: nginx", r"nginx/1\."],
        safe_checks=["nginx_status_probe", "alias_traversal_misconfig_check"],
        config_audit_checks=["off_by_slash_alias_traversal", "default_welcome_page"],
        cve_tags=["nginx"],
        validation_modules=["file.traversal"],
        evidence_requirements=["nginx_banner", "alias_traversal_payload"],
    ),
    "iis": WebAppProfile(
        name="Microsoft IIS",
        category="Web Server",
        signature_patterns=[r"Server: Microsoft-IIS", r"X-Powered-By: ASP.NET"],
        safe_checks=["iis_shortname_enumeration", "trace_axd_exposure", "elmah_axd_exposure"],
        config_audit_checks=["aspnet_detailed_errors", "web_config_leak"],
        cve_tags=["iis", "asp_net"],
        validation_modules=["file.sensitive", "injection.sqli"],
        evidence_requirements=["iis_banner", "shortname_response_diff"],
    ),
    "tomcat": WebAppProfile(
        name="Apache Tomcat",
        category="Application Server",
        signature_patterns=[r"Apache Tomcat", r"Apache-Coyote", r"/manager/html"],
        safe_checks=["tomcat_manager_discovery", "host_manager_discovery", "default_credentials_probe"],
        config_audit_checks=["ghostcat_cve_2020_1938", "examples_servlets_exposed"],
        cve_tags=["tomcat", "cve_2020_1938"],
        validation_modules=["auth.login", "file.sensitive"],
        evidence_requirements=["tomcat_version_title", "manager_auth_prompt"],
    ),
    "rest_api": WebAppProfile(
        name="REST API",
        category="API",
        signature_patterns=[r"application/json", r"/api/v[1-9]/", r"/swagger", r"/openapi.json"],
        safe_checks=["openapi_spec_discovery", "swagger_ui_check", "http_methods_fuzzing"],
        config_audit_checks=["unauthenticated_api_docs", "mass_assignment_check", "cors_wildcard"],
        cve_tags=["swagger", "openapi", "rest_api"],
        validation_modules=["api.rest", "access.idor"],
        evidence_requirements=["openapi_json_sample", "swagger_endpoint_url"],
    ),
    "graphql": WebAppProfile(
        name="GraphQL",
        category="API",
        signature_patterns=[r"/graphql", r"GraphQL Query", r"query\s*\{"],
        safe_checks=["introspection_query_probe", "graphiql_ui_check", "field_suggestion_check"],
        config_audit_checks=["introspection_enabled_in_prod", "dos_batching_allowed"],
        cve_tags=["graphql", "apollo_server"],
        validation_modules=["api.graphql", "access.idor"],
        evidence_requirements=["introspection_schema_types", "graphiql_url"],
    ),
    "websocket": WebAppProfile(
        name="WebSocket",
        category="Protocol",
        signature_patterns=[r"Upgrade: websocket", r"Connection: Upgrade", r"Sec-WebSocket-Accept"],
        safe_checks=["ws_handshake_probe", "origin_validation_probe"],
        config_audit_checks=["cross_site_websocket_hijacking", "unauthenticated_ws_connection"],
        cve_tags=["websocket"],
        validation_modules=["api.rest"],
        evidence_requirements=["ws_handshake_response", "origin_reflection"],
    ),
}


class WebAppProfileRegistry:
    """Fast lookup registry for the 15 deep web application profiles (V8 §23)."""

    @classmethod
    def get_profile(cls, name: str) -> Optional[WebAppProfile]:
        return WEBAPP_PROFILES.get(name.lower().strip())

    @classmethod
    def list_profiles(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": p.name,
                "category": p.category,
                "safe_checks": p.safe_checks,
                "validation_modules": p.validation_modules,
            }
            for p in WEBAPP_PROFILES.values()
        ]
