"""Centralized Vulnerability Contract Registry (V10 Evidence-Driven Validation Architecture).

Registers technical contracts for all supported vulnerability categories, ensuring
that no finding can be confirmed without satisfying its specific technical invariants.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from app.validation.contracts.model import SafeValidationLevel, VulnerabilityContract

logger = logging.getLogger("validation.contracts")


class ContractRegistry:
    """Registry maintaining formal verification contracts for all vulnerability families."""

    def __init__(self) -> None:
        self._contracts: Dict[str, VulnerabilityContract] = {}
        self._initialize_built_in_contracts()

    def register(self, contract: VulnerabilityContract) -> None:
        """Register or override a vulnerability contract."""
        self._contracts[contract.id.lower()] = contract
        logger.debug("Registered vulnerability contract: %s (%s)", contract.id, contract.name)

    def get(self, vulnerability_id: str) -> Optional[VulnerabilityContract]:
        """Retrieve contract by ID (case-insensitive)."""
        clean_id = vulnerability_id.lower().strip()
        # Direct lookup or canonical alias
        if clean_id in self._contracts:
            return self._contracts[clean_id]

        # Alias mappings
        alias_map = {
            "sql_injection": "sqli",
            "cross_site_scripting": "xss",
            "remote_code_execution": "rce",
            "server_side_request_forgery": "ssrf",
            "local_file_inclusion": "path_traversal",
            "lfi": "path_traversal",
            "bola": "idor",
            "broken_object_level_authorization": "idor",
            "arbitrary_file_upload": "file_upload",
            "unvalidated_redirect": "open_redirect",
            "slowloris_dos": "slowloris",
        }
        mapped_id = alias_map.get(clean_id)
        if mapped_id and mapped_id in self._contracts:
            return self._contracts[mapped_id]

        return None

    def get_all(self) -> List[VulnerabilityContract]:
        """Return list of all registered contracts."""
        return list(self._contracts.values())

    def _initialize_built_in_contracts(self) -> None:
        """Initialize built-in contracts for all primary vulnerability families."""

        # 1. SQL Injection (SQLi)
        self.register(
            VulnerabilityContract(
                id="sqli",
                name="SQL Injection",
                category="injection",
                cwe_id="CWE-89",
                detection_strategy="Parameter mutation with SQL syntactic markers and timing primitives.",
                validation_strategy="Differential comparison between baseline, true-boolean control, false-boolean control, and syntax differential.",
                required_evidence=[
                    "baseline_response",
                    "control_response",
                    "differential_response",
                    "deterministic_repeatability",
                ],
                supporting_evidence=[
                    "database_error_signature",
                    "time_delay_differential",
                    "dbms_fingerprint",
                ],
                confirmation_rules=[
                    "True-condition payload matches baseline structure while false-condition causes consistent divergence.",
                    "Time-delay probe causes reproducible differential exceeding baseline latency by >= 3.0 seconds.",
                    "Database syntax error distinctly exposed only on unescaped quote mutation.",
                ],
                rejection_rules=[
                    "Generic HTTP 500 error without differential syntax confirmation.",
                    "Unstable baseline response with high jitter.",
                    "Parameter accepted with HTTP 200 without behavioral change.",
                ],
                confidence_model={"min_confidence_for_confirmation": 85, "requires_differential": True},
                safe_validation_level=SafeValidationLevel.DIFFERENTIAL_PROBE,
            )
        )

        # 2. Cross-Site Scripting (XSS)
        self.register(
            VulnerabilityContract(
                id="xss",
                name="Cross-Site Scripting",
                category="injection",
                cwe_id="CWE-79",
                detection_strategy="Canary injection into reflection sinks and DOM elements.",
                validation_strategy="Context-aware reflection analysis (HTML tag, attribute, script block, DOM sink) and executable context verification.",
                required_evidence=[
                    "unencoded_reflection_evidence",
                    "executable_context_proof",
                    "baseline_comparison",
                ],
                supporting_evidence=[
                    "dom_sink_trace",
                    "csp_absence_or_bypass",
                    "browser_console_execution",
                ],
                confirmation_rules=[
                    "Special characters (< > ' \" `) reflected completely unencoded in executable HTML/JS context.",
                    "Payload breaks out of attribute/tag boundary and introduces executable handler/tag without sanitization.",
                ],
                rejection_rules=[
                    "Reflection is HTML-entity encoded (e.g. &lt;script&gt; or &quot;).",
                    "Reflection is contained strictly within a non-executable context (e.g. JSON string with Content-Type application/json).",
                    "Parameter accepted or reflected in safe plain-text element.",
                ],
                confidence_model={"min_confidence_for_confirmation": 85, "requires_executable_context": True},
                safe_validation_level=SafeValidationLevel.NON_DESTRUCTIVE_BENIGN,
            )
        )

        # 3. Remote Code Execution (RCE)
        self.register(
            VulnerabilityContract(
                id="rce",
                name="Remote Code Execution",
                category="injection",
                cwe_id="CWE-94",
                detection_strategy="Benign mathematical evaluation or echo canary injection.",
                validation_strategy="Non-destructive canary execution verification (e.g. echo token hash, expr calculation) with zero system disruption.",
                required_evidence=[
                    "canary_execution_output",
                    "baseline_absence_proof",
                    "repeatable_execution_marker",
                ],
                supporting_evidence=[
                    "system_environment_marker",
                    "time_delay_execution_probe",
                ],
                confirmation_rules=[
                    "Server response contains pre-computed non-destructive canary token or mathematical result impossible via static text reflection.",
                    "Controlled time-delay command causes exact reproducible sleep duration.",
                ],
                rejection_rules=[
                    "Generic HTTP 500 error code.",
                    "Input accepted with HTTP 200 without execution proof.",
                    "Destructive or state-altering commands.",
                ],
                confidence_model={"min_confidence_for_confirmation": 95, "requires_canary_proof": True},
                safe_validation_level=SafeValidationLevel.NON_DESTRUCTIVE_BENIGN,
            )
        )

        # 4. Server-Side Request Forgery (SSRF)
        self.register(
            VulnerabilityContract(
                id="ssrf",
                name="Server-Side Request Forgery",
                category="network",
                cwe_id="CWE-918",
                detection_strategy="Supplying controlled loopback (127.0.0.1/metadata) or authorized listener tokens.",
                validation_strategy="Differential response analysis comparing external vs internal loopback endpoints and authorized out-of-band verification.",
                required_evidence=[
                    "internal_service_interaction_proof",
                    "baseline_external_differential",
                ],
                supporting_evidence=[
                    "cloud_metadata_response",
                    "internal_port_differential",
                    "oob_dns_http_interaction",
                ],
                confirmation_rules=[
                    "Server fetches and exposes internal network resource or cloud instance identity document.",
                    "Differential timing or status proves connection to internal loopback socket vs unreachable port.",
                ],
                rejection_rules=[
                    "URL parameter accepted with HTTP 200 without network fetch.",
                    "Generic HTTP 400/500 on invalid URL.",
                    "Unverified third-party external URLs.",
                ],
                confidence_model={"min_confidence_for_confirmation": 85, "requires_internal_proof": True},
                safe_validation_level=SafeValidationLevel.DIFFERENTIAL_PROBE,
            )
        )

        # 5. Path Traversal / LFI
        self.register(
            VulnerabilityContract(
                id="path_traversal",
                name="Path Traversal / Local File Inclusion",
                category="file_system",
                cwe_id="CWE-22",
                detection_strategy="Injecting directory traversal sequences (../, %2e%2e/) targeting known canonical files.",
                validation_strategy="Content signature verification of known system/application files (/etc/passwd, win.ini, web.config, .env).",
                required_evidence=[
                    "canonical_file_content_signature",
                    "baseline_control_comparison",
                ],
                supporting_evidence=[
                    "system_user_account_list",
                    "environment_variable_definitions",
                ],
                confirmation_rules=[
                    "Response body contains structured multi-line file content matching regular expression signature (e.g. root:x:0:0 or [fonts]).",
                    "Baseline request without traversal returns completely different application content or 404.",
                ],
                rejection_rules=[
                    "HTTP 200 returned on path without exposing unauthorized file contents.",
                    "Normalized redirect or generic home page response.",
                    "Error string matching 'traversal detected' with no file disclosure.",
                ],
                confidence_model={"min_confidence_for_confirmation": 90, "requires_content_signature": True},
                safe_validation_level=SafeValidationLevel.NON_DESTRUCTIVE_BENIGN,
            )
        )

        # 6. Insecure Direct Object Reference (IDOR / BOLA)
        self.register(
            VulnerabilityContract(
                id="idor",
                name="Broken Object Level Authorization (IDOR)",
                category="authorization",
                cwe_id="CWE-639",
                detection_strategy="Object ID manipulation across isolated user identity contexts.",
                validation_strategy="Matrix comparison: User A accessing Resource B owned exclusively by User B, compared against unauthenticated baseline.",
                required_evidence=[
                    "identity_context_a",
                    "identity_context_b",
                    "cross_tenant_resource_data",
                    "authorization_boundary_violation_proof",
                ],
                supporting_evidence=[
                    "state_modification_proof",
                    "differential_user_identifier_leak",
                ],
                confirmation_rules=[
                    "Actor A successfully reads or modifies private data belonging exclusively to Actor B with HTTP 200 containing Actor B sensitive attributes.",
                    "Server does not enforce ownership boundary between disparate authenticated sessions.",
                ],
                rejection_rules=[
                    "Single user accessing own resource returning HTTP 200.",
                    "Endpoint returning public data accessible to any user without authentication.",
                    "HTTP 403 / 401 correctly enforced when ID is altered.",
                ],
                confidence_model={"min_confidence_for_confirmation": 90, "requires_multi_identity_matrix": True},
                safe_validation_level=SafeValidationLevel.CONTROLLED_MUTATION,
            )
        )

        # 7. Authentication Bypass
        self.register(
            VulnerabilityContract(
                id="auth_bypass",
                name="Authentication Bypass",
                category="authentication",
                cwe_id="CWE-287",
                detection_strategy="Header manipulation (X-Forwarded-For, X-Custom-Auth), path truncation, or parameter pollution on protected administrative routes.",
                validation_strategy="State verification comparing access to protected functional route in unauthenticated state vs authenticated administrative state.",
                required_evidence=[
                    "unauthenticated_protected_data_access",
                    "protected_endpoint_functional_proof",
                    "baseline_unauthorized_state",
                ],
                supporting_evidence=[
                    "session_token_minting",
                    "admin_dashboard_dom_elements",
                ],
                confirmation_rules=[
                    "Protected functional administrative endpoint returns full sensitive dashboard content in unauthenticated context when bypass vector applied.",
                    "Baseline request without bypass header/path returns 401/403/Redirect to login.",
                ],
                rejection_rules=[
                    "Login page or public landing page returning HTTP 200.",
                    "Endpoint returning static public assets (css/js/images).",
                    "Partial response with generic 'unauthorized' message in body despite HTTP 200 status code.",
                ],
                confidence_model={"min_confidence_for_confirmation": 90, "requires_protected_resource_proof": True},
                safe_validation_level=SafeValidationLevel.CONTROLLED_MUTATION,
            )
        )

        # 8. Arbitrary File Upload
        self.register(
            VulnerabilityContract(
                id="file_upload",
                name="Arbitrary File Upload",
                category="file_system",
                cwe_id="CWE-434",
                detection_strategy="Multipart upload probing with benign script extensions (.phtml, .php5, .svg) and content types.",
                validation_strategy="Multi-stage validation: Upload Acceptance -> Storage Location Discovery -> Script Execution Verification.",
                required_evidence=[
                    "upload_acceptance_evidence",
                    "storage_url_path",
                    "canary_execution_output",
                ],
                supporting_evidence=[
                    "mime_type_filter_bypass",
                    "extension_filter_bypass",
                ],
                confirmation_rules=[
                    "Uploaded file is accessible via web server and server executes the script, returning benign MD5 hash echo token.",
                ],
                rejection_rules=[
                    "Upload form accepts file but serves it as static octet-stream/text/plain without executing code.",
                    "File uploaded to isolated storage bucket (e.g. S3) without script execution capability.",
                    "HTTP 200 on upload form submission without verifying file storage or execution.",
                ],
                confidence_model={"min_confidence_for_confirmation": 95, "requires_execution_stage": True},
                safe_validation_level=SafeValidationLevel.NON_DESTRUCTIVE_BENIGN,
            )
        )

        # 9. Open Redirect
        self.register(
            VulnerabilityContract(
                id="open_redirect",
                name="Unvalidated URL Redirect",
                category="web",
                cwe_id="CWE-601",
                detection_strategy="Injecting external domain targets into redirect parameters (next=, url=, return=).",
                validation_strategy="Inspection of HTTP 301/302/307 Location response header to confirm user-controlled external host destination.",
                required_evidence=[
                    "location_header_external_target",
                    "baseline_control_comparison",
                ],
                supporting_evidence=[
                    "javascript_location_assignment",
                ],
                confirmation_rules=[
                    "HTTP response Location header contains exact external domain destination (e.g. https://example.com/...) supplied in input.",
                ],
                rejection_rules=[
                    "Redirect remains on same origin or relative path (e.g. /login -> /dashboard).",
                    "Target domain stripped or prepended with internal application host.",
                    "HTTP 200 rendered page with sanitized links.",
                ],
                confidence_model={"min_confidence_for_confirmation": 85, "requires_external_location": True},
                safe_validation_level=SafeValidationLevel.NON_DESTRUCTIVE_BENIGN,
            )
        )

        # 10. CORS Misconfiguration
        self.register(
            VulnerabilityContract(
                id="cors",
                name="Cross-Origin Resource Sharing Misconfiguration",
                category="web",
                cwe_id="CWE-942",
                detection_strategy="Supplying untrusted Origin headers with credential request probing.",
                validation_strategy="Header inspection evaluating reflection of arbitrary origin alongside Access-Control-Allow-Credentials: true on authenticated sensitive routes.",
                required_evidence=[
                    "origin_reflection_proof",
                    "allow_credentials_true_header",
                    "sensitive_data_exposure_proof",
                ],
                supporting_evidence=[
                    "null_origin_acceptance",
                ],
                confirmation_rules=[
                    "Arbitrary untrusted Origin header is reflected in Access-Control-Allow-Origin AND Access-Control-Allow-Credentials is true on an authenticated endpoint exposing private data.",
                ],
                rejection_rules=[
                    "Access-Control-Allow-Origin: * without Allow-Credentials on public data.",
                    "Origin header ignored or rejected.",
                    "Wildcard CORS on public static assets.",
                ],
                confidence_model={"min_confidence_for_confirmation": 85, "requires_credentials_and_sensitive_data": True},
                safe_validation_level=SafeValidationLevel.NON_DESTRUCTIVE_BENIGN,
            )
        )

        # 11. Slowloris / Incomplete HTTP Connection DoS
        self.register(
            VulnerabilityContract(
                id="slowloris",
                name="Slowloris Incomplete HTTP Connection Handling",
                category="denial_of_service",
                cwe_id="CWE-400",
                detection_strategy="Controlled low-bandwidth incomplete HTTP header streaming under strict safety bounds.",
                validation_strategy="Multi-socket connection pool telemetry checking connection timeout thresholds, server keep-alive starvation, and baseline concurrent availability.",
                required_evidence=[
                    "connection_hold_duration_exceeding_timeout",
                    "resource_handling_differential",
                    "baseline_availability_comparison",
                ],
                supporting_evidence=[
                    "socket_keepalive_anomaly",
                    "worker_thread_exhaustion_telemetry",
                ],
                confirmation_rules=[
                    "Server maintains incomplete HTTP connections indefinitely (> 60s without timeout) while concurrent baseline client requests experience measurable queue starvation.",
                    "Controlled minimal connection holding causes server socket pool exhaustion verified against concurrent control probes.",
                ],
                rejection_rules=[
                    "Server returns HTTP 200 or 400 immediately on connection.",
                    "Server enforces strict connection timeout (< 10s) and drops slow sockets.",
                    "Simple network latency or slow response without connection state starvation.",
                ],
                confidence_model={"min_confidence_for_confirmation": 90, "requires_connection_starvation_proof": True},
                safe_validation_level=SafeValidationLevel.CONTROLLED_MUTATION,
            )
        )

        # 12. CSRF (Cross-Site Request Forgery)
        self.register(
            VulnerabilityContract(
                id="csrf",
                name="Cross-Site Request Forgery",
                category="authorization",
                cwe_id="CWE-352",
                detection_strategy="State-changing request analysis (POST/PUT/DELETE) without anti-CSRF tokens or SameSite cookie protection.",
                validation_strategy="Simulated cross-origin submission verifying successful state modification without CSRF tokens.",
                required_evidence=[
                    "state_changing_action_proof",
                    "missing_or_unvalidated_csrf_token",
                    "samesite_cookie_absence",
                ],
                supporting_evidence=[
                    "idempotent_get_state_change",
                ],
                confirmation_rules=[
                    "State-changing endpoint executes action successfully when request is sent with authenticated cookie but missing/invalid anti-CSRF token.",
                ],
                rejection_rules=[
                    "Endpoint is safe/read-only (GET request without side effects).",
                    "Strict/Lax SameSite cookies prevent cross-site dispatch.",
                    "Header-based authentication (Bearer token) required instead of ambient cookies.",
                ],
                confidence_model={"min_confidence_for_confirmation": 85, "requires_state_change_proof": True},
                safe_validation_level=SafeValidationLevel.CONTROLLED_MUTATION,
            )
        )

        # 13. JWT Weaknesses
        self.register(
            VulnerabilityContract(
                id="jwt",
                name="JSON Web Token Security Weakness",
                category="crypto",
                cwe_id="CWE-347",
                detection_strategy="Token modification with none-algorithm, key confusion, expired timestamps, or signature stripping.",
                validation_strategy="Submitting modified JWT to protected route and evaluating authorization acceptance.",
                required_evidence=[
                    "tampered_token_acceptance_proof",
                    "protected_resource_access",
                    "baseline_control_comparison",
                ],
                supporting_evidence=[
                    "none_algorithm_acceptance",
                    "weak_secret_recovery",
                ],
                confirmation_rules=[
                    "Server accepts forged JWT with 'none' algorithm or altered payload claims and grants access to protected user resource.",
                ],
                rejection_rules=[
                    "Server returns HTTP 401 / 403 on tampered token signature.",
                    "Token parsed but signature strictly enforced.",
                ],
                confidence_model={"min_confidence_for_confirmation": 90, "requires_tampered_token_acceptance": True},
                safe_validation_level=SafeValidationLevel.CONTROLLED_MUTATION,
            )
        )


contract_registry = ContractRegistry()
