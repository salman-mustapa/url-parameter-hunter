import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = Path(os.environ.get("STORAGE_DIR", str(BASE_DIR / "storage"))).resolve()
SCREENSHOTS_DIR = STORAGE_DIR / "screenshots"
EVIDENCE_DIR = STORAGE_DIR / "evidence"
REPORTS_DIR = STORAGE_DIR / "reports"
ARTIFACTS_DIR = STORAGE_DIR / "artifacts"
QUARANTINE_DIR = STORAGE_DIR / "quarantine"

for d in (STORAGE_DIR, SCREENSHOTS_DIR, EVIDENCE_DIR, REPORTS_DIR, ARTIFACTS_DIR, QUARANTINE_DIR):
    d.mkdir(parents=True, exist_ok=True)

DEFAULT_SQLITE_URL = f"sqlite+aiosqlite:///{STORAGE_DIR / 'bughunter.db'}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", str(BASE_DIR / ".env")), extra="ignore")
    app_env: str = os.getenv("APP_ENV", "development")
    database_url: str = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    cookie_secure: bool = os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
    seed_default_users: bool = os.getenv("SEED_DEFAULT_USERS", "false").lower() in ("true", "1", "yes")
    bootstrap_admin_username: str = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "")
    bootstrap_admin_email: str = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "")
    bootstrap_admin_password: str = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
    bootstrap_user_username: str = os.getenv("BOOTSTRAP_USER_USERNAME", "")
    bootstrap_user_email: str = os.getenv("BOOTSTRAP_USER_EMAIL", "")
    bootstrap_user_password: str = os.getenv("BOOTSTRAP_USER_PASSWORD", "")
    proxy_pool: str = os.getenv("PROXY_POOL", "")
    oob_callback_host: str = os.getenv("OOB_CALLBACK_HOST", "localhost:9001")
    cors_origins: str = ""
    performance_mode: str = os.getenv("PERFORMANCE_MODE", "balanced")
    low_resource_mode: bool = os.getenv("LOW_RESOURCE_MODE", "false").lower() in ("true", "1", "yes")
    allow_private_networks: bool = os.getenv("ALLOW_PRIVATE_NETWORKS", "false").lower() in ("true", "1", "yes")
    rate_limit_rps: int = 15
    max_concurrent_hosts: int = 12
    max_concurrent_scans: int = 2
    max_pending_scans: int = 20
    max_browser_captures: int = 1
    browser_capture_enabled: bool = False
    max_assets_per_scan: int = 2500
    max_urls_per_scan: int = 20000
    max_crawl_depth: int = 3
    max_runtime_minutes: int = 45
    port_timeout_seconds: float = 1.5
    port_rps: int = 250
    max_port_hosts: int = 40
    max_web_hosts: int = 25
    max_http_hosts: int = 30
    http_timeout_seconds: float = 8.0
    max_http_connections: int = 64
    max_http_keepalive_connections: int = 16
    max_concurrent_port_probes: int = 32
    max_concurrent_service_validations: int = 2
    max_subprocesses: int = 4
    subprocess_max_output_bytes: int = 4 * 1024 * 1024
    scheduler_queue_max_size: int = 1000
    result_event_queue_size: int = 2000
    nonstandard_http_probe_max_bytes: int = 262144
    nonstandard_http_probe_max_redirects: int = 3
    credential_audit_enabled: bool = True
    credential_audit_max_attempts: int = 10
    credential_audit_delay_seconds: float = 0.75
    nmap_vuln_enabled: bool = True
    nmap_vuln_timeout_seconds: float = 120.0
    nmap_vuln_max_ports: int = 12
    nmap_vuln_script_timeout_seconds: int = 30
    sse_replay_limit: int = 500
    sse_client_queue_size: int = 256
    sse_keepalive_seconds: float = 10.0
    auto_resume_scans_on_startup: bool = False
    max_auto_resume_scans: int = 2
    wordlist_path: str = str(BASE_DIR / "wordlists" / "subdomains.txt")
    # AI / LLM Orchestration Configuration
    llm_enabled: bool = os.getenv("LLM_ENABLED", "true").lower() in ("true", "1", "yes")
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai_compatible")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "nousresearch/hermes-3-llama-3.1-8b")
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    llm_max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "2048"))
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    ninerouter_api_key: str = os.getenv("NINEROUTER_API_KEY", "")
    # Database Connection Pool Configuration
    db_pool_size: int = int(os.getenv("DB_POOL_SIZE", "10"))
    db_max_overflow: int = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    db_pool_timeout: float = float(os.getenv("DB_POOL_TIMEOUT", "60.0"))
    db_pool_recycle: int = int(os.getenv("DB_POOL_RECYCLE", "1800"))

    app_version: str = "2.0.0"

    def model_post_init(self, __context) -> None:
        """Apply hard upper bounds for explicitly constrained deployments."""
        mode = (self.performance_mode or "balanced").strip().lower()
        if self.low_resource_mode or mode == "low":
            self.performance_mode = "low"
            self.max_concurrent_hosts = min(self.max_concurrent_hosts, 3)
            self.max_concurrent_scans = 1
            self.max_port_hosts = min(self.max_port_hosts, 4)
            self.max_web_hosts = min(self.max_web_hosts, 4)
            self.max_http_hosts = min(self.max_http_hosts, 5)
            self.max_http_connections = min(self.max_http_connections, 16)
            self.max_http_keepalive_connections = min(self.max_http_keepalive_connections, 4)
            self.max_concurrent_port_probes = min(self.max_concurrent_port_probes, 8)
            self.max_concurrent_service_validations = min(self.max_concurrent_service_validations, 1)
            self.max_subprocesses = min(self.max_subprocesses, 1)
            self.db_pool_size = min(self.db_pool_size, 4)
            self.db_max_overflow = min(self.db_max_overflow, 2)
            self.sse_client_queue_size = min(self.sse_client_queue_size, 128)
            self.result_event_queue_size = min(self.result_event_queue_size, 1000)


settings = Settings()
