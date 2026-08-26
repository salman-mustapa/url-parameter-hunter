import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
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
    database_url: str = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    proxy_pool: str = os.getenv("PROXY_POOL", "")
    oob_callback_host: str = os.getenv("OOB_CALLBACK_HOST", "localhost:9001")
    cors_origins: str = "*"
    rate_limit_rps: int = 15
    max_concurrent_hosts: int = 12
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


settings = Settings()