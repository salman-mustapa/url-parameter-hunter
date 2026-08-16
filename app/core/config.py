import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_SQLITE_URL = f"sqlite+aiosqlite:///{STORAGE_DIR / 'bughunter.db'}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", str(BASE_DIR / ".env")), extra="ignore")
    database_url: str = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)
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
    security_mode: str = "SAFE"
    app_version: str = "1.0.0"


settings = Settings()