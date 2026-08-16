from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", str(BASE_DIR / ".env")), extra="ignore")
    database_url: str = "postgresql+asyncpg://bughunter:bughunter@postgres:5432/bughunter"
    cors_origins: str = "*"
    rate_limit_rps: int = 10
    max_concurrent_hosts: int = 8
    max_assets_per_scan: int = 2000
    max_urls_per_scan: int = 20000
    max_crawl_depth: int = 3
    max_runtime_minutes: int = 45
    port_timeout_seconds: float = 2.0
    port_rps: int = 200
    max_port_hosts: int = 30
    max_web_hosts: int = 15
    max_http_hosts: int = 20
    http_timeout_seconds: float = 10.0
    wordlist_path: str = str(BASE_DIR / "wordlists" / "subdomains.txt")
    security_mode: str = "SAFE"


settings = Settings()