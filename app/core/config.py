from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", str(BASE_DIR / ".env")), extra="ignore")
    database_url: str = "postgresql+psycopg2://bug hunter:bug hunter@postgres:5432/bughunter"
    redis_url: str = "redis://redis:6379/0"
    secret_key: str = "change-me-in-production"
    cors_origins: str = "*"
    scan_profiles: str = '{"passive":{},"standard":{"max_ports":1000},"deep":{"max_ports":65535}}'
    rate_limit_rps: int = 5
    max_concurrent_hosts: int = 10
    sqlite_path: str = str(BASE_DIR / "storage" / "dev.sqlite")

settings = Settings()
