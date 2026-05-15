"""
app/core/config.py
──────────────────
Central application configuration loaded from environment variables / .env.
All other modules import `settings` from here — never read os.environ directly.
"""

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Application ────────────────────────────────────────────────────────────
    app_name: str = "NetScan"
    app_version: str = "1.0.0"
    debug: bool = False
    secret_key: str = "change-me-before-deploying"

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./netscan.db"

    # ── Nmap ───────────────────────────────────────────────────────────────────
    nmap_path: str = "/usr/bin/nmap"
    default_scan_timeout: int = 300   # seconds
    max_concurrent_scans: int = 3

    # ── Redis / Celery ─────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Reporting ──────────────────────────────────────────────────────────────
    reports_dir: Path = Path("./reports")

    # ── CORS ───────────────────────────────────────────────────────────────────
    allowed_origins: List[str] = ["http://localhost", "http://127.0.0.1"]

    # ── Logging ────────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    log_file: Path = Path("./logs/netscan.log")

    # ── Derived / Validation ───────────────────────────────────────────────────
    @field_validator("reports_dir", "log_file", mode="before")
    @classmethod
    def ensure_parents_exist(cls, v: str | Path) -> Path:
        p = Path(v)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton Settings instance."""
    return Settings()


# Module-level convenience alias
settings: Settings = get_settings()
