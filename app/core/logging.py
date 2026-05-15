"""
app/core/logging.py
───────────────────
Structured logging configuration for NetScan.
Call `setup_logging()` once at application startup.
"""

import logging
import logging.handlers
import sys
from pathlib import Path

from app.core.config import settings


def setup_logging() -> None:
    """
    Configure root logger with:
    - Console handler (stdout, coloured for human readability)
    - Rotating file handler (machine-readable, persisted to disk)
    """
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Ensure log directory exists
    log_path: Path = Path(settings.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    fmt_console = logging.Formatter(
        fmt="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    fmt_file = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)d %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt_console)
    console_handler.setLevel(log_level)

    # Rotating file handler (10 MB × 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt_file)
    file_handler.setLevel(log_level)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Convenience factory — use in every module instead of getLogger directly."""
    return logging.getLogger(name)
