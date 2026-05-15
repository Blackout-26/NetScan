"""
app/models/scan.py
──────────────────
Scan represents a single scanning job initiated by the user.
One Scan → many Devices → many Ports.
"""

import enum
import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, Enum, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class ScanStatus(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """
    Top-level scan record.

    Columns
    -------
    id          : surrogate PK (integer, auto-increment)
    uuid        : external-facing identifier (never expose raw PK to API consumers)
    target      : IP, hostname, or CIDR range supplied by the user
    status      : current state of the scan job
    scan_type   : "quick" (top-1000) | "full" (1-65535) | "service" (version detect)
    created_at  : when the scan was created
    started_at  : when the scanner actually began work
    finished_at : when the scanner finished (success or failure)
    error_msg   : last error message if status == FAILED
    task_id     : Celery task ID for status polling
    total_hosts : number of hosts that responded
    open_ports  : total open ports found across all hosts
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False,
        default=lambda: str(uuid.uuid4()),
    )
    target: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING,
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="full")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    error_msg: Mapped[Optional[str]] = mapped_column(Text)
    task_id: Mapped[Optional[str]] = mapped_column(String(128))
    total_hosts: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    devices: Mapped[List["Device"]] = relationship(  # type: ignore[name-defined]
        "Device", back_populates="scan", cascade="all, delete-orphan",
    )
    reports: Mapped[List["Report"]] = relationship(  # type: ignore[name-defined]
        "Report", back_populates="scan", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target!r} status={self.status}>"

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None
