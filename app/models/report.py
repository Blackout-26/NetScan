"""
app/models/report.py
────────────────────
A Report is a generated artefact (PDF, JSON, CSV) produced from a Scan.
"""

import enum
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class ReportFormat(str, enum.Enum):
    PDF  = "pdf"
    JSON = "json"
    CSV  = "csv"


class Report(Base):
    """
    Represents a generated report for a scan.

    Columns
    -------
    id          : surrogate PK
    uuid        : external identifier
    scan_id     : FK → Scan
    format      : pdf | json | csv
    file_path   : absolute path to the generated file on disk
    file_size   : size in bytes
    created_at  : generation timestamp
    """

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uuid: Mapped[str] = mapped_column(
        String(36), unique=True, nullable=False,
        default=lambda: str(uuid.uuid4()),
    )
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat), nullable=False, default=ReportFormat.PDF,
    )
    file_path: Mapped[Optional[str]] = mapped_column(String(512))
    file_size: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")  # type: ignore[name-defined]

    def __repr__(self) -> str:
        return f"<Report scan_id={self.scan_id} format={self.format} uuid={self.uuid}>"

    @property
    def filename(self) -> str:
        if self.file_path:
            return Path(self.file_path).name
        return f"report_{self.uuid}.{self.format.value}"
