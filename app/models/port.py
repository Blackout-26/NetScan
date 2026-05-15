"""
app/models/port.py
──────────────────
A Port record captures everything nmap detected about an open port
on a specific device.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Port(Base):
    """
    Represents a single scanned port on a Device.

    Columns
    -------
    id              : surrogate PK
    device_id       : FK → Device
    port_number     : 1–65535
    protocol        : tcp | udp
    state           : open | closed | filtered | open|filtered
    service         : service name from nmap (e.g., 'http', 'ssh')
    product         : product name (e.g., 'Apache httpd')
    version         : product version string (e.g., '2.4.51')
    extra_info      : nmap extra info field
    banner          : grabbed banner (first 512 chars)
    cpe             : Common Platform Enumeration string
    risk_level      : High | Medium | Low | Info
    risk_name       : short label for the risk rule that matched
    description     : human-readable risk description
    recommendation  : actionable security recommendation
    cve_hints       : JSON list of relevant CVE identifiers
    is_notable      : true for ports that need immediate attention
    scanned_at      : timestamp of this specific port scan
    """

    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    port_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    service: Mapped[str] = mapped_column(String(64), default="unknown")
    product: Mapped[Optional[str]] = mapped_column(String(128))
    version: Mapped[Optional[str]] = mapped_column(String(64))
    extra_info: Mapped[Optional[str]] = mapped_column(String(256))
    banner: Mapped[Optional[str]] = mapped_column(Text)
    cpe: Mapped[Optional[str]] = mapped_column(String(256))
    risk_level: Mapped[str] = mapped_column(String(16), default="Info", index=True)
    risk_name: Mapped[str] = mapped_column(String(64), default="Unknown")
    description: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    cve_hints: Mapped[Optional[str]] = mapped_column(Text)   # JSON list stored as string
    is_notable: Mapped[bool] = mapped_column(Boolean, default=False)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    # Relationships
    device: Mapped["Device"] = relationship("Device", back_populates="ports")  # type: ignore[name-defined]

    def __repr__(self) -> str:
        return (
            f"<Port {self.protocol}/{self.port_number} "
            f"service={self.service!r} risk={self.risk_level}>"
        )
