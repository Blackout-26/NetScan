"""
app/models/device.py
────────────────────
A Device is a host discovered during a scan.
One Scan → many Devices → many Ports.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Device(Base):
    """
    Represents a single discovered host on the network.

    Columns
    -------
    id            : surrogate PK
    scan_id       : FK → Scan
    ip_address    : dotted-decimal IPv4 (or IPv6) address
    hostname      : reverse DNS name if resolved, else empty string
    mac_address   : hardware address (requires root / --privileged nmap)
    vendor        : NIC vendor from MAC OUI lookup
    os_guess      : nmap OS detection best guess
    os_accuracy   : accuracy percentage of OS guess (0-100)
    overall_risk  : High | Medium | Low | Info
    risk_score    : sum of all port risk scores
    open_ports    : count of open ports on this device
    state         : up | down | unknown
    discovered_at : timestamp when this device was first recorded
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(256), default="")
    mac_address: Mapped[Optional[str]] = mapped_column(String(17))
    vendor: Mapped[Optional[str]] = mapped_column(String(128))
    os_guess: Mapped[Optional[str]] = mapped_column(String(256))
    os_accuracy: Mapped[Optional[int]] = mapped_column(Integer)
    overall_risk: Mapped[str] = mapped_column(String(16), default="Info")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[str] = mapped_column(String(16), default="up")
    extra_info: Mapped[Optional[str]] = mapped_column(Text)   # raw JSON blob
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="devices")  # type: ignore[name-defined]
    ports: Mapped[List["Port"]] = relationship(  # type: ignore[name-defined]
        "Port", back_populates="device", cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Device ip={self.ip_address} risk={self.overall_risk} ports={self.open_ports}>"
