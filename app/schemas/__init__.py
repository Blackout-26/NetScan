"""
app/schemas/__init__.py
────────────────────────
Pydantic v2 schemas used for API request validation and response serialisation.
Kept separate from ORM models (never pass ORM objects over the wire directly).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ─────────────────────────────────────────────────────────────────────────────
# Scan schemas
# ─────────────────────────────────────────────────────────────────────────────


class ScanCreate(BaseModel):
    """Payload to initiate a new scan."""
    target: str = Field(
        ...,
        examples=["192.168.1.0/24", "10.0.0.1", "scanme.nmap.org"],
        description="IP address, hostname, or CIDR range to scan.",
    )
    scan_type: str = Field(
        default="full",
        pattern="^(quick|full|service)$",
        description="quick = top 1000 ports | full = all 65535 | service = version detect",
    )

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target must not be empty")
        return v.strip()


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    target: str
    status: str
    scan_type: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    error_msg: Optional[str]
    task_id: Optional[str]
    total_hosts: int
    open_ports: int
    duration_seconds: Optional[float]


class ScanListResponse(BaseModel):
    total: int
    scans: List[ScanResponse]


# ─────────────────────────────────────────────────────────────────────────────
# Port schemas
# ─────────────────────────────────────────────────────────────────────────────


class PortResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port_number: int
    protocol: str
    state: str
    service: str
    product: Optional[str]
    version: Optional[str]
    risk_level: str
    risk_name: str
    description: str
    recommendation: str
    cve_hints: Optional[str]
    is_notable: bool


# ─────────────────────────────────────────────────────────────────────────────
# Device schemas
# ─────────────────────────────────────────────────────────────────────────────


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    hostname: str
    mac_address: Optional[str]
    vendor: Optional[str]
    os_guess: Optional[str]
    os_accuracy: Optional[int]
    overall_risk: str
    risk_score: int
    open_ports: int
    state: str
    discovered_at: datetime
    ports: List[PortResponse] = []


class DeviceListResponse(BaseModel):
    total: int
    devices: List[DeviceResponse]


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard schemas
# ─────────────────────────────────────────────────────────────────────────────


class RiskBreakdown(BaseModel):
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class DashboardStats(BaseModel):
    total_scans: int
    active_scans: int
    total_devices: int
    total_open_ports: int
    risk_breakdown: RiskBreakdown
    recent_scans: List[ScanResponse]


# ─────────────────────────────────────────────────────────────────────────────
# Report schemas
# ─────────────────────────────────────────────────────────────────────────────


class ReportCreate(BaseModel):
    scan_uuid: str
    format: str = Field(default="pdf", pattern="^(pdf|json|csv)$")


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    uuid: str
    scan_id: int
    format: str
    file_path: Optional[str]
    file_size: Optional[int]
    created_at: datetime
    filename: str


# ─────────────────────────────────────────────────────────────────────────────
# Generic responses
# ─────────────────────────────────────────────────────────────────────────────


class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
