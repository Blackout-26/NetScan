"""
app/api/routes/devices.py
──────────────────────────
REST endpoints for querying devices discovered in scans.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.deps import require_auth
from app.database.session import get_db
from app.models.device import Device
from app.models.port import Port
from app.models.user import User
from app.schemas import DeviceListResponse, DeviceResponse, PortResponse

router = APIRouter(prefix="/devices", tags=["Devices"])


@router.get(
    "/",
    response_model=DeviceListResponse,
    summary="List discovered devices (optionally filter by scan or risk level)",
)
async def list_devices(
    scan_uuid: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> DeviceListResponse:
    from sqlalchemy import func
    from app.models.scan import Scan

    q = select(Device).options(selectinload(Device.ports))

    if scan_uuid:
        scan_result = await db.execute(select(Scan).where(Scan.uuid == scan_uuid))
        scan = scan_result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        q = q.where(Device.scan_id == scan.id)

    if risk_level:
        q = q.where(Device.overall_risk == risk_level)

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    q = q.order_by(Device.risk_score.desc()).offset(skip).limit(limit)
    result = await db.execute(q)
    devices = result.scalars().all()

    return DeviceListResponse(
        total=total,
        devices=[
            DeviceResponse(
                **{c: getattr(d, c) for c in DeviceResponse.model_fields if c != "ports"},
                ports=[PortResponse.model_validate(p) for p in d.ports],
            )
            for d in devices
        ],
    )


@router.get(
    "/{device_id}",
    response_model=DeviceResponse,
    summary="Get a single device with all its ports",
)
async def get_device(
    device_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> DeviceResponse:
    result = await db.execute(
        select(Device)
        .where(Device.id == device_id)
        .options(selectinload(Device.ports))
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return DeviceResponse(
        **{c: getattr(device, c) for c in DeviceResponse.model_fields if c != "ports"},
        ports=[PortResponse.model_validate(p) for p in device.ports],
    )


@router.get(
    "/{device_id}/ports",
    response_model=list[PortResponse],
    summary="Get all ports for a device, optionally filtered by risk",
)
async def get_device_ports(
    device_id: int,
    risk_level: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> list[PortResponse]:
    q = select(Port).where(Port.device_id == device_id)
    if risk_level:
        q = q.where(Port.risk_level == risk_level)
    q = q.order_by(Port.port_number)

    result = await db.execute(q)
    ports = result.scalars().all()
    return [PortResponse.model_validate(p) for p in ports]
