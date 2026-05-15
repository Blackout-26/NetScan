"""
app/services/scan_service.py
─────────────────────────────
Business logic layer for scan operations.
All direct DB writes go through here, not the routes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.models.device import Device
from app.models.port import Port
from app.models.scan import Scan, ScanStatus
from app.scanner.engine import ScanResult

logger = get_logger(__name__)


async def create_scan(db: AsyncSession, target: str, scan_type: str) -> Scan:
    """Create a new Scan record in PENDING state and return it."""
    scan = Scan(
        uuid=str(uuid.uuid4()),
        target=target,
        scan_type=scan_type,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    logger.info("Created scan %s for target=%s type=%s", scan.uuid, target, scan_type)
    return scan


async def persist_scan_results(
    db: AsyncSession,
    scan: Scan,
    scan_result: ScanResult,
) -> None:
    """
    Write all discovered devices and ports from a ScanResult into the DB.
    Called from within the Celery worker task after scanning finishes.
    """
    for scanned_device in scan_result.devices:
        device = Device(
            scan_id=scan.id,
            ip_address=scanned_device.ip_address,
            hostname=scanned_device.hostname,
            mac_address=scanned_device.mac_address or None,
            vendor=scanned_device.vendor or None,
            os_guess=scanned_device.os_guess or None,
            os_accuracy=scanned_device.os_accuracy or None,
            state=scanned_device.state,
            overall_risk=scanned_device.overall_risk,
            risk_score=scanned_device.risk_score,
            open_ports=scanned_device.open_ports,
            extra_info=scanned_device.extra_info,
        )
        db.add(device)
        await db.flush()   # get device.id

        for sp in scanned_device.ports:
            port = Port(
                device_id=device.id,
                port_number=sp.port_number,
                protocol=sp.protocol,
                state=sp.state,
                service=sp.service,
                product=sp.product or None,
                version=sp.version or None,
                extra_info=sp.extra_info or None,
                banner=sp.banner or None,
                cpe=sp.cpe or None,
                risk_level=sp.risk_level,
                risk_name=sp.risk_name,
                description=sp.description,
                recommendation=sp.recommendation,
                cve_hints=sp.cve_hints,
                is_notable=sp.is_notable,
            )
            db.add(port)

    logger.info(
        "Persisted %d devices for scan %s",
        len(scan_result.devices), scan.uuid,
    )


async def get_scan_by_uuid(db: AsyncSession, scan_uuid: str) -> Optional[Scan]:
    result = await db.execute(
        select(Scan).where(Scan.uuid == scan_uuid)
    )
    return result.scalar_one_or_none()


async def get_scan_with_devices(db: AsyncSession, scan_uuid: str) -> Optional[Scan]:
    result = await db.execute(
        select(Scan)
        .where(Scan.uuid == scan_uuid)
        .options(selectinload(Scan.devices).selectinload(Device.ports))
    )
    return result.scalar_one_or_none()


async def list_scans(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 20,
) -> tuple[int, List[Scan]]:
    count_result = await db.execute(select(func.count(Scan.id)))
    total = count_result.scalar_one()

    result = await db.execute(
        select(Scan)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return total, list(result.scalars().all())


async def cancel_scan(db: AsyncSession, scan_uuid: str) -> Optional[Scan]:
    scan = await get_scan_by_uuid(db, scan_uuid)
    if scan and scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        if scan.task_id:
            from app.scanner.tasks import celery_app
            celery_app.control.revoke(scan.task_id, terminate=True, signal="SIGTERM")
        scan.status = ScanStatus.CANCELLED
        scan.finished_at = datetime.now(tz=timezone.utc)
        await db.flush()
    return scan


async def get_dashboard_stats(db: AsyncSession) -> dict:
    from app.models.scan import ScanStatus

    total_scans_result = await db.execute(select(func.count(Scan.id)))
    total_scans = total_scans_result.scalar_one()

    active_result = await db.execute(
        select(func.count(Scan.id)).where(
            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING])
        )
    )
    active_scans = active_result.scalar_one()

    total_devices_result = await db.execute(select(func.count(Device.id)))
    total_devices = total_devices_result.scalar_one()

    total_ports_result = await db.execute(select(func.count(Port.id)))
    total_open_ports = total_ports_result.scalar_one()

    # Risk breakdown across all devices
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for level in risk_counts:
        res = await db.execute(
            select(func.count(Device.id)).where(Device.overall_risk == level)
        )
        risk_counts[level] = res.scalar_one()

    _, recent_scans = await list_scans(db, skip=0, limit=5)

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "total_devices": total_devices,
        "total_open_ports": total_open_ports,
        "risk_breakdown": {
            "high": risk_counts["High"],
            "medium": risk_counts["Medium"],
            "low": risk_counts["Low"],
            "info": risk_counts["Info"],
        },
        "recent_scans": recent_scans,
    }
