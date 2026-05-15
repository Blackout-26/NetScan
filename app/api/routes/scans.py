"""
app/api/routes/scans.py
────────────────────────
REST endpoints for managing scan lifecycle.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import require_auth
from app.core.logging import get_logger
from app.database.session import get_db
from app.models.user import User
from app.schemas import (
    MessageResponse,
    ScanCreate,
    ScanListResponse,
    ScanResponse,
)
from app.services import scan_service

logger = get_logger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate a new scan",
)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> ScanResponse:
    """
    Create a scan job and dispatch it to the background worker.
    Returns immediately with the scan UUID you can use to poll status.
    """
    scan = await scan_service.create_scan(
        db=db,
        target=payload.target,
        scan_type=payload.scan_type,
    )

    # Dispatch Celery task
    try:
        from app.scanner.tasks import run_scan_task
        task = run_scan_task.delay(
            scan_uuid=scan.uuid,
            target=payload.target,
            scan_type=payload.scan_type,
        )
        scan.task_id = task.id
        await db.flush()
        logger.info("Dispatched scan task %s for %s", task.id, payload.target)
    except Exception as exc:
        # Redis/Celery unavailable — mark as failed immediately
        logger.error("Failed to dispatch scan task: %s", exc)
        from app.models.scan import ScanStatus
        scan.status = ScanStatus.FAILED
        scan.error_msg = f"Failed to start worker: {exc}"
        await db.flush()

    return ScanResponse.model_validate(scan)


@router.get(
    "/",
    response_model=ScanListResponse,
    summary="List all scans (paginated)",
)
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> ScanListResponse:
    total, scans = await scan_service.list_scans(db, skip=skip, limit=limit)
    return ScanListResponse(
        total=total,
        scans=[ScanResponse.model_validate(s) for s in scans],
    )


@router.get(
    "/{scan_uuid}",
    response_model=ScanResponse,
    summary="Get scan status and metadata",
)
async def get_scan(
    scan_uuid: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> ScanResponse:
    scan = await scan_service.get_scan_by_uuid(db, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.delete(
    "/{scan_uuid}",
    response_model=MessageResponse,
    summary="Cancel a running scan",
)
async def cancel_scan(
    scan_uuid: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> MessageResponse:
    scan = await scan_service.cancel_scan(db, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return MessageResponse(message=f"Scan {scan_uuid} cancelled.")
