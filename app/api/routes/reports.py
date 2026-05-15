"""
app/api/routes/reports.py
──────────────────────────
Endpoints for report generation and download.
"""

import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import require_auth
from app.database.session import get_db
from app.models.report import Report
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas import ReportCreate, ReportResponse
from app.services.report_service import generate_report

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post(
    "/",
    response_model=ReportResponse,
    summary="Generate a report for a completed scan",
)
async def create_report(
    payload: ReportCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> ReportResponse:
    scan_result = await db.execute(
        select(Scan).where(Scan.uuid == payload.scan_uuid)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot generate report — scan status is '{scan.status.value}'. Must be 'completed'.",
        )

    report = await generate_report(db=db, scan=scan, fmt=payload.format)
    return ReportResponse.model_validate(report)


@router.get(
    "/{report_uuid}/download",
    summary="Download a generated report file",
)
async def download_report(
    report_uuid: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> FileResponse:
    result = await db.execute(
        select(Report).where(Report.uuid == report_uuid)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    media_types = {"pdf": "application/pdf", "json": "application/json", "csv": "text/csv"}
    return FileResponse(
        path=report.file_path,
        media_type=media_types.get(report.format.value, "application/octet-stream"),
        filename=report.filename,
    )
