"""
app/api/routes/dashboard.py
────────────────────────────
Dashboard stats and health-check endpoints.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import require_auth
from app.database.session import get_db
from app.models.user import User
from app.schemas import DashboardStats, RiskBreakdown, ScanResponse
from app.services.scan_service import get_dashboard_stats

router = APIRouter(tags=["Dashboard"])


@router.get("/health", summary="Health check")
async def health() -> dict:
    return {"status": "ok", "service": "NetScan"}


@router.get(
    "/dashboard/stats",
    response_model=DashboardStats,
    summary="Get aggregated dashboard statistics",
)
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_auth),
) -> DashboardStats:
    data = await get_dashboard_stats(db)
    return DashboardStats(
        total_scans=data["total_scans"],
        active_scans=data["active_scans"],
        total_devices=data["total_devices"],
        total_open_ports=data["total_open_ports"],
        risk_breakdown=RiskBreakdown(**data["risk_breakdown"]),
        recent_scans=[ScanResponse.model_validate(s) for s in data["recent_scans"]],
    )
