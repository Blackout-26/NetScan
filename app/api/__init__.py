"""
app/api/__init__.py
────────────────────
Assembles all route modules into a single APIRouter
that is mounted onto the main FastAPI app.
"""

from fastapi import APIRouter

from app.api.routes.auth import router as auth_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.devices import router as devices_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scans import router as scans_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)       # public — no auth required
api_router.include_router(dashboard_router)  # protected below via deps
api_router.include_router(scans_router)
api_router.include_router(devices_router)
api_router.include_router(reports_router)
