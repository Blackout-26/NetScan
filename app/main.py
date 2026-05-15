from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import api_router
from app.core.config import settings
from app.core.deps import get_current_user
from app.core.logging import get_logger, setup_logging
from app.database.session import get_db_context, init_db

setup_logging()
logger = get_logger(__name__)
BASE_DIR = Path(__file__).resolve().parent.parent

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("NetScan starting up...")
    await init_db()
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    from app.services.auth_service import seed_default_admin
    async with get_db_context() as db:
        await seed_default_admin(db)
    logger.info("NetScan ready - v%s", settings.app_version)
    yield
    logger.info("NetScan shutting down.")

app = FastAPI(
    title="NetScan",
    description="Network Port Scanner and Risk Analyzer",
    version=settings.app_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates_dir = BASE_DIR / "templates"
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=templates_dir)
app.include_router(api_router)

async def _get_user(request: Request):
    async with get_db_context() as db:
        return await get_current_user(request, db)

@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    user = await _get_user(request)
    if user:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    user = await _get_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if user.is_first_login:
        return RedirectResponse("/setup", status_code=302)
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/scans", response_class=HTMLResponse, include_in_schema=False)
async def scans_page(request: Request):
    user = await _get_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("scans.html", {"request": request})

@app.get("/scans/{scan_uuid}", response_class=HTMLResponse, include_in_schema=False)
async def scan_detail_page(request: Request, scan_uuid: str):
    user = await _get_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("scan_detail.html", {"request": request, "scan_uuid": scan_uuid})

@app.get("/setup", response_class=HTMLResponse, include_in_schema=False)
async def setup_page(request: Request):
    user = await _get_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if not user.is_first_login:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("setup.html", {"request": request})

@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
async def settings_page(request: Request):
    user = await _get_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("settings.html", {"request": request, "username": user.username})
