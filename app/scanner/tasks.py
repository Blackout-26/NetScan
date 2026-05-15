"""
app/scanner/tasks.py
────────────────────
Celery task definitions for background scanning.
Each scan job runs here so it never blocks the FastAPI event loop.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from celery import Celery
from celery.utils.log import get_task_logger

from app.core.config import settings

logger = get_task_logger(__name__)

# ── Celery application ─────────────────────────────────────────────────────────
celery_app = Celery(
    "netscan",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_soft_time_limit=settings.default_scan_timeout + 60,   # grace period
    task_time_limit=settings.default_scan_timeout + 120,
    worker_max_tasks_per_child=50,    # recycle workers to prevent memory leaks
    worker_concurrency=settings.max_concurrent_scans,
)


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from a synchronous Celery task."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="netscan.run_scan",
    max_retries=1,
    default_retry_delay=30,
)
def run_scan_task(self, scan_uuid: str, target: str, scan_type: str = "full") -> dict:
    """
    Background task that:
      1. Marks the Scan record as RUNNING
      2. Calls the Nmap engine
      3. Persists all results to the database
      4. Marks the Scan as COMPLETED or FAILED
    """
    from app.database.session import get_db_context
    from app.models.scan import Scan, ScanStatus
    from app.scanner.engine import run_scan
    from app.services.scan_service import persist_scan_results

    logger.info("Task started — scan_uuid=%s target=%s type=%s", scan_uuid, target, scan_type)

    async def _execute() -> dict:
        async with get_db_context() as db:
            from sqlalchemy import select
            result = await db.execute(select(Scan).where(Scan.uuid == scan_uuid))
            scan: Scan | None = result.scalar_one_or_none()

            if scan is None:
                logger.error("Scan %s not found in DB", scan_uuid)
                return {"status": "error", "error": "Scan record not found"}

            # Mark as running
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(tz=timezone.utc)
            scan.task_id = self.request.id
            await db.flush()

        # ── Run the actual Nmap scan (blocking, outside the DB session) ────────
        scan_result = run_scan(target=target, scan_type=scan_type)

        # ── Persist results ────────────────────────────────────────────────────
        async with get_db_context() as db:
            from sqlalchemy import select
            result = await db.execute(select(Scan).where(Scan.uuid == scan_uuid))
            scan = result.scalar_one_or_none()
            if scan is None:
                return {"status": "error", "error": "Scan record disappeared"}

            if scan_result.error:
                scan.status = ScanStatus.FAILED
                scan.error_msg = scan_result.error
                scan.finished_at = scan_result.finished_at
            else:
                await persist_scan_results(db=db, scan=scan, scan_result=scan_result)
                scan.status = ScanStatus.COMPLETED
                scan.finished_at = scan_result.finished_at
                scan.total_hosts = scan_result.total_hosts
                scan.open_ports = scan_result.total_open_ports

            await db.flush()

        logger.info(
            "Scan %s finished — status=%s hosts=%d ports=%d",
            scan_uuid,
            "completed" if not scan_result.error else "failed",
            scan_result.total_hosts,
            scan_result.total_open_ports,
        )
        return {
            "status": "completed" if not scan_result.error else "failed",
            "total_hosts": scan_result.total_hosts,
            "open_ports": scan_result.total_open_ports,
        }

    try:
        return _run_async(_execute())
    except Exception as exc:
        logger.exception("Task error for scan %s: %s", scan_uuid, exc)
        # Mark the scan as failed in the DB
        async def _mark_failed() -> None:
            from app.database.session import get_db_context
            from app.models.scan import Scan, ScanStatus
            from sqlalchemy import select

            async with get_db_context() as db:
                result = await db.execute(select(Scan).where(Scan.uuid == scan_uuid))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_msg = str(exc)
                    scan.finished_at = datetime.now(tz=timezone.utc)
                    await db.flush()

        _run_async(_mark_failed())
        raise
