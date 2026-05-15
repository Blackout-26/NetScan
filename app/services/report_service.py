"""
app/services/report_service.py
────────────────────────────────
Generates PDF, JSON, and CSV reports from completed scans.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.models.device import Device
from app.models.port import Port
from app.models.report import Report, ReportFormat
from app.models.scan import Scan

logger = get_logger(__name__)


async def generate_report(
    db: AsyncSession,
    scan: Scan,
    fmt: str = "pdf",
) -> Report:
    """Generate a report for a completed scan and return the Report record."""
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    report_uuid = str(uuid.uuid4())
    fmt_enum = ReportFormat(fmt)
    filename = f"netscan_report_{report_uuid}.{fmt}"
    file_path = settings.reports_dir / filename

    # Load scan with devices and ports
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan.id)
        .options(selectinload(Scan.devices).selectinload(Device.ports))
    )
    full_scan = result.scalar_one()

    if fmt_enum == ReportFormat.PDF:
        _generate_pdf(full_scan, file_path)
    elif fmt_enum == ReportFormat.JSON:
        _generate_json(full_scan, file_path)
    elif fmt_enum == ReportFormat.CSV:
        _generate_csv(full_scan, file_path)

    file_size = file_path.stat().st_size if file_path.exists() else 0

    report = Report(
        uuid=report_uuid,
        scan_id=scan.id,
        format=fmt_enum,
        file_path=str(file_path),
        file_size=file_size,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    logger.info("Generated %s report %s (%d bytes)", fmt, report_uuid, file_size)
    return report


# ─────────────────────────────────────────────────────────────────────────────
# PDF generation (ReportLab)
# ─────────────────────────────────────────────────────────────────────────────

def _generate_pdf(scan: Scan, path: Path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
        )

        doc = SimpleDocTemplate(str(path), pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story = []

        # ── Cover ──────────────────────────────────────────────────────────────
        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                     fontSize=22, spaceAfter=6)
        story.append(Paragraph("NetScan Security Report", title_style))
        story.append(Paragraph(
            f"Target: <b>{scan.target}</b> &nbsp;|&nbsp; "
            f"Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            styles["Normal"],
        ))
        story.append(HRFlowable(width="100%", spaceAfter=12))

        # ── Summary ────────────────────────────────────────────────────────────
        story.append(Paragraph("Scan Summary", styles["Heading2"]))
        summary_data = [
            ["Field", "Value"],
            ["Scan ID", scan.uuid],
            ["Target", scan.target],
            ["Scan Type", scan.scan_type.title()],
            ["Status", scan.status.value.title()],
            ["Started", str(scan.started_at)[:19] if scan.started_at else "—"],
            ["Finished", str(scan.finished_at)[:19] if scan.finished_at else "—"],
            ["Duration", f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "—"],
            ["Devices Found", str(scan.total_hosts)],
            ["Total Open Ports", str(scan.open_ports)],
        ]
        t = Table(summary_data, colWidths=[5*cm, 11*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4*cm))

        # ── Devices ────────────────────────────────────────────────────────────
        RISK_COLORS = {
            "High":   colors.HexColor("#fee2e2"),
            "Medium": colors.HexColor("#fef9c3"),
            "Low":    colors.HexColor("#dcfce7"),
            "Info":   colors.HexColor("#f1f5f9"),
        }

        story.append(Paragraph("Discovered Devices", styles["Heading2"]))
        for device in scan.devices:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(
                f"<b>{device.ip_address}</b>  {device.hostname or ''}  "
                f"— Risk: <b>{device.overall_risk}</b>  |  Open Ports: {device.open_ports}",
                styles["Heading3"],
            ))

            if device.ports:
                port_data = [["Port", "Protocol", "Service", "Product/Version", "Risk", "Recommendation"]]
                for p in sorted(device.ports, key=lambda x: x.port_number):
                    port_data.append([
                        str(p.port_number),
                        p.protocol.upper(),
                        p.service,
                        f"{p.product or ''} {p.version or ''}".strip() or "—",
                        p.risk_level,
                        p.recommendation[:80] + "…" if len(p.recommendation) > 80 else p.recommendation,
                    ])
                pt = Table(port_data, colWidths=[1.5*cm, 2*cm, 2.5*cm, 3*cm, 1.5*cm, 5.5*cm])
                pt.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE",   (0, 0), (-1, -1), 7.5),
                    ("PADDING",    (0, 0), (-1, -1), 4),
                    ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                    *[
                        ("BACKGROUND", (0, i+1), (-1, i+1), RISK_COLORS.get(port_data[i+1][4], colors.white))
                        for i in range(len(port_data)-1)
                    ],
                ]))
                story.append(pt)

        doc.build(story)
    except ImportError:
        # Fallback: write plain text if reportlab is missing
        with open(path, "w") as f:
            f.write(f"NetScan Report — {scan.target}\n")
            f.write(f"Devices: {scan.total_hosts}, Open Ports: {scan.open_ports}\n")


# ─────────────────────────────────────────────────────────────────────────────
# JSON export
# ─────────────────────────────────────────────────────────────────────────────

def _generate_json(scan: Scan, path: Path) -> None:
    data = {
        "scan": {
            "uuid": scan.uuid,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status.value,
            "created_at": str(scan.created_at),
            "total_hosts": scan.total_hosts,
            "open_ports": scan.open_ports,
        },
        "devices": [
            {
                "ip": d.ip_address,
                "hostname": d.hostname,
                "os": d.os_guess,
                "overall_risk": d.overall_risk,
                "risk_score": d.risk_score,
                "ports": [
                    {
                        "port": p.port_number,
                        "protocol": p.protocol,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                        "risk_level": p.risk_level,
                        "recommendation": p.recommendation,
                        "cve_hints": json.loads(p.cve_hints or "[]"),
                    }
                    for p in d.ports
                ],
            }
            for d in scan.devices
        ],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


# ─────────────────────────────────────────────────────────────────────────────
# CSV export
# ─────────────────────────────────────────────────────────────────────────────

def _generate_csv(scan: Scan, path: Path) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "IP Address", "Hostname", "OS", "Overall Risk",
            "Port", "Protocol", "Service", "Product", "Version",
            "Risk Level", "Risk Name", "Recommendation",
        ])
        for d in scan.devices:
            for p in d.ports:
                writer.writerow([
                    d.ip_address, d.hostname, d.os_guess or "", d.overall_risk,
                    p.port_number, p.protocol, p.service,
                    p.product or "", p.version or "",
                    p.risk_level, p.risk_name, p.recommendation,
                ])
