from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import nmap

from app.core.config import settings
from app.core.logging import get_logger
from app.core.risk import RiskLevel, PortRiskResult, classify_port, summarise_device

logger = get_logger(__name__)

# -----------------------------------------------------------------------------
# Portable Nmap PATH injection
# Reads NMAP_PATH from .env so it works on any machine without code changes.
# On Linux: NMAP_PATH=/usr/bin/nmap
# On Windows: NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
# -----------------------------------------------------------------------------

_nmap_dir = os.path.dirname(str(settings.nmap_path))
if _nmap_dir and _nmap_dir not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _nmap_dir
    logger.debug("Injected Nmap directory into PATH: %s", _nmap_dir)


# -----------------------------------------------------------------------------
# Result data-classes (pure Python, no SQLAlchemy)
# -----------------------------------------------------------------------------


@dataclass
class ScannedPort:
    port_number: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str
    banner: str
    cpe: str
    risk_level: str
    risk_name: str
    description: str
    recommendation: str
    cve_hints: str
    is_notable: bool


@dataclass
class ScannedDevice:
    ip_address: str
    hostname: str
    mac_address: str
    vendor: str
    os_guess: str
    os_accuracy: int
    state: str
    overall_risk: str
    risk_score: int
    open_ports: int
    extra_info: str
    ports: List[ScannedPort] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    scan_type: str
    started_at: datetime
    finished_at: datetime
    devices: List[ScannedDevice] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def total_hosts(self) -> int:
        return len(self.devices)

    @property
    def total_open_ports(self) -> int:
        return sum(d.open_ports for d in self.devices)


# -----------------------------------------------------------------------------
# Nmap argument builder
# -----------------------------------------------------------------------------

_SCAN_ARGS: Dict[str, str] = {
    "quick":   "-sV -O --top-ports 1000 -T4",
    "full":    "-sV -O -p 1-65535 -T4",
    "service": "-sV --version-intensity 9 -O --top-ports 1000 -T4",
}

# Fallback locations tried if PATH injection is insufficient
_NMAP_FALLBACK_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
    "/usr/bin",
    "/usr/local/bin",
]


def _build_nmap_args(scan_type: str) -> str:
    args = _SCAN_ARGS.get(scan_type, _SCAN_ARGS["full"])
    args += " -sC"
    return args


def _get_port_scanner() -> nmap.PortScanner:
    """
    Return a PortScanner instance.

    Priority order:
      1. Use PATH as injected from .env NMAP_PATH setting
      2. Try each known fallback installation directory
      3. Raise a clear, human-readable error explaining how to fix it
    """
    try:
        return nmap.PortScanner()
    except nmap.PortScannerError:
        logger.warning("Nmap not found via PATH — trying fallback locations...")

    for path in _NMAP_FALLBACK_PATHS:
        try:
            scanner = nmap.PortScanner(nmap_search_path=(path,))
            os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + path
            logger.info("Found Nmap via fallback path: %s", path)
            return scanner
        except nmap.PortScannerError:
            continue

    raise nmap.PortScannerError(
        "Nmap executable not found. Please install Nmap and set NMAP_PATH "
        "in your .env file to the full path of the nmap executable.\n"
        "  Windows: NMAP_PATH=C:\\Program Files (x86)\\Nmap\\nmap.exe\n"
        "  Linux:   NMAP_PATH=/usr/bin/nmap"
    )


# -----------------------------------------------------------------------------
# Result parser
# -----------------------------------------------------------------------------


def _parse_host(ip: str, host_data: Dict[str, Any]) -> ScannedDevice:
    """Convert a raw python-nmap host dict into a ScannedDevice."""

    hostnames = host_data.get("hostnames", [])
    hostname = hostnames[0].get("name", "") if hostnames else ""
    if not hostname:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ""

    addresses = host_data.get("addresses", {})
    mac = addresses.get("mac", "")
    vendor_data = host_data.get("vendor", {})
    vendor = vendor_data.get(mac, "") if mac else ""

    os_guess = ""
    os_accuracy = 0
    osmatch = host_data.get("osmatch", [])
    if osmatch:
        best = osmatch[0]
        os_guess = best.get("name", "")
        os_accuracy = int(best.get("accuracy", 0))

    state = host_data.get("status", {}).get("state", "up")

    scanned_ports: List[ScannedPort] = []

    for proto in ("tcp", "udp"):
        proto_data = host_data.get(proto, {})
        for port_num_str, port_info in proto_data.items():
            port_num = int(port_num_str)
            port_state = port_info.get("state", "")
            if port_state not in ("open", "open|filtered"):
                continue

            service  = port_info.get("name", "unknown")
            product  = port_info.get("product", "")
            version  = port_info.get("version", "")
            extra    = port_info.get("extrainfo", "")
            cpe      = port_info.get("cpe", "")

            script_data = port_info.get("script", {})
            banner = (
                script_data.get("banner", "")
                or script_data.get("http-title", "")
                or ""
            )[:512]

            risk_result = classify_port(
                port=port_num,
                protocol=proto,
                service=service,
                state=port_state,
                banner=banner or None,
            )

            is_notable = risk_result.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM)

            scanned_ports.append(ScannedPort(
                port_number=port_num,
                protocol=proto,
                state=port_state,
                service=service,
                product=product,
                version=version,
                extra_info=extra,
                banner=banner,
                cpe=cpe,
                risk_level=risk_result.risk_level.value,
                risk_name=risk_result.risk_name,
                description=risk_result.description,
                recommendation=risk_result.recommendation,
                cve_hints=json.dumps(risk_result.cve_hints),
                is_notable=is_notable,
            ))

    port_risk_results = [
        PortRiskResult(
            port=p.port_number,
            protocol=p.protocol,
            service=p.service,
            state=p.state,
            risk_level=RiskLevel(p.risk_level),
            risk_name=p.risk_name,
            description=p.description,
            recommendation=p.recommendation,
            cve_hints=json.loads(p.cve_hints),
        )
        for p in scanned_ports
    ]

    summary = summarise_device(
        ip_address=ip,
        hostname=hostname,
        port_results=port_risk_results,
    )

    return ScannedDevice(
        ip_address=ip,
        hostname=hostname,
        mac_address=mac,
        vendor=vendor,
        os_guess=os_guess,
        os_accuracy=os_accuracy,
        state=state,
        overall_risk=summary.overall_risk.value,
        risk_score=summary.risk_score,
        open_ports=summary.open_port_count,
        extra_info=json.dumps({"osmatch": osmatch[:3]}),
        ports=scanned_ports,
    )


# -----------------------------------------------------------------------------
# Public scanner function
# -----------------------------------------------------------------------------


def run_scan(target: str, scan_type: str = "full") -> ScanResult:
    """
    Execute an Nmap scan synchronously and return a structured ScanResult.

    This is intentionally blocking — call it inside a Celery worker task,
    never directly in an async FastAPI route.

    Parameters
    ----------
    target    : IP address, hostname, or CIDR range (e.g. "192.168.1.0/24")
    scan_type : "quick" | "full" | "service"
    """
    started_at = datetime.now(tz=timezone.utc)
    logger.info("Starting %s scan on target: %s", scan_type, target)

    try:
        nm = _get_port_scanner()
    except nmap.PortScannerError as exc:
        logger.error("Could not initialise Nmap: %s", exc)
        return ScanResult(
            target=target,
            scan_type=scan_type,
            started_at=started_at,
            finished_at=datetime.now(tz=timezone.utc),
            error=str(exc),
        )

    nmap_args = _build_nmap_args(scan_type)

    try:
        nm.scan(
            hosts=target,
            arguments=nmap_args,
            timeout=settings.default_scan_timeout,
        )
    except nmap.PortScannerError as exc:
        logger.error("Nmap scan failed for %s: %s", target, exc)
        return ScanResult(
            target=target,
            scan_type=scan_type,
            started_at=started_at,
            finished_at=datetime.now(tz=timezone.utc),
            error=str(exc),
        )
    except Exception as exc:
        logger.exception("Unexpected error during scan of %s", target)
        return ScanResult(
            target=target,
            scan_type=scan_type,
            started_at=started_at,
            finished_at=datetime.now(tz=timezone.utc),
            error=f"Unexpected error: {exc}",
        )

    devices: List[ScannedDevice] = []
    for ip in nm.all_hosts():
        host_data = nm[ip]
        try:
            device = _parse_host(ip, host_data)
            devices.append(device)
            logger.debug(
                "Parsed host %s: %d open ports, risk=%s",
                ip, device.open_ports, device.overall_risk,
            )
        except Exception:
            logger.exception("Failed to parse host %s — skipping.", ip)

    finished_at = datetime.now(tz=timezone.utc)
    logger.info(
        "Scan of %s complete. Hosts: %d, Open ports: %d, Duration: %.1fs",
        target,
        len(devices),
        sum(d.open_ports for d in devices),
        (finished_at - started_at).total_seconds(),
    )

    return ScanResult(
        target=target,
        scan_type=scan_type,
        started_at=started_at,
        finished_at=finished_at,
        devices=devices,
    )