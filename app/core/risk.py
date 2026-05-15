"""
app/core/risk.py
────────────────
Risk classification engine.

Each open port/service combination is evaluated against a tiered rule set
to produce a RiskLevel (HIGH | MEDIUM | LOW | INFO) and a human-readable
recommendation.  The engine is intentionally kept pure (no I/O) so it is
fast, deterministic, and easy to unit-test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Enums & Data-classes
# ─────────────────────────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def score(self) -> int:
        return {"High": 3, "Medium": 2, "Low": 1, "Info": 0}[self.value]


@dataclass(frozen=True)
class RiskRule:
    """A single classification rule."""
    name: str
    level: RiskLevel
    description: str
    recommendation: str


@dataclass
class PortRiskResult:
    port: int
    protocol: str
    service: str
    state: str
    risk_level: RiskLevel
    risk_name: str
    description: str
    recommendation: str
    cve_hints: List[str] = field(default_factory=list)


@dataclass
class DeviceRiskSummary:
    ip_address: str
    hostname: str
    overall_risk: RiskLevel
    risk_score: int
    port_results: List[PortRiskResult] = field(default_factory=list)
    open_port_count: int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Rule-sets
# ─────────────────────────────────────────────────────────────────────────────

# Format: port -> RiskRule
# Ports can be exact (21) or evaluated by service-name below.
_PORT_RULES: Dict[int, RiskRule] = {
    # ── Critical / plaintext protocols ──────────────────────────────────────
    21: RiskRule(
        name="FTP",
        level=RiskLevel.HIGH,
        description="FTP transmits credentials in plaintext and is vulnerable to interception.",
        recommendation="Disable FTP. Use SFTP (SSH File Transfer Protocol) or FTPS instead.",
    ),
    23: RiskRule(
        name="Telnet",
        level=RiskLevel.HIGH,
        description="Telnet sends all data including passwords in plaintext over the network.",
        recommendation="Immediately disable Telnet. Replace with SSH on port 22.",
    ),
    69: RiskRule(
        name="TFTP",
        level=RiskLevel.HIGH,
        description="TFTP provides unauthenticated file transfer — frequently abused for lateral movement.",
        recommendation="Disable TFTP unless absolutely required; restrict via firewall if needed.",
    ),
    512: RiskRule(
        name="rexec",
        level=RiskLevel.HIGH,
        description="Remote execution service with minimal authentication.",
        recommendation="Disable rexec. Use SSH for secure remote execution.",
    ),
    513: RiskRule(
        name="rlogin",
        level=RiskLevel.HIGH,
        description="Legacy remote login with no encryption.",
        recommendation="Disable rlogin. Use SSH.",
    ),
    514: RiskRule(
        name="rsh/syslog",
        level=RiskLevel.HIGH,
        description="Remote Shell (rsh) sends data in plaintext and can be exploited for privilege escalation.",
        recommendation="Disable rsh. Use SSH. If this is syslog, restrict to trusted IPs via firewall.",
    ),
    1521: RiskRule(
        name="Oracle DB",
        level=RiskLevel.HIGH,
        description="Oracle database listener exposed — potential for unauthenticated enumeration or exploitation.",
        recommendation="Restrict access to the DB port to authorised application servers only via firewall.",
    ),
    3306: RiskRule(
        name="MySQL/MariaDB",
        level=RiskLevel.HIGH,
        description="Database server exposed to the network. Risk of brute force or SQL injection over the wire.",
        recommendation="Bind MySQL to 127.0.0.1. Use SSH tunnels or a VPN for remote access.",
    ),
    5432: RiskRule(
        name="PostgreSQL",
        level=RiskLevel.HIGH,
        description="PostgreSQL database exposed to the network.",
        recommendation="Bind PostgreSQL to localhost or a private interface. Use SSL and restrict pg_hba.conf.",
    ),
    27017: RiskRule(
        name="MongoDB",
        level=RiskLevel.HIGH,
        description="MongoDB exposed without authentication has been responsible for massive data breaches.",
        recommendation="Enable MongoDB authentication, bind to localhost, and use TLS.",
    ),
    6379: RiskRule(
        name="Redis",
        level=RiskLevel.HIGH,
        description="Redis is often deployed without authentication and can be used for RCE.",
        recommendation="Set a strong Redis password, bind to 127.0.0.1, and disable dangerous commands.",
    ),
    9200: RiskRule(
        name="Elasticsearch",
        level=RiskLevel.HIGH,
        description="Elasticsearch exposed without auth is a known vector for large-scale data exfiltration.",
        recommendation="Enable X-Pack security, restrict network access, and use TLS.",
    ),

    # ── Medium risk ──────────────────────────────────────────────────────────
    22: RiskRule(
        name="SSH",
        level=RiskLevel.MEDIUM,
        description="SSH is secure but exposure increases brute-force attack surface.",
        recommendation="Disable password auth, use key-based auth, enable fail2ban, and consider non-standard port.",
    ),
    80: RiskRule(
        name="HTTP",
        level=RiskLevel.MEDIUM,
        description="Unencrypted HTTP exposes transmitted data to interception.",
        recommendation="Redirect all HTTP traffic to HTTPS. Deploy a valid TLS certificate.",
    ),
    8080: RiskRule(
        name="HTTP-Alt",
        level=RiskLevel.MEDIUM,
        description="Alternate HTTP port — often a development server exposed unintentionally.",
        recommendation="Ensure this is intentional. Restrict to internal networks if it is a dev service.",
    ),
    25: RiskRule(
        name="SMTP",
        level=RiskLevel.MEDIUM,
        description="Open SMTP relay risk — can be abused for spam or email spoofing.",
        recommendation="Restrict SMTP relay, require authentication, enable STARTTLS.",
    ),
    110: RiskRule(
        name="POP3",
        level=RiskLevel.MEDIUM,
        description="POP3 transmits credentials in plaintext.",
        recommendation="Use POP3S (port 995) or migrate to IMAP with TLS.",
    ),
    143: RiskRule(
        name="IMAP",
        level=RiskLevel.MEDIUM,
        description="IMAP without TLS transmits credentials in plaintext.",
        recommendation="Use IMAPS (port 993) with a valid TLS certificate.",
    ),
    2049: RiskRule(
        name="NFS",
        level=RiskLevel.MEDIUM,
        description="NFS exports can be misconfigured to allow unauthorised access to filesystems.",
        recommendation="Restrict NFS exports to trusted IPs. Audit /etc/exports. Use NFSv4 with Kerberos.",
    ),
    3389: RiskRule(
        name="RDP",
        level=RiskLevel.MEDIUM,
        description="RDP exposed to the network is a common ransomware entry point.",
        recommendation="Place RDP behind a VPN. Enable Network Level Authentication (NLA). Restrict by IP.",
    ),
    5900: RiskRule(
        name="VNC",
        level=RiskLevel.MEDIUM,
        description="VNC with weak or no authentication provides full graphical access.",
        recommendation="Never expose VNC directly. Tunnel through SSH. Use strong passwords.",
    ),
    111: RiskRule(
        name="RPC portmapper",
        level=RiskLevel.MEDIUM,
        description="RPC portmapper enables enumeration of all RPC services on the host.",
        recommendation="Block port 111 at the firewall unless NFS/NIS are intentionally required.",
    ),

    # ── Low risk ─────────────────────────────────────────────────────────────
    443: RiskRule(
        name="HTTPS",
        level=RiskLevel.LOW,
        description="HTTPS is the secure web standard. Verify certificate validity and configuration.",
        recommendation="Run ssl-labs or testssl.sh to verify TLS configuration. Keep certificates current.",
    ),
    53: RiskRule(
        name="DNS",
        level=RiskLevel.LOW,
        description="DNS open to external queries may allow zone transfers or amplification attacks.",
        recommendation="Restrict recursive DNS to internal clients. Disable zone transfers to unauthorised IPs.",
    ),
    67: RiskRule(
        name="DHCP",
        level=RiskLevel.LOW,
        description="DHCP server — rogue DHCP servers can redirect traffic.",
        recommendation="Enable DHCP snooping on managed switches. Ensure only one authorised DHCP server exists.",
    ),
    123: RiskRule(
        name="NTP",
        level=RiskLevel.LOW,
        description="NTP can be abused for amplification DDoS.",
        recommendation="Restrict NTP to monlist-safe versions. Disable monlist (noquery option).",
    ),
    161: RiskRule(
        name="SNMP",
        level=RiskLevel.LOW,
        description="SNMP v1/v2 use community strings instead of real authentication.",
        recommendation="Migrate to SNMPv3. Change default community strings. Restrict by IP.",
    ),
    389: RiskRule(
        name="LDAP",
        level=RiskLevel.LOW,
        description="LDAP without TLS exposes directory information.",
        recommendation="Use LDAPS (port 636) or StartTLS. Restrict access to internal networks.",
    ),
    993: RiskRule(
        name="IMAPS",
        level=RiskLevel.LOW,
        description="IMAPS with TLS — ensure certificate is valid and protocol is up to date.",
        recommendation="Ensure TLS 1.2+ only. Disable SSLv3 and TLS 1.0/1.1.",
    ),
    995: RiskRule(
        name="POP3S",
        level=RiskLevel.LOW,
        description="POP3S with TLS — ensure certificate is valid.",
        recommendation="Verify TLS certificate validity and enforce modern cipher suites.",
    ),
}

# Service-name-based rules (fallback when port is not in the table above)
_SERVICE_NAME_RULES: Dict[str, RiskRule] = {
    "ftp": _PORT_RULES[21],
    "telnet": _PORT_RULES[23],
    "tftp": _PORT_RULES[69],
    "ssh": _PORT_RULES[22],
    "smtp": _PORT_RULES[25],
    "http": _PORT_RULES[80],
    "https": _PORT_RULES[443],
    "mysql": _PORT_RULES[3306],
    "postgresql": _PORT_RULES[5432],
    "redis": _PORT_RULES[6379],
    "mongodb": _PORT_RULES[27017],
    "rdp": _PORT_RULES[3389],
    "vnc": _PORT_RULES[5900],
    "snmp": _PORT_RULES[161],
    "ldap": _PORT_RULES[389],
    "nfs": _PORT_RULES[2049],
    "dns": _PORT_RULES[53],
    "ntp": _PORT_RULES[123],
}

# Default rule for ports/services not in the tables above
_DEFAULT_RULE = RiskRule(
    name="Unknown/Other",
    level=RiskLevel.INFO,
    description="Service running on this port was not matched against a known risk pattern.",
    recommendation=(
        "Investigate whether this service is necessary. "
        "If not, disable it and close the port via firewall."
    ),
)

# CVE hints associated with specific port numbers (illustrative)
_CVE_HINTS: Dict[int, List[str]] = {
    21:    ["CVE-2011-0762 (vsftpd backdoor)", "CVE-2010-4221 (ProFTPD RCE)"],
    22:    ["CVE-2018-10933 (libssh auth bypass)", "CVE-2023-38408 (OpenSSH agent)"],
    23:    ["CVE-2011-4862 (Telnetd buffer overflow)"],
    80:    ["CVE-2021-41773 (Apache path traversal)", "CVE-2021-26855 (Exchange SSRF)"],
    3306: ["CVE-2012-2122 (MySQL auth bypass)", "CVE-2016-6662 (MySQL RCE)"],
    3389: ["CVE-2019-0708 (BlueKeep RCE)", "CVE-2020-0609 (RDP gateway RCE)"],
    5432: ["CVE-2019-9193 (PostgreSQL COPY TO/FROM RCE)"],
    6379: ["CVE-2022-0543 (Redis Lua sandbox escape)"],
    27017: ["CVE-2015-7882 (MongoDB unauthenticated access)"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def classify_port(
    port: int,
    protocol: str,
    service: str,
    state: str,
    *,
    banner: Optional[str] = None,
) -> PortRiskResult:
    """
    Classify a single open port and return a PortRiskResult.

    Lookup order:
      1. Exact port number in _PORT_RULES
      2. Service name (lower-cased) in _SERVICE_NAME_RULES
      3. Default INFO rule
    """
    rule = (
        _PORT_RULES.get(port)
        or _SERVICE_NAME_RULES.get(service.lower().split("/")[0])
        or _DEFAULT_RULE
    )

    # Upgrade LOW→MEDIUM if banner leaks a version string
    effective_level = rule.level
    if banner and re.search(r"\d+\.\d+", banner):
        if effective_level == RiskLevel.LOW:
            effective_level = RiskLevel.MEDIUM

    return PortRiskResult(
        port=port,
        protocol=protocol,
        service=service,
        state=state,
        risk_level=effective_level,
        risk_name=rule.name,
        description=rule.description,
        recommendation=rule.recommendation,
        cve_hints=_CVE_HINTS.get(port, []),
    )


def summarise_device(
    ip_address: str,
    hostname: str,
    port_results: List[PortRiskResult],
) -> DeviceRiskSummary:
    """
    Roll up per-port results into an overall device risk summary.
    The device's overall risk is the maximum risk level of any open port.
    """
    if not port_results:
        return DeviceRiskSummary(
            ip_address=ip_address,
            hostname=hostname,
            overall_risk=RiskLevel.INFO,
            risk_score=0,
            port_results=[],
            open_port_count=0,
        )

    total_score = sum(r.risk_level.score for r in port_results)
    max_level = max(port_results, key=lambda r: r.risk_level.score).risk_level

    return DeviceRiskSummary(
        ip_address=ip_address,
        hostname=hostname,
        overall_risk=max_level,
        risk_score=total_score,
        port_results=port_results,
        open_port_count=len(port_results),
    )


def get_risk_color(level: RiskLevel) -> str:
    """Return a Bootstrap-compatible colour class for the given risk level."""
    return {
        RiskLevel.HIGH:   "danger",
        RiskLevel.MEDIUM: "warning",
        RiskLevel.LOW:    "success",
        RiskLevel.INFO:   "secondary",
    }[level]
