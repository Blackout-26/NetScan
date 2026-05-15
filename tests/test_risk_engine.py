"""
tests/test_risk_engine.py
──────────────────────────
Unit tests for the risk classification engine.
Run with: pytest tests/ -v
"""

import pytest
from app.core.risk import (
    RiskLevel,
    classify_port,
    summarise_device,
    get_risk_color,
)


class TestClassifyPort:
    def test_telnet_is_high_risk(self):
        result = classify_port(23, "tcp", "telnet", "open")
        assert result.risk_level == RiskLevel.HIGH

    def test_ftp_is_high_risk(self):
        result = classify_port(21, "tcp", "ftp", "open")
        assert result.risk_level == RiskLevel.HIGH
        assert result.cve_hints  # should have CVE hints

    def test_ssh_is_medium(self):
        result = classify_port(22, "tcp", "ssh", "open")
        assert result.risk_level == RiskLevel.MEDIUM

    def test_https_is_low(self):
        result = classify_port(443, "tcp", "https", "open")
        assert result.risk_level == RiskLevel.LOW

    def test_unknown_port_is_info(self):
        result = classify_port(54321, "tcp", "unknown", "open")
        assert result.risk_level == RiskLevel.INFO

    def test_banner_with_version_upgrades_low_to_medium(self):
        result = classify_port(443, "tcp", "https", "open", banner="Apache/2.4.51")
        assert result.risk_level == RiskLevel.MEDIUM

    def test_service_name_lookup(self):
        # Port 9999 is not in the table, but service name 'ftp' should match
        result = classify_port(9999, "tcp", "ftp", "open")
        assert result.risk_level == RiskLevel.HIGH

    def test_recommendation_not_empty(self):
        result = classify_port(3389, "tcp", "rdp", "open")
        assert len(result.recommendation) > 10


class TestSummariseDevice:
    def test_empty_device_is_info(self):
        summary = summarise_device("10.0.0.1", "host", [])
        assert summary.overall_risk == RiskLevel.INFO
        assert summary.risk_score == 0

    def test_max_risk_determines_overall(self):
        from app.core.risk import PortRiskResult
        ports = [
            PortRiskResult(1, "tcp", "ssh", "open", RiskLevel.MEDIUM, "SSH", "", ""),
            PortRiskResult(2, "tcp", "telnet", "open", RiskLevel.HIGH, "Telnet", "", ""),
        ]
        summary = summarise_device("10.0.0.1", "host", ports)
        assert summary.overall_risk == RiskLevel.HIGH

    def test_risk_score_is_cumulative(self):
        from app.core.risk import PortRiskResult
        ports = [
            PortRiskResult(1, "tcp", "https", "open", RiskLevel.LOW, "HTTPS", "", ""),
            PortRiskResult(2, "tcp", "ssh", "open", RiskLevel.MEDIUM, "SSH", "", ""),
        ]
        summary = summarise_device("10.0.0.1", "host", ports)
        assert summary.risk_score == RiskLevel.LOW.score + RiskLevel.MEDIUM.score


class TestGetRiskColor:
    def test_high_maps_to_danger(self):
        assert get_risk_color(RiskLevel.HIGH) == "danger"

    def test_low_maps_to_success(self):
        assert get_risk_color(RiskLevel.LOW) == "success"
