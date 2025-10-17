"""Test risk engine functionality."""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.api.services.risk_engine import RiskEngine
from src.api.models.scan_result import ScanResult


class TestRiskEngine:
    """Test risk calculation and analysis."""

    def setUp(self):
        """Set up test data."""
        self.risk_engine = RiskEngine()

    def test_calculate_finding_risk_critical(self):
        """Test risk calculation for critical findings."""
        finding = {
            "severity": "critical",
            "confidence": "high",
            "exploitability": "high",
            "impact": "high",
            "public_exposure": True,
            "compliance_violation": True
        }
        
        risk_score = self.risk_engine.calculate_finding_risk(finding)
        assert risk_score >= 8.5  # Critical findings should have high risk scores
        assert risk_score <= 10.0

    def test_calculate_finding_risk_low(self):
        """Test risk calculation for low severity findings."""
        finding = {
            "severity": "low",
            "confidence": "medium",
            "exploitability": "low",
            "impact": "low",
            "public_exposure": False,
            "compliance_violation": False
        }
        
        risk_score = self.risk_engine.calculate_finding_risk(finding)
        assert risk_score >= 1.0
        assert risk_score <= 4.0  # Low findings should have lower risk scores

    def test_calculate_overall_risk_empty(self):
        """Test overall risk calculation with no findings."""
        scan_results = []
        overall_risk = self.risk_engine.calculate_overall_risk(scan_results)
        
        assert overall_risk["risk_score"] == 0.0
        assert overall_risk["risk_level"] == "minimal"
        assert overall_risk["critical_count"] == 0

    def test_calculate_overall_risk_mixed_findings(self):
        """Test overall risk calculation with mixed severity findings."""
        scan_results = [
            Mock(
                severity="critical",
                risk_score=9.5,
                finding_type="public_s3_bucket",
                resource_id="bucket-1"
            ),
            Mock(
                severity="high",
                risk_score=7.8,
                finding_type="weak_iam_policy",
                resource_id="policy-1"
            ),
            Mock(
                severity="medium",
                risk_score=5.2,
                finding_type="security_group_open",
                resource_id="sg-1"
            ),
            Mock(
                severity="low",
                risk_score=2.1,
                finding_type="unused_key_pair",
                resource_id="key-1"
            )
        ]
        
        overall_risk = self.risk_engine.calculate_overall_risk(scan_results)
        
        assert overall_risk["risk_score"] > 0
        assert overall_risk["critical_count"] == 1
        assert overall_risk["high_count"] == 1
        assert overall_risk["medium_count"] == 1
        assert overall_risk["low_count"] == 1
        assert overall_risk["total_findings"] == 4

    def test_get_risk_level_classification(self):
        """Test risk level classification."""
        assert self.risk_engine._get_risk_level(9.5) == "critical"
        assert self.risk_engine._get_risk_level(7.5) == "high"
        assert self.risk_engine._get_risk_level(5.5) == "medium"
        assert self.risk_engine._get_risk_level(3.5) == "low"
        assert self.risk_engine._get_risk_level(1.0) == "minimal"

    def test_calculate_compliance_score_perfect(self):
        """Test compliance score calculation with perfect compliance."""
        findings = []  # No compliance violations
        score = self.risk_engine.calculate_compliance_score(findings, "cis")
        
        assert score["compliance_percentage"] == 100.0
        assert score["total_controls"] > 0
        assert score["passed_controls"] == score["total_controls"]

    def test_calculate_compliance_score_with_violations(self):
        """Test compliance score with compliance violations."""
        findings = [
            {"compliance_violations": ["CIS-1.1", "CIS-1.2"]},
            {"compliance_violations": ["CIS-2.1"]},
            {"compliance_violations": []}  # No violations
        ]
        
        score = self.risk_engine.calculate_compliance_score(findings, "cis")
        
        assert score["compliance_percentage"] < 100.0
        assert len(score["failed_controls"]) == 3  # CIS-1.1, CIS-1.2, CIS-2.1
        assert score["passed_controls"] < score["total_controls"]

    def test_generate_risk_trends_no_data(self):
        """Test risk trend generation with no historical data."""
        trends = self.risk_engine.generate_risk_trends([])
        
        assert len(trends) == 30  # 30 days of data
        assert all(day["risk_score"] == 0 for day in trends)

    def test_generate_risk_trends_with_data(self):
        """Test risk trend generation with historical data."""
        # Mock scan results over time
        scan_results = []
        for i in range(10):
            scan_date = datetime.utcnow() - timedelta(days=i)
            scan_results.append(
                Mock(
                    created_at=scan_date,
                    risk_score=8.0 - (i * 0.5),  # Decreasing risk over time
                    severity="high" if i < 5 else "medium"
                )
            )
        
        trends = self.risk_engine.generate_risk_trends(scan_results)
        
        assert len(trends) == 30
        # Should have data for the last 10 days
        assert any(day["risk_score"] > 0 for day in trends[:10])

    def test_calculate_security_posture_strong(self):
        """Test security posture calculation for strong security."""
        findings = [
            {"severity": "low", "risk_score": 2.0},
            {"severity": "medium", "risk_score": 4.0}
        ]
        
        posture = self.risk_engine.calculate_security_posture(findings)
        
        assert posture["posture_level"] in ["strong", "good"]
        assert posture["improvement_score"] > 7.0

    def test_calculate_security_posture_weak(self):
        """Test security posture calculation for weak security."""
        findings = [
            {"severity": "critical", "risk_score": 9.5},
            {"severity": "critical", "risk_score": 9.8},
            {"severity": "high", "risk_score": 8.2},
            {"severity": "high", "risk_score": 7.9}
        ]
        
        posture = self.risk_engine.calculate_security_posture(findings)
        
        assert posture["posture_level"] in ["weak", "poor"]
        assert posture["improvement_score"] < 5.0

    def test_get_remediation_priority_critical_public(self):
        """Test remediation priority for critical public findings."""
        finding = {
            "severity": "critical",
            "risk_score": 9.5,
            "public_exposure": True,
            "exploitability": "high",
            "finding_type": "public_s3_bucket"
        }
        
        priority = self.risk_engine.get_remediation_priority(finding)
        
        assert priority["priority_level"] == "immediate"
        assert priority["sla_hours"] <= 4
        assert "public exposure" in priority["reasoning"].lower()

    def test_get_remediation_priority_low_internal(self):
        """Test remediation priority for low severity internal findings."""
        finding = {
            "severity": "low",
            "risk_score": 2.0,
            "public_exposure": False,
            "exploitability": "low",
            "finding_type": "unused_security_group"
        }
        
        priority = self.risk_engine.get_remediation_priority(finding)
        
        assert priority["priority_level"] == "low"
        assert priority["sla_hours"] >= 168  # 1 week
        assert "low risk" in priority["reasoning"].lower()

    def test_calculate_risk_by_service_aws(self):
        """Test risk calculation by AWS service."""
        findings = [
            {"service": "s3", "severity": "critical", "risk_score": 9.0},
            {"service": "s3", "severity": "high", "risk_score": 7.5},
            {"service": "iam", "severity": "medium", "risk_score": 5.0},
            {"service": "ec2", "severity": "low", "risk_score": 2.0}
        ]
        
        risk_by_service = self.risk_engine.calculate_risk_by_service(findings)
        
        assert "s3" in risk_by_service
        assert "iam" in risk_by_service
        assert "ec2" in risk_by_service
        
        assert risk_by_service["s3"]["average_risk"] > risk_by_service["iam"]["average_risk"]
        assert risk_by_service["s3"]["finding_count"] == 2
        assert risk_by_service["iam"]["finding_count"] == 1

    def test_generate_executive_summary(self):
        """Test executive summary generation."""
        scan_results = [
            Mock(
                severity="critical",
                risk_score=9.2,
                finding_type="public_s3_bucket",
                service="s3",
                compliance_violations=["CIS-2.1.1"]
            ),
            Mock(
                severity="high",
                risk_score=7.8,
                finding_type="overprivileged_iam_role",
                service="iam",
                compliance_violations=["CIS-1.16"]
            )
        ]
        
        summary = self.risk_engine.generate_executive_summary(scan_results)
        
        assert "overall_risk_level" in summary
        assert "key_findings" in summary
        assert "recommendations" in summary
        assert "compliance_status" in summary
        
        assert len(summary["key_findings"]) <= 5  # Top 5 findings
        assert len(summary["recommendations"]) > 0

    def test_calculate_mttr_metrics(self):
        """Test MTTR (Mean Time To Remediation) calculation."""
        # Mock alerts with resolution times
        alerts = [
            Mock(
                severity="critical",
                created_at=datetime.utcnow() - timedelta(hours=2),
                resolved_at=datetime.utcnow(),
                status="resolved"
            ),
            Mock(
                severity="high",
                created_at=datetime.utcnow() - timedelta(hours=8),
                resolved_at=datetime.utcnow() - timedelta(hours=2),
                status="resolved"
            ),
            Mock(
                severity="medium",
                created_at=datetime.utcnow() - timedelta(days=1),
                resolved_at=None,  # Still open
                status="open"
            )
        ]
        
        mttr_metrics = self.risk_engine.calculate_mttr_metrics(alerts)
        
        assert "overall_mttr_hours" in mttr_metrics
        assert "by_severity" in mttr_metrics
        assert "resolution_rate" in mttr_metrics
        
        # Should have MTTR data for critical and high
        assert "critical" in mttr_metrics["by_severity"]
        assert "high" in mttr_metrics["by_severity"]
