"""Test alert functionality."""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.database import Base
from src.api.services.alert_service import AlertService
from src.api.models.alert import Alert
from src.api.models.user import User


# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_alerts.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


class TestAlertService:
    """Test alert service functionality."""

    def setUp(self):
        """Set up test database session."""
        self.db = TestingSessionLocal()
        self.alert_service = AlertService(self.db)

    def tearDown(self):
        """Clean up test database session."""
        self.db.close()

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_create_alert_from_finding(self, mock_init):
        """Test creating alert from scan finding."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock finding data
        finding = {
            "finding_id": "test-finding-123",
            "severity": "critical", 
            "title": "Public S3 Bucket Detected",
            "description": "S3 bucket 'test-bucket' has public read access",
            "resource_id": "test-bucket",
            "service": "s3",
            "region": "us-east-1",
            "compliance_violations": ["CIS-2.1.1"],
            "risk_score": 9.2
        }
        
        scan_id = "scan-456"
        user_id = 1
        
        # Mock database operations
        alert_service.db.add = Mock()
        alert_service.db.commit = Mock()
        alert_service.db.refresh = Mock()
        
        alert = alert_service.create_alert_from_finding(finding, scan_id, user_id)
        
        assert alert.severity == "critical"
        assert alert.title == "Public S3 Bucket Detected"
        assert alert.resource_id == "test-bucket"
        assert alert.status == "open"
        assert alert.scan_id == scan_id

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_get_alerts_by_severity(self, mock_init):
        """Test getting alerts filtered by severity."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock query result
        mock_alerts = [
            Mock(severity="critical", id=1),
            Mock(severity="critical", id=2),
            Mock(severity="high", id=3)
        ]
        
        alert_service.db.query.return_value.filter.return_value.offset.return_value.limit.return_value.all.return_value = mock_alerts[:2]
        alert_service.db.query.return_value.filter.return_value.count.return_value = 2
        
        result = alert_service.get_alerts(severity="critical", skip=0, limit=10)
        
        assert len(result["items"]) == 2
        assert result["total"] == 2
        assert all(alert.severity == "critical" for alert in result["items"])

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_update_alert_status(self, mock_init):
        """Test updating alert status."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock existing alert
        mock_alert = Mock()
        mock_alert.id = 1
        mock_alert.status = "open"
        mock_alert.acknowledged_at = None
        mock_alert.resolved_at = None
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        alert_service.db.commit = Mock()
        
        # Update to acknowledged
        updated_alert = alert_service.update_alert_status(1, "acknowledged")
        
        assert updated_alert.status == "acknowledged"
        assert updated_alert.acknowledged_at is not None

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_get_alert_statistics(self, mock_init):
        """Test getting alert statistics."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock statistics query results
        mock_total_query = Mock()
        mock_total_query.count.return_value = 25
        
        mock_severity_query = Mock()
        mock_severity_query.all.return_value = [
            ("critical", 5),
            ("high", 8),
            ("medium", 7),
            ("low", 5)
        ]
        
        mock_status_query = Mock()
        mock_status_query.all.return_value = [
            ("open", 15),
            ("acknowledged", 7),
            ("resolved", 3)
        ]
        
        alert_service.db.query.return_value = mock_total_query
        alert_service.db.query.return_value.with_entities.return_value.group_by.return_value.all.side_effect = [
            mock_severity_query.all.return_value,
            mock_status_query.all.return_value
        ]
        
        stats = alert_service.get_alert_statistics()
        
        assert stats["total_alerts"] == 25
        assert stats["by_severity"]["critical"] == 5
        assert stats["by_severity"]["high"] == 8
        assert stats["by_status"]["open"] == 15
        assert stats["by_status"]["resolved"] == 3

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_calculate_mttr(self, mock_init):
        """Test Mean Time To Resolution calculation."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock resolved alerts with resolution times
        now = datetime.utcnow()
        mock_alerts = [
            Mock(
                created_at=now - timedelta(hours=4),
                resolved_at=now - timedelta(hours=2),
                severity="critical"
            ),
            Mock(
                created_at=now - timedelta(hours=12),
                resolved_at=now - timedelta(hours=4),
                severity="high"
            ),
            Mock(
                created_at=now - timedelta(days=2),
                resolved_at=now - timedelta(days=1),
                severity="medium"
            )
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = mock_alerts
        
        mttr = alert_service.calculate_mttr()
        
        assert "overall_mttr_hours" in mttr
        assert "by_severity" in mttr
        assert mttr["overall_mttr_hours"] > 0
        assert "critical" in mttr["by_severity"]

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_get_trending_alerts(self, mock_init):
        """Test getting trending alerts over time."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock alert trends over last 7 days
        now = datetime.utcnow()
        mock_trends = []
        for i in range(7):
            date = now - timedelta(days=i)
            mock_trends.append((date.date(), 10 - i))  # Decreasing trend
        
        alert_service.db.query.return_value.with_entities.return_value.filter.return_value.group_by.return_value.order_by.return_value.all.return_value = mock_trends
        
        trends = alert_service.get_trending_alerts(days=7)
        
        assert len(trends) == 7
        assert all("date" in trend and "count" in trend for trend in trends)

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_bulk_update_alerts(self, mock_init):
        """Test bulk updating multiple alerts."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock alerts to update
        mock_alerts = [
            Mock(id=1, status="open"),
            Mock(id=2, status="open"),
            Mock(id=3, status="open")
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = mock_alerts
        alert_service.db.commit = Mock()
        
        updated_count = alert_service.bulk_update_alerts([1, 2, 3], {"status": "acknowledged"})
        
        assert updated_count == 3
        for alert in mock_alerts:
            assert alert.status == "acknowledged"

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_get_alerts_by_resource(self, mock_init):
        """Test getting alerts for specific resource."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        resource_id = "s3-bucket-123"
        mock_alerts = [
            Mock(resource_id=resource_id, severity="critical"),
            Mock(resource_id=resource_id, severity="high")
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = mock_alerts
        
        alerts = alert_service.get_alerts_by_resource(resource_id)
        
        assert len(alerts) == 2
        assert all(alert.resource_id == resource_id for alert in alerts)

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_create_alert_suppression_rule(self, mock_init):
        """Test creating alert suppression rule."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        rule = {
            "name": "Suppress dev environment alerts",
            "conditions": {
                "resource_tags": {"environment": "dev"},
                "severity": ["low", "info"]
            },
            "expiry_date": datetime.utcnow() + timedelta(days=30)
        }
        
        alert_service.db.add = Mock()
        alert_service.db.commit = Mock()
        
        created_rule = alert_service.create_suppression_rule(rule)
        
        assert created_rule["name"] == rule["name"]
        assert created_rule["conditions"] == rule["conditions"]

    @patch('src.api.services.alert_service.AlertService.__init__')
    def test_check_alert_suppression(self, mock_init):
        """Test checking if alert should be suppressed."""
        mock_init.return_value = None
        alert_service = AlertService(None)
        alert_service.db = Mock()
        
        # Mock suppression rules
        mock_rules = [
            Mock(
                conditions={
                    "resource_tags": {"environment": "dev"},
                    "severity": ["low"]
                },
                expiry_date=datetime.utcnow() + timedelta(days=10)
            )
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = mock_rules
        
        # Test alert that should be suppressed
        alert_data = {
            "severity": "low",
            "resource_tags": {"environment": "dev", "team": "backend"}
        }
        
        is_suppressed = alert_service.check_suppression(alert_data)
        assert is_suppressed is True
        
        # Test alert that should not be suppressed
        alert_data = {
            "severity": "critical",
            "resource_tags": {"environment": "prod"}
        }
        
        is_suppressed = alert_service.check_suppression(alert_data)
        assert is_suppressed is False


# Cleanup
def teardown_module():
    """Clean up test database."""
    import os
    if os.path.exists("./test_alerts.db"):
        os.remove("./test_alerts.db")
