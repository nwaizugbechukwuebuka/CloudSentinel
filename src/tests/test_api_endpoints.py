"""Test API endpoints functionality."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import Mock, patch
import os

from src.api.main import app
from src.api.database import get_db, Base


# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_api.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture
def auth_token():
    """Create authenticated user and return token."""
    # Register user
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "testpass123",
            "role": "admin"
        }
    )
    
    # Login and get token
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "test@example.com",
            "password": "testpass123"
        }
    )
    return response.json()["access_token"]


class TestHealthEndpoints:
    """Test health and monitoring endpoints."""

    def test_health_check(self):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data

    def test_metrics_endpoint(self):
        """Test metrics endpoint."""
        response = client.get("/metrics")
        assert response.status_code == 200


class TestScanEndpoints:
    """Test scanning endpoints."""

    def test_get_scans_unauthorized(self):
        """Test getting scans without authentication."""
        response = client.get("/api/v1/scan/scans")
        assert response.status_code == 401

    def test_get_scans_authorized(self, auth_token):
        """Test getting scans with authentication."""
        response = client.get(
            "/api/v1/scan/scans",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    @patch('src.api.routes.scan.scan_service.initiate_scan')
    def test_start_scan(self, mock_initiate_scan, auth_token):
        """Test starting a scan."""
        mock_initiate_scan.return_value = {
            "scan_id": "test-scan-123",
            "status": "initiated",
            "cloud_provider": "aws"
        }
        
        response = client.post(
            "/api/v1/scan/start",
            json={
                "cloud_provider": "aws",
                "credentials": {
                    "access_key_id": "test_key",
                    "secret_access_key": "test_secret",
                    "region": "us-east-1"
                },
                "scan_config": {
                    "services": ["s3", "iam", "ec2"],
                    "deep_scan": False
                }
            },
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == "test-scan-123"
        assert data["status"] == "initiated"

    def test_start_scan_invalid_provider(self, auth_token):
        """Test starting scan with invalid provider."""
        response = client.post(
            "/api/v1/scan/start",
            json={
                "cloud_provider": "invalid",
                "credentials": {},
                "scan_config": {}
            },
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400

    def test_get_scan_status_not_found(self, auth_token):
        """Test getting status of non-existent scan."""
        response = client.get(
            "/api/v1/scan/status/non-existent-scan",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 404

    def test_get_scan_results_not_found(self, auth_token):
        """Test getting results of non-existent scan."""
        response = client.get(
            "/api/v1/scan/results/non-existent-scan",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 404

    def test_get_cloud_providers(self, auth_token):
        """Test getting supported cloud providers."""
        response = client.get(
            "/api/v1/scan/providers",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "aws" in data
        assert "azure" in data
        assert "gcp" in data


class TestAlertEndpoints:
    """Test alert endpoints."""

    def test_get_alerts_unauthorized(self):
        """Test getting alerts without authentication."""
        response = client.get("/api/v1/alerts/")
        assert response.status_code == 401

    def test_get_alerts_authorized(self, auth_token):
        """Test getting alerts with authentication."""
        response = client.get(
            "/api/v1/alerts/",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    def test_get_alert_stats(self, auth_token):
        """Test getting alert statistics."""
        response = client.get(
            "/api/v1/alerts/stats",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_alerts" in data
        assert "by_severity" in data
        assert "by_status" in data

    def test_update_alert_status_not_found(self, auth_token):
        """Test updating non-existent alert."""
        response = client.patch(
            "/api/v1/alerts/999/status",
            json={"status": "acknowledged"},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 404

    def test_update_alert_status_invalid(self, auth_token):
        """Test updating alert with invalid status."""
        response = client.patch(
            "/api/v1/alerts/1/status",
            json={"status": "invalid_status"},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 422


class TestReportEndpoints:
    """Test report endpoints."""

    def test_get_dashboard_stats(self, auth_token):
        """Test getting dashboard statistics."""
        response = client.get(
            "/api/v1/reports/dashboard",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "active_alerts" in data
        assert "risk_score" in data
        assert "recent_scans" in data

    def test_get_security_score(self, auth_token):
        """Test getting security score."""
        response = client.get(
            "/api/v1/reports/security-score",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "overall_score" in data
        assert "by_provider" in data
        assert "trends" in data

    def test_get_compliance_report(self, auth_token):
        """Test getting compliance report."""
        response = client.get(
            "/api/v1/reports/compliance?framework=cis",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "framework" in data
        assert "compliance_percentage" in data
        assert "controls" in data

    def test_export_report_csv(self, auth_token):
        """Test exporting report as CSV."""
        response = client.get(
            "/api/v1/reports/export?format=csv&report_type=vulnerabilities",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"

    def test_export_report_json(self, auth_token):
        """Test exporting report as JSON."""
        response = client.get(
            "/api/v1/reports/export?format=json&report_type=alerts",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"

    def test_export_report_invalid_format(self, auth_token):
        """Test exporting report with invalid format."""
        response = client.get(
            "/api/v1/reports/export?format=xml&report_type=alerts",
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 400


class TestErrorHandling:
    """Test error handling across endpoints."""

    def test_404_not_found(self):
        """Test 404 error handling."""
        response = client.get("/api/v1/non-existent-endpoint")
        assert response.status_code == 404

    def test_method_not_allowed(self):
        """Test 405 method not allowed."""
        response = client.delete("/api/v1/scan/scans")
        assert response.status_code == 405

    def test_validation_error(self, auth_token):
        """Test validation error handling."""
        response = client.post(
            "/api/v1/scan/start",
            json={
                "cloud_provider": "",  # Invalid empty provider
                "credentials": {},
                "scan_config": {}
            },
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        assert response.status_code == 422


# Cleanup
def teardown_module():
    """Clean up test database."""
    if os.path.exists("./test_api.db"):
        os.remove("./test_api.db")
