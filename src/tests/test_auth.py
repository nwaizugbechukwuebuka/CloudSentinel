"""Test authentication functionality."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import tempfile
import os

from src.api.main import app
from src.api.database import get_db, Base
from src.api.services.auth_services import auth_service


# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
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


class TestAuthentication:
    """Test authentication endpoints."""

    def test_register_user(self):
        """Test user registration."""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "test@example.com",
                "username": "testuser",
                "password": "testpass123",
                "full_name": "Test User",
                "role": "viewer"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["username"] == "testuser"
        assert data["role"] == "viewer"

    def test_register_duplicate_user(self):
        """Test registering duplicate user fails."""
        # First registration
        client.post(
            "/api/v1/auth/register",
            json={
                "email": "duplicate@example.com",
                "username": "duplicate",
                "password": "testpass123",
                "role": "viewer"
            }
        )
        
        # Second registration should fail
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "duplicate@example.com",
                "username": "duplicate2",
                "password": "testpass123",
                "role": "viewer"
            }
        )
        assert response.status_code == 400

    def test_login_success(self):
        """Test successful login."""
        # Register user first
        client.post(
            "/api/v1/auth/register",
            json={
                "email": "login@example.com",
                "username": "loginuser",
                "password": "testpass123",
                "role": "analyst"
            }
        )
        
        # Login
        response = client.post(
            "/api/v1/auth/token",
            data={
                "username": "login@example.com",
                "password": "testpass123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user_id" in data
        assert data["role"] == "analyst"

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        response = client.post(
            "/api/v1/auth/token",
            data={
                "username": "nonexistent@example.com",
                "password": "wrongpass"
            }
        )
        assert response.status_code == 401

    def test_get_current_user(self):
        """Test getting current user info."""
        # Register and login
        client.post(
            "/api/v1/auth/register",
            json={
                "email": "current@example.com",
                "username": "currentuser",
                "password": "testpass123",
                "role": "admin"
            }
        )
        
        login_response = client.post(
            "/api/v1/auth/token",
            data={
                "username": "current@example.com",
                "password": "testpass123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Get user info
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "current@example.com"
        assert data["username"] == "currentuser"
        assert data["role"] == "admin"

    def test_get_current_user_unauthorized(self):
        """Test getting current user without token."""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401

    def test_validate_token(self):
        """Test token validation."""
        # Register and login
        client.post(
            "/api/v1/auth/register",
            json={
                "email": "validate@example.com",
                "username": "validateuser",
                "password": "testpass123",
                "role": "viewer"
            }
        )
        
        login_response = client.post(
            "/api/v1/auth/token",
            data={
                "username": "validate@example.com",
                "password": "testpass123"
            }
        )
        token = login_response.json()["access_token"]
        
        # Validate token
        response = client.get(
            "/api/v1/auth/validate",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["email"] == "validate@example.com"


class TestAuthService:
    """Test authentication service functions."""

    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "testpass123"
        hashed = auth_service.get_password_hash(password)
        
        assert hashed != password
        assert auth_service.verify_password(password, hashed)
        assert not auth_service.verify_password("wrongpass", hashed)

    def test_token_creation_and_verification(self):
        """Test JWT token creation and verification."""
        email = "test@example.com"
        token = auth_service.create_access_token(data={"sub": email})
        
        assert token is not None
        verified_email = auth_service.verify_token(token)
        assert verified_email == email

    def test_invalid_token_verification(self):
        """Test verification of invalid token."""
        invalid_token = "invalid.token.here"
        result = auth_service.verify_token(invalid_token)
        assert result is None


# Cleanup
def teardown_module():
    """Clean up test database."""
    if os.path.exists("./test.db"):
        os.remove("./test.db")
