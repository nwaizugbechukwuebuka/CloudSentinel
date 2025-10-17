"""User model for authentication and authorization."""

from sqlalchemy import Column, String, Boolean, DateTime, Enum
from sqlalchemy.orm import relationship
from .base import BaseModel
import enum


class UserRole(str, enum.Enum):
    """User role enumeration."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(BaseModel):
    """User model for authentication."""
    
    __tablename__ = "users"
    
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100))
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)
    last_login = Column(DateTime)
    
    # Relationships
    alerts = relationship("Alert", back_populates="assigned_user")
    scan_results = relationship("ScanResult", back_populates="user")
    
    def __repr__(self):
        return f"<User(email='{self.email}', username='{self.username}')>"
