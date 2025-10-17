"""Scan result model for storing cloud security scan results."""

from sqlalchemy import Column, String, Text, Integer, Float, DateTime, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship
from .base import BaseModel
import enum


class CloudProvider(str, enum.Enum):
    """Cloud provider enumeration."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class ScanStatus(str, enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(str, enum.Enum):
    """Risk level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanResult(BaseModel):
    """Model for storing cloud security scan results."""
    
    __tablename__ = "scan_results"
    
    # Scan metadata
    scan_id = Column(String(100), unique=True, index=True, nullable=False)
    provider = Column(Enum(CloudProvider), nullable=False)
    region = Column(String(50))
    account_id = Column(String(50))
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    
    # Scan details
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    resource_name = Column(String(255))
    
    # Vulnerability details
    finding_type = Column(String(100))
    risk_level = Column(Enum(RiskLevel))
    title = Column(String(255))
    description = Column(Text)
    remediation = Column(Text)
    
    # Compliance and scoring
    compliance_frameworks = Column(JSON)  # List of frameworks (CIS, SOC2, etc.)
    risk_score = Column(Float)  # 0-10 scale
    
    # Additional metadata
    tags = Column(JSON)  # Resource tags
    configuration = Column(JSON)  # Resource configuration details
    
    # Relationships
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="scan_results")
    alerts = relationship("Alert", back_populates="scan_result")
    
    def __repr__(self):
        return f"<ScanResult(scan_id='{self.scan_id}', provider='{self.provider}', risk_level='{self.risk_level}')>"
