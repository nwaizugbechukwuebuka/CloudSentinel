"""Alert model for security notifications and incident management."""

from sqlalchemy import Column, String, Text, Integer, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from .base import BaseModel
from .scan_result import RiskLevel
import enum


class AlertStatus(str, enum.Enum):
    """Alert status enumeration."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertSeverity(str, enum.Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Alert(BaseModel):
    """Model for security alerts and notifications."""
    
    __tablename__ = "alerts"
    
    # Alert identification
    alert_id = Column(String(100), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Categorization
    severity = Column(Enum(AlertSeverity), nullable=False)
    risk_level = Column(Enum(RiskLevel), nullable=False)
    category = Column(String(100))  # e.g., "misconfiguration", "compliance", "exposure"
    
    # Status management
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    # Assignment
    assigned_user_id = Column(Integer, ForeignKey("users.id"))
    assigned_user = relationship("User", back_populates="alerts")
    
    # Source information
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"))
    scan_result = relationship("ScanResult", back_populates="alerts")
    
    # Remediation
    remediation_steps = Column(Text)
    remediation_priority = Column(Integer)  # 1-5 scale
    
    # Notification tracking
    notification_sent = Column(Boolean, default=False)
    notification_count = Column(Integer, default=0)
    last_notification = Column(DateTime)
    
    def __repr__(self):
        return f"<Alert(alert_id='{self.alert_id}', severity='{self.severity}', status='{self.status}')>"
