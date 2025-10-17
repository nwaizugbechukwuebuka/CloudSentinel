"""Alert API routes for CloudSentinel."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from src.api.database import get_db
from src.api.models.user import User, UserRole
from src.api.models.alert import Alert, AlertStatus, AlertSeverity
from src.api.models.scan_result import RiskLevel
from src.api.services.auth_services import get_current_active_user, require_role
from src.utils.logger import logger

router = APIRouter()


# Pydantic models
class AlertResponse(BaseModel):
    id: int
    alert_id: str
    title: str
    description: str
    severity: str
    risk_level: str
    status: str
    category: str
    is_acknowledged: bool
    remediation_steps: Optional[str]
    remediation_priority: Optional[int]
    created_at: str
    acknowledged_at: Optional[str]
    resolved_at: Optional[str]
    
    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    is_acknowledged: Optional[bool] = None
    assigned_user_id: Optional[int] = None


class AlertFilter(BaseModel):
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    risk_level: Optional[RiskLevel] = None
    category: Optional[str] = None


@router.get("", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[AlertSeverity] = None,
    status: Optional[AlertStatus] = None,
    risk_level: Optional[RiskLevel] = None,
    category: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get alerts with optional filtering."""
    try:
        query = db.query(Alert)
        
        # Filter by user's scan results if not admin
        if current_user.role != UserRole.ADMIN:
            from src.api.models.scan_result import ScanResult
            query = query.join(ScanResult).filter(ScanResult.user_id == current_user.id)
        
        # Apply filters
        if severity:
            query = query.filter(Alert.severity == severity)
        if status:
            query = query.filter(Alert.status == status)
        if risk_level:
            query = query.filter(Alert.risk_level == risk_level)
        if category:
            query = query.filter(Alert.category == category)
        
        # Order by creation date (newest first)
        query = query.order_by(Alert.created_at.desc())
        
        alerts = query.offset(offset).limit(limit).all()
        
        response_data = []
        for alert in alerts:
            response_data.append(AlertResponse(
                id=alert.id,
                alert_id=alert.alert_id,
                title=alert.title,
                description=alert.description,
                severity=alert.severity.value,
                risk_level=alert.risk_level.value,
                status=alert.status.value,
                category=alert.category or "unknown",
                is_acknowledged=alert.is_acknowledged,
                remediation_steps=alert.remediation_steps,
                remediation_priority=alert.remediation_priority,
                created_at=alert.created_at.isoformat(),
                acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None
            ))
        
        return response_data
        
    except Exception as e:
        logger.error("Failed to get alerts", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get alerts: {str(e)}"
        )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific alert by ID."""
    try:
        query = db.query(Alert).filter(Alert.alert_id == alert_id)
        
        # Filter by user's scan results if not admin
        if current_user.role != UserRole.ADMIN:
            from src.api.models.scan_result import ScanResult
            query = query.join(ScanResult).filter(ScanResult.user_id == current_user.id)
        
        alert = query.first()
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        return AlertResponse(
            id=alert.id,
            alert_id=alert.alert_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value,
            risk_level=alert.risk_level.value,
            status=alert.status.value,
            category=alert.category or "unknown",
            is_acknowledged=alert.is_acknowledged,
            remediation_steps=alert.remediation_steps,
            remediation_priority=alert.remediation_priority,
            created_at=alert.created_at.isoformat(),
            acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get alert", error=str(e), alert_id=alert_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get alert: {str(e)}"
        )


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: str,
    alert_update: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ANALYST))
):
    """Update an alert."""
    try:
        query = db.query(Alert).filter(Alert.alert_id == alert_id)
        
        # Filter by user's scan results if not admin
        if current_user.role != UserRole.ADMIN:
            from src.api.models.scan_result import ScanResult
            query = query.join(ScanResult).filter(ScanResult.user_id == current_user.id)
        
        alert = query.first()
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        # Update fields
        if alert_update.status is not None:
            alert.status = alert_update.status
            if alert_update.status == AlertStatus.RESOLVED:
                alert.resolved_at = datetime.utcnow()
        
        if alert_update.is_acknowledged is not None:
            alert.is_acknowledged = alert_update.is_acknowledged
            if alert_update.is_acknowledged:
                alert.acknowledged_at = datetime.utcnow()
            else:
                alert.acknowledged_at = None
        
        if alert_update.assigned_user_id is not None:
            alert.assigned_user_id = alert_update.assigned_user_id
        
        db.commit()
        db.refresh(alert)
        
        logger.info(
            "Alert updated",
            alert_id=alert_id,
            user_id=current_user.id,
            status=alert.status.value
        )
        
        return AlertResponse(
            id=alert.id,
            alert_id=alert.alert_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value,
            risk_level=alert.risk_level.value,
            status=alert.status.value,
            category=alert.category or "unknown",
            is_acknowledged=alert.is_acknowledged,
            remediation_steps=alert.remediation_steps,
            remediation_priority=alert.remediation_priority,
            created_at=alert.created_at.isoformat(),
            acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update alert", error=str(e), alert_id=alert_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update alert: {str(e)}"
        )


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ANALYST))
):
    """Acknowledge an alert."""
    try:
        query = db.query(Alert).filter(Alert.alert_id == alert_id)
        
        # Filter by user's scan results if not admin
        if current_user.role != UserRole.ADMIN:
            from src.api.models.scan_result import ScanResult
            query = query.join(ScanResult).filter(ScanResult.user_id == current_user.id)
        
        alert = query.first()
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        alert.is_acknowledged = True
        alert.acknowledged_at = datetime.utcnow()
        alert.assigned_user_id = current_user.id
        
        db.commit()
        
        logger.info(
            "Alert acknowledged",
            alert_id=alert_id,
            user_id=current_user.id
        )
        
        return {"message": "Alert acknowledged successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to acknowledge alert", error=str(e), alert_id=alert_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to acknowledge alert: {str(e)}"
        )


@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ANALYST))
):
    """Resolve an alert."""
    try:
        query = db.query(Alert).filter(Alert.alert_id == alert_id)
        
        # Filter by user's scan results if not admin
        if current_user.role != UserRole.ADMIN:
            from src.api.models.scan_result import ScanResult
            query = query.join(ScanResult).filter(ScanResult.user_id == current_user.id)
        
        alert = query.first()
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.utcnow()
        alert.assigned_user_id = current_user.id
        
        db.commit()
        
        logger.info(
            "Alert resolved",
            alert_id=alert_id,
            user_id=current_user.id
        )
        
        return {"message": "Alert resolved successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to resolve alert", error=str(e), alert_id=alert_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to resolve alert: {str(e)}"
        )


@router.get("/stats/summary")
async def get_alert_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get alert statistics summary."""
    try:
        from sqlalchemy import func
        
        query = db.query(Alert)
        
        # Filter by user's scan results if not admin
        if current_user.role != UserRole.ADMIN:
            from src.api.models.scan_result import ScanResult
            query = query.join(ScanResult).filter(ScanResult.user_id == current_user.id)
        
        # Total alerts
        total_alerts = query.count()
        
        # Status distribution
        status_stats = query.with_entities(
            Alert.status,
            func.count(Alert.id)
        ).group_by(Alert.status).all()
        
        status_distribution = {status.value: count for status, count in status_stats}
        
        # Severity distribution
        severity_stats = query.with_entities(
            Alert.severity,
            func.count(Alert.id)
        ).group_by(Alert.severity).all()
        
        severity_distribution = {severity.value: count for severity, count in severity_stats}
        
        # Open alerts count
        open_alerts = query.filter(
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING])
        ).count()
        
        return {
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "status_distribution": status_distribution,
            "severity_distribution": severity_distribution
        }
        
    except Exception as e:
        logger.error("Failed to get alert statistics", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get alert statistics: {str(e)}"
        )
