"""Alert service for managing security alerts and notifications."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from src.api.models.alert import Alert
from src.api.models.scan_result import ScanResult
from src.api.models.user import User
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AlertService:
    """Service for managing security alerts and notifications."""

    def __init__(self, db: Session):
        self.db = db

    def create_alert_from_finding(
        self, 
        finding: Dict[str, Any], 
        scan_id: str, 
        user_id: int
    ) -> Alert:
        """Create an alert from a security finding."""
        try:
            alert = Alert(
                title=finding.get("title", "Security Issue Detected"),
                description=finding.get("description", ""),
                severity=finding.get("severity", "medium"),
                status="open",
                resource_id=finding.get("resource_id", ""),
                resource_type=finding.get("resource_type", ""),
                service=finding.get("service", ""),
                cloud_provider=finding.get("cloud_provider", ""),
                region=finding.get("region", ""),
                risk_score=finding.get("risk_score", 5.0),
                compliance_violations=finding.get("compliance_violations", []),
                remediation_steps=finding.get("remediation_steps", []),
                scan_id=scan_id,
                finding_id=finding.get("finding_id", ""),
                user_id=user_id,
                created_at=datetime.utcnow(),
                metadata=finding.get("metadata", {})
            )
            
            self.db.add(alert)
            self.db.commit()
            self.db.refresh(alert)
            
            logger.info(f"Created alert {alert.id} for finding {finding.get('finding_id')}")
            return alert
            
        except Exception as e:
            logger.error(f"Error creating alert: {str(e)}")
            self.db.rollback()
            raise

    def get_alerts(
        self,
        user_id: Optional[int] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        service: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get alerts with filtering options."""
        try:
            query = self.db.query(Alert)
            
            # Apply filters
            if user_id:
                query = query.filter(Alert.user_id == user_id)
            if severity:
                query = query.filter(Alert.severity == severity)
            if status:
                query = query.filter(Alert.status == status)
            if service:
                query = query.filter(Alert.service == service)
            if cloud_provider:
                query = query.filter(Alert.cloud_provider == cloud_provider)
            
            # Get total count
            total = query.count()
            
            # Apply pagination
            alerts = query.offset(skip).limit(limit).all()
            
            return {
                "items": alerts,
                "total": total,
                "skip": skip,
                "limit": limit
            }
            
        except Exception as e:
            logger.error(f"Error getting alerts: {str(e)}")
            raise

    def update_alert_status(
        self, 
        alert_id: int, 
        status: str, 
        user_id: Optional[int] = None,
        notes: Optional[str] = None
    ) -> Alert:
        """Update alert status."""
        try:
            alert = self.db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                raise ValueError(f"Alert {alert_id} not found")
            
            alert.status = status
            alert.updated_at = datetime.utcnow()
            
            if status == "acknowledged":
                alert.acknowledged_at = datetime.utcnow()
                alert.acknowledged_by = user_id
            elif status == "resolved":
                alert.resolved_at = datetime.utcnow()
                alert.resolved_by = user_id
            
            if notes:
                alert.notes = notes
            
            self.db.commit()
            self.db.refresh(alert)
            
            logger.info(f"Updated alert {alert_id} status to {status}")
            return alert
            
        except Exception as e:
            logger.error(f"Error updating alert status: {str(e)}")
            self.db.rollback()
            raise

    def bulk_update_alerts(
        self, 
        alert_ids: List[int], 
        updates: Dict[str, Any]
    ) -> int:
        """Bulk update multiple alerts."""
        try:
            query = self.db.query(Alert).filter(Alert.id.in_(alert_ids))
            
            update_data = {
                "updated_at": datetime.utcnow()
            }
            update_data.update(updates)
            
            # Handle special status updates
            if updates.get("status") == "acknowledged":
                update_data["acknowledged_at"] = datetime.utcnow()
            elif updates.get("status") == "resolved":
                update_data["resolved_at"] = datetime.utcnow()
            
            updated_count = query.update(update_data)
            self.db.commit()
            
            logger.info(f"Bulk updated {updated_count} alerts")
            return updated_count
            
        except Exception as e:
            logger.error(f"Error bulk updating alerts: {str(e)}")
            self.db.rollback()
            raise

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics and metrics."""
        try:
            # Total alerts
            total_alerts = self.db.query(Alert).count()
            
            # Alerts by severity
            severity_stats = self.db.query(
                Alert.severity,
                func.count(Alert.id)
            ).group_by(Alert.severity).all()
            
            # Alerts by status
            status_stats = self.db.query(
                Alert.status,
                func.count(Alert.id)
            ).group_by(Alert.status).all()
            
            # Alerts by service
            service_stats = self.db.query(
                Alert.service,
                func.count(Alert.id)
            ).group_by(Alert.service).all()
            
            # Recent alerts (last 24 hours)
            recent_cutoff = datetime.utcnow() - timedelta(hours=24)
            recent_alerts = self.db.query(Alert).filter(
                Alert.created_at >= recent_cutoff
            ).count()
            
            return {
                "total_alerts": total_alerts,
                "by_severity": {severity: count for severity, count in severity_stats},
                "by_status": {status: count for status, count in status_stats},
                "by_service": {service: count for service, count in service_stats},
                "recent_24h": recent_alerts
            }
            
        except Exception as e:
            logger.error(f"Error getting alert statistics: {str(e)}")
            raise

    def get_alerts_by_resource(self, resource_id: str) -> List[Alert]:
        """Get all alerts for a specific resource."""
        try:
            return self.db.query(Alert).filter(
                Alert.resource_id == resource_id
            ).order_by(Alert.created_at.desc()).all()
            
        except Exception as e:
            logger.error(f"Error getting alerts for resource {resource_id}: {str(e)}")
            raise

    def calculate_mttr(self, days: int = 30) -> Dict[str, Any]:
        """Calculate Mean Time To Resolution metrics."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get resolved alerts within the time period
            resolved_alerts = self.db.query(Alert).filter(
                and_(
                    Alert.status == "resolved",
                    Alert.resolved_at >= cutoff_date,
                    Alert.resolved_at.isnot(None),
                    Alert.created_at.isnot(None)
                )
            ).all()
            
            if not resolved_alerts:
                return {
                    "overall_mttr_hours": 0,
                    "by_severity": {},
                    "resolution_rate": 0,
                    "total_resolved": 0
                }
            
            # Calculate resolution times
            resolution_times = []
            by_severity = {}
            
            for alert in resolved_alerts:
                resolution_time = (alert.resolved_at - alert.created_at).total_seconds() / 3600
                resolution_times.append(resolution_time)
                
                if alert.severity not in by_severity:
                    by_severity[alert.severity] = []
                by_severity[alert.severity].append(resolution_time)
            
            # Calculate averages
            overall_mttr = sum(resolution_times) / len(resolution_times)
            severity_mttr = {
                severity: sum(times) / len(times)
                for severity, times in by_severity.items()
            }
            
            # Calculate resolution rate
            total_alerts = self.db.query(Alert).filter(
                Alert.created_at >= cutoff_date
            ).count()
            resolution_rate = (len(resolved_alerts) / total_alerts * 100) if total_alerts > 0 else 0
            
            return {
                "overall_mttr_hours": round(overall_mttr, 2),
                "by_severity": {k: round(v, 2) for k, v in severity_mttr.items()},
                "resolution_rate": round(resolution_rate, 2),
                "total_resolved": len(resolved_alerts)
            }
            
        except Exception as e:
            logger.error(f"Error calculating MTTR: {str(e)}")
            raise

    def get_trending_alerts(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get alert trends over time."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Get daily alert counts
            daily_counts = self.db.query(
                func.date(Alert.created_at).label('date'),
                func.count(Alert.id).label('count')
            ).filter(
                Alert.created_at >= cutoff_date
            ).group_by(
                func.date(Alert.created_at)
            ).order_by('date').all()
            
            # Fill in missing days with zero counts
            trends = []
            current_date = cutoff_date.date()
            end_date = datetime.utcnow().date()
            
            count_dict = {date: count for date, count in daily_counts}
            
            while current_date <= end_date:
                trends.append({
                    "date": current_date.isoformat(),
                    "count": count_dict.get(current_date, 0)
                })
                current_date += timedelta(days=1)
            
            return trends
            
        except Exception as e:
            logger.error(f"Error getting alert trends: {str(e)}")
            raise

    def create_suppression_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert suppression rule."""
        try:
            # In a real implementation, this would create a suppression rule
            # For now, we'll return a mock response
            rule = {
                "id": hash(str(rule_data)) % 10000,
                "name": rule_data.get("name"),
                "conditions": rule_data.get("conditions", {}),
                "created_at": datetime.utcnow().isoformat(),
                "expiry_date": rule_data.get("expiry_date"),
                "is_active": True
            }
            
            logger.info(f"Created suppression rule: {rule['name']}")
            return rule
            
        except Exception as e:
            logger.error(f"Error creating suppression rule: {str(e)}")
            raise

    def check_suppression(self, alert_data: Dict[str, Any]) -> bool:
        """Check if an alert should be suppressed based on rules."""
        try:
            # In a real implementation, this would check against stored suppression rules
            # For now, we'll implement basic logic
            
            # Example: suppress low severity alerts in dev environment
            if (alert_data.get("severity") == "low" and 
                alert_data.get("resource_tags", {}).get("environment") == "dev"):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking suppression: {str(e)}")
            return False

    def get_high_priority_alerts(self, limit: int = 10) -> List[Alert]:
        """Get high priority alerts that need immediate attention."""
        try:
            return self.db.query(Alert).filter(
                and_(
                    Alert.status == "open",
                    or_(
                        Alert.severity == "critical",
                        and_(Alert.severity == "high", Alert.risk_score >= 8.0)
                    )
                )
            ).order_by(
                Alert.risk_score.desc(),
                Alert.created_at.desc()
            ).limit(limit).all()
            
        except Exception as e:
            logger.error(f"Error getting high priority alerts: {str(e)}")
            raise

    def auto_acknowledge_duplicates(self, alert: Alert) -> int:
        """Automatically acknowledge duplicate alerts for the same resource."""
        try:
            # Find similar alerts for the same resource
            duplicate_alerts = self.db.query(Alert).filter(
                and_(
                    Alert.resource_id == alert.resource_id,
                    Alert.finding_id == alert.finding_id,
                    Alert.status == "open",
                    Alert.id != alert.id
                )
            ).all()
            
            acknowledged_count = 0
            for dup_alert in duplicate_alerts:
                dup_alert.status = "acknowledged"
                dup_alert.acknowledged_at = datetime.utcnow()
                dup_alert.notes = f"Auto-acknowledged as duplicate of alert {alert.id}"
                acknowledged_count += 1
            
            if acknowledged_count > 0:
                self.db.commit()
                logger.info(f"Auto-acknowledged {acknowledged_count} duplicate alerts")
            
            return acknowledged_count
            
        except Exception as e:
            logger.error(f"Error auto-acknowledging duplicates: {str(e)}")
            self.db.rollback()
            return 0
