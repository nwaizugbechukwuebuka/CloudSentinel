"""
Celery Tasks for Alert Management
Handles background processing of security alerts, notifications, and escalations.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from celery import current_app
from sqlalchemy.orm import Session

# Import models and services
from ..api.database import get_db
from ..api.models.alert import Alert
from ..api.models.scan_result import ScanResult
from ..api.services.alert_service import AlertService
from ..api.services.risk_engine import RiskEngine
from ..api.utils.logger import get_logger

logger = get_logger(__name__)

# Initialize services
alert_service = AlertService()
risk_engine = RiskEngine()

@current_app.task(bind=True, max_retries=3)
def process_scan_results_for_alerts(self, scan_id: str) -> Dict[str, Any]:
    """
    Process scan results and generate alerts for high-risk findings.
    
    Args:
        scan_id: ID of the scan to process
        
    Returns:
        Dict containing processing results
    """
    try:
        logger.info(f"Processing scan results for alerts: scan_id={scan_id}")
        
        with next(get_db()) as db:
            # Get scan results
            scan_results = db.query(ScanResult).filter(
                ScanResult.scan_id == scan_id
            ).all()
            
            if not scan_results:
                logger.warning(f"No scan results found for scan_id={scan_id}")
                return {'status': 'no_results', 'alerts_created': 0}
            
            alerts_created = 0
            alerts_updated = 0
            
            for result in scan_results:
                try:
                    # Calculate risk score for the finding
                    risk_score = risk_engine.calculate_finding_risk(
                        severity=result.severity,
                        category=result.category,
                        resource_type=result.resource_type,
                        compliance_violations=result.compliance_violations or [],
                        exposed_to_internet=result.exposed_to_internet,
                        has_encryption=result.encrypted,
                        additional_context={
                            'cloud_provider': result.cloud_provider,
                            'service_name': result.service_name,
                            'region': result.region
                        }
                    )
                    
                    # Create alert if risk score is above threshold
                    if risk_score >= 6.0 or result.severity in ['critical', 'high']:
                        # Check if alert already exists for this finding
                        existing_alert = db.query(Alert).filter(
                            Alert.finding_id == result.id
                        ).first()
                        
                        if existing_alert:
                            # Update existing alert
                            alert_service.update_alert(
                                db=db,
                                alert_id=existing_alert.id,
                                updates={
                                    'risk_score': risk_score,
                                    'last_seen': datetime.utcnow(),
                                    'occurrence_count': existing_alert.occurrence_count + 1
                                }
                            )
                            alerts_updated += 1
                        else:
                            # Create new alert
                            alert_data = {
                                'finding_id': result.id,
                                'title': result.title,
                                'description': result.description,
                                'severity': result.severity,
                                'category': result.category,
                                'cloud_provider': result.cloud_provider,
                                'service_name': result.service_name,
                                'resource_id': result.resource_id,
                                'region': result.region,
                                'risk_score': risk_score,
                                'status': 'open',
                                'priority': _determine_alert_priority(result.severity, risk_score),
                                'tags': _generate_alert_tags(result),
                                'first_seen': datetime.utcnow(),
                                'last_seen': datetime.utcnow(),
                                'occurrence_count': 1
                            }
                            
                            alert_service.create_alert_from_finding(
                                db=db,
                                finding_data=alert_data
                            )
                            alerts_created += 1
                            
                            # Trigger notification if critical
                            if result.severity == 'critical':
                                send_critical_alert_notification.delay(result.id)
                    
                except Exception as e:
                    logger.error(f"Error processing scan result {result.id}: {str(e)}")
                    continue
            
            logger.info(f"Alert processing completed: created={alerts_created}, updated={alerts_updated}")
            
            return {
                'status': 'success',
                'alerts_created': alerts_created,
                'alerts_updated': alerts_updated,
                'scan_results_processed': len(scan_results)
            }
            
    except Exception as exc:
        logger.error(f"Error in process_scan_results_for_alerts: {str(exc)}")
        # Retry with exponential backoff
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)

@current_app.task(bind=True, max_retries=3)
def send_critical_alert_notification(self, finding_id: str) -> Dict[str, Any]:
    """
    Send immediate notification for critical security alerts.
    
    Args:
        finding_id: ID of the finding that triggered the alert
        
    Returns:
        Dict containing notification results
    """
    try:
        logger.info(f"Sending critical alert notification: finding_id={finding_id}")
        
        with next(get_db()) as db:
            # Get the scan result and alert
            scan_result = db.query(ScanResult).filter(ScanResult.id == finding_id).first()
            if not scan_result:
                logger.error(f"Scan result not found: {finding_id}")
                return {'status': 'error', 'message': 'Finding not found'}
            
            alert = db.query(Alert).filter(Alert.finding_id == finding_id).first()
            if not alert:
                logger.error(f"Alert not found for finding: {finding_id}")
                return {'status': 'error', 'message': 'Alert not found'}
            
            # Prepare notification data
            notification_data = {
                'alert_id': alert.id,
                'title': f"CRITICAL SECURITY ALERT: {scan_result.title}",
                'severity': scan_result.severity,
                'cloud_provider': scan_result.cloud_provider,
                'service_name': scan_result.service_name,
                'resource_id': scan_result.resource_id,
                'region': scan_result.region,
                'risk_score': alert.risk_score,
                'description': scan_result.description,
                'remediation_guidance': scan_result.remediation_guidance,
                'created_at': alert.created_at.isoformat(),
                'dashboard_url': f"/alerts/{alert.id}"
            }
            
            # Send notifications through multiple channels
            notification_results = {}
            
            # Email notification
            try:
                email_result = send_email_notification.delay(
                    template='critical_alert',
                    recipients=_get_critical_alert_recipients(),
                    data=notification_data
                )
                notification_results['email'] = 'queued'
            except Exception as e:
                logger.error(f"Failed to queue email notification: {str(e)}")
                notification_results['email'] = 'failed'
            
            # Slack notification
            try:
                slack_result = send_slack_notification.delay(
                    channel='#security-alerts',
                    message=_format_slack_critical_alert(notification_data)
                )
                notification_results['slack'] = 'queued'
            except Exception as e:
                logger.error(f"Failed to queue Slack notification: {str(e)}")
                notification_results['slack'] = 'failed'
            
            # PagerDuty notification
            try:
                pagerduty_result = send_pagerduty_alert.delay(
                    severity='critical',
                    summary=notification_data['title'],
                    source=f"{scan_result.cloud_provider}:{scan_result.service_name}",
                    details=notification_data
                )
                notification_results['pagerduty'] = 'queued'
            except Exception as e:
                logger.error(f"Failed to queue PagerDuty notification: {str(e)}")
                notification_results['pagerduty'] = 'failed'
            
            # Update alert with notification status
            alert_service.update_alert(
                db=db,
                alert_id=alert.id,
                updates={
                    'notifications_sent': True,
                    'last_notification_sent': datetime.utcnow()
                }
            )
            
            return {
                'status': 'success',
                'finding_id': finding_id,
                'alert_id': alert.id,
                'notifications': notification_results
            }
            
    except Exception as exc:
        logger.error(f"Error in send_critical_alert_notification: {str(exc)}")
        raise self.retry(countdown=30 * (2 ** self.request.retries), exc=exc)

@current_app.task
def process_alert_escalations() -> Dict[str, Any]:
    """
    Process alert escalations based on age and severity.
    Runs periodically to escalate unresolved alerts.
    
    Returns:
        Dict containing escalation results
    """
    try:
        logger.info("Processing alert escalations")
        
        with next(get_db()) as db:
            # Define escalation rules
            escalation_rules = [
                {'severity': 'critical', 'age_hours': 2, 'escalation_level': 1},
                {'severity': 'critical', 'age_hours': 4, 'escalation_level': 2},
                {'severity': 'high', 'age_hours': 24, 'escalation_level': 1},
                {'severity': 'high', 'age_hours': 72, 'escalation_level': 2},
                {'severity': 'medium', 'age_hours': 168, 'escalation_level': 1},  # 1 week
            ]
            
            escalated_alerts = 0
            
            for rule in escalation_rules:
                # Calculate cutoff time
                cutoff_time = datetime.utcnow() - timedelta(hours=rule['age_hours'])
                
                # Find alerts that need escalation
                alerts_to_escalate = db.query(Alert).filter(
                    Alert.severity == rule['severity'],
                    Alert.status == 'open',
                    Alert.created_at <= cutoff_time,
                    Alert.escalation_level < rule['escalation_level']
                ).all()
                
                for alert in alerts_to_escalate:
                    # Update escalation level
                    alert_service.update_alert(
                        db=db,
                        alert_id=alert.id,
                        updates={
                            'escalation_level': rule['escalation_level'],
                            'last_escalated': datetime.utcnow()
                        }
                    )
                    
                    # Send escalation notification
                    send_escalation_notification.delay(
                        alert_id=alert.id,
                        escalation_level=rule['escalation_level']
                    )
                    
                    escalated_alerts += 1
                    
                    logger.info(f"Escalated alert {alert.id} to level {rule['escalation_level']}")
            
            return {
                'status': 'success',
                'escalated_alerts': escalated_alerts
            }
            
    except Exception as e:
        logger.error(f"Error in process_alert_escalations: {str(e)}")
        return {'status': 'error', 'message': str(e)}

@current_app.task
def auto_resolve_alerts() -> Dict[str, Any]:
    """
    Automatically resolve alerts based on configured rules.
    
    Returns:
        Dict containing auto-resolution results
    """
    try:
        logger.info("Processing automatic alert resolution")
        
        with next(get_db()) as db:
            resolved_alerts = 0
            
            # Rule 1: Auto-resolve alerts where the underlying finding is no longer present
            # This would require checking recent scans for the same resource
            
            # Rule 2: Auto-resolve low-severity alerts older than 30 days
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            old_low_alerts = db.query(Alert).filter(
                Alert.severity == 'low',
                Alert.status == 'open',
                Alert.created_at <= thirty_days_ago
            ).all()
            
            for alert in old_low_alerts:
                alert_service.update_alert(
                    db=db,
                    alert_id=alert.id,
                    updates={
                        'status': 'auto_resolved',
                        'resolved_at': datetime.utcnow(),
                        'resolution_reason': 'Auto-resolved: Low severity alert older than 30 days'
                    }
                )
                resolved_alerts += 1
            
            # Rule 3: Auto-resolve duplicate alerts (keeping the most recent)
            # Group alerts by resource and finding type
            duplicate_groups = db.query(Alert).filter(
                Alert.status == 'open'
            ).all()
            
            # Group by resource_id and category
            resource_groups = {}
            for alert in duplicate_groups:
                key = f"{alert.resource_id}:{alert.category}"
                if key not in resource_groups:
                    resource_groups[key] = []
                resource_groups[key].append(alert)
            
            # Resolve older duplicates
            for alerts in resource_groups.values():
                if len(alerts) > 1:
                    # Sort by creation time, keep the most recent
                    alerts.sort(key=lambda a: a.created_at, reverse=True)
                    for alert in alerts[1:]:  # Skip the first (most recent)
                        alert_service.update_alert(
                            db=db,
                            alert_id=alert.id,
                            updates={
                                'status': 'auto_resolved',
                                'resolved_at': datetime.utcnow(),
                                'resolution_reason': 'Auto-resolved: Duplicate alert'
                            }
                        )
                        resolved_alerts += 1
            
            logger.info(f"Auto-resolved {resolved_alerts} alerts")
            
            return {
                'status': 'success',
                'resolved_alerts': resolved_alerts
            }
            
    except Exception as e:
        logger.error(f"Error in auto_resolve_alerts: {str(e)}")
        return {'status': 'error', 'message': str(e)}

@current_app.task
def generate_alert_metrics() -> Dict[str, Any]:
    """
    Generate alert metrics and statistics for dashboards and reporting.
    
    Returns:
        Dict containing alert metrics
    """
    try:
        logger.info("Generating alert metrics")
        
        with next(get_db()) as db:
            # Calculate various metrics
            metrics = alert_service.get_alert_statistics(db)
            
            # Calculate additional derived metrics
            total_alerts = metrics.get('total_alerts', 0)
            open_alerts = metrics.get('open_alerts', 0)
            
            # Alert resolution rate
            resolution_rate = ((total_alerts - open_alerts) / total_alerts * 100) if total_alerts > 0 else 0
            
            # Average time to resolution (MTTR)
            mttr = alert_service.calculate_mttr(db)
            
            # Alert volume trends (last 7 days)
            seven_days_ago = datetime.utcnow() - timedelta(days=7)
            recent_alerts = db.query(Alert).filter(
                Alert.created_at >= seven_days_ago
            ).count()
            
            # Critical alert percentage
            critical_alerts = metrics.get('severity_breakdown', {}).get('critical', 0)
            critical_percentage = (critical_alerts / total_alerts * 100) if total_alerts > 0 else 0
            
            enhanced_metrics = {
                **metrics,
                'resolution_rate_percentage': round(resolution_rate, 2),
                'mean_time_to_resolution_hours': round(mttr, 2),
                'alerts_last_7_days': recent_alerts,
                'critical_alert_percentage': round(critical_percentage, 2),
                'generated_at': datetime.utcnow().isoformat()
            }
            
            # Store metrics for dashboard display
            # This could be cached in Redis or stored in a metrics table
            
            return {
                'status': 'success',
                'metrics': enhanced_metrics
            }
            
    except Exception as e:
        logger.error(f"Error in generate_alert_metrics: {str(e)}")
        return {'status': 'error', 'message': str(e)}

@current_app.task(bind=True, max_retries=3)
def send_email_notification(self, template: str, recipients: List[str], data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send email notification for alerts.
    
    Args:
        template: Email template name
        recipients: List of email addresses
        data: Template data
        
    Returns:
        Dict containing send results
    """
    try:
        # This would integrate with your email service (SendGrid, SES, etc.)
        logger.info(f"Sending email notification to {len(recipients)} recipients")
        
        # Mock email sending - replace with actual email service integration
        for recipient in recipients:
            logger.info(f"Would send {template} email to {recipient}")
        
        return {
            'status': 'success',
            'recipients_count': len(recipients),
            'template': template
        }
        
    except Exception as exc:
        logger.error(f"Error sending email notification: {str(exc)}")
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)

@current_app.task(bind=True, max_retries=3)
def send_slack_notification(self, channel: str, message: str) -> Dict[str, Any]:
    """
    Send Slack notification for alerts.
    
    Args:
        channel: Slack channel
        message: Message to send
        
    Returns:
        Dict containing send results
    """
    try:
        # This would integrate with Slack API
        logger.info(f"Sending Slack notification to {channel}")
        
        # Mock Slack sending - replace with actual Slack API integration
        logger.info(f"Would send to {channel}: {message}")
        
        return {
            'status': 'success',
            'channel': channel
        }
        
    except Exception as exc:
        logger.error(f"Error sending Slack notification: {str(exc)}")
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)

@current_app.task(bind=True, max_retries=3)
def send_pagerduty_alert(self, severity: str, summary: str, source: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send PagerDuty alert for critical findings.
    
    Args:
        severity: Alert severity
        summary: Alert summary
        source: Alert source
        details: Alert details
        
    Returns:
        Dict containing send results
    """
    try:
        # This would integrate with PagerDuty API
        logger.info(f"Sending PagerDuty alert: {severity} - {summary}")
        
        # Mock PagerDuty sending - replace with actual PagerDuty API integration
        logger.info(f"Would send PagerDuty alert from {source}")
        
        return {
            'status': 'success',
            'severity': severity,
            'source': source
        }
        
    except Exception as exc:
        logger.error(f"Error sending PagerDuty alert: {str(exc)}")
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)

@current_app.task
def send_escalation_notification(alert_id: str, escalation_level: int) -> Dict[str, Any]:
    """
    Send escalation notification for alerts.
    
    Args:
        alert_id: Alert ID
        escalation_level: New escalation level
        
    Returns:
        Dict containing notification results
    """
    try:
        logger.info(f"Sending escalation notification for alert {alert_id}, level {escalation_level}")
        
        with next(get_db()) as db:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return {'status': 'error', 'message': 'Alert not found'}
            
            # Determine escalation recipients based on level
            recipients = _get_escalation_recipients(escalation_level)
            
            notification_data = {
                'alert_id': alert.id,
                'title': f"ESCALATED ALERT (Level {escalation_level}): {alert.title}",
                'severity': alert.severity,
                'escalation_level': escalation_level,
                'age_hours': (datetime.utcnow() - alert.created_at).total_seconds() / 3600,
                'dashboard_url': f"/alerts/{alert.id}"
            }
            
            # Send escalation email
            send_email_notification.delay(
                template='alert_escalation',
                recipients=recipients,
                data=notification_data
            )
            
            return {
                'status': 'success',
                'alert_id': alert_id,
                'escalation_level': escalation_level
            }
            
    except Exception as e:
        logger.error(f"Error in send_escalation_notification: {str(e)}")
        return {'status': 'error', 'message': str(e)}

# Helper functions

def _determine_alert_priority(severity: str, risk_score: float) -> str:
    """Determine alert priority based on severity and risk score"""
    if severity == 'critical' or risk_score >= 9:
        return 'p1'
    elif severity == 'high' or risk_score >= 7:
        return 'p2'
    elif severity == 'medium' or risk_score >= 5:
        return 'p3'
    else:
        return 'p4'

def _generate_alert_tags(scan_result) -> List[str]:
    """Generate tags for alert based on scan result"""
    tags = [
        scan_result.cloud_provider,
        scan_result.service_name,
        scan_result.severity,
        scan_result.category
    ]
    
    if scan_result.exposed_to_internet:
        tags.append('internet-exposed')
    
    if not scan_result.encrypted:
        tags.append('unencrypted')
    
    if scan_result.compliance_violations:
        tags.extend([f"compliance-{violation}" for violation in scan_result.compliance_violations])
    
    return list(set(tags))  # Remove duplicates

def _get_critical_alert_recipients() -> List[str]:
    """Get email recipients for critical alerts"""
    # This would typically come from configuration or database
    return [
        'security-team@company.com',
        'devops-oncall@company.com',
        'ciso@company.com'
    ]

def _get_escalation_recipients(escalation_level: int) -> List[str]:
    """Get email recipients for escalated alerts"""
    if escalation_level == 1:
        return ['team-lead@company.com', 'security-team@company.com']
    elif escalation_level == 2:
        return ['director@company.com', 'ciso@company.com']
    else:
        return ['ceo@company.com', 'cto@company.com']

def _format_slack_critical_alert(data: Dict[str, Any]) -> str:
    """Format critical alert message for Slack"""
    return f"""
🚨 *CRITICAL SECURITY ALERT* 🚨

*{data['title']}*

• *Provider:* {data['cloud_provider']}
• *Service:* {data['service_name']}
• *Resource:* {data['resource_id']}
• *Region:* {data['region']}
• *Risk Score:* {data['risk_score']}/10

*Description:* {data['description'][:200]}...

<{data['dashboard_url']}|View in Dashboard>
""".strip()
