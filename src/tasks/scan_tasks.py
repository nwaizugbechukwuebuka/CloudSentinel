"""
Celery Tasks for Security Scanning
Handles background execution of security scans across cloud providers.
"""

import asyncio
import json
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from celery import current_app, group, chain
from sqlalchemy.orm import Session

# Import scanners and services
from ..scanner.aws_scanner import AWSScanner
from ..scanner.azure_scanner import AzureScanner
from ..scanner.gcp_scanner import GCPScanner
from ..scanner.report_builder import ReportBuilder
from ..api.database import get_db
from ..api.models.scan_result import ScanResult
from ..api.models.alert import Alert
from ..api.services.alert_service import AlertService
from ..api.services.risk_engine import RiskEngine
from ..api.utils.logger import get_logger
from ..tasks.alert_tasks import process_scan_results_for_alerts

logger = get_logger(__name__)

# Initialize services
alert_service = AlertService()
risk_engine = RiskEngine()
report_builder = ReportBuilder()

@current_app.task(bind=True, max_retries=3)
def execute_aws_scan(
    self, 
    scan_id: str, 
    access_key: str, 
    secret_key: str, 
    region: str = 'us-east-1',
    services: Optional[List[str]] = None,
    config: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Execute AWS security scan.
    
    Args:
        scan_id: Unique scan identifier
        access_key: AWS access key
        secret_key: AWS secret key
        region: AWS region to scan
        services: List of services to scan (optional)
        config: Additional scan configuration
        
    Returns:
        Dict containing scan results
    """
    try:
        logger.info(f"Starting AWS scan: scan_id={scan_id}, region={region}")
        
        # Update scan status to running
        update_scan_status(scan_id, 'running', {'current_service': 'initializing'})
        
        # Initialize AWS scanner
        scanner = AWSScanner(
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            config=config or {}
        )
        
        # Set up progress callback
        def progress_callback(service: str, progress: float, message: str = ""):
            update_scan_progress(scan_id, service, progress, message)
        
        scanner.set_progress_callback(progress_callback)
        
        # Execute scan
        scan_results = scanner.scan_all_services(services or [])
        
        # Process and store results
        return process_and_store_scan_results(scan_id, 'aws', scan_results)
        
    except Exception as exc:
        logger.error(f"Error in AWS scan {scan_id}: {str(exc)}")
        update_scan_status(scan_id, 'failed', {'error': str(exc), 'traceback': traceback.format_exc()})
        
        # Retry with exponential backoff
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)

@current_app.task(bind=True, max_retries=3)
def execute_azure_scan(
    self,
    scan_id: str,
    subscription_id: str,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    resource_groups: Optional[List[str]] = None,
    config: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Execute Azure security scan.
    """
    try:
        logger.info(f"Starting Azure scan: scan_id={scan_id}, subscription={subscription_id}")
        
        update_scan_status(scan_id, 'running', {'current_service': 'initializing'})
        
        # Initialize Azure scanner
        scanner = AzureScanner(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            config=config or {}
        )
        
        # Set up progress callback
        def progress_callback(service: str, progress: float, message: str = ""):
            update_scan_progress(scan_id, service, progress, message)
        
        scanner.set_progress_callback(progress_callback)
        
        # Execute scan
        scan_results = scanner.scan_all_services(resource_groups or [])
        
        # Process and store results
        return process_and_store_scan_results(scan_id, 'azure', scan_results)
        
    except Exception as exc:
        logger.error(f"Error in Azure scan {scan_id}: {str(exc)}")
        update_scan_status(scan_id, 'failed', {'error': str(exc), 'traceback': traceback.format_exc()})
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)

@current_app.task(bind=True, max_retries=3)
def execute_gcp_scan(
    self,
    scan_id: str,
    project_id: str,
    service_account_path: str,
    regions: Optional[List[str]] = None,
    config: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Execute GCP security scan.
    """
    try:
        logger.info(f"Starting GCP scan: scan_id={scan_id}, project={project_id}")
        
        update_scan_status(scan_id, 'running', {'current_service': 'initializing'})
        
        # Initialize GCP scanner
        scanner = GCPScanner(
            project_id=project_id,
            service_account_path=service_account_path,
            config=config or {}
        )
        
        # Set up progress callback
        def progress_callback(service: str, progress: float, message: str = ""):
            update_scan_progress(scan_id, service, progress, message)
        
        scanner.set_progress_callback(progress_callback)
        
        # Execute scan
        scan_results = scanner.scan_all_services(regions or [])
        
        # Process and store results
        return process_and_store_scan_results(scan_id, 'gcp', scan_results)
        
    except Exception as exc:
        logger.error(f"Error in GCP scan {scan_id}: {str(exc)}")
        update_scan_status(scan_id, 'failed', {'error': str(exc), 'traceback': traceback.format_exc()})
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=exc)

@current_app.task
def execute_multi_cloud_scan(scan_configs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Execute security scans across multiple cloud providers in parallel.
    """
    try:
        logger.info(f"Starting multi-cloud scan with {len(scan_configs)} providers")
        
        # Create parallel scan tasks
        scan_tasks = []
        
        for config in scan_configs:
            provider = config.get('provider')
            scan_id = config.get('scan_id')
            
            if provider == 'aws':
                task = execute_aws_scan.s(
                    scan_id=scan_id,
                    access_key=config.get('access_key'),
                    secret_key=config.get('secret_key'),
                    region=config.get('region', 'us-east-1'),
                    services=config.get('services'),
                    config=config.get('config')
                )
            elif provider == 'azure':
                task = execute_azure_scan.s(
                    scan_id=scan_id,
                    subscription_id=config.get('subscription_id'),
                    tenant_id=config.get('tenant_id'),
                    client_id=config.get('client_id'),
                    client_secret=config.get('client_secret'),
                    resource_groups=config.get('resource_groups'),
                    config=config.get('config')
                )
            elif provider == 'gcp':
                task = execute_gcp_scan.s(
                    scan_id=scan_id,
                    project_id=config.get('project_id'),
                    service_account_path=config.get('service_account_path'),
                    regions=config.get('regions'),
                    config=config.get('config')
                )
            else:
                logger.warning(f"Unsupported provider: {provider}")
                continue
            
            scan_tasks.append(task)
        
        # Execute scans in parallel
        job = group(scan_tasks)
        result = job.apply_async()
        
        # Wait for all scans to complete
        scan_results = result.get()
        
        # Aggregate results
        total_findings = sum(r.get('total_findings', 0) for r in scan_results)
        avg_risk_scores = [r.get('avg_risk_score', 0) for r in scan_results if r.get('avg_risk_score')]
        overall_avg_risk = sum(avg_risk_scores) / len(avg_risk_scores) if avg_risk_scores else 0
        
        # Combine severity breakdowns
        combined_severity = {}
        for result in scan_results:
            severity_breakdown = result.get('severity_breakdown', {})
            for severity, count in severity_breakdown.items():
                combined_severity[severity] = combined_severity.get(severity, 0) + count
        
        logger.info(f"Multi-cloud scan completed: total_findings={total_findings}")
        
        return {
            'status': 'success',
            'provider_results': scan_results,
            'total_findings': total_findings,
            'overall_avg_risk_score': round(overall_avg_risk, 2),
            'combined_severity_breakdown': combined_severity,
            'scan_count': len(scan_results)
        }
        
    except Exception as e:
        logger.error(f"Error in multi-cloud scan: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

@current_app.task
def generate_scan_report(scan_id: str, report_type: str = 'detailed', output_format: str = 'pdf') -> Dict[str, Any]:
    """
    Generate report for completed scan.
    """
    try:
        logger.info(f"Generating {report_type} report for scan {scan_id}")
        
        with next(get_db()) as db:
            # Get scan results
            scan_results = db.query(ScanResult).filter(
                ScanResult.scan_id == scan_id
            ).all()
            
            if not scan_results:
                return {
                    'status': 'error',
                    'message': f'No scan results found for scan_id: {scan_id}'
                }
            
            # Prepare data for report
            scan_data = [{'scan_id': scan_id, 'created_at': scan_results[0].created_at}]
            findings_data = [
                {
                    'id': result.id,
                    'title': result.title,
                    'description': result.description,
                    'severity': result.severity,
                    'category': result.category,
                    'cloud_provider': result.cloud_provider,
                    'service_name': result.service_name,
                    'resource_id': result.resource_id,
                    'region': result.region,
                    'risk_score': result.risk_score,
                    'created_at': result.created_at.isoformat(),
                    'compliance_violations': result.compliance_violations,
                    'remediation_guidance': result.remediation_guidance
                }
                for result in scan_results
            ]
            
            # Create report metadata
            from ..scanner.report_builder import ReportMetadata
            metadata = ReportMetadata(
                title=f"Security Scan Report - {scan_id}",
                subtitle=f"{report_type.title()} Security Analysis",
                generated_at=datetime.utcnow().isoformat(),
                scan_period_start=min(r.created_at for r in scan_results).isoformat(),
                scan_period_end=max(r.created_at for r in scan_results).isoformat(),
                cloud_providers=list(set(r.cloud_provider for r in scan_results)),
                total_scans=1,
                total_findings=len(scan_results),
                report_type=report_type
            )
            
            # Generate report based on type
            if report_type == 'executive':
                report_path = report_builder.generate_executive_summary_report(
                    scan_data=scan_data,
                    findings_data=findings_data,
                    metadata=metadata,
                    output_format=output_format
                )
            elif report_type == 'detailed':
                report_path = report_builder.generate_detailed_technical_report(
                    scan_data=scan_data,
                    findings_data=findings_data,
                    metadata=metadata,
                    include_remediation=True,
                    output_format=output_format
                )
            else:
                return {
                    'status': 'error',
                    'message': f'Unsupported report type: {report_type}'
                }
            
            logger.info(f"Report generated successfully: {report_path}")
            
            return {
                'status': 'success',
                'scan_id': scan_id,
                'report_type': report_type,
                'output_format': output_format,
                'report_path': report_path,
                'findings_count': len(findings_data)
            }
            
    except Exception as e:
        logger.error(f"Error generating scan report: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }

# Helper functions

def process_and_store_scan_results(scan_id: str, provider: str, scan_results: List[Dict]) -> Dict[str, Any]:
    """
    Process and store scan results in database.
    """
    stored_results = []
    risk_scores = []
    
    with next(get_db()) as db:
        for result in scan_results:
            try:
                # Calculate risk score
                risk_score = risk_engine.calculate_finding_risk(
                    severity=result.get('severity'),
                    category=result.get('category'),
                    resource_type=result.get('resource_type'),
                    compliance_violations=result.get('compliance_violations', []),
                    exposed_to_internet=result.get('exposed_to_internet', False),
                    has_encryption=result.get('encrypted', False),
                    additional_context={
                        'cloud_provider': provider,
                        'service_name': result.get('service_name'),
                        'region': result.get('region')
                    }
                )
                risk_scores.append(risk_score)
                
                # Create scan result record
                scan_result = ScanResult(
                    scan_id=scan_id,
                    cloud_provider=provider,
                    service_name=result.get('service_name'),
                    resource_type=result.get('resource_type'),
                    resource_id=result.get('resource_id'),
                    region=result.get('region'),
                    title=result.get('title'),
                    description=result.get('description'),
                    severity=result.get('severity'),
                    category=result.get('category'),
                    finding_type=result.get('finding_type'),
                    risk_score=risk_score,
                    raw_data=result,
                    compliance_violations=result.get('compliance_violations', []),
                    remediation_guidance=result.get('remediation_guidance'),
                    exposed_to_internet=result.get('exposed_to_internet', False),
                    encrypted=result.get('encrypted', False),
                    created_at=datetime.utcnow()
                )
                
                db.add(scan_result)
                stored_results.append(scan_result)
                
            except Exception as e:
                logger.error(f"Error storing scan result: {str(e)}")
                continue
        
        db.commit()
    
    # Calculate metrics
    total_findings = len(stored_results)
    avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    
    severity_counts = {}
    for result in stored_results:
        severity = result.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Update scan status
    scan_metadata = {
        'total_findings': total_findings,
        'avg_risk_score': round(avg_risk_score, 2),
        'severity_breakdown': severity_counts,
        'services_scanned': list(set([r.service_name for r in stored_results]))
    }
    
    update_scan_status(scan_id, 'completed', scan_metadata)
    
    # Trigger alert processing
    process_scan_results_for_alerts.delay(scan_id)
    
    logger.info(f"{provider.upper()} scan completed: scan_id={scan_id}, findings={total_findings}")
    
    return {
        'status': 'success',
        'scan_id': scan_id,
        'total_findings': total_findings,
        'avg_risk_score': avg_risk_score,
        'severity_breakdown': severity_counts
    }

def update_scan_status(scan_id: str, status: str, metadata: Dict[str, Any]) -> None:
    """Update scan status and metadata"""
    # This would update a scan status table/cache
    logger.info(f"Scan {scan_id} status updated to {status}")
    # Implementation would depend on your scan tracking mechanism

def update_scan_progress(scan_id: str, service: str, progress: float, message: str) -> None:
    """Update scan progress"""
    logger.info(f"Scan {scan_id} progress: {service} {progress:.1f}% - {message}")
    # This would update real-time progress tracking
