"""Report API routes for CloudSentinel."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import io
import csv
import json

from src.api.database import get_db
from src.api.models.user import User, UserRole
from src.api.models.scan_result import ScanResult, CloudProvider, RiskLevel
from src.api.models.alert import Alert
from src.api.services.auth_services import get_current_active_user, require_role
from src.utils.logger import logger

router = APIRouter()


# Pydantic models
class ReportRequest(BaseModel):
    report_type: str  # "security_summary", "compliance", "detailed"
    provider: Optional[CloudProvider] = None
    risk_level: Optional[RiskLevel] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    format: str = "json"  # "json", "csv", "pdf"


class SecuritySummaryResponse(BaseModel):
    total_findings: int
    risk_distribution: Dict[str, int]
    provider_distribution: Dict[str, int]
    resource_type_distribution: Dict[str, int]
    compliance_frameworks: Dict[str, int]
    top_vulnerabilities: List[Dict[str, Any]]
    trend_data: List[Dict[str, Any]]


class ComplianceReportResponse(BaseModel):
    framework: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    compliance_score: float
    findings_by_framework: List[Dict[str, Any]]


@router.post("/generate", response_model=Dict[str, Any])
async def generate_report(
    report_request: ReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Generate a security report."""
    try:
        if report_request.report_type == "security_summary":
            report_data = await _generate_security_summary(db, current_user, report_request)
        elif report_request.report_type == "compliance":
            report_data = await _generate_compliance_report(db, current_user, report_request)
        elif report_request.report_type == "detailed":
            report_data = await _generate_detailed_report(db, current_user, report_request)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid report type"
            )
        
        logger.info(
            "Report generated",
            report_type=report_request.report_type,
            user_id=current_user.id,
            format=report_request.format
        )
        
        return report_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to generate report", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate report: {str(e)}"
        )


async def _generate_security_summary(
    db: Session,
    current_user: User,
    report_request: ReportRequest
) -> Dict[str, Any]:
    """Generate security summary report."""
    
    # Base query
    query = db.query(ScanResult).filter(
        ScanResult.user_id == current_user.id,
        ScanResult.resource_type != "scan_job"
    )
    
    # Apply filters
    if report_request.provider:
        query = query.filter(ScanResult.provider == report_request.provider)
    if report_request.risk_level:
        query = query.filter(ScanResult.risk_level == report_request.risk_level)
    if report_request.date_from:
        query = query.filter(ScanResult.created_at >= report_request.date_from)
    if report_request.date_to:
        query = query.filter(ScanResult.created_at <= report_request.date_to)
    
    findings = query.all()
    
    # Calculate statistics
    total_findings = len(findings)
    
    # Risk distribution
    risk_distribution = {}
    for finding in findings:
        risk = finding.risk_level.value
        risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
    
    # Provider distribution
    provider_distribution = {}
    for finding in findings:
        provider = finding.provider.value
        provider_distribution[provider] = provider_distribution.get(provider, 0) + 1
    
    # Resource type distribution
    resource_type_distribution = {}
    for finding in findings:
        resource_type = finding.resource_type
        resource_type_distribution[resource_type] = resource_type_distribution.get(resource_type, 0) + 1
    
    # Compliance frameworks
    compliance_frameworks = {}
    for finding in findings:
        if finding.compliance_frameworks:
            for framework in finding.compliance_frameworks:
                compliance_frameworks[framework] = compliance_frameworks.get(framework, 0) + 1
    
    # Top vulnerabilities
    vulnerability_types = {}
    for finding in findings:
        vuln_type = finding.finding_type
        if vuln_type not in vulnerability_types:
            vulnerability_types[vuln_type] = {
                "type": vuln_type,
                "count": 0,
                "average_risk_score": 0,
                "total_risk_score": 0
            }
        vulnerability_types[vuln_type]["count"] += 1
        vulnerability_types[vuln_type]["total_risk_score"] += finding.risk_score or 0
    
    # Calculate averages and sort
    for vuln_type, data in vulnerability_types.items():
        if data["count"] > 0:
            data["average_risk_score"] = data["total_risk_score"] / data["count"]
    
    top_vulnerabilities = sorted(
        list(vulnerability_types.values()),
        key=lambda x: x["average_risk_score"],
        reverse=True
    )[:10]
    
    # Trend data (last 30 days)
    trend_data = []
    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=30)
    
    current_date = start_date
    while current_date <= end_date:
        day_findings = [f for f in findings if f.created_at.date() == current_date]
        trend_data.append({
            "date": current_date.isoformat(),
            "findings_count": len(day_findings),
            "critical_count": len([f for f in day_findings if f.risk_level == RiskLevel.CRITICAL]),
            "high_count": len([f for f in day_findings if f.risk_level == RiskLevel.HIGH])
        })
        current_date += timedelta(days=1)
    
    return {
        "report_type": "security_summary",
        "generated_at": datetime.utcnow().isoformat(),
        "user_id": current_user.id,
        "filters": {
            "provider": report_request.provider.value if report_request.provider else None,
            "risk_level": report_request.risk_level.value if report_request.risk_level else None,
            "date_from": report_request.date_from.isoformat() if report_request.date_from else None,
            "date_to": report_request.date_to.isoformat() if report_request.date_to else None
        },
        "summary": {
            "total_findings": total_findings,
            "risk_distribution": risk_distribution,
            "provider_distribution": provider_distribution,
            "resource_type_distribution": resource_type_distribution,
            "compliance_frameworks": compliance_frameworks,
            "top_vulnerabilities": top_vulnerabilities,
            "trend_data": trend_data
        }
    }


async def _generate_compliance_report(
    db: Session,
    current_user: User,
    report_request: ReportRequest
) -> Dict[str, Any]:
    """Generate compliance report."""
    
    # Get findings
    query = db.query(ScanResult).filter(
        ScanResult.user_id == current_user.id,
        ScanResult.resource_type != "scan_job"
    )
    
    # Apply filters
    if report_request.provider:
        query = query.filter(ScanResult.provider == report_request.provider)
    if report_request.date_from:
        query = query.filter(ScanResult.created_at >= report_request.date_from)
    if report_request.date_to:
        query = query.filter(ScanResult.created_at <= report_request.date_to)
    
    findings = query.all()
    
    # Group findings by compliance framework
    frameworks_data = {}
    
    for finding in findings:
        if finding.compliance_frameworks:
            for framework in finding.compliance_frameworks:
                if framework not in frameworks_data:
                    frameworks_data[framework] = {
                        "framework": framework,
                        "total_findings": 0,
                        "critical_findings": 0,
                        "high_findings": 0,
                        "medium_findings": 0,
                        "low_findings": 0,
                        "findings_by_type": {}
                    }
                
                frameworks_data[framework]["total_findings"] += 1
                
                # Count by risk level
                if finding.risk_level == RiskLevel.CRITICAL:
                    frameworks_data[framework]["critical_findings"] += 1
                elif finding.risk_level == RiskLevel.HIGH:
                    frameworks_data[framework]["high_findings"] += 1
                elif finding.risk_level == RiskLevel.MEDIUM:
                    frameworks_data[framework]["medium_findings"] += 1
                elif finding.risk_level == RiskLevel.LOW:
                    frameworks_data[framework]["low_findings"] += 1
                
                # Count by finding type
                finding_type = finding.finding_type
                if finding_type not in frameworks_data[framework]["findings_by_type"]:
                    frameworks_data[framework]["findings_by_type"][finding_type] = 0
                frameworks_data[framework]["findings_by_type"][finding_type] += 1
    
    # Calculate compliance scores (simplified)
    for framework_data in frameworks_data.values():
        total = framework_data["total_findings"]
        critical_high = framework_data["critical_findings"] + framework_data["high_findings"]
        
        if total > 0:
            # Simple scoring: reduce score based on critical/high findings
            compliance_score = max(0, 100 - (critical_high / total) * 100)
            framework_data["compliance_score"] = round(compliance_score, 2)
        else:
            framework_data["compliance_score"] = 100.0
    
    return {
        "report_type": "compliance",
        "generated_at": datetime.utcnow().isoformat(),
        "user_id": current_user.id,
        "filters": {
            "provider": report_request.provider.value if report_request.provider else None,
            "date_from": report_request.date_from.isoformat() if report_request.date_from else None,
            "date_to": report_request.date_to.isoformat() if report_request.date_to else None
        },
        "compliance_data": list(frameworks_data.values())
    }


async def _generate_detailed_report(
    db: Session,
    current_user: User,
    report_request: ReportRequest
) -> Dict[str, Any]:
    """Generate detailed findings report."""
    
    # Get findings
    query = db.query(ScanResult).filter(
        ScanResult.user_id == current_user.id,
        ScanResult.resource_type != "scan_job"
    )
    
    # Apply filters
    if report_request.provider:
        query = query.filter(ScanResult.provider == report_request.provider)
    if report_request.risk_level:
        query = query.filter(ScanResult.risk_level == report_request.risk_level)
    if report_request.date_from:
        query = query.filter(ScanResult.created_at >= report_request.date_from)
    if report_request.date_to:
        query = query.filter(ScanResult.created_at <= report_request.date_to)
    
    findings = query.order_by(ScanResult.risk_score.desc()).all()
    
    # Format findings
    detailed_findings = []
    for finding in findings:
        detailed_findings.append({
            "id": finding.id,
            "scan_id": finding.scan_id,
            "provider": finding.provider.value,
            "region": finding.region,
            "account_id": finding.account_id,
            "resource_type": finding.resource_type,
            "resource_id": finding.resource_id,
            "resource_name": finding.resource_name,
            "finding_type": finding.finding_type,
            "risk_level": finding.risk_level.value,
            "risk_score": finding.risk_score,
            "title": finding.title,
            "description": finding.description,
            "remediation": finding.remediation,
            "compliance_frameworks": finding.compliance_frameworks,
            "tags": finding.tags,
            "configuration": finding.configuration,
            "created_at": finding.created_at.isoformat()
        })
    
    return {
        "report_type": "detailed",
        "generated_at": datetime.utcnow().isoformat(),
        "user_id": current_user.id,
        "filters": {
            "provider": report_request.provider.value if report_request.provider else None,
            "risk_level": report_request.risk_level.value if report_request.risk_level else None,
            "date_from": report_request.date_from.isoformat() if report_request.date_from else None,
            "date_to": report_request.date_to.isoformat() if report_request.date_to else None
        },
        "total_findings": len(detailed_findings),
        "findings": detailed_findings
    }


@router.get("/export/{report_type}")
async def export_report(
    report_type: str,
    format: str = "csv",
    provider: Optional[CloudProvider] = None,
    risk_level: Optional[RiskLevel] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Export report data in various formats."""
    try:
        if format not in ["csv", "json"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported export format"
            )
        
        # Generate report data
        report_request = ReportRequest(
            report_type=report_type,
            provider=provider,
            risk_level=risk_level,
            format=format
        )
        
        if report_type == "detailed":
            report_data = await _generate_detailed_report(db, current_user, report_request)
            findings = report_data["findings"]
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Export only supported for detailed reports"
            )
        
        if format == "csv":
            # Generate CSV
            output = io.StringIO()
            if findings:
                writer = csv.DictWriter(output, fieldnames=findings[0].keys())
                writer.writeheader()
                writer.writerows(findings)
            
            output.seek(0)
            
            return StreamingResponse(
                io.BytesIO(output.getvalue().encode('utf-8')),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=cloudsentinel_{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"}
            )
        
        elif format == "json":
            # Generate JSON
            json_data = json.dumps(report_data, indent=2)
            
            return StreamingResponse(
                io.BytesIO(json_data.encode('utf-8')),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=cloudsentinel_{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"}
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to export report", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export report: {str(e)}"
        )


@router.get("/dashboard/summary")
async def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get dashboard summary data."""
    try:
        from sqlalchemy import func, distinct
        
        # Total scans
        total_scans = db.query(func.count(distinct(ScanResult.scan_id))).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type == "scan_job"
        ).scalar() or 0
        
        # Total findings
        total_findings = db.query(func.count(ScanResult.id)).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type != "scan_job"
        ).scalar() or 0
        
        # Total alerts
        alert_query = db.query(func.count(Alert.id)).join(ScanResult).filter(
            ScanResult.user_id == current_user.id
        )
        total_alerts = alert_query.scalar() or 0
        
        # Open alerts
        open_alerts = alert_query.filter(
            Alert.status.in_(['open', 'investigating'])
        ).scalar() or 0
        
        # Recent scans (last 7 days)
        recent_date = datetime.utcnow() - timedelta(days=7)
        recent_scans = db.query(func.count(distinct(ScanResult.scan_id))).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type == "scan_job",
            ScanResult.created_at >= recent_date
        ).scalar() or 0
        
        # Risk distribution
        risk_query = db.query(
            ScanResult.risk_level,
            func.count(ScanResult.id)
        ).filter(
            ScanResult.user_id == current_user.id,
            ScanResult.resource_type != "scan_job"
        ).group_by(ScanResult.risk_level).all()
        
        risk_distribution = {risk.value: count for risk, count in risk_query}
        
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "recent_scans": recent_scans,
            "risk_distribution": risk_distribution
        }
        
    except Exception as e:
        logger.error("Failed to get dashboard summary", error=str(e), user_id=current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get dashboard summary: {str(e)}"
        )
